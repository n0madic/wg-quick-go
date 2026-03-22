package utils

import (
	"fmt"
	"net"
	"strings"
)

// SetupRoutesCommon implements the common route setup logic used across all platforms
func SetupRoutesCommon(interfaceName string, allowedIPs []net.IPNet, table string, outputParser *OutputParser,
	cmdRunner interface {
		RunWithOutput(command string, args ...string) ([]byte, error)
	},
	getAllowedIPsFunc func() ([]net.IPNet, error),
	addRouteFunc func(net.IPNet) error) error {

	if table == "off" {
		return nil
	}

	// Get allowed IPs from wg if not provided
	if len(allowedIPs) == 0 {
		var err error
		allowedIPs, err = getAllowedIPsFunc()
		if err != nil {
			return err
		}
	}

	// Sort by mask size (more specific first)
	SortAllowedIPsBySpecificity(allowedIPs)

	for _, allowedIP := range allowedIPs {
		if err := addRouteFunc(allowedIP); err != nil {
			return fmt.Errorf("failed to add route %s: %w", allowedIP.String(), err)
		}
	}

	return nil
}

// AddDefaultRouteOverrideBSD implements the BSD-style default route override using split routing
func AddDefaultRouteOverrideBSD(interfaceName string, route net.IPNet,
	cmdRunner interface {
		Run(command string, args ...string) error
	}) error {

	isIPv4, _, _ := GetIPProtocolInfo(route)

	var family string
	if isIPv4 {
		family = "-inet"
	} else {
		family = "-inet6"
	}

	if isIPv4 {
		// Add 0.0.0.0/1 and 128.0.0.0/1 to override 0.0.0.0/0
		if err := cmdRunner.Run("route", "add", family, "0.0.0.0/1", "-interface", interfaceName); err != nil {
			return err
		}
		return cmdRunner.Run("route", "add", family, "128.0.0.0/1", "-interface", interfaceName)
	} else {
		// Add ::/1 and 8000::/1 to override ::/0
		if err := cmdRunner.Run("route", "add", family, "::/1", "-interface", interfaceName); err != nil {
			return err
		}
		return cmdRunner.Run("route", "add", family, "8000::/1", "-interface", interfaceName)
	}
}

// CheckRouteExistsBSD checks if a route already exists using BSD-style route commands
func CheckRouteExistsBSD(route net.IPNet, interfaceName string, useQuietFlag bool,
	cmdRunner interface {
		RunWithOutput(command string, args ...string) ([]byte, error)
	}) bool {

	isIPv4, _, _ := GetIPProtocolInfo(route)

	var family string
	if isIPv4 {
		family = "-inet"
	} else {
		family = "-inet6"
	}

	var args []string
	if useQuietFlag {
		args = []string{"-n", "get", family, route.String()}
	} else {
		args = []string{family, "get", route.String()}
	}

	checkOutput, err := cmdRunner.RunWithOutput("route", args...)
	if err != nil {
		return false
	}

	return strings.Contains(string(checkOutput), interfaceName)
}

// CheckBSDRoutingTableInUse checks if routing table is in use (BSD systems)
func CheckBSDRoutingTableInUse(table int, useTableFlag bool,
	cmdRunner interface {
		RunWithOutput(command string, args ...string) ([]byte, error)
	}) bool {

	var args []string
	if useTableFlag {
		args = []string{"-rn", "-T", fmt.Sprintf("%d", table)}
	} else {
		args = []string{"-rn", "-F", fmt.Sprintf("%d", table)}
	}

	output, err := cmdRunner.RunWithOutput("netstat", args...)
	if err != nil {
		return false
	}

	// If there are routes in this table, it's in use
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "Routing") && !strings.HasPrefix(line, "Destination") {
			return true
		}
	}

	return false
}

// RouteGetMTUForEndpoint gets MTU for route to endpoint using platform-appropriate commands
func RouteGetMTUForEndpoint(endpoint string, useBSDRoute bool, useQuietFlag bool,
	cmdRunner interface {
		RunWithOutput(command string, args ...string) ([]byte, error)
	}) (int, error) {

	host, err := ParseEndpointHost(endpoint)
	if err != nil {
		return 0, err
	}

	// Build route command args based on platform
	var args []string
	if useBSDRoute {
		if useQuietFlag {
			args = []string{"-n", "get", host}
		} else {
			args = []string{"get", host}
		}
	} else {
		// Linux style (though this function is primarily for BSD)
		args = []string{"get", host}
	}

	output, err := cmdRunner.RunWithOutput("route", args...)
	if err != nil {
		return 1500, nil // Default MTU
	}

	// Extract interface from route output using shared parsing logic
	var intf string
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				intf = parts[1]
				break
			}
		}
	}

	if intf == "" {
		return 1500, nil
	}

	// Get interface MTU
	ifconfigOutput, err := cmdRunner.RunWithOutput("ifconfig", intf)
	if err != nil {
		return 1500, nil
	}

	if mtu, err := ParseMTUFromOutput(ifconfigOutput); err == nil && mtu > 0 {
		return mtu, nil
	}

	return 1500, nil
}
