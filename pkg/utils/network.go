package utils

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ParseMTUFromOutput extracts MTU value from command output
func ParseMTUFromOutput(output []byte) (int, error) {
	re := regexp.MustCompile(`mtu (\d+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) > 1 {
		return strconv.Atoi(matches[1])
	}
	return 0, nil
}

// GetIPProtocolInfo returns protocol information for an IP address
func GetIPProtocolInfo(addr net.IPNet) (isIPv4 bool, linuxProto string, bsdProto string) {
	isIPv4 = addr.IP.To4() != nil
	if isIPv4 {
		return true, "-4", "inet"
	}
	return false, "-6", "inet6"
}

// ParseAllowedIPsFromWgOutput extracts allowed IPs from wg show output
func ParseAllowedIPsFromWgOutput(output []byte, outputParser *OutputParser) ([]net.IPNet, error) {
	var allowedIPs []net.IPNet
	ipData := outputParser.ParseRegex(output, `(?P<ip>[0-9a-f:.]+/\d+)`)

	for _, data := range ipData {
		if ipStr, exists := data["ip"]; exists {
			_, ipnet, err := net.ParseCIDR(ipStr)
			if err != nil {
				continue
			}
			allowedIPs = append(allowedIPs, *ipnet)
		}
	}

	return allowedIPs, nil
}

// ParseEndpointHost extracts host from endpoint string
func ParseEndpointHost(endpoint string) (string, error) {
	host, _, err := net.SplitHostPort(endpoint)
	return host, err
}

// ParseIPAddressesFromOutput extracts IP addresses from command output using regex
func ParseIPAddressesFromOutput(output []byte, pattern string) []string {
	re := regexp.MustCompile(pattern)
	matches := re.FindAllString(string(output), -1)

	var result []string
	for _, match := range matches {
		match = strings.TrimSpace(match)
		if match != "" {
			result = append(result, match)
		}
	}

	return result
}

// DefaultRouteInfo contains gateway and interface information from default route
type DefaultRouteInfo struct {
	Gateway   string
	Interface string
}

// GetDefaultRouteInfoBSD gets both gateway and interface from BSD route command in one call
func GetDefaultRouteInfoBSD(cmdRunner interface {
	RunWithOutput(command string, args ...string) ([]byte, error)
}) (*DefaultRouteInfo, error) {
	output, err := cmdRunner.RunWithOutput("route", "-n", "get", "default")
	if err != nil {
		return nil, fmt.Errorf("failed to get default route: %w", err)
	}

	info := &DefaultRouteInfo{}
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Parse gateway line: "gateway: 192.168.1.1"
		if strings.HasPrefix(line, "gateway:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				info.Gateway = parts[1]
			}
		}

		// Parse interface line: "interface: en0"
		if strings.HasPrefix(line, "interface:") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				info.Interface = parts[1]
			}
		}
	}

	// Validate that we found both pieces of information
	if info.Gateway == "" {
		return nil, fmt.Errorf("default gateway not found in route output")
	}
	if info.Interface == "" {
		return nil, fmt.Errorf("default interface not found in route output")
	}

	return info, nil
}

// CalculateOptimalMTUFromInterface calculates MTU based on interface MTU minus overhead
func CalculateOptimalMTUFromInterface(interfaceName string, overhead int, cmdRunner interface {
	RunWithOutput(command string, args ...string) ([]byte, error)
}) (int, error) {
	ifconfigOutput, err := cmdRunner.RunWithOutput("ifconfig", interfaceName)
	if err != nil {
		return 1420, fmt.Errorf("failed to get interface MTU: %w", err)
	}

	mtu, err := ParseMTUFromOutput(ifconfigOutput)
	if err != nil || mtu == 0 {
		return 1420, fmt.Errorf("could not determine interface MTU")
	}

	return mtu - overhead, nil
}

// CalculateOptimalMTUFromDefaultRoute calculates MTU based on default route interface
func CalculateOptimalMTUFromDefaultRoute(useBSDRoute bool, cmdRunner interface {
	RunWithOutput(command string, args ...string) ([]byte, error)
}) (int, error) {
	var defaultIntf string
	var err error

	if useBSDRoute {
		// Use unified BSD route command for macOS - more efficient single call
		routeInfo, routeErr := GetDefaultRouteInfoBSD(cmdRunner)
		if routeErr != nil {
			return 1420, routeErr
		}
		defaultIntf = routeInfo.Interface
	} else {
		// Use netstat for FreeBSD/OpenBSD
		output, netstatErr := cmdRunner.RunWithOutput("netstat", "-rn", "-f", "inet")
		if netstatErr != nil {
			return 1420, netstatErr
		}
		defaultIntf, err = ParseNetstatDefaultRoute(output)
		if err != nil {
			return 1420, fmt.Errorf("could not determine default interface: %w", err)
		}
	}

	return CalculateOptimalMTUFromInterface(defaultIntf, 80, cmdRunner)
}

// CalculateOptimalMTUMaxOfEndpoints calculates MTU using MAX-of-endpoints strategy.
// This matches the original FreeBSD/OpenBSD bash behavior: iterate all peer endpoints,
// find the route interface for each, get its MTU, and take the maximum.
func CalculateOptimalMTUMaxOfEndpoints(interfaceName string, cmdRunner interface {
	RunWithOutput(command string, args ...string) ([]byte, error)
}) (int, error) {
	output, err := cmdRunner.RunWithOutput("wg", "show", interfaceName, "endpoints")
	if err != nil {
		return 0, err
	}

	endpointRe := regexp.MustCompile(`\[?([a-z0-9:.]+)\]?:\d+`)
	interfaceRe := regexp.MustCompile(`(?m)^\s*interface:\s*(\S+)`)
	maxMTU := 0

	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		matches := endpointRe.FindStringSubmatch(fields[1])
		if len(matches) < 2 {
			continue
		}

		host := matches[1]
		family := "-inet"
		if strings.Contains(host, ":") {
			family = "-inet6"
		}

		// Get route info for this endpoint
		routeOut, err := cmdRunner.RunWithOutput("route", "-n", "get", family, host)
		if err != nil {
			continue
		}

		ifMatches := interfaceRe.FindStringSubmatch(string(routeOut))
		if len(ifMatches) < 2 {
			continue
		}
		intf := ifMatches[1]

		// Get interface MTU
		ifOut, err := cmdRunner.RunWithOutput("ifconfig", intf)
		if err != nil {
			continue
		}

		mtu, err := ParseMTUFromOutput(ifOut)
		if err == nil && mtu > maxMTU {
			maxMTU = mtu
		}
	}

	if maxMTU == 0 {
		return 0, fmt.Errorf("no endpoint MTU found")
	}

	return maxMTU - 80, nil
}

// ParseNetstatDefaultRoute extracts default route interface from BSD netstat output
func ParseNetstatDefaultRoute(output []byte) (string, error) {
	re := regexp.MustCompile(`^(default|0\.0\.0\.0/0)\s+\S+\s+\S+\s+\S+\s+\S+\s+(\w+)\s*$`)
	lines := strings.Split(string(output), "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		matches := re.FindStringSubmatch(line)
		if len(matches) > 2 {
			return matches[2], nil
		}
	}

	return "", fmt.Errorf("default route interface not found")
}

// ParseBSDInterfaceAddresses extracts IP addresses from BSD ifconfig output (FreeBSD/OpenBSD)
func ParseBSDInterfaceAddresses(output []byte) []string {
	re := regexp.MustCompile(`inet6?\s+([^\s]+)`)
	matches := re.FindAllStringSubmatch(string(output), -1)

	var result []string
	for _, match := range matches {
		if len(match) > 1 {
			addr := match[1]
			// Skip link-local, loopback, and other special addresses
			if !strings.HasPrefix(addr, "127.") &&
				!strings.HasPrefix(addr, "fe80:") &&
				!strings.HasPrefix(addr, "::1") &&
				!strings.Contains(addr, "%") { // Skip addresses with scope
				result = append(result, addr)
			}
		}
	}

	return result
}
