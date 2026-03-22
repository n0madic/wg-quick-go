package utils

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

// SystemCommandRunner interface for running system commands
type SystemCommandRunner interface {
	Run(name string, args ...string) error
	RunWithOutput(name string, args ...string) ([]byte, error)
	RunWithInput(input string, name string, args ...string) error
}

// GetUserspaceCommand returns the WireGuard userspace implementation command
func GetUserspaceCommand() string {
	userspaceCmd := os.Getenv("WG_QUICK_USERSPACE_IMPLEMENTATION")
	if userspaceCmd == "" {
		userspaceCmd = "wireguard-go"
	}
	return userspaceCmd
}

// IsUserspaceForced returns true if WG_QUICK_USERSPACE_IMPLEMENTATION was explicitly set
func IsUserspaceForced() bool {
	_, exists := os.LookupEnv("WG_QUICK_USERSPACE_IMPLEMENTATION")
	return exists
}

// SortAllowedIPsBySpecificity sorts allowed IPs by mask size (more specific first)
func SortAllowedIPsBySpecificity(allowedIPs []net.IPNet) {
	sort.Slice(allowedIPs, func(i, j int) bool {
		iOnes, _ := allowedIPs[i].Mask.Size()
		jOnes, _ := allowedIPs[j].Mask.Size()
		return iOnes > jOnes
	})
}

// GetWireGuardInfo executes wg show command for specific information type
func GetWireGuardInfo(interfaceName string, infoType string, cmdRunner SystemCommandRunner) ([]byte, error) {
	return cmdRunner.RunWithOutput("wg", "show", interfaceName, infoType)
}

// ParseWireGuardEndpoints extracts endpoint information from wg show output
func ParseWireGuardEndpoints(output []byte, outputParser *OutputParser) []string {
	var endpoints []string
	endpointData := outputParser.ParseRegex(output, `\s+(?P<endpoint>[^\s]+:\d+)`)

	for _, data := range endpointData {
		if endpoint, exists := data["endpoint"]; exists {
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints
}

// CheckUserspaceImplementation checks if userspace implementation is available
func CheckUserspaceImplementation(cmdRunner SystemCommandRunner) error {
	userspaceCmd := GetUserspaceCommand()
	if _, err := cmdRunner.RunWithOutput("which", userspaceCmd); err != nil {
		return fmt.Errorf("WireGuard userspace implementation (%s) not found", userspaceCmd)
	}
	return nil
}

// ConfigureWireGuardAddconf configures a WireGuard interface using `wg addconf`,
// piping the raw config via stdin. This matches the original bash:
//
//	cmd wg addconf "$INTERFACE" <(echo "$WG_CONFIG")
func ConfigureWireGuardAddconf(interfaceName, rawWGConfig string, cmdRunner SystemCommandRunner) error {
	return cmdRunner.RunWithInput(rawWGConfig, "wg", "addconf", interfaceName, "/dev/stdin")
}

// GetAllowedIPsFromInterface gets all allowed IPs from WireGuard interface
func GetAllowedIPsFromInterface(interfaceName string, outputParser *OutputParser, cmdRunner SystemCommandRunner) ([]net.IPNet, error) {
	output, err := GetWireGuardInfo(interfaceName, "allowed-ips", cmdRunner)
	if err != nil {
		return nil, err
	}

	return ParseAllowedIPsFromWgOutput(output, outputParser)
}

// GetWireGuardEndpoints gets all peer endpoints from WireGuard interface
func GetWireGuardEndpoints(interfaceName string, cmdRunner SystemCommandRunner) ([]string, error) {
	output, err := cmdRunner.RunWithOutput("wg", "show", interfaceName, "endpoints")
	if err != nil {
		return nil, fmt.Errorf("failed to get WireGuard endpoints: %w", err)
	}

	var endpoints []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || line == "(none)" {
			continue
		}

		// Format: "peer_key\tendpoint_host:port"
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			endpoint := parts[1]
			endpoints = append(endpoints, endpoint)
		}
	}

	return endpoints, nil
}

// FilterIPEndpoints filters endpoints to only include IP addresses (not domains)
func FilterIPEndpoints(endpoints []string) []string {
	var ipEndpoints []string

	for _, endpoint := range endpoints {
		// Extract host from host:port
		if host, _, err := net.SplitHostPort(endpoint); err == nil {
			// Only add if it's a valid IP address (not domain)
			if ip := net.ParseIP(host); ip != nil {
				ipEndpoints = append(ipEndpoints, host)
			}
		}
	}

	return ipEndpoints
}

// GetWireGuardIPEndpoints gets all IP-based peer endpoints (excludes domain names)
func GetWireGuardIPEndpoints(interfaceName string, cmdRunner SystemCommandRunner) ([]string, error) {
	endpoints, err := GetWireGuardEndpoints(interfaceName, cmdRunner)
	if err != nil {
		return nil, err
	}

	return FilterIPEndpoints(endpoints), nil
}
