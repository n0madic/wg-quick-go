package utils

import (
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Config represents WireGuard interface configuration (forward declaration for validation)
type Config interface {
	GetInterfaceAddresses() []net.IPNet
}

// ValidateInterfaceAddresses validates that all interface addresses are properly configured
func ValidateInterfaceAddresses(addresses []net.IPNet) error {
	for _, addr := range addresses {
		if addr.IP == nil {
			return fmt.Errorf("invalid address configuration")
		}
	}
	return nil
}

// ValidateInterfaceName checks if interface name is valid (like original bash script)
func ValidateInterfaceName(name string) error {
	if name == "" {
		return fmt.Errorf("interface name cannot be empty")
	}
	if len(name) > 15 {
		return fmt.Errorf("interface name too long (max 15 characters)")
	}

	// Same regex as original bash script: [a-zA-Z0-9_=+.-]{1,15}
	validNameRegex := regexp.MustCompile(`^[a-zA-Z0-9_=+.-]+$`)
	if !validNameRegex.MatchString(name) {
		return fmt.Errorf("interface name contains invalid characters (allowed: a-zA-Z0-9_=+.-)")
	}

	// Check for reserved interface names
	reservedNames := []string{"lo", "eth0", "wlan0", "docker0", "virbr0"}
	for _, reserved := range reservedNames {
		if name == reserved {
			return fmt.Errorf("interface name '%s' is reserved", name)
		}
	}

	return nil
}

// ValidateAllowedIPs validates allowed IPs configuration
func ValidateAllowedIPs(allowedIPs []net.IPNet) error {
	for _, ip := range allowedIPs {
		if ip.IP == nil {
			return fmt.Errorf("invalid allowed IP configuration")
		}
	}
	return nil
}

// IsDefaultRoute checks if the given route is a default route (0.0.0.0/0 or ::/0)
func IsDefaultRoute(route net.IPNet) bool {
	ones, _ := route.Mask.Size()
	return ones == 0
}

// IsIPv4Address checks if the given IP is IPv4
func IsIPv4Address(ip net.IP) bool {
	return ip.To4() != nil
}

// IsIPv6Address checks if the given IP is IPv6
func IsIPv6Address(ip net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil
}

// ValidateEndpoint validates WireGuard peer endpoint (like original bash script)
func ValidateEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil // Empty endpoint is allowed
	}

	// Regex from original bash script: ^\[?([a-z0-9:.]+)\]?:[0-9]+$
	endpointRegex := regexp.MustCompile(`^\[?([a-z0-9:.]+)\]?:[0-9]+$`)
	if !endpointRegex.MatchString(strings.ToLower(endpoint)) {
		return fmt.Errorf("invalid endpoint format: %s (expected [host]:port or host:port)", endpoint)
	}

	// Extract and validate port
	parts := strings.Split(endpoint, ":")
	if len(parts) < 2 {
		return fmt.Errorf("endpoint missing port: %s", endpoint)
	}

	portStr := parts[len(parts)-1]
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("invalid port in endpoint %s: %s", endpoint, portStr)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("port out of range (1-65535) in endpoint %s: %d", endpoint, port)
	}

	return nil
}

// ValidateDNSAddress validates DNS server address
func ValidateDNSAddress(dns string) error {
	if dns == "" {
		return fmt.Errorf("DNS address cannot be empty")
	}

	// Try to parse as IP address
	ip := net.ParseIP(dns)
	if ip == nil {
		// Try as hostname (basic validation)
		hostnameRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$`)
		if !hostnameRegex.MatchString(dns) {
			return fmt.Errorf("invalid DNS address: %s (not a valid IP or hostname)", dns)
		}
	}

	return nil
}

// ValidateMTU validates MTU value
func ValidateMTU(mtu int) error {
	if mtu < 0 {
		return fmt.Errorf("MTU cannot be negative")
	}
	if mtu > 0 && mtu < 68 {
		return fmt.Errorf("MTU too small (minimum 68 for IPv4)")
	}
	if mtu > 65535 {
		return fmt.Errorf("MTU too large (maximum 65535)")
	}
	return nil
}

// ValidateTable validates routing table specification
func ValidateTable(table string) error {
	if table == "" || table == "auto" || table == "off" {
		return nil // These are valid special values
	}

	// Try to parse as number
	tableNum, err := strconv.Atoi(table)
	if err != nil {
		return fmt.Errorf("invalid table specification: %s (must be number, 'auto', or 'off')", table)
	}

	if tableNum < 0 {
		return fmt.Errorf("table number cannot be negative: %d", tableNum)
	}
	if tableNum > 2147483647 {
		return fmt.Errorf("table number too large: %d", tableNum)
	}

	return nil
}

// ValidateFwMark validates fwmark value
func ValidateFwMark(fwmark int) error {
	if fwmark < 0 {
		return fmt.Errorf("fwmark cannot be negative")
	}
	if uint32(fwmark) > ^uint32(0) { // 2^32 - 1
		return fmt.Errorf("fwmark too large (maximum %d)", ^uint32(0))
	}
	return nil
}

// ValidatePrivateKey validates WireGuard private key format
func ValidatePrivateKey(key string) error {
	if key == "" {
		return fmt.Errorf("private key cannot be empty")
	}

	// WireGuard keys are base64 encoded, 44 characters
	keyRegex := regexp.MustCompile(`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$`)
	if !keyRegex.MatchString(key) {
		return fmt.Errorf("invalid private key format")
	}

	return nil
}

// ValidatePublicKey validates WireGuard public key format
func ValidatePublicKey(key string) error {
	if key == "" {
		return fmt.Errorf("public key cannot be empty")
	}

	// WireGuard keys are base64 encoded, 44 characters
	keyRegex := regexp.MustCompile(`^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$`)
	if !keyRegex.MatchString(key) {
		return fmt.Errorf("invalid public key format")
	}

	return nil
}

// CheckFilePermissions checks configuration file permissions and returns a
// warning message if the file is world-accessible. Matches the original bash:
//
//	(( ... & 0007 )) && echo "Warning: \`$CONFIG_FILE' is world accessible" >&2
//
// The original script only warns (does not abort), so callers should log the
// returned message rather than treating it as a fatal error.
func CheckFilePermissions(filename string) (warning string, err error) {
	fileInfo, err := os.Stat(filename)
	if err != nil {
		return "", fmt.Errorf("cannot access file %s: %w", filename, err)
	}

	perm := fileInfo.Mode().Perm()

	// Match original bash: check world-access bits (other read/write/exec)
	if perm&0007 != 0 {
		return fmt.Sprintf("Warning: `%s' is world accessible", filename), nil
	}

	return "", nil
}

// ValidateIPNetwork validates IP network CIDR notation
func ValidateIPNetwork(cidr string) error {
	if cidr == "" {
		return fmt.Errorf("IP network cannot be empty")
	}

	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid IP network: %s (%w)", cidr, err)
	}

	// Validate prefix length
	ones, bits := network.Mask.Size()
	if ones < 0 || ones > bits {
		return fmt.Errorf("invalid prefix length in %s", cidr)
	}

	return nil
}

// ValidateNoNetworkConflicts checks for network conflicts with existing interfaces
func ValidateNoNetworkConflicts(addresses []net.IPNet) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil // Can't check, but don't fail
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue // Skip down or loopback interfaces
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ifaceNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			// Check if any of our addresses conflict with existing interfaces
			for _, ourAddr := range addresses {
				if networksOverlap(ourAddr, *ifaceNet) {
					return fmt.Errorf("address %s conflicts with existing interface %s (%s)",
						ourAddr.String(), iface.Name, ifaceNet.String())
				}
			}
		}
	}

	return nil
}

// networksOverlap checks if two IP networks overlap
func networksOverlap(net1, net2 net.IPNet) bool {
	// Check if net1 contains net2's network address
	if net1.Contains(net2.IP) {
		return true
	}
	// Check if net2 contains net1's network address
	if net2.Contains(net1.IP) {
		return true
	}
	return false
}

// ValidateRouteConflicts checks for routing conflicts
func ValidateRouteConflicts(allowedIPs []net.IPNet) error {
	// This is a simplified check - in practice, you'd want to check routing table
	for i, ip1 := range allowedIPs {
		for j, ip2 := range allowedIPs {
			if i != j && networksOverlap(ip1, ip2) {
				return fmt.Errorf("overlapping allowed IPs: %s and %s", ip1.String(), ip2.String())
			}
		}
	}
	return nil
}

// ValidateInterfaceNotExists checks that interface doesn't already exist
func ValidateInterfaceNotExists(name string) error {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil // Can't check, but don't fail
	}

	for _, iface := range interfaces {
		if iface.Name == name {
			return fmt.Errorf("interface %s already exists", name)
		}
	}

	return nil
}

// ValidateFIBTable validates FreeBSD FIB (Forwarding Information Base) table number
func ValidateFIBTable(table int) error {
	if table < 0 {
		return fmt.Errorf("FIB table number cannot be negative")
	}
	// FreeBSD supports FIB tables 0-65535
	if table > 65535 {
		return fmt.Errorf("FIB table number too large (max 65535)")
	}
	return nil
}
