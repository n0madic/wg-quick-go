package platform

import (
	"net"

	"github.com/n0madic/wg-quick-go/pkg/config"
	"github.com/n0madic/wg-quick-go/pkg/runner"
	"github.com/n0madic/wg-quick-go/pkg/utils"
)

// PlatformManager defines platform-specific operations
type PlatformManager interface {
	// Interface management
	CreateInterface(interfaceName string) error
	DeleteInterface(interfaceName string) error
	InterfaceExists(interfaceName string) bool

	// Address management
	AddAddress(interfaceName string, addr net.IPNet) error
	GetCurrentAddresses(interfaceName string) []string

	// MTU and interface properties
	SetMTUAndUp(interfaceName string, mtu int) error
	GetCurrentMTU(interfaceName string) int
	CalculateOptimalMTU(interfaceName string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) (int, error)

	// DNS management
	SetupDNS(interfaceName string, dns []net.IP, search []string) error
	CleanupDNS(interfaceName string)
	// GetCurrentDNS returns live DNS nameserver IPs for the interface.
	// Linux/FreeBSD read from resolvconf; macOS/OpenBSD return nil (matching original bash TODO).
	GetCurrentDNS(interfaceName string) []string

	// Routing
	SetupRoutes(interfaceName string, allowedIPs []net.IPNet, table string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error
	AddRoute(interfaceName string, route net.IPNet, table string) error
	AddDefaultRoute(interfaceName string, route net.IPNet, fwmark int, cmdRunner runner.SystemCommandRunner) error

	// Firewall management
	SetupFirewall(interfaceName string, fwmark int, addresses []net.IPNet, cmdRunner runner.SystemCommandRunner) error
	CleanupFirewall(interfaceName string, cmdRunner runner.SystemCommandRunner)

	// Utility functions
	GetFwMark(interfaceName string, cmdRunner runner.SystemCommandRunner) (int, error)
	TableInUse(table int, cmdRunner runner.SystemCommandRunner) bool
	GetMTUForEndpoint(endpoint string, cmdRunner runner.SystemCommandRunner) (int, error)

	// WireGuard configuration
	ConfigureWireGuard(interfaceName string, config *config.Config, cmdRunner runner.SystemCommandRunner) error
	GetWireGuardInterfaceName(interfaceName string) string
	// GetRealInterfaceName returns the actual OS-level interface name.
	// On macOS this is the utun name, on OpenBSD the allocated wg slot.
	// On Linux/FreeBSD the real name equals the logical name.
	GetRealInterfaceName(interfaceName string) string

	// Route monitor daemon for BSD platforms
	StartMonitor(interfaceName string, config *config.Config, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error
	StopMonitor(interfaceName string)

	// Platform-specific validation
	CheckRequirements() error
	ValidateConfig(config *config.Config) error
	SetCommandRunner(cmdRunner runner.SystemCommandRunner)
}

// NewPlatformManager creates a platform-specific manager
// The actual implementation is in platform-specific files
