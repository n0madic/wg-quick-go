//go:build !linux && !darwin && !freebsd && !openbsd

package platform

import (
	"fmt"
	"net"

	"github.com/n0madic/wg-quick-go/pkg/config"
	"github.com/n0madic/wg-quick-go/pkg/logger"
	"github.com/n0madic/wg-quick-go/pkg/runner"
	"github.com/n0madic/wg-quick-go/pkg/utils"
)

// StubPlatformManager provides a stub implementation for unsupported platforms
type StubPlatformManager struct {
	logger logger.Logger
}

// newPlatformManager creates a stub platform manager for unsupported platforms
func newPlatformManager(logger logger.Logger) PlatformManager {
	return &StubPlatformManager{logger: logger}
}

// All methods return "not supported" errors
func (spm *StubPlatformManager) CreateInterface(interfaceName string) error {
	return fmt.Errorf("interface creation not supported on this platform")
}

func (spm *StubPlatformManager) DeleteInterface(interfaceName string) error {
	return fmt.Errorf("interface deletion not supported on this platform")
}

func (spm *StubPlatformManager) InterfaceExists(interfaceName string) bool {
	return false
}

func (spm *StubPlatformManager) AddAddress(interfaceName string, addr net.IPNet) error {
	return fmt.Errorf("address management not supported on this platform")
}

func (spm *StubPlatformManager) GetCurrentAddresses(interfaceName string) []string {
	return nil
}

func (spm *StubPlatformManager) SetMTUAndUp(interfaceName string, mtu int) error {
	return fmt.Errorf("MTU configuration not supported on this platform")
}

func (spm *StubPlatformManager) GetCurrentMTU(interfaceName string) int {
	return 0
}

func (spm *StubPlatformManager) CalculateOptimalMTU(interfaceName string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) (int, error) {
	return 0, fmt.Errorf("MTU calculation not supported on this platform")
}

func (spm *StubPlatformManager) SetupDNS(interfaceName string, dns []net.IP, search []string) error {
	return fmt.Errorf("DNS configuration not supported on this platform")
}

func (spm *StubPlatformManager) CleanupDNS(interfaceName string) {
	// No-op
}

func (spm *StubPlatformManager) GetCurrentDNS(interfaceName string) []string {
	return nil
}

func (spm *StubPlatformManager) SetupRoutes(interfaceName string, allowedIPs []net.IPNet, table string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error {
	return fmt.Errorf("route configuration not supported on this platform")
}

func (spm *StubPlatformManager) AddRoute(interfaceName string, route net.IPNet, table string) error {
	return fmt.Errorf("route addition not supported on this platform")
}

func (spm *StubPlatformManager) AddDefaultRoute(interfaceName string, route net.IPNet, fwmark int, cmdRunner runner.SystemCommandRunner) error {
	return fmt.Errorf("default route configuration not supported on this platform")
}

func (spm *StubPlatformManager) SetupFirewall(interfaceName string, fwmark int, addresses []net.IPNet, cmdRunner runner.SystemCommandRunner) error {
	return fmt.Errorf("firewall configuration not supported on this platform")
}

func (spm *StubPlatformManager) CleanupFirewall(interfaceName string, cmdRunner runner.SystemCommandRunner) {
	// No-op
}

func (spm *StubPlatformManager) GetFwMark(interfaceName string, cmdRunner runner.SystemCommandRunner) (int, error) {
	return 0, fmt.Errorf("fwmark not supported on this platform")
}

func (spm *StubPlatformManager) TableInUse(table int, cmdRunner runner.SystemCommandRunner) bool {
	return false
}

func (spm *StubPlatformManager) GetMTUForEndpoint(endpoint string, cmdRunner runner.SystemCommandRunner) (int, error) {
	return 0, fmt.Errorf("endpoint MTU detection not supported on this platform")
}

func (spm *StubPlatformManager) CheckRequirements() error {
	return fmt.Errorf("this platform is not supported")
}

func (spm *StubPlatformManager) ValidateConfig(config *config.Config) error {
	return fmt.Errorf("configuration validation not supported on this platform")
}

func (spm *StubPlatformManager) ConfigureWireGuard(interfaceName string, config *config.Config, cmdRunner runner.SystemCommandRunner) error {
	return fmt.Errorf("WireGuard configuration not supported on this platform")
}

func (spm *StubPlatformManager) GetWireGuardInterfaceName(interfaceName string) string {
	return interfaceName
}

func (spm *StubPlatformManager) GetRealInterfaceName(interfaceName string) string {
	return interfaceName
}

func (spm *StubPlatformManager) StartMonitor(interfaceName string, config *config.Config, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error {
	return nil
}

func (spm *StubPlatformManager) StopMonitor(interfaceName string) {}

func (spm *StubPlatformManager) SetCommandRunner(cmdRunner runner.SystemCommandRunner) {
	// No-op for stub
}
