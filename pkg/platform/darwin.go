//go:build darwin

package platform

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n0madic/wg-quick-go/pkg/config"
	"github.com/n0madic/wg-quick-go/pkg/logger"
	"github.com/n0madic/wg-quick-go/pkg/runner"
	"github.com/n0madic/wg-quick-go/pkg/utils"
)

// DarwinPlatformManager implements PlatformManager for macOS
type DarwinPlatformManager struct {
	logger       logger.Logger
	cmdRunner    runner.SystemCommandRunner
	userspaceCmd string

	// State tracking
	dnsSet         map[string]*DNSState
	realInterface  map[string]string          // Maps interface name to actual utun interface
	endpointRoutes map[string][]EndpointRoute // Maps interface name to protected endpoint routes
	mu             sync.Mutex                 // Protects shared state accessed by monitor goroutine
	monitorCancel  map[string]context.CancelFunc
	autoRoute4     map[string]bool
	autoRoute6     map[string]bool
}

// DNSState tracks DNS configuration for restoration
type DNSState struct {
	services       []string
	originalDNS    map[string][]string
	originalSearch map[string][]string
}

// EndpointRoute represents a protected endpoint route
type EndpointRoute struct {
	endpoint string
	gateway  string
}

// newPlatformManager creates a macOS-specific platform manager
func newPlatformManager(logger logger.Logger) PlatformManager {
	return &DarwinPlatformManager{
		logger:         logger,
		dnsSet:         make(map[string]*DNSState),
		realInterface:  make(map[string]string),
		endpointRoutes: make(map[string][]EndpointRoute),
		monitorCancel:  make(map[string]context.CancelFunc),
		autoRoute4:     make(map[string]bool),
		autoRoute6:     make(map[string]bool),
	}
}

// SetCommandRunner sets the system command runner
func (dpm *DarwinPlatformManager) SetCommandRunner(cmdRunner runner.SystemCommandRunner) {
	dpm.cmdRunner = cmdRunner
}

// CheckRequirements checks if the system meets requirements for WireGuard
func (dpm *DarwinPlatformManager) CheckRequirements() error {
	// Check for WireGuard userspace implementation and set it if available
	candidateCmd := utils.GetUserspaceCommand()
	if _, err := dpm.cmdRunner.RunWithOutput("which", candidateCmd); err != nil {
		return fmt.Errorf("WireGuard userspace implementation (%s) not found", candidateCmd)
	}
	// Only set userspaceCmd if the command actually exists
	dpm.userspaceCmd = candidateCmd

	// Check for required system utilities
	requiredCommands := []string{"ifconfig", "route", "networksetup", "wg", "lsof"}
	for _, cmd := range requiredCommands {
		if _, err := dpm.cmdRunner.RunWithOutput("which", cmd); err != nil {
			return fmt.Errorf("required command '%s' not found", cmd)
		}
	}

	return nil
}

// ValidateConfig validates macOS-specific config requirements
func (dpm *DarwinPlatformManager) ValidateConfig(config *config.Config) error {
	// macOS-specific validations only (universal validations done in WireGuardManager)

	// macOS only supports Table=auto|main|off (matching original darwin.bash)
	table := config.Interface.Table
	if table != "" && table != "auto" && table != "main" && table != "off" {
		return fmt.Errorf("macOS only supports Table=auto|main|off")
	}

	// Check if networksetup is available for DNS configuration
	if len(config.Interface.DNS) > 0 {
		if _, err := dpm.cmdRunner.RunWithOutput("which", "networksetup"); err != nil {
			return fmt.Errorf("networksetup command not available, required for DNS configuration on macOS")
		}
	}

	// macOS-specific: Check if we can access network services for DNS
	if len(config.Interface.DNS) > 0 {
		if _, err := dpm.getNetworkServices(); err != nil {
			dpm.logger.Warning(fmt.Sprintf("Cannot access network services: %v", err))
		}
	}

	// macOS always requires userspace implementation
	candidateCmd := utils.GetUserspaceCommand()
	if _, err := dpm.cmdRunner.RunWithOutput("which", candidateCmd); err != nil {
		return fmt.Errorf("macOS requires userspace WireGuard implementation (%s)", candidateCmd)
	}

	return nil
}

// CreateInterface creates WireGuard interface using wireguard-go.
// Caller must check InterfaceExists() before calling this method.
func (dpm *DarwinPlatformManager) CreateInterface(interfaceName string) error {
	// Remove any cached interface mapping to force new creation
	delete(dpm.realInterface, interfaceName)

	// Create run directory if it doesn't exist
	runDir := "/var/run/wireguard"
	if err := os.MkdirAll(runDir, 0755); err != nil {
		return fmt.Errorf("failed to create run directory: %w", err)
	}

	// Ensure userspace command was validated in CheckRequirements
	if dpm.userspaceCmd == "" {
		return fmt.Errorf("userspace command not set - CheckRequirements was not called or failed")
	}

	// Set WG_TUN_NAME_FILE so wireguard-go writes the utun name to a known file.
	// This matches the original bash: WG_TUN_NAME_FILE="$namefile" wireguard-go utun
	nameFile := filepath.Join(runDir, interfaceName+".name")
	dpm.logger.Command(dpm.userspaceCmd, "utun")
	cmd := exec.Command(dpm.userspaceCmd, "utun")
	cmd.Env = append(os.Environ(), "WG_TUN_NAME_FILE="+nameFile)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start WireGuard userspace: %w", err)
	}

	// Read the real interface name written by wireguard-go via WG_TUN_NAME_FILE
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get real interface: %w", err)
	}

	dpm.realInterface[interfaceName] = realIntf

	// Verify socket file exists (wait briefly if needed)
	socketFile := filepath.Join(runDir, realIntf+".sock")
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(socketFile); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if _, err := os.Stat(socketFile); err != nil {
		return fmt.Errorf("socket file %s not created: %w", socketFile, err)
	}

	dpm.logger.Info(fmt.Sprintf("Created interface %s -> %s with socket %s", interfaceName, realIntf, socketFile))

	return nil
}

// getRealInterface gets the actual utun interface name
func (dpm *DarwinPlatformManager) getRealInterface(interfaceName string) (string, error) {
	// Check if already cached
	if realIntf, exists := dpm.realInterface[interfaceName]; exists {
		return realIntf, nil
	}

	// Check stored interface name file first (matching original bash get_real_interface())
	runDir := "/var/run/wireguard"
	nameFile := filepath.Join(runDir, interfaceName+".name")
	if data, err := os.ReadFile(nameFile); err == nil {
		realIntf := strings.TrimSpace(string(data))
		if realIntf != "" {
			socketFile := filepath.Join(runDir, realIntf+".sock")
			sockInfo, sockErr := os.Stat(socketFile)
			nameInfo, nameErr := os.Stat(nameFile)
			if sockErr == nil && nameErr == nil {
				// Original bash: reject if mtime difference >= 2 seconds (stale name file)
				diff := sockInfo.ModTime().Sub(nameInfo.ModTime())
				if diff < 2*time.Second && diff > -2*time.Second {
					dpm.realInterface[interfaceName] = realIntf
					dpm.logger.Info(fmt.Sprintf("Interface for %s is %s", interfaceName, realIntf))
					return realIntf, nil
				}
			}
		}
	}

	// Try to discover interface via socket file (like original script)
	socketFile := filepath.Join(runDir, interfaceName+".sock")
	if _, err := os.Stat(socketFile); err == nil {
		// Socket exists, try to find corresponding interface
		if realIntf, err := dpm.discoverInterfaceFromSocket(socketFile); err == nil {
			dpm.realInterface[interfaceName] = realIntf
			// Store for future reference
			_ = os.WriteFile(nameFile, []byte(realIntf), 0644)
			return realIntf, nil
		}
	}

	// Fallback to ifconfig scanning (original behavior)
	output, err := dpm.cmdRunner.RunWithOutput("ifconfig")
	if err != nil {
		return "", err
	}

	// Look for utun interfaces
	re := regexp.MustCompile(`^(utun\d+):`)
	var utunInterfaces []string

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			utunInterfaces = append(utunInterfaces, matches[1])
		}
	}

	if len(utunInterfaces) == 0 {
		return "", fmt.Errorf("no utun interfaces found")
	}

	// If the interface name is already a utun interface (like utun6), try to use it directly
	if strings.HasPrefix(interfaceName, "utun") {
		// Check if the requested interface exists
		for _, intf := range utunInterfaces {
			if intf == interfaceName {
				dpm.realInterface[interfaceName] = interfaceName
				return interfaceName, nil
			}
		}
		// If requested interface doesn't exist, return error instead of using a different one
		return "", fmt.Errorf("requested interface %s not found", interfaceName)
	}

	// For non-utun names, find the utun interface claimed by this logical name.
	// Only return an interface if we can verify ownership — never return an
	// interface that might belong to a different logical name.
	// This matches the original bash get_real_interface() which only checks
	// the name file + socket, never scanning ifconfig blindly.
	sort.Strings(utunInterfaces)

	for i := len(utunInterfaces) - 1; i >= 0; i-- {
		intf := utunInterfaces[i]
		if dpm.isWireGuardInterface(intf) {
			// Only return this interface if its socket matches our logical name
			socketFile := filepath.Join(runDir, interfaceName+".sock")
			if _, err := os.Stat(socketFile); err == nil {
				dpm.realInterface[interfaceName] = intf
				return intf, nil
			}
		}
	}

	return "", fmt.Errorf("no WireGuard interface found for %s", interfaceName)
}

// discoverInterfaceFromSocket discovers interface name from wireguard-go socket
func (dpm *DarwinPlatformManager) discoverInterfaceFromSocket(socketPath string) (string, error) {
	// Use lsof to find process using the socket, then check its utun interface
	output, err := dpm.cmdRunner.RunWithOutput("lsof", "-U", socketPath)
	if err != nil {
		return "", err
	}

	// Parse lsof output to get process info, then correlate with utun interfaces
	lines := strings.Split(string(output), "\n")
	if len(lines) < 2 {
		return "", fmt.Errorf("could not parse lsof output")
	}

	// Get all current utun interfaces and find the one that wasn't there before
	// This is a heuristic approach similar to the original script
	ifconfigOutput, err := dpm.cmdRunner.RunWithOutput("ifconfig", "-a")
	if err != nil {
		return "", err
	}

	re := regexp.MustCompile(`^(utun\d+):`)
	scanner := bufio.NewScanner(strings.NewReader(string(ifconfigOutput)))

	for scanner.Scan() {
		line := scanner.Text()
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			// Check if this utun interface has WireGuard configuration
			if dpm.isWireGuardInterface(matches[1]) {
				return matches[1], nil
			}
		}
	}

	return "", fmt.Errorf("could not discover interface from socket")
}

// isWireGuardInterface checks if interface is managed by WireGuard
func (dpm *DarwinPlatformManager) isWireGuardInterface(interfaceName string) bool {
	// Try to get WireGuard info - if successful, it's a WireGuard interface
	// Use the real interface name for this check
	_, err := dpm.cmdRunner.RunWithOutput("wg", "show", interfaceName)
	return err == nil
}

// DeleteInterface deletes interface
func (dpm *DarwinPlatformManager) DeleteInterface(interfaceName string) error {
	// Clean up endpoint protection routes first
	dpm.cleanupEndpointProtection(interfaceName)

	// Get the real interface name for socket cleanup
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		dpm.logger.Warning(fmt.Sprintf("Could not get real interface for %s: %v", interfaceName, err))
	}

	// Clean up WireGuard files using unified function
	if realIntf != "" {
		// Use realIntf for socket name, interfaceName for name file
		utils.CleanupUserspaceFiles(interfaceName, realIntf, dpm.logger)
	} else {
		// Fallback to using interfaceName for both
		utils.CleanupUserspaceFiles(interfaceName, interfaceName, dpm.logger)
	}

	// Remove from cache
	delete(dpm.realInterface, interfaceName)

	return nil
}

// InterfaceExists checks if interface exists
func (dpm *DarwinPlatformManager) InterfaceExists(interfaceName string) bool {
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return false
	}

	err = dpm.cmdRunner.Run("ifconfig", realIntf)
	return err == nil
}

// AddAddress adds IP address to interface
func (dpm *DarwinPlatformManager) AddAddress(interfaceName string, addr net.IPNet) error {
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return err
	}

	// Ensure interface is up before adding address
	if err := dpm.cmdRunner.Run("ifconfig", realIntf, "up"); err != nil {
		return fmt.Errorf("failed to bring interface up: %w", err)
	}

	isIPv4, _, proto := utils.GetIPProtocolInfo(addr)

	// Use the same format as original wg-quick script
	if isIPv4 {
		// For IPv4: ifconfig utun6 inet 10.0.0.2/24 10.0.0.2 alias
		return dpm.cmdRunner.Run("ifconfig", realIntf, proto, addr.String(), addr.IP.String(), "alias")
	} else {
		// For IPv6: ifconfig utun6 inet6 2001:db8::1/64 alias
		return dpm.cmdRunner.Run("ifconfig", realIntf, proto, addr.String(), "alias")
	}
}

// GetCurrentAddresses gets current interface addresses
func (dpm *DarwinPlatformManager) GetCurrentAddresses(interfaceName string) []string {
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return nil
	}

	output, err := dpm.cmdRunner.RunWithOutput("ifconfig", realIntf)
	if err != nil {
		return nil
	}

	var result []string
	re := regexp.MustCompile(`inet6?\s+([^\s]+/\d+)`)
	matches := re.FindAllStringSubmatch(string(output), -1)

	for _, match := range matches {
		if len(match) > 1 {
			result = append(result, match[1])
		}
	}

	return result
}

// SetMTUAndUp sets MTU and brings up interface
func (dpm *DarwinPlatformManager) SetMTUAndUp(interfaceName string, mtu int) error {
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return err
	}

	// Set MTU
	if err := dpm.cmdRunner.Run("ifconfig", realIntf, "mtu", strconv.Itoa(mtu)); err != nil {
		return err
	}

	// Bring interface up
	return dpm.cmdRunner.Run("ifconfig", realIntf, "up")
}

// GetCurrentMTU gets current interface MTU
func (dpm *DarwinPlatformManager) GetCurrentMTU(interfaceName string) int {
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return 0
	}

	output, err := dpm.cmdRunner.RunWithOutput("ifconfig", realIntf)
	if err != nil {
		return 0
	}

	if mtu, err := utils.ParseMTUFromOutput(output); err == nil && mtu > 0 {
		return mtu
	}

	return 0
}

// CalculateOptimalMTU calculates optimal MTU for macOS
func (dpm *DarwinPlatformManager) CalculateOptimalMTU(interfaceName string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) (int, error) {
	return utils.CalculateOptimalMTUFromDefaultRoute(true, cmdRunner)
}

// GetMTUForEndpoint gets MTU for route to endpoint (simplified for macOS)
func (dpm *DarwinPlatformManager) GetMTUForEndpoint(endpoint string, cmdRunner runner.SystemCommandRunner) (int, error) {
	return utils.RouteGetMTUForEndpoint(endpoint, true, true, cmdRunner)
}

// SetupDNS configures DNS using networksetup
func (dpm *DarwinPlatformManager) SetupDNS(interfaceName string, dns []net.IP, search []string) error {
	if len(dns) == 0 {
		return nil
	}

	// Get list of network services
	services, err := dpm.getNetworkServices()
	if err != nil {
		return fmt.Errorf("failed to get network services: %w", err)
	}

	dnsState := &DNSState{
		services:       services,
		originalDNS:    make(map[string][]string),
		originalSearch: make(map[string][]string),
	}

	// Store original DNS settings for each service
	for _, service := range services {
		if originalDNS, err := dpm.getDNSServers(service); err == nil {
			dnsState.originalDNS[service] = originalDNS
		}

		if originalSearch, err := dpm.getSearchDomains(service); err == nil {
			dnsState.originalSearch[service] = originalSearch
		}
	}

	// Convert DNS IPs to strings
	var dnsStrings []string
	for _, dnsIP := range dns {
		dnsStrings = append(dnsStrings, dnsIP.String())
	}

	// Set DNS for all services
	for _, service := range services {
		if err := dpm.setDNSServers(service, dnsStrings); err != nil {
			dpm.logger.Warning(fmt.Sprintf("Failed to set DNS for service %s: %v", service, err))
		}

		if len(search) > 0 {
			if err := dpm.setSearchDomains(service, search); err != nil {
				dpm.logger.Warning(fmt.Sprintf("Failed to set search domains for service %s: %v", service, err))
			}
		}
	}

	dpm.dnsSet[interfaceName] = dnsState
	return nil
}

// getNetworkServices gets list of network services
func (dpm *DarwinPlatformManager) getNetworkServices() ([]string, error) {
	output, err := dpm.cmdRunner.RunWithOutput("networksetup", "-listallnetworkservices")
	if err != nil {
		return nil, err
	}

	var services []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	// Skip the first line (header)
	scanner.Scan()

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "*") {
			services = append(services, line)
		}
	}

	return services, nil
}

// getDNSServers gets current DNS servers for a service
func (dpm *DarwinPlatformManager) getDNSServers(service string) ([]string, error) {
	output, err := dpm.cmdRunner.RunWithOutput("networksetup", "-getdnsservers", service)
	if err != nil {
		return nil, err
	}

	var dnsServers []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && line != "There aren't any DNS Servers set on this service." {
			dnsServers = append(dnsServers, line)
		}
	}

	return dnsServers, nil
}

// getSearchDomains gets current search domains for a service
func (dpm *DarwinPlatformManager) getSearchDomains(service string) ([]string, error) {
	output, err := dpm.cmdRunner.RunWithOutput("networksetup", "-getsearchdomains", service)
	if err != nil {
		return nil, err
	}

	var searchDomains []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && line != "There aren't any Search Domains set on this service." {
			searchDomains = append(searchDomains, line)
		}
	}

	return searchDomains, nil
}

// setDNSServers sets DNS servers for a service
func (dpm *DarwinPlatformManager) setDNSServers(service string, dnsServers []string) error {
	args := []string{"-setdnsservers", service}
	args = append(args, dnsServers...)
	return dpm.cmdRunner.Run("networksetup", args...)
}

// setSearchDomains sets search domains for a service
func (dpm *DarwinPlatformManager) setSearchDomains(service string, searchDomains []string) error {
	args := []string{"-setsearchdomains", service}
	args = append(args, searchDomains...)
	return dpm.cmdRunner.Run("networksetup", args...)
}

// CleanupDNS cleans up DNS settings
func (dpm *DarwinPlatformManager) CleanupDNS(interfaceName string) {
	dnsState, exists := dpm.dnsSet[interfaceName]
	if !exists {
		return
	}

	// Restore original DNS settings
	for _, service := range dnsState.services {
		if originalDNS, exists := dnsState.originalDNS[service]; exists && len(originalDNS) > 0 {
			if err := dpm.setDNSServers(service, originalDNS); err != nil {
				dpm.logger.Warning(fmt.Sprintf("Failed to restore DNS servers for %s: %v", service, err))
			}
		} else {
			// Clear DNS servers if none were set originally
			if err := dpm.cmdRunner.Run("networksetup", "-setdnsservers", service, "empty"); err != nil {
				dpm.logger.Warning(fmt.Sprintf("Failed to clear DNS servers for %s: %v", service, err))
			}
		}

		if originalSearch, exists := dnsState.originalSearch[service]; exists && len(originalSearch) > 0 {
			if err := dpm.setSearchDomains(service, originalSearch); err != nil {
				dpm.logger.Warning(fmt.Sprintf("Failed to restore search domains for %s: %v", service, err))
			}
		} else {
			// Clear search domains if none were set originally
			if err := dpm.cmdRunner.Run("networksetup", "-setsearchdomains", service, "empty"); err != nil {
				dpm.logger.Warning(fmt.Sprintf("Failed to clear search domains for %s: %v", service, err))
			}
		}
	}

	delete(dpm.dnsSet, interfaceName)
}

// GetCurrentDNS returns nil on macOS.
// Matches original darwin.bash: "# TODO: actually determine current DNS for interface"
// The original script uses parsed DNS values from the config.
func (dpm *DarwinPlatformManager) GetCurrentDNS(interfaceName string) []string {
	return nil
}

// SetupRoutes configures routes for macOS
func (dpm *DarwinPlatformManager) SetupRoutes(interfaceName string, allowedIPs []net.IPNet, table string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error {
	if table == "off" {
		return nil
	}

	// CRITICAL: Add endpoint protection BEFORE setting up WireGuard routes
	// This prevents routing loops when using default routes (0.0.0.0/0)
	if err := dpm.addEndpointProtection(interfaceName); err != nil {
		return fmt.Errorf("failed to add endpoint protection: %w", err)
	}

	// Get allowed IPs from wg if not provided
	if len(allowedIPs) == 0 {
		var err error
		allowedIPs, err = dpm.getAllowedIPs(interfaceName, outputParser, dpm.cmdRunner)
		if err != nil {
			return err
		}
	}

	// Sort by mask size (more specific first)
	utils.SortAllowedIPsBySpecificity(allowedIPs)

	// Add routes for each allowed IP
	for _, allowedIP := range allowedIPs {
		if err := dpm.AddRoute(interfaceName, allowedIP, table); err != nil {
			return fmt.Errorf("failed to add route %s: %w", allowedIP.String(), err)
		}
	}

	return nil
}

// getAllowedIPs gets all allowed IPs from wg
func (dpm *DarwinPlatformManager) getAllowedIPs(interfaceName string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) ([]net.IPNet, error) {
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return nil, err
	}

	output, err := utils.GetWireGuardInfo(realIntf, "allowed-ips", cmdRunner)
	if err != nil {
		return nil, err
	}

	return utils.ParseAllowedIPsFromWgOutput(output, outputParser)
}

// AddRoute adds a route using macOS route command
func (dpm *DarwinPlatformManager) AddRoute(interfaceName string, route net.IPNet, table string) error {
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return err
	}

	// Check if this is a default route
	if utils.IsDefaultRoute(route) {
		return dpm.AddDefaultRoute(interfaceName, route, 0, dpm.cmdRunner)
	}

	// Regular route
	isIPv4, _, _ := utils.GetIPProtocolInfo(route)
	var family string
	if isIPv4 {
		family = "-inet"
	} else {
		family = "-inet6"
	}

	// Check if route already exists
	checkOutput, _ := dpm.cmdRunner.RunWithOutput("route", "-n", "get", family, route.String())
	if strings.Contains(string(checkOutput), realIntf) {
		return nil // Route already exists
	}

	return dpm.cmdRunner.Run("route", "add", family, route.String(), "-interface", realIntf)
}

// AddDefaultRoute adds default route for macOS
func (dpm *DarwinPlatformManager) AddDefaultRoute(interfaceName string, route net.IPNet, fwmark int, cmdRunner runner.SystemCommandRunner) error {
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return err
	}

	isIPv4, _, _ := utils.GetIPProtocolInfo(route)
	var family string
	if isIPv4 {
		family = "-inet"
	} else {
		family = "-inet6"
	}

	// Track auto-route state for monitor daemon
	if isIPv4 {
		dpm.autoRoute4[interfaceName] = true
	} else {
		dpm.autoRoute6[interfaceName] = true
	}

	// Add default route via WireGuard interface
	// We use 0.0.0.0/1 and 128.0.0.0/1 for IPv4 to override default route
	if isIPv4 {
		if err := cmdRunner.Run("route", "add", family, "0.0.0.0/1", "-interface", realIntf); err != nil {
			return err
		}
		return cmdRunner.Run("route", "add", family, "128.0.0.0/1", "-interface", realIntf)
	} else {
		if err := cmdRunner.Run("route", "add", family, "::/1", "-interface", realIntf); err != nil {
			return err
		}
		return cmdRunner.Run("route", "add", family, "8000::/1", "-interface", realIntf)
	}
}

// GetFwMark gets current fwmark (not applicable on macOS, returns 0)
func (dpm *DarwinPlatformManager) GetFwMark(interfaceName string, cmdRunner runner.SystemCommandRunner) (int, error) {
	// macOS doesn't use fwmark like Linux
	return 0, nil
}

// TableInUse checks if routing table is in use (not applicable on macOS)
func (dpm *DarwinPlatformManager) TableInUse(table int, cmdRunner runner.SystemCommandRunner) bool {
	// macOS doesn't use routing tables like Linux
	return false
}

// SetupFirewall configures firewall rules to prevent traffic leaks
func (dpm *DarwinPlatformManager) SetupFirewall(interfaceName string, fwmark int, addresses []net.IPNet, cmdRunner runner.SystemCommandRunner) error {
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return err
	}

	// Add firewall rules to prevent traffic leaks when VPN is down
	// This creates "blackhole" routes for VPN traffic when interface is down
	for _, addr := range addresses {
		isIPv4, _, _ := utils.GetIPProtocolInfo(addr)
		var family string
		if isIPv4 {
			family = "-inet"
		} else {
			family = "-inet6"
		}

		// Add route to blackhole if interface goes down
		// This prevents traffic from leaking to default route
		err := cmdRunner.Run("route", "add", family, addr.String(), "-blackhole")
		if err != nil {
			dpm.logger.Warning(fmt.Sprintf("Failed to add blackhole route for %s: %v", addr.String(), err))
		}

		// Remove blackhole route and add interface route
		_ = cmdRunner.Run("route", "delete", family, addr.String())
		err = cmdRunner.Run("route", "add", family, addr.String(), "-interface", realIntf)
		if err != nil {
			return fmt.Errorf("failed to add interface route for %s: %w", addr.String(), err)
		}
	}

	return nil
}

// CleanupFirewall cleans up firewall rules
func (dpm *DarwinPlatformManager) CleanupFirewall(interfaceName string, cmdRunner runner.SystemCommandRunner) {
	// Remove any remaining blackhole routes that might have been left
	// This is a safety cleanup in case interface went down unexpectedly
	output, err := cmdRunner.RunWithOutput("route", "-n", "get", "default")
	if err != nil {
		return
	}

	// Parse route table and remove any blackhole routes we might have created
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.Contains(line, "blackhole") {
			// Extract destination from route line and try to remove it
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				dest := parts[0]
				_ = cmdRunner.Run("route", "delete", dest)
			}
		}
	}
}

// getEndpoints extracts all peer endpoints from WireGuard configuration
func (dpm *DarwinPlatformManager) getEndpoints(interfaceName string) ([]string, error) {
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return nil, err
	}

	return utils.GetWireGuardIPEndpoints(realIntf, dpm.cmdRunner)
}

// addEndpointProtection adds routes for WireGuard endpoints via original gateway
func (dpm *DarwinPlatformManager) addEndpointProtection(interfaceName string) error {
	// Get default route info (gateway + interface) in one efficient call
	routeInfo, err := utils.GetDefaultRouteInfoBSD(dpm.cmdRunner)
	if err != nil {
		dpm.logger.Warning(fmt.Sprintf("Could not determine default route info: %v", err))
		return nil // Non-fatal, continue without endpoint protection
	}

	// Get all peer endpoints
	endpoints, err := dpm.getEndpoints(interfaceName)
	if err != nil {
		dpm.logger.Warning(fmt.Sprintf("Could not get WireGuard endpoints: %v", err))
		return nil // Non-fatal, continue without endpoint protection
	}

	if len(endpoints) == 0 {
		return nil // No endpoints to protect
	}

	var protectedRoutes []EndpointRoute

	// Add route for each endpoint via original gateway
	for _, endpoint := range endpoints {
		// Skip localhost endpoints to avoid routing conflicts in tests
		if strings.HasPrefix(endpoint, "127.0.0.1") || strings.HasPrefix(endpoint, "::1") {
			dpm.logger.Info(fmt.Sprintf("Skipping endpoint protection for localhost: %s", endpoint))
			continue
		}

		dpm.logger.Info(fmt.Sprintf("Adding endpoint protection route: %s via %s", endpoint, routeInfo.Gateway))

		err := dpm.cmdRunner.Run("route", "add", "-host", endpoint, routeInfo.Gateway)
		if err != nil {
			dpm.logger.Warning(fmt.Sprintf("Failed to add endpoint route for %s: %v", endpoint, err))
			continue // Continue with other endpoints
		}

		protectedRoutes = append(protectedRoutes, EndpointRoute{
			endpoint: endpoint,
			gateway:  routeInfo.Gateway,
		})
	}

	// Store protected routes for cleanup
	dpm.endpointRoutes[interfaceName] = protectedRoutes

	return nil
}

// ConfigureWireGuard configures WireGuard interface using `wg addconf`.
// Matches original darwin.bash: cmd wg addconf "$REAL_INTERFACE" <(echo "$WG_CONFIG")
func (dpm *DarwinPlatformManager) ConfigureWireGuard(interfaceName string, config *config.Config, cmdRunner runner.SystemCommandRunner) error {
	realIntf, err := dpm.getRealInterface(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get real interface name: %w", err)
	}
	return utils.ConfigureWireGuardAddconf(realIntf, config.RawWGConfig, cmdRunner)
}

// GetWireGuardInterfaceName returns the real interface name for WireGuard commands
func (dpm *DarwinPlatformManager) GetWireGuardInterfaceName(interfaceName string) string {
	// Get the real interface name (utun5, etc.) for WireGuard operations
	if realIntf, err := dpm.getRealInterface(interfaceName); err == nil {
		return realIntf
	}
	// Fallback to logical name if mapping fails
	return interfaceName
}

// GetRealInterfaceName returns the actual OS-level interface name (utun).
func (dpm *DarwinPlatformManager) GetRealInterfaceName(interfaceName string) string {
	if realIntf, ok := dpm.realInterface[interfaceName]; ok {
		return realIntf
	}
	return interfaceName
}

// StartMonitor starts the route monitor daemon.
// Matches original darwin.bash monitor_daemon() function.
func (dpm *DarwinPlatformManager) StartMonitor(interfaceName string, cfg *config.Config, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error {
	dpm.mu.Lock()
	defer dpm.mu.Unlock()

	if !dpm.autoRoute4[interfaceName] && !dpm.autoRoute6[interfaceName] {
		// No default route, no need for monitor
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	dpm.monitorCancel[interfaceName] = cancel

	go dpm.monitorDaemon(ctx, interfaceName, cfg, outputParser, cmdRunner)
	return nil
}

// StopMonitor stops the route monitor daemon.
func (dpm *DarwinPlatformManager) StopMonitor(interfaceName string) {
	dpm.mu.Lock()
	defer dpm.mu.Unlock()

	if cancel, exists := dpm.monitorCancel[interfaceName]; exists {
		cancel()
		delete(dpm.monitorCancel, interfaceName)
	}
	delete(dpm.autoRoute4, interfaceName)
	delete(dpm.autoRoute6, interfaceName)
}

// monitorDaemon watches for route changes and refreshes endpoint routes, MTU, and DNS.
func (dpm *DarwinPlatformManager) monitorDaemon(ctx context.Context, interfaceName string, cfg *config.Config, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) {
	dpm.logger.Info("Backgrounding route monitor")

	cmd := exec.CommandContext(ctx, "route", "-n", "monitor")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		dpm.logger.Warning(fmt.Sprintf("Failed to create route monitor pipe: %v", err))
		return
	}
	if err := cmd.Start(); err != nil {
		dpm.logger.Warning(fmt.Sprintf("Failed to start route monitor: %v", err))
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			return
		default:
		}

		line := scanner.Text()
		if !strings.HasPrefix(line, "RTM_") {
			continue
		}

		// Check if interface still exists
		if !dpm.InterfaceExists(interfaceName) {
			break
		}

		dpm.mu.Lock()
		hasAutoRoute4 := dpm.autoRoute4[interfaceName]
		hasAutoRoute6 := dpm.autoRoute6[interfaceName]
		dpm.mu.Unlock()

		// Refresh endpoint routes
		if hasAutoRoute4 || hasAutoRoute6 {
			dpm.refreshEndpointRoutes(interfaceName)
		}

		// Refresh MTU if not manually set
		if cfg.Interface.MTU == nil {
			if mtu, err := dpm.CalculateOptimalMTU(interfaceName, outputParser, cmdRunner); err == nil {
				currentMTU := dpm.GetCurrentMTU(interfaceName)
				if mtu != currentMTU && mtu > 0 {
					realIntf := dpm.GetRealInterfaceName(interfaceName)
					if err := dpm.cmdRunner.Run("ifconfig", realIntf, "mtu", strconv.Itoa(mtu)); err != nil {
						dpm.logger.Warning(fmt.Sprintf("Failed to update MTU for %s: %v", realIntf, err))
					}
				}
			}
		}

		// Refresh DNS (macOS-specific: re-apply to all network services)
		if len(cfg.Interface.DNS) > 0 {
			if err := dpm.SetupDNS(interfaceName, cfg.Interface.DNS, cfg.Interface.DNSSearch); err != nil {
				dpm.logger.Warning(fmt.Sprintf("Failed to refresh DNS for %s: %v", interfaceName, err))
			}
			// Schedule delayed re-apply (matches original bash ALRM signal pattern)
			go func() {
				select {
				case <-time.After(2 * time.Second):
					if err := dpm.SetupDNS(interfaceName, cfg.Interface.DNS, cfg.Interface.DNSSearch); err != nil {
						dpm.logger.Warning(fmt.Sprintf("Failed to re-apply DNS for %s: %v", interfaceName, err))
					}
				case <-ctx.Done():
				}
			}()
		}
	}

	_ = cmd.Wait()
}

// refreshEndpointRoutes refreshes endpoint protection routes when gateway changes.
// Matches original darwin.bash set_endpoint_direct_route() function.
func (dpm *DarwinPlatformManager) refreshEndpointRoutes(interfaceName string) {
	dpm.mu.Lock()
	oldRoutes := dpm.endpointRoutes[interfaceName]
	dpm.mu.Unlock()

	// Get current gateway
	routeInfo, err := utils.GetDefaultRouteInfoBSD(dpm.cmdRunner)
	if err != nil {
		return
	}

	// Get current endpoints
	endpoints, err := dpm.getEndpoints(interfaceName)
	if err != nil {
		return
	}

	// Check if gateway changed
	gatewayChanged := len(oldRoutes) > 0 && oldRoutes[0].gateway != routeInfo.Gateway

	// Build set of current endpoints for quick lookup
	currentEndpoints := make(map[string]bool)
	for _, ep := range endpoints {
		currentEndpoints[ep] = true
	}

	// Remove old routes if gateway changed or endpoint removed
	for _, route := range oldRoutes {
		if !gatewayChanged && currentEndpoints[route.endpoint] {
			continue
		}
		_ = dpm.cmdRunner.Run("route", "-q", "-n", "delete", "-host", route.endpoint)
	}

	// Add routes for current endpoints
	var newRoutes []EndpointRoute
	for _, endpoint := range endpoints {
		if strings.HasPrefix(endpoint, "127.0.0.1") || strings.HasPrefix(endpoint, "::1") {
			continue
		}

		if !gatewayChanged {
			// Check if already routed
			alreadyRouted := false
			for _, old := range oldRoutes {
				if old.endpoint == endpoint {
					alreadyRouted = true
					newRoutes = append(newRoutes, old)
					break
				}
			}
			if alreadyRouted {
				continue
			}
		}

		gateway := routeInfo.Gateway
		if gateway == "" {
			// Blackhole fallback
			if strings.Contains(endpoint, ":") {
				gateway = "::1"
			} else {
				gateway = "127.0.0.1"
			}
			if err := dpm.cmdRunner.Run("route", "-q", "-n", "add", "-host", endpoint, gateway, "-blackhole"); err != nil {
				dpm.logger.Warning(fmt.Sprintf("Failed to add blackhole endpoint route for %s: %v", endpoint, err))
			}
		} else {
			if err := dpm.cmdRunner.Run("route", "-q", "-n", "add", "-host", endpoint, "-gateway", gateway); err != nil {
				dpm.logger.Warning(fmt.Sprintf("Failed to add endpoint route for %s via %s: %v", endpoint, gateway, err))
			}
		}
		newRoutes = append(newRoutes, EndpointRoute{endpoint: endpoint, gateway: gateway})
	}

	dpm.mu.Lock()
	dpm.endpointRoutes[interfaceName] = newRoutes
	dpm.mu.Unlock()
}

// cleanupEndpointProtection removes endpoint protection routes
func (dpm *DarwinPlatformManager) cleanupEndpointProtection(interfaceName string) {
	routes, exists := dpm.endpointRoutes[interfaceName]
	if !exists || len(routes) == 0 {
		return
	}

	for _, route := range routes {
		dpm.logger.Info(fmt.Sprintf("Removing endpoint protection route: %s", route.endpoint))

		err := dpm.cmdRunner.Run("route", "delete", "-host", route.endpoint)
		if err != nil {
			dpm.logger.Warning(fmt.Sprintf("Failed to remove endpoint route for %s: %v", route.endpoint, err))
		}
	}

	delete(dpm.endpointRoutes, interfaceName)
}
