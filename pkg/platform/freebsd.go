//go:build freebsd

package platform

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/n0madic/wg-quick-go/pkg/config"
	"github.com/n0madic/wg-quick-go/pkg/logger"
	"github.com/n0madic/wg-quick-go/pkg/runner"
	"github.com/n0madic/wg-quick-go/pkg/utils"
)

// FreeBSDPlatformManager implements PlatformManager for FreeBSD
type FreeBSDPlatformManager struct {
	logger       logger.Logger
	cmdRunner    runner.SystemCommandRunner
	userspaceCmd string

	// State tracking
	dnsSet         map[string]bool
	firewallSet    map[string]bool
	usingKernel    map[string]bool // Track if interface uses kernel or userspace implementation
	mu             sync.Mutex
	monitorCancel  map[string]context.CancelFunc
	autoRoute4     map[string]bool
	autoRoute6     map[string]bool
	endpointRoutes map[string][]endpointRoute
}

// endpointRoute represents a protected endpoint route
type endpointRoute struct {
	endpoint string
	gateway  string
}

// newPlatformManager creates a FreeBSD-specific platform manager
func newPlatformManager(logger logger.Logger) PlatformManager {
	return &FreeBSDPlatformManager{
		logger:         logger,
		dnsSet:         make(map[string]bool),
		firewallSet:    make(map[string]bool),
		usingKernel:    make(map[string]bool),
		monitorCancel:  make(map[string]context.CancelFunc),
		autoRoute4:     make(map[string]bool),
		autoRoute6:     make(map[string]bool),
		endpointRoutes: make(map[string][]endpointRoute),
	}
}

// SetCommandRunner sets the system command runner
func (fpm *FreeBSDPlatformManager) SetCommandRunner(cmdRunner runner.SystemCommandRunner) {
	fpm.cmdRunner = cmdRunner
}

// CheckRequirements checks if the system meets requirements for WireGuard
func (fpm *FreeBSDPlatformManager) CheckRequirements() error {
	// Check if running as root
	if err := utils.CheckRootPrivileges(); err != nil {
		return err
	}

	// If userspace is forced, only check userspace implementation
	if utils.IsUserspaceForced() {
		candidateCmd := utils.GetUserspaceCommand()
		if _, err := fpm.cmdRunner.RunWithOutput("which", candidateCmd); err != nil {
			return fmt.Errorf("forced userspace implementation (%s) not found", candidateCmd)
		}
		fpm.userspaceCmd = candidateCmd
	} else {
		// Check for WireGuard kernel module
		err := fpm.cmdRunner.Run("kldstat", "-q", "-m", "if_wg")
		if err != nil {
			// Try to load the module
			if loadErr := fpm.cmdRunner.Run("kldload", "if_wg"); loadErr != nil {
				fpm.logger.Warning("WireGuard kernel module not available, will use userspace implementation")

				// Check for userspace implementation
				candidateCmd := utils.GetUserspaceCommand()
				if _, err := fpm.cmdRunner.RunWithOutput("which", candidateCmd); err != nil {
					return fmt.Errorf("neither WireGuard kernel module nor userspace implementation found")
				}
				// Only set userspaceCmd if the command actually exists
				fpm.userspaceCmd = candidateCmd
			} else {
				// Kernel module loaded successfully, but still check userspace for potential fallback
				candidateCmd := utils.GetUserspaceCommand()
				if _, err := fpm.cmdRunner.RunWithOutput("which", candidateCmd); err == nil {
					fpm.userspaceCmd = candidateCmd
				}
			}
		} else {
			// Kernel module already available, but still check userspace for potential fallback
			candidateCmd := utils.GetUserspaceCommand()
			if _, err := fpm.cmdRunner.RunWithOutput("which", candidateCmd); err == nil {
				fpm.userspaceCmd = candidateCmd
			}
		}
	}

	// Check for required system utilities
	requiredCommands := []string{"ifconfig", "route", "wg"}
	if err := utils.CheckRequiredCommands(requiredCommands, fpm.cmdRunner); err != nil {
		return err
	}

	return nil
}

// ValidateConfig validates FreeBSD-specific config requirements
func (fpm *FreeBSDPlatformManager) ValidateConfig(config *config.Config) error {
	// FreeBSD-specific validations only (universal validations done in WireGuardManager)

	// Check if resolvconf is available for DNS configuration
	if len(config.Interface.DNS) > 0 {
		if _, err := fpm.cmdRunner.RunWithOutput("which", "resolvconf"); err != nil {
			fpm.logger.Warning("resolvconf not available, DNS configuration may not work properly")
		}
	}

	// FreeBSD-specific: validate FIB table if specified
	if config.Interface.Table != "" && config.Interface.Table != "auto" && config.Interface.Table != "off" {
		if tableNum, err := strconv.Atoi(config.Interface.Table); err == nil {
			if err := utils.ValidateFIBTable(tableNum); err != nil {
				return fmt.Errorf("FreeBSD FIB table validation: %w", err)
			}
		}
	}

	// Check if we can create wg interfaces (kernel module test)
	if !utils.IsUserspaceForced() {
		// Test if we can create a temporary wg interface
		testInterface := "wg-test-" + fmt.Sprintf("%d", os.Getpid())
		if err := fpm.cmdRunner.Run("ifconfig", "wg", "create", "name", testInterface); err == nil {
			// Clean up test interface
			fpm.cmdRunner.Run("ifconfig", testInterface, "destroy")
		} else {
			fpm.logger.Info("FreeBSD kernel WireGuard module not available, will use userspace")
		}
	}

	return nil
}

// CreateInterface creates WireGuard interface
func (fpm *FreeBSDPlatformManager) CreateInterface(interfaceName string) error {
	// Check if userspace implementation is forced (when WG_QUICK_USERSPACE_IMPLEMENTATION is set)
	if utils.IsUserspaceForced() && fpm.userspaceCmd != "" {
		fpm.logger.Info(fmt.Sprintf("Using forced userspace implementation: %s", fpm.userspaceCmd))
		if err := fpm.cmdRunner.Run(fpm.userspaceCmd, interfaceName); err != nil {
			return fmt.Errorf("failed to start WireGuard userspace: %w", err)
		}
		fpm.usingKernel[interfaceName] = false
		return nil
	}

	// Try kernel module first
	err := fpm.cmdRunner.Run("ifconfig", "wg", "create", "name", interfaceName)
	if err == nil {
		fpm.usingKernel[interfaceName] = true
		return nil
	}

	// Fallback to userspace implementation
	if fpm.userspaceCmd == "" {
		return fmt.Errorf("WireGuard kernel interface creation failed and no userspace implementation found")
	}

	fpm.logger.Info("WireGuard kernel interface creation failed, using userspace implementation")

	if err := fpm.cmdRunner.Run(fpm.userspaceCmd, interfaceName); err != nil {
		return fmt.Errorf("failed to start WireGuard userspace: %w", err)
	}

	fpm.usingKernel[interfaceName] = false
	return nil
}

// DeleteInterface deletes interface
func (fpm *FreeBSDPlatformManager) DeleteInterface(interfaceName string) error {
	// Clean up endpoint protection routes first
	fpm.cleanupEndpointProtection(interfaceName)

	var err error

	if fpm.usingKernel[interfaceName] {
		// Kernel interface - destroy using ifconfig
		err = fpm.cmdRunner.Run("ifconfig", interfaceName, "destroy")
	} else {
		// Userspace interface - clean up socket file to stop the process
		utils.CleanupUserspaceFiles(interfaceName, interfaceName, fpm.logger)
	}

	// Poll until interface disappears (matching original freebsd.bash behavior)
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if !fpm.InterfaceExists(interfaceName) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if fpm.InterfaceExists(interfaceName) {
		fpm.logger.Warning(fmt.Sprintf("Interface %s still exists after timeout", interfaceName))
	}

	delete(fpm.usingKernel, interfaceName)
	return err
}

// InterfaceExists checks if interface exists
func (fpm *FreeBSDPlatformManager) InterfaceExists(interfaceName string) bool {
	return utils.CheckInterfaceExistsBSD(interfaceName, fpm.cmdRunner)
}

// AddAddress adds IP address to interface
func (fpm *FreeBSDPlatformManager) AddAddress(interfaceName string, addr net.IPNet) error {
	isIPv4, _, _ := utils.GetIPProtocolInfo(addr)

	var family string
	if isIPv4 {
		family = "inet"
	} else {
		family = "inet6"
	}

	return fpm.cmdRunner.Run("ifconfig", interfaceName, family, addr.String(), "alias")
}

// GetCurrentAddresses gets current interface addresses
func (fpm *FreeBSDPlatformManager) GetCurrentAddresses(interfaceName string) []string {
	output, err := fpm.cmdRunner.RunWithOutput("ifconfig", interfaceName)
	if err != nil {
		return nil
	}

	return utils.ParseBSDInterfaceAddresses(output)
}

// SetMTUAndUp sets MTU and brings up interface
func (fpm *FreeBSDPlatformManager) SetMTUAndUp(interfaceName string, mtu int) error {
	// Set MTU and bring interface up
	return fpm.cmdRunner.Run("ifconfig", interfaceName, "mtu", strconv.Itoa(mtu), "up")
}

// GetCurrentMTU gets current interface MTU
func (fpm *FreeBSDPlatformManager) GetCurrentMTU(interfaceName string) int {
	return utils.GetInterfaceMTUFromIfconfig(interfaceName, fpm.cmdRunner)
}

// CalculateOptimalMTU calculates optimal MTU for FreeBSD using MAX-of-endpoints strategy.
// Matches original freebsd.bash: takes the maximum MTU from all endpoint paths.
func (fpm *FreeBSDPlatformManager) CalculateOptimalMTU(interfaceName string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) (int, error) {
	result, err := utils.CalculateOptimalMTUMaxOfEndpoints(interfaceName, cmdRunner)
	if err == nil && result > 0 {
		return result, nil
	}
	// Fallback to default route MTU
	return utils.CalculateOptimalMTUFromDefaultRoute(false, cmdRunner)
}

// GetMTUForEndpoint gets MTU for route to endpoint
func (fpm *FreeBSDPlatformManager) GetMTUForEndpoint(endpoint string, cmdRunner runner.SystemCommandRunner) (int, error) {
	return utils.RouteGetMTUForEndpoint(endpoint, true, false, cmdRunner)
}

// SetupDNS configures DNS using resolvconf
func (fpm *FreeBSDPlatformManager) SetupDNS(interfaceName string, dns []net.IP, search []string) error {
	if len(dns) == 0 {
		return nil
	}

	// Check if resolvconf is available
	if _, err := fpm.cmdRunner.RunWithOutput("which", "resolvconf"); err != nil {
		fpm.logger.Warning("resolvconf not found, skipping DNS configuration")
		return nil
	}

	var resolvConf strings.Builder

	for _, dnsIP := range dns {
		resolvConf.WriteString(fmt.Sprintf("nameserver %s\n", dnsIP.String()))
	}

	if len(search) > 0 {
		resolvConf.WriteString(fmt.Sprintf("search %s\n", strings.Join(search, " ")))
	}

	// Use -x flag for exclusive mode (matching original freebsd.bash)
	err := fpm.cmdRunner.RunWithInput(resolvConf.String(), "resolvconf", "-a", interfaceName, "-x")
	if err != nil {
		return err
	}

	fpm.dnsSet[interfaceName] = true
	return nil
}

// CleanupDNS cleans up DNS settings
func (fpm *FreeBSDPlatformManager) CleanupDNS(interfaceName string) {
	if !fpm.dnsSet[interfaceName] {
		return
	}

	fpm.cmdRunner.Run("resolvconf", "-d", interfaceName)
	delete(fpm.dnsSet, interfaceName)
}

// GetCurrentDNS reads live DNS nameserver IPs from resolvconf.
// Matches original freebsd.bash save_config: resolvconf -l "$INTERFACE"
func (fpm *FreeBSDPlatformManager) GetCurrentDNS(interfaceName string) []string {
	output, err := fpm.cmdRunner.RunWithOutput("resolvconf", "-l", interfaceName)
	if err != nil {
		return nil
	}

	re := regexp.MustCompile(`^nameserver\s+([a-zA-Z0-9_=+:%.-]+)$`)
	var nameservers []string
	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		if matches := re.FindStringSubmatch(scanner.Text()); len(matches) > 1 {
			nameservers = append(nameservers, matches[1])
		}
	}
	return nameservers
}

// SetupRoutes configures routes
func (fpm *FreeBSDPlatformManager) SetupRoutes(interfaceName string, allowedIPs []net.IPNet, table string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error {
	return utils.SetupRoutesCommon(interfaceName, allowedIPs, table, outputParser, cmdRunner,
		func() ([]net.IPNet, error) {
			return utils.GetAllowedIPsFromInterface(interfaceName, outputParser, cmdRunner)
		},
		func(route net.IPNet) error {
			return fpm.AddRoute(interfaceName, route, table)
		})
}

// AddRoute adds a route
func (fpm *FreeBSDPlatformManager) AddRoute(interfaceName string, route net.IPNet, table string) error {
	// Check if this is a default route
	if utils.IsDefaultRoute(route) {
		return fpm.AddDefaultRoute(interfaceName, route, 0, fpm.cmdRunner)
	}

	isIPv4, _, _ := utils.GetIPProtocolInfo(route)

	var family string
	if isIPv4 {
		family = "-inet"
	} else {
		family = "-inet6"
	}

	// Check if route already exists
	if utils.CheckRouteExistsBSD(route, interfaceName, false, fpm.cmdRunner) {
		return nil // Route already exists
	}

	return fpm.cmdRunner.Run("route", "add", family, route.String(), "-interface", interfaceName)
}

// AddDefaultRoute adds default route with FreeBSD-specific handling
func (fpm *FreeBSDPlatformManager) AddDefaultRoute(interfaceName string, route net.IPNet, fwmark int, cmdRunner runner.SystemCommandRunner) error {
	// Track auto-route state for monitor daemon
	isIPv4, _, _ := utils.GetIPProtocolInfo(route)
	if isIPv4 {
		fpm.autoRoute4[interfaceName] = true
	} else {
		fpm.autoRoute6[interfaceName] = true
	}

	// Add endpoint protection before setting up split routes
	fpm.addEndpointProtection(interfaceName)

	return utils.AddDefaultRouteOverrideBSD(interfaceName, route, cmdRunner)
}

// GetFwMark gets current fwmark (FreeBSD doesn't use fwmark like Linux)
func (fpm *FreeBSDPlatformManager) GetFwMark(interfaceName string, cmdRunner runner.SystemCommandRunner) (int, error) {
	// FreeBSD doesn't use fwmark like Linux, but we can check WireGuard's fwmark setting
	output, err := cmdRunner.RunWithOutput("wg", "show", interfaceName, "fwmark")
	if err != nil {
		return 0, err
	}

	fwmarkStr := strings.TrimSpace(string(output))
	if fwmarkStr == "off" || fwmarkStr == "" {
		return 0, fmt.Errorf("no fwmark set")
	}

	return strconv.Atoi(fwmarkStr)
}

// TableInUse checks if routing table is in use (FreeBSD uses FIBs)
func (fpm *FreeBSDPlatformManager) TableInUse(table int, cmdRunner runner.SystemCommandRunner) bool {
	return utils.CheckBSDRoutingTableInUse(table, false, cmdRunner)
}

// SetupFirewall configures firewall rules using FreeBSD's pf
func (fpm *FreeBSDPlatformManager) SetupFirewall(interfaceName string, fwmark int, addresses []net.IPNet, cmdRunner runner.SystemCommandRunner) error {
	// FreeBSD firewall setup using pf (Packet Filter)
	// This is optional - FreeBSD may not need the same firewall rules as Linux
	// Similar to macOS, the routing setup might be sufficient

	// Check if pf is available and enabled
	if _, err := cmdRunner.RunWithOutput("which", "pfctl"); err != nil {
		fpm.logger.Warning("pfctl not found, skipping firewall configuration")
		return nil
	}

	// For now, we'll keep this minimal like macOS
	// Advanced pf rules could be added later if needed for leak protection
	fpm.firewallSet[interfaceName] = true
	return nil
}

// CleanupFirewall cleans up firewall rules
func (fpm *FreeBSDPlatformManager) CleanupFirewall(interfaceName string, cmdRunner runner.SystemCommandRunner) {
	if !fpm.firewallSet[interfaceName] {
		return
	}

	// Clean up any pf rules if they were created
	// For now, this is a no-op like macOS
	delete(fpm.firewallSet, interfaceName)
}

// ConfigureWireGuard configures WireGuard interface using `wg addconf`.
// Matches original freebsd.bash: echo "$WG_CONFIG" | cmd wg addconf "$INTERFACE" /dev/stdin
func (fpm *FreeBSDPlatformManager) ConfigureWireGuard(interfaceName string, config *config.Config, cmdRunner runner.SystemCommandRunner) error {
	return utils.ConfigureWireGuardAddconf(interfaceName, config.RawWGConfig, cmdRunner)
}

// GetWireGuardInterfaceName returns the interface name for WireGuard commands
func (fpm *FreeBSDPlatformManager) GetWireGuardInterfaceName(interfaceName string) string {
	// FreeBSD uses the interface name directly
	return interfaceName
}

// GetRealInterfaceName returns the actual OS-level interface name.
// On FreeBSD, real name equals the logical name.
func (fpm *FreeBSDPlatformManager) GetRealInterfaceName(interfaceName string) string {
	return interfaceName
}

// StartMonitor starts the route monitor daemon.
// Matches original freebsd.bash monitor_daemon() function.
func (fpm *FreeBSDPlatformManager) StartMonitor(interfaceName string, cfg *config.Config, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error {
	fpm.mu.Lock()
	defer fpm.mu.Unlock()

	if !fpm.autoRoute4[interfaceName] && !fpm.autoRoute6[interfaceName] {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	fpm.monitorCancel[interfaceName] = cancel

	go fpm.monitorDaemon(ctx, interfaceName, cfg, outputParser, cmdRunner)
	return nil
}

// StopMonitor stops the route monitor daemon.
func (fpm *FreeBSDPlatformManager) StopMonitor(interfaceName string) {
	fpm.mu.Lock()
	defer fpm.mu.Unlock()

	if cancel, exists := fpm.monitorCancel[interfaceName]; exists {
		cancel()
		delete(fpm.monitorCancel, interfaceName)
	}
	delete(fpm.autoRoute4, interfaceName)
	delete(fpm.autoRoute6, interfaceName)
}

// monitorDaemon watches for route changes and refreshes endpoint routes and MTU.
func (fpm *FreeBSDPlatformManager) monitorDaemon(ctx context.Context, interfaceName string, cfg *config.Config, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) {
	fpm.logger.Info("Backgrounding route monitor")

	cmd := exec.CommandContext(ctx, "route", "-n", "monitor")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		fpm.logger.Warning(fmt.Sprintf("Failed to create route monitor pipe: %v", err))
		return
	}
	if err := cmd.Start(); err != nil {
		fpm.logger.Warning(fmt.Sprintf("Failed to start route monitor: %v", err))
		return
	}

	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			cmd.Process.Kill()
			cmd.Wait()
			return
		default:
		}

		line := scanner.Text()
		if !strings.HasPrefix(line, "RTM_") {
			continue
		}

		if !fpm.InterfaceExists(interfaceName) {
			break
		}

		fpm.mu.Lock()
		hasAutoRoute4 := fpm.autoRoute4[interfaceName]
		hasAutoRoute6 := fpm.autoRoute6[interfaceName]
		fpm.mu.Unlock()

		if hasAutoRoute4 || hasAutoRoute6 {
			fpm.refreshEndpointRoutes(interfaceName)
		}

		// Refresh MTU if not manually set
		if cfg.Interface.MTU == nil {
			if mtu, err := fpm.CalculateOptimalMTU(interfaceName, outputParser, cmdRunner); err == nil {
				currentMTU := fpm.GetCurrentMTU(interfaceName)
				if mtu != currentMTU && mtu > 0 {
					fpm.cmdRunner.Run("ifconfig", interfaceName, "mtu", strconv.Itoa(mtu))
				}
			}
		}
	}

	cmd.Wait()
}

// addEndpointProtection adds routes for WireGuard endpoints via original gateway.
func (fpm *FreeBSDPlatformManager) addEndpointProtection(interfaceName string) {
	routeInfo, err := utils.GetDefaultRouteInfoBSD(fpm.cmdRunner)
	if err != nil {
		return
	}

	endpoints, err := fpm.getEndpoints(interfaceName)
	if err != nil || len(endpoints) == 0 {
		return
	}

	var routes []endpointRoute
	for _, endpoint := range endpoints {
		if strings.HasPrefix(endpoint, "127.0.0.1") || strings.HasPrefix(endpoint, "::1") {
			continue
		}

		gateway := routeInfo.Gateway
		if gateway == "" {
			if strings.Contains(endpoint, ":") {
				gateway = "::1"
			} else {
				gateway = "127.0.0.1"
			}
			fpm.cmdRunner.Run("route", "-q", "-n", "add", "-host", endpoint, gateway, "-blackhole")
		} else {
			fpm.cmdRunner.Run("route", "-q", "-n", "add", "-host", endpoint, "-gateway", gateway)
		}
		routes = append(routes, endpointRoute{endpoint: endpoint, gateway: gateway})
	}

	fpm.mu.Lock()
	fpm.endpointRoutes[interfaceName] = routes
	fpm.mu.Unlock()
}

// cleanupEndpointProtection removes endpoint protection routes.
func (fpm *FreeBSDPlatformManager) cleanupEndpointProtection(interfaceName string) {
	fpm.mu.Lock()
	routes := fpm.endpointRoutes[interfaceName]
	delete(fpm.endpointRoutes, interfaceName)
	fpm.mu.Unlock()

	for _, route := range routes {
		fpm.cmdRunner.Run("route", "-q", "-n", "delete", "-host", route.endpoint)
	}
}

// getEndpoints gets current WireGuard peer endpoints.
func (fpm *FreeBSDPlatformManager) getEndpoints(interfaceName string) ([]string, error) {
	return utils.GetWireGuardIPEndpoints(interfaceName, fpm.cmdRunner)
}

// refreshEndpointRoutes refreshes endpoint protection routes when gateway changes.
func (fpm *FreeBSDPlatformManager) refreshEndpointRoutes(interfaceName string) {
	fpm.mu.Lock()
	oldRoutes := fpm.endpointRoutes[interfaceName]
	fpm.mu.Unlock()

	routeInfo, err := utils.GetDefaultRouteInfoBSD(fpm.cmdRunner)
	if err != nil {
		return
	}

	endpoints, err := fpm.getEndpoints(interfaceName)
	if err != nil {
		return
	}

	gatewayChanged := false
	if len(oldRoutes) > 0 && oldRoutes[0].gateway != routeInfo.Gateway {
		gatewayChanged = true
	}

	currentEndpoints := make(map[string]bool)
	for _, ep := range endpoints {
		currentEndpoints[ep] = true
	}

	for _, route := range oldRoutes {
		if !gatewayChanged && currentEndpoints[route.endpoint] {
			continue
		}
		fpm.cmdRunner.Run("route", "-q", "-n", "delete", "-host", route.endpoint)
	}

	var newRoutes []endpointRoute
	for _, endpoint := range endpoints {
		if strings.HasPrefix(endpoint, "127.0.0.1") || strings.HasPrefix(endpoint, "::1") {
			continue
		}

		if !gatewayChanged {
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
			if strings.Contains(endpoint, ":") {
				gateway = "::1"
			} else {
				gateway = "127.0.0.1"
			}
			fpm.cmdRunner.Run("route", "-q", "-n", "add", "-host", endpoint, gateway, "-blackhole")
		} else {
			fpm.cmdRunner.Run("route", "-q", "-n", "add", "-host", endpoint, "-gateway", gateway)
		}
		newRoutes = append(newRoutes, endpointRoute{endpoint: endpoint, gateway: gateway})
	}

	fpm.mu.Lock()
	fpm.endpointRoutes[interfaceName] = newRoutes
	fpm.mu.Unlock()
}
