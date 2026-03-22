//go:build openbsd

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

	"github.com/n0madic/wg-quick-go/pkg/config"
	"github.com/n0madic/wg-quick-go/pkg/logger"
	"github.com/n0madic/wg-quick-go/pkg/runner"
	"github.com/n0madic/wg-quick-go/pkg/utils"
)

// openBSDRouteRunner wraps the command runner to add -q flag for OpenBSD route commands
type openBSDRouteRunner struct {
	cmdRunner interface { // This should be runner.SystemCommandRunner
		Run(command string, args ...string) error
		RunWithOutput(command string, args ...string) ([]byte, error)
	}
}

func (r *openBSDRouteRunner) Run(command string, args ...string) error {
	if command == "route" && len(args) > 0 && args[0] == "add" {
		// Insert -q flag for OpenBSD route add commands
		newArgs := []string{"-q"}
		newArgs = append(newArgs, args...)
		return r.cmdRunner.Run(command, newArgs...)
	}
	return r.cmdRunner.Run(command, args...)
}

func (r *openBSDRouteRunner) RunWithOutput(command string, args ...string) ([]byte, error) {
	return r.cmdRunner.RunWithOutput(command, args...)
}

// OpenBSDPlatformManager implements PlatformManager for OpenBSD
type OpenBSDPlatformManager struct {
	logger       logger.Logger
	cmdRunner    runner.SystemCommandRunner
	userspaceCmd string

	// State tracking
	dnsSet           map[string]*OpenBSDDNSState
	firewallSet      map[string]bool
	interfaceIndexes map[string]int // Track WireGuard interface indexes
	mu               sync.Mutex
	monitorCancel    map[string]context.CancelFunc
	autoRoute4       map[string]bool
	autoRoute6       map[string]bool
	endpointRoutes   map[string][]obsdEndpointRoute
}

// OpenBSDDNSState tracks DNS configuration for restoration
type OpenBSDDNSState struct {
	backupPath  string // path to resolv.conf backup (e.g., /etc/resolv.conf.wg-quick-backup.wg0)
	usedRouteNS bool
}

// obsdEndpointRoute represents a protected endpoint route
type obsdEndpointRoute struct {
	endpoint string
	gateway  string
}

// newPlatformManager creates an OpenBSD-specific platform manager
func newPlatformManager(logger logger.Logger) PlatformManager {
	return &OpenBSDPlatformManager{
		logger:           logger,
		dnsSet:           make(map[string]*OpenBSDDNSState),
		firewallSet:      make(map[string]bool),
		interfaceIndexes: make(map[string]int),
		monitorCancel:    make(map[string]context.CancelFunc),
		autoRoute4:       make(map[string]bool),
		autoRoute6:       make(map[string]bool),
		endpointRoutes:   make(map[string][]obsdEndpointRoute),
	}
}

// SetCommandRunner sets the system command runner
func (opm *OpenBSDPlatformManager) SetCommandRunner(cmdRunner runner.SystemCommandRunner) {
	opm.cmdRunner = cmdRunner
}

// CheckRequirements checks if the system meets requirements for WireGuard
func (opm *OpenBSDPlatformManager) CheckRequirements() error {
	// Check if running as root or with doas
	if err := utils.CheckRootPrivileges(); err != nil {
		return fmt.Errorf("this program must be run as root or with doas")
	}

	// Check for WireGuard userspace implementation (OpenBSD typically uses userspace)
	candidateCmd := utils.GetUserspaceCommand()
	if _, err := opm.cmdRunner.RunWithOutput("which", candidateCmd); err != nil {
		return fmt.Errorf("WireGuard userspace implementation (%s) not found", candidateCmd)
	}
	// Only set userspaceCmd if the command actually exists
	opm.userspaceCmd = candidateCmd

	// Check for required system utilities
	requiredCommands := []string{"ifconfig", "route", "wg"}
	if err := utils.CheckRequiredCommands(requiredCommands, opm.cmdRunner); err != nil {
		return err
	}

	return nil
}

// ValidateConfig validates OpenBSD-specific config requirements
func (opm *OpenBSDPlatformManager) ValidateConfig(config *config.Config) error {
	// OpenBSD-specific validations only (universal validations done in WireGuardManager)

	// Check DNS daemon configuration (OpenBSD uses unwind/resolvd)
	if len(config.Interface.DNS) > 0 {
		// Check for DNS daemons
		dnsAvailable := false
		for _, daemon := range []string{"unwind", "resolvd"} {
			if _, err := opm.cmdRunner.RunWithOutput("which", daemon); err == nil {
				dnsAvailable = true
				break
			}
		}

		if !dnsAvailable {
			// Check if we can write to resolv.conf directly
			if _, err := os.Stat("/etc/resolv.conf"); err != nil {
				opm.logger.Warning("No DNS daemon and cannot access /etc/resolv.conf, DNS configuration may not work")
			}
		}
	}

	// OpenBSD primarily uses userspace implementation
	if opm.userspaceCmd == "" {
		return fmt.Errorf("OpenBSD requires userspace WireGuard implementation")
	}

	// Check if we can find available wg interface slots
	if existing, err := opm.getExistingWgInterfaces(); err == nil && len(existing) >= 256 {
		opm.logger.Warning("All wg interface slots may be in use")
	}

	return nil
}

// CreateInterface creates WireGuard interface using OpenBSD-specific method.
// Matches original openbsd.bash add_if() with retry loop for race conditions.
func (opm *OpenBSDPlatformManager) CreateInterface(interfaceName string) error {
	for {
		// Find existing wg interfaces (matching original: wg show interfaces | sed ...)
		existingIFs, err := opm.getExistingWgInterfaces()
		if err != nil {
			return fmt.Errorf("failed to list existing interfaces: %w", err)
		}

		// Find first available index
		index := -1
		for i := 0; i <= 2147483647; i++ {
			if !existingIFs[i] {
				index = i
				break
			}
		}
		if index < 0 {
			return fmt.Errorf("no available wg interface slots")
		}

		realIntfName := fmt.Sprintf("wg%d", index)

		// Create interface with wg-quick description (matching original bash format)
		output, err := opm.cmdRunner.RunWithOutput("ifconfig", realIntfName, "create",
			"description", fmt.Sprintf("wg-quick: %s", interfaceName))
		if err == nil {
			opm.interfaceIndexes[interfaceName] = index
			return nil
		}

		// Retry on race condition (matching original: SIOCIFCREATE: File exists → continue)
		if strings.Contains(string(output), "File exists") {
			continue
		}

		// Real failure
		return fmt.Errorf("failed to create interface %s: %w", realIntfName, err)
	}
}

// getExistingWgInterfaces returns a set of existing wg interface indexes.
func (opm *OpenBSDPlatformManager) getExistingWgInterfaces() (map[int]bool, error) {
	output, err := opm.cmdRunner.RunWithOutput("wg", "show", "interfaces")
	if err != nil {
		// If wg fails, fall back to ifconfig parsing
		return opm.getExistingWgInterfacesFromIfconfig()
	}

	existing := make(map[int]bool)
	re := regexp.MustCompile(`wg(\d+)`)
	for _, match := range re.FindAllStringSubmatch(string(output), -1) {
		if idx, err := strconv.Atoi(match[1]); err == nil {
			existing[idx] = true
		}
	}
	return existing, nil
}

// getExistingWgInterfacesFromIfconfig falls back to ifconfig for interface discovery.
func (opm *OpenBSDPlatformManager) getExistingWgInterfacesFromIfconfig() (map[int]bool, error) {
	output, err := opm.cmdRunner.RunWithOutput("ifconfig")
	if err != nil {
		return nil, err
	}

	existing := make(map[int]bool)
	re := regexp.MustCompile(`^wg(\d+):`)
	for _, line := range strings.Split(string(output), "\n") {
		if m := re.FindStringSubmatch(line); len(m) > 1 {
			if idx, err := strconv.Atoi(m[1]); err == nil {
				existing[idx] = true
			}
		}
	}
	return existing, nil
}

// getRealInterface gets the actual wg interface name for a logical interface.
// First checks in-memory cache, then falls back to scanning ifconfig descriptions.
// This allows `down` to work even when called from a different process than `up`.
func (opm *OpenBSDPlatformManager) getRealInterface(interfaceName string) (string, error) {
	// Check cached mapping first
	if index, exists := opm.interfaceIndexes[interfaceName]; exists {
		return fmt.Sprintf("wg%d", index), nil
	}

	// Fallback: scan ifconfig for description (matching original openbsd.bash get_real_interface)
	realIntf, err := opm.findInterfaceByDescription(interfaceName)
	if err != nil {
		return "", fmt.Errorf("interface %s not found", interfaceName)
	}

	// Cache the discovered mapping
	re := regexp.MustCompile(`^wg(\d+)$`)
	if m := re.FindStringSubmatch(realIntf); len(m) > 1 {
		if idx, err := strconv.Atoi(m[1]); err == nil {
			opm.interfaceIndexes[interfaceName] = idx
		}
	}

	return realIntf, nil
}

// findInterfaceByDescription scans ifconfig output for a wg interface with
// the matching "wg-quick: <name>" description.
// Matches original openbsd.bash get_real_interface() behavior.
func (opm *OpenBSDPlatformManager) findInterfaceByDescription(interfaceName string) (string, error) {
	output, err := opm.cmdRunner.RunWithOutput("ifconfig")
	if err != nil {
		return "", err
	}

	var currentIntf string
	intfRe := regexp.MustCompile(`^(wg\d+):\s`)
	descRe := regexp.MustCompile(`^\s+description:\s+wg-quick:\s+(.+)`)

	for _, line := range strings.Split(string(output), "\n") {
		if m := intfRe.FindStringSubmatch(line); len(m) > 1 {
			currentIntf = m[1]
			continue
		}
		if m := descRe.FindStringSubmatch(line); len(m) > 1 && currentIntf != "" {
			if strings.TrimSpace(m[1]) == interfaceName {
				return currentIntf, nil
			}
		}
	}

	return "", fmt.Errorf("no wg interface with description 'wg-quick: %s' found", interfaceName)
}

// DeleteInterface deletes interface
func (opm *OpenBSDPlatformManager) DeleteInterface(interfaceName string) error {
	// Clean up endpoint protection routes first
	opm.cleanupEndpointProtection(interfaceName)

	realIntf, err := opm.getRealInterface(interfaceName)
	if err != nil {
		// Clean up userspace files even if interface lookup fails
		utils.CleanupUserspaceFiles(interfaceName, interfaceName, opm.logger)
		return err
	}

	// Destroy the interface
	err = opm.cmdRunner.Run("ifconfig", realIntf, "destroy")

	// Clean up userspace files (in case userspace implementation was used)
	utils.CleanupUserspaceFiles(interfaceName, interfaceName, opm.logger)

	delete(opm.interfaceIndexes, interfaceName)
	return err
}

// InterfaceExists checks if interface exists
func (opm *OpenBSDPlatformManager) InterfaceExists(interfaceName string) bool {
	realIntf, err := opm.getRealInterface(interfaceName)
	if err != nil {
		return false
	}

	err = opm.cmdRunner.Run("ifconfig", realIntf)
	return err == nil
}

// AddAddress adds IP address to interface
func (opm *OpenBSDPlatformManager) AddAddress(interfaceName string, addr net.IPNet) error {
	realIntf, err := opm.getRealInterface(interfaceName)
	if err != nil {
		return err
	}

	isIPv4, _, _ := utils.GetIPProtocolInfo(addr)

	var family string
	if isIPv4 {
		family = "inet"
	} else {
		family = "inet6"
	}

	return opm.cmdRunner.Run("ifconfig", realIntf, family, addr.String(), "alias")
}

// GetCurrentAddresses gets current interface addresses
func (opm *OpenBSDPlatformManager) GetCurrentAddresses(interfaceName string) []string {
	realIntf, err := opm.getRealInterface(interfaceName)
	if err != nil {
		return nil
	}

	output, err := opm.cmdRunner.RunWithOutput("ifconfig", realIntf)
	if err != nil {
		return nil
	}

	// Reuse BSD address parsing utility
	return utils.ParseBSDInterfaceAddresses(output)
}

// SetMTUAndUp sets MTU and brings up interface
func (opm *OpenBSDPlatformManager) SetMTUAndUp(interfaceName string, mtu int) error {
	realIntf, err := opm.getRealInterface(interfaceName)
	if err != nil {
		return err
	}

	// Set MTU and bring interface up
	return opm.cmdRunner.Run("ifconfig", realIntf, "mtu", strconv.Itoa(mtu), "up")
}

// GetCurrentMTU gets current interface MTU
func (opm *OpenBSDPlatformManager) GetCurrentMTU(interfaceName string) int {
	realIntf, err := opm.getRealInterface(interfaceName)
	if err != nil {
		return 0
	}

	return utils.GetInterfaceMTUFromIfconfig(realIntf, opm.cmdRunner)
}

// CalculateOptimalMTU calculates optimal MTU for OpenBSD
// CalculateOptimalMTU calculates optimal MTU for OpenBSD using MAX-of-endpoints strategy.
// Matches original openbsd.bash: takes the maximum MTU from all endpoint paths.
func (opm *OpenBSDPlatformManager) CalculateOptimalMTU(interfaceName string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) (int, error) {
	// Use real interface name for wg show
	realIntf := opm.GetRealInterfaceName(interfaceName)
	result, err := utils.CalculateOptimalMTUMaxOfEndpoints(realIntf, cmdRunner)
	if err == nil && result > 0 {
		return result, nil
	}
	// Fallback to default route MTU
	return utils.CalculateOptimalMTUFromDefaultRoute(false, cmdRunner)
}

// GetMTUForEndpoint gets MTU for route to endpoint
func (opm *OpenBSDPlatformManager) GetMTUForEndpoint(endpoint string, cmdRunner runner.SystemCommandRunner) (int, error) {
	return utils.RouteGetMTUForEndpoint(endpoint, true, true, cmdRunner)
}

// SetupDNS configures DNS using OpenBSD-specific methods.
// Matches original openbsd.bash set_dns() behavior.
func (opm *OpenBSDPlatformManager) SetupDNS(interfaceName string, dns []net.IP, search []string) error {
	if len(dns) == 0 {
		return nil
	}

	// Check for DNS daemons (matching original warnings)
	hasUnwind := opm.cmdRunner.Run("pgrep", "-qx", "unwind") == nil
	hasResolvd := opm.cmdRunner.Run("pgrep", "-qx", "resolvd") == nil

	if hasUnwind {
		opm.logger.Warning("unwind will leak DNS queries")
	} else if hasResolvd {
		opm.logger.Warning("resolvd may leak DNS queries")
	} else {
		// Original: "resolvd is not running, DNS will not be configured"
		opm.logger.Info("resolvd is not running, DNS will not be configured")
		return nil
	}

	dnsState := &OpenBSDDNSState{}
	realIntf := opm.GetRealInterfaceName(interfaceName)
	backupPath := fmt.Sprintf("/etc/resolv.conf.wg-quick-backup.%s", interfaceName)

	// Backup resolv.conf (matching original: cmd cp /etc/resolv.conf "...backup.$INTERFACE")
	opm.cmdRunner.Run("cp", "/etc/resolv.conf", backupPath)
	dnsState.backupPath = backupPath

	// Write search domains to resolv.conf if present
	if len(search) > 0 {
		searchLine := fmt.Sprintf("search %s\n", strings.Join(search, " "))
		opm.cmdRunner.RunWithInput(searchLine, "tee", "/etc/resolv.conf")
	}

	// Set nameservers via route (matching original: route nameserver ${REAL_INTERFACE} ${DNS[@]})
	args := []string{"nameserver", realIntf}
	for _, dnsIP := range dns {
		args = append(args, dnsIP.String())
	}
	if err := opm.cmdRunner.Run("route", args...); err != nil {
		return fmt.Errorf("failed to set nameservers: %w", err)
	}
	dnsState.usedRouteNS = true

	opm.dnsSet[interfaceName] = dnsState
	return nil
}

// CleanupDNS cleans up DNS settings.
// Matches original openbsd.bash unset_dns().
func (opm *OpenBSDPlatformManager) CleanupDNS(interfaceName string) {
	dnsState, exists := opm.dnsSet[interfaceName]
	if !exists {
		return
	}

	if dnsState.usedRouteNS {
		// Clear route nameservers (matching original: route nameserver ${REAL_INTERFACE})
		realIntf := opm.GetRealInterfaceName(interfaceName)
		opm.cmdRunner.Run("route", "nameserver", realIntf)
	}

	// Restore resolv.conf from backup (matching original: cmd mv "...backup.$INTERFACE" /etc/resolv.conf)
	if dnsState.backupPath != "" {
		opm.cmdRunner.Run("mv", dnsState.backupPath, "/etc/resolv.conf")
	}

	delete(opm.dnsSet, interfaceName)
}

// GetCurrentDNS returns nil on OpenBSD.
// Matches original openbsd.bash: "# TODO: actually determine current DNS for interface"
// The original script uses parsed DNS values from the config.
func (opm *OpenBSDPlatformManager) GetCurrentDNS(interfaceName string) []string {
	return nil
}

// SetupRoutes configures routes
func (opm *OpenBSDPlatformManager) SetupRoutes(interfaceName string, allowedIPs []net.IPNet, table string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error {
	return utils.SetupRoutesCommon(interfaceName, allowedIPs, table, outputParser, cmdRunner,
		func() ([]net.IPNet, error) {
			return opm.getAllowedIPs(interfaceName, outputParser, cmdRunner)
		},
		func(route net.IPNet) error {
			return opm.AddRoute(interfaceName, route, table)
		})
}

// getAllowedIPs gets all allowed IPs from wg
func (opm *OpenBSDPlatformManager) getAllowedIPs(interfaceName string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) ([]net.IPNet, error) {
	realIntf, err := opm.getRealInterface(interfaceName)
	if err != nil {
		return nil, err
	}

	return utils.GetAllowedIPsFromInterface(realIntf, outputParser, cmdRunner)
}

// AddRoute adds a route
func (opm *OpenBSDPlatformManager) AddRoute(interfaceName string, route net.IPNet, table string) error {
	realIntf, err := opm.getRealInterface(interfaceName)
	if err != nil {
		return err
	}

	// Check if this is a default route
	if utils.IsDefaultRoute(route) {
		return opm.AddDefaultRoute(interfaceName, route, 0, opm.cmdRunner)
	}

	isIPv4, _, _ := utils.GetIPProtocolInfo(route)

	var family string
	if isIPv4 {
		family = "-inet"
	} else {
		family = "-inet6"
	}

	// Check if route already exists
	if utils.CheckRouteExistsBSD(route, realIntf, true, opm.cmdRunner) {
		return nil // Route already exists
	}

	return (&openBSDRouteRunner{opm.cmdRunner}).Run("route", "add", family, route.String(), "-interface", realIntf)
}

// AddDefaultRoute adds default route with OpenBSD-specific handling
func (opm *OpenBSDPlatformManager) AddDefaultRoute(interfaceName string, route net.IPNet, fwmark int, cmdRunner runner.SystemCommandRunner) error {
	realIntf, err := opm.getRealInterface(interfaceName)
	if err != nil {
		return err
	}

	// Track auto-route state for monitor daemon
	isIPv4, _, _ := utils.GetIPProtocolInfo(route)
	if isIPv4 {
		opm.autoRoute4[interfaceName] = true
	} else {
		opm.autoRoute6[interfaceName] = true
	}

	// Add endpoint protection before setting up split routes
	opm.addEndpointProtection(interfaceName)

	return utils.AddDefaultRouteOverrideBSD(realIntf, route, &openBSDRouteRunner{cmdRunner})
}

// GetFwMark gets current fwmark (OpenBSD doesn't use fwmark like Linux)
func (opm *OpenBSDPlatformManager) GetFwMark(interfaceName string, cmdRunner runner.SystemCommandRunner) (int, error) {
	// OpenBSD doesn't use fwmark like Linux, but we can check WireGuard's fwmark setting
	realIntf, err := opm.getRealInterface(interfaceName)
	if err != nil {
		return 0, err
	}

	output, err := cmdRunner.RunWithOutput("wg", "show", realIntf, "fwmark")
	if err != nil {
		return 0, err
	}

	fwmarkStr := strings.TrimSpace(string(output))
	if fwmarkStr == "off" || fwmarkStr == "" {
		return 0, fmt.Errorf("no fwmark set")
	}

	return strconv.Atoi(fwmarkStr)
}

// TableInUse checks if routing table is in use (OpenBSD uses rdomain)
func (opm *OpenBSDPlatformManager) TableInUse(table int, cmdRunner runner.SystemCommandRunner) bool {
	return utils.CheckBSDRoutingTableInUse(table, true, cmdRunner)
}

// SetupFirewall configures firewall rules using OpenBSD's pf
func (opm *OpenBSDPlatformManager) SetupFirewall(interfaceName string, fwmark int, addresses []net.IPNet, cmdRunner runner.SystemCommandRunner) error {
	// OpenBSD firewall setup using pf (Packet Filter)
	// This is optional - OpenBSD may not need the same firewall rules as Linux
	// Similar to FreeBSD and macOS, the routing setup might be sufficient

	// Check if pf is available and enabled
	if _, err := cmdRunner.RunWithOutput("which", "pfctl"); err != nil {
		opm.logger.Warning("pfctl not found, skipping firewall configuration")
		return nil
	}

	// For now, we'll keep this minimal like other BSD variants
	// Advanced pf rules could be added later if needed for leak protection
	opm.firewallSet[interfaceName] = true
	return nil
}

// CleanupFirewall cleans up firewall rules
func (opm *OpenBSDPlatformManager) CleanupFirewall(interfaceName string, cmdRunner runner.SystemCommandRunner) {
	if !opm.firewallSet[interfaceName] {
		return
	}

	// Clean up any pf rules if they were created
	// For now, this is a no-op like other BSD variants
	delete(opm.firewallSet, interfaceName)
}

// ConfigureWireGuard configures WireGuard interface using `wg addconf`.
// Matches original openbsd.bash: cmd wg addconf "$REAL_INTERFACE" <(echo "$WG_CONFIG")
func (opm *OpenBSDPlatformManager) ConfigureWireGuard(interfaceName string, config *config.Config, cmdRunner runner.SystemCommandRunner) error {
	realIntf, err := opm.getRealInterface(interfaceName)
	if err != nil {
		return fmt.Errorf("failed to get real interface name: %w", err)
	}
	return utils.ConfigureWireGuardAddconf(realIntf, config.RawWGConfig, cmdRunner)
}

// GetWireGuardInterfaceName returns the interface name for WireGuard commands
func (opm *OpenBSDPlatformManager) GetWireGuardInterfaceName(interfaceName string) string {
	// OpenBSD uses the interface name directly
	return interfaceName
}

// GetRealInterfaceName returns the actual OS-level interface name (wg slot).
func (opm *OpenBSDPlatformManager) GetRealInterfaceName(interfaceName string) string {
	if idx, ok := opm.interfaceIndexes[interfaceName]; ok {
		return fmt.Sprintf("wg%d", idx)
	}
	return interfaceName
}

// StartMonitor starts the route monitor daemon.
// Matches original openbsd.bash monitor_daemon() function.
func (opm *OpenBSDPlatformManager) StartMonitor(interfaceName string, cfg *config.Config, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error {
	opm.mu.Lock()
	defer opm.mu.Unlock()

	if !opm.autoRoute4[interfaceName] && !opm.autoRoute6[interfaceName] {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	opm.monitorCancel[interfaceName] = cancel

	go opm.monitorDaemon(ctx, interfaceName, cfg, outputParser, cmdRunner)
	return nil
}

// StopMonitor stops the route monitor daemon.
func (opm *OpenBSDPlatformManager) StopMonitor(interfaceName string) {
	opm.mu.Lock()
	defer opm.mu.Unlock()

	if cancel, exists := opm.monitorCancel[interfaceName]; exists {
		cancel()
		delete(opm.monitorCancel, interfaceName)
	}
	delete(opm.autoRoute4, interfaceName)
	delete(opm.autoRoute6, interfaceName)
}

// monitorDaemon watches for route changes and refreshes endpoint routes and MTU.
func (opm *OpenBSDPlatformManager) monitorDaemon(ctx context.Context, interfaceName string, cfg *config.Config, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) {
	opm.logger.Info("Backgrounding route monitor")

	cmd := exec.CommandContext(ctx, "route", "-n", "monitor")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		opm.logger.Warning(fmt.Sprintf("Failed to create route monitor pipe: %v", err))
		return
	}
	if err := cmd.Start(); err != nil {
		opm.logger.Warning(fmt.Sprintf("Failed to start route monitor: %v", err))
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

		if !opm.InterfaceExists(interfaceName) {
			break
		}

		opm.mu.Lock()
		hasAutoRoute4 := opm.autoRoute4[interfaceName]
		hasAutoRoute6 := opm.autoRoute6[interfaceName]
		opm.mu.Unlock()

		if hasAutoRoute4 || hasAutoRoute6 {
			opm.refreshEndpointRoutes(interfaceName)
		}

		// Refresh MTU if not manually set
		if cfg.Interface.MTU == nil {
			if mtu, err := opm.CalculateOptimalMTU(interfaceName, outputParser, cmdRunner); err == nil {
				currentMTU := opm.GetCurrentMTU(interfaceName)
				if mtu != currentMTU && mtu > 0 {
					realIntf := opm.GetRealInterfaceName(interfaceName)
					opm.cmdRunner.Run("ifconfig", realIntf, "mtu", strconv.Itoa(mtu))
				}
			}
		}
	}

	cmd.Wait()
}

// addEndpointProtection adds routes for WireGuard endpoints via original gateway.
func (opm *OpenBSDPlatformManager) addEndpointProtection(interfaceName string) {
	routeInfo, err := utils.GetDefaultRouteInfoBSD(opm.cmdRunner)
	if err != nil {
		return
	}

	realIntf := opm.GetRealInterfaceName(interfaceName)
	endpoints, err := utils.GetWireGuardIPEndpoints(realIntf, opm.cmdRunner)
	if err != nil || len(endpoints) == 0 {
		return
	}

	var routes []obsdEndpointRoute
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
			opm.cmdRunner.Run("route", "-q", "-n", "add", "-host", endpoint, gateway, "-blackhole")
		} else {
			opm.cmdRunner.Run("route", "-q", "-n", "add", "-host", endpoint, "-gateway", gateway)
		}
		routes = append(routes, obsdEndpointRoute{endpoint: endpoint, gateway: gateway})
	}

	opm.mu.Lock()
	opm.endpointRoutes[interfaceName] = routes
	opm.mu.Unlock()
}

// cleanupEndpointProtection removes endpoint protection routes.
func (opm *OpenBSDPlatformManager) cleanupEndpointProtection(interfaceName string) {
	opm.mu.Lock()
	routes := opm.endpointRoutes[interfaceName]
	delete(opm.endpointRoutes, interfaceName)
	opm.mu.Unlock()

	for _, route := range routes {
		opm.cmdRunner.Run("route", "-q", "-n", "delete", "-host", route.endpoint)
	}
}

// refreshEndpointRoutes refreshes endpoint protection routes when gateway changes.
func (opm *OpenBSDPlatformManager) refreshEndpointRoutes(interfaceName string) {
	opm.mu.Lock()
	oldRoutes := opm.endpointRoutes[interfaceName]
	opm.mu.Unlock()

	routeInfo, err := utils.GetDefaultRouteInfoBSD(opm.cmdRunner)
	if err != nil {
		return
	}

	realIntf := opm.GetRealInterfaceName(interfaceName)
	endpoints, err := utils.GetWireGuardIPEndpoints(realIntf, opm.cmdRunner)
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
		opm.cmdRunner.Run("route", "-q", "-n", "delete", "-host", route.endpoint)
	}

	var newRoutes []obsdEndpointRoute
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
			opm.cmdRunner.Run("route", "-q", "-n", "add", "-host", endpoint, gateway, "-blackhole")
		} else {
			opm.cmdRunner.Run("route", "-q", "-n", "add", "-host", endpoint, "-gateway", gateway)
		}
		newRoutes = append(newRoutes, obsdEndpointRoute{endpoint: endpoint, gateway: gateway})
	}

	opm.mu.Lock()
	opm.endpointRoutes[interfaceName] = newRoutes
	opm.mu.Unlock()
}
