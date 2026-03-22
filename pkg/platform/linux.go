//go:build linux

package platform

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/n0madic/wg-quick-go/pkg/config"
	"github.com/n0madic/wg-quick-go/pkg/logger"
	"github.com/n0madic/wg-quick-go/pkg/runner"
	"github.com/n0madic/wg-quick-go/pkg/utils"

	"github.com/vishvananda/netlink"
)

// LinuxPlatformManager implements PlatformManager for Linux
type LinuxPlatformManager struct {
	logger       logger.Logger
	cmdRunner    runner.SystemCommandRunner
	userspaceCmd string

	// State tracking
	dnsSet      map[string]bool
	firewallSet map[string]bool
	activeTable map[string]int // interfaceName → fwmark/table used for policy routing
}

// newPlatformManager creates a Linux-specific platform manager
func newPlatformManager(logger logger.Logger) PlatformManager {
	return &LinuxPlatformManager{
		logger:      logger,
		dnsSet:      make(map[string]bool),
		firewallSet: make(map[string]bool),
		activeTable: make(map[string]int),
	}
}

// SetCommandRunner sets the system command runner
func (lpm *LinuxPlatformManager) SetCommandRunner(cmdRunner runner.SystemCommandRunner) {
	lpm.cmdRunner = cmdRunner
}

// CheckRequirements checks if the system meets requirements for WireGuard (like original bash script)
func (lpm *LinuxPlatformManager) CheckRequirements() error {
	// Check root privileges (like original bash script)
	if err := utils.CheckRootPrivileges(); err != nil {
		return err
	}

	// Validate required system commands are available
	requiredCommands := []string{"wg", "ip"}
	for _, cmd := range requiredCommands {
		if _, err := lpm.cmdRunner.RunWithOutput("which", cmd); err != nil {
			return fmt.Errorf("required command '%s' not found", cmd)
		}
	}

	// If userspace is forced, only check userspace implementation
	if utils.IsUserspaceForced() {
		candidateCmd := utils.GetUserspaceCommand()
		if _, err := lpm.cmdRunner.RunWithOutput("which", candidateCmd); err != nil {
			return fmt.Errorf("forced userspace implementation (%s) not found", candidateCmd)
		}
		lpm.userspaceCmd = candidateCmd
	} else {
		// Check for WireGuard availability (kernel module or userspace)
		err := lpm.cmdRunner.Run("modprobe", "wireguard")
		if err != nil {
			// Check for userspace implementation
			candidateCmd := utils.GetUserspaceCommand()
			if _, err := lpm.cmdRunner.RunWithOutput("which", candidateCmd); err != nil {
				return fmt.Errorf("neither WireGuard kernel module nor userspace implementation found")
			}
			// Only set userspaceCmd if the command actually exists
			lpm.userspaceCmd = candidateCmd
		} else {
			// Kernel module available, but still check userspace for potential fallback
			candidateCmd := utils.GetUserspaceCommand()
			if _, err := lpm.cmdRunner.RunWithOutput("which", candidateCmd); err == nil {
				lpm.userspaceCmd = candidateCmd
			}
			// If userspace not available, that's OK - we have kernel module
		}
	}

	return nil
}

// ValidateConfig validates Linux-specific config requirements
func (lpm *LinuxPlatformManager) ValidateConfig(config *config.Config) error {
	// Linux-specific validations only (universal validations done in WireGuardManager)

	// Check if resolvconf is available for DNS configuration
	if len(config.Interface.DNS) > 0 {
		if _, err := lpm.cmdRunner.RunWithOutput("which", "resolvconf"); err != nil {
			lpm.logger.Warning("resolvconf not available, DNS configuration may not work properly")
		}
	}

	// Table "auto" or "" is handled during route setup — no pre-check needed here.

	// Linux-specific: check if we have necessary capabilities for netlink
	// (This is mainly for containers or restricted environments)
	if !lpm.canUseNetlink() {
		return fmt.Errorf("insufficient privileges for netlink operations")
	}

	return nil
}

// canUseNetlink checks if we can use netlink operations
func (lpm *LinuxPlatformManager) canUseNetlink() bool {
	// Try a simple netlink operation to test capabilities
	_, err := net.Interfaces()
	return err == nil
}

// CreateInterface creates WireGuard interface
func (lpm *LinuxPlatformManager) CreateInterface(interfaceName string) error {
	// Check if userspace implementation is forced (when WG_QUICK_USERSPACE_IMPLEMENTATION is set)
	if utils.IsUserspaceForced() && lpm.userspaceCmd != "" {
		lpm.logger.Info(fmt.Sprintf("Using forced userspace implementation: %s", lpm.userspaceCmd))
		return lpm.cmdRunner.Run(lpm.userspaceCmd, interfaceName)
	}

	// Try kernel module first using netlink
	link := &netlink.GenericLink{
		LinkAttrs: netlink.LinkAttrs{
			Name: interfaceName,
		},
		LinkType: "wireguard",
	}

	err := netlink.LinkAdd(link)
	if err != nil {
		// Fallback to userspace implementation
		if lpm.userspaceCmd == "" {
			return fmt.Errorf("WireGuard kernel module not available and no userspace implementation found")
		}
		lpm.logger.Info("WireGuard kernel module not available, using userspace implementation")
		return lpm.cmdRunner.Run(lpm.userspaceCmd, interfaceName)
	}

	return nil
}

// DeleteInterface deletes interface
func (lpm *LinuxPlatformManager) DeleteInterface(interfaceName string) error {
	// Clean up policy routing rules BEFORE deleting the link
	// (matching original linux.bash del_if() behavior)
	lpm.cleanupPolicyRouting(interfaceName)

	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		// Interface doesn't exist, clean up userspace files anyway
		utils.CleanupUserspaceFiles(interfaceName, interfaceName, lpm.logger)
		return err
	}

	// Try to delete the interface using netlink
	err = netlink.LinkDel(link)

	// Clean up userspace files regardless of netlink success
	// (in case userspace implementation was used)
	utils.CleanupUserspaceFiles(interfaceName, interfaceName, lpm.logger)

	return err
}

// InterfaceExists checks if interface exists
func (lpm *LinuxPlatformManager) InterfaceExists(interfaceName string) bool {
	_, err := netlink.LinkByName(interfaceName)
	return err == nil
}

// AddAddress adds IP address to interface
func (lpm *LinuxPlatformManager) AddAddress(interfaceName string, addr net.IPNet) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return err
	}

	netlinkAddr := &netlink.Addr{
		IPNet: &addr,
	}

	return netlink.AddrAdd(link, netlinkAddr)
}

// GetCurrentAddresses gets current interface addresses
func (lpm *LinuxPlatformManager) GetCurrentAddresses(interfaceName string) []string {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return nil
	}

	addrs, err := netlink.AddrList(link, netlink.FAMILY_ALL)
	if err != nil {
		return nil
	}

	var result []string
	for _, addr := range addrs {
		result = append(result, addr.IPNet.String())
	}

	return result
}

// SetMTUAndUp sets MTU and brings up interface
func (lpm *LinuxPlatformManager) SetMTUAndUp(interfaceName string, mtu int) error {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return err
	}

	// Set MTU
	if err := netlink.LinkSetMTU(link, mtu); err != nil {
		return err
	}

	// Bring interface up
	return netlink.LinkSetUp(link)
}

// GetCurrentMTU gets current interface MTU
func (lpm *LinuxPlatformManager) GetCurrentMTU(interfaceName string) int {
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return 0
	}

	return link.Attrs().MTU
}

// CalculateOptimalMTU calculates optimal MTU
func (lpm *LinuxPlatformManager) CalculateOptimalMTU(interfaceName string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) (int, error) {
	// Get endpoints from wg
	output, err := utils.GetWireGuardInfo(interfaceName, "endpoints", cmdRunner)
	if err != nil {
		return 1420, err
	}

	minMTU := 1500
	endpoints := utils.ParseWireGuardEndpoints(output, outputParser)

	for _, endpoint := range endpoints {
		if mtu, err := lpm.GetMTUForEndpoint(endpoint, cmdRunner); err == nil && mtu < minMTU {
			minMTU = mtu
		}
	}

	// Subtract WireGuard overhead
	return minMTU - 80, nil
}

// GetMTUForEndpoint gets MTU for route to endpoint
func (lpm *LinuxPlatformManager) GetMTUForEndpoint(endpoint string, cmdRunner runner.SystemCommandRunner) (int, error) {
	host, err := utils.ParseEndpointHost(endpoint)
	if err != nil {
		return 0, err
	}

	// Parse destination IP
	dstIP := net.ParseIP(host)
	if dstIP == nil {
		return 1500, nil
	}

	// Get route to destination
	routes, err := netlink.RouteGet(dstIP)
	if err != nil || len(routes) == 0 {
		return 1500, nil
	}

	route := routes[0]
	if route.LinkIndex == 0 {
		return 1500, nil
	}

	// Get link information
	link, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		return 1500, nil
	}

	return link.Attrs().MTU, nil
}

// getResolvconfIfacePrefix returns the interface prefix for resolvconf DNS priority.
// Matches original linux.bash resolvconf_iface_prefix() function.
func (lpm *LinuxPlatformManager) getResolvconfIfacePrefix() string {
	const ifaceOrderFile = "/etc/resolvconf/interface-order"
	if _, err := os.Stat(ifaceOrderFile); err != nil {
		return ""
	}

	// Original bash checks: [[ ! -L $(type -P resolvconf) ]]
	// Only apply prefix when resolvconf is NOT a symlink (i.e., is the real binary)
	resolvconfPath, err := exec.LookPath("resolvconf")
	if err != nil {
		return ""
	}
	fi, err := os.Lstat(resolvconfPath)
	if err != nil || fi.Mode()&os.ModeSymlink != 0 {
		return ""
	}

	data, err := os.ReadFile(ifaceOrderFile)
	if err != nil {
		return ""
	}

	re := regexp.MustCompile(`^([A-Za-z0-9-]+)\*$`)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if matches := re.FindStringSubmatch(line); len(matches) > 1 {
			return matches[1] + "."
		}
	}
	return ""
}

// SetupDNS configures DNS using resolvconf (like original script)
func (lpm *LinuxPlatformManager) SetupDNS(interfaceName string, dns []net.IP, search []string) error {
	if len(dns) == 0 {
		return nil
	}

	var resolvConf strings.Builder

	for _, dnsIP := range dns {
		resolvConf.WriteString(fmt.Sprintf("nameserver %s\n", dnsIP.String()))
	}

	if len(search) > 0 {
		resolvConf.WriteString(fmt.Sprintf("search %s\n", strings.Join(search, " ")))
	}

	// Use interface prefix for DNS priority (matching original resolvconf_iface_prefix())
	prefix := lpm.getResolvconfIfacePrefix()

	// Use the same resolvconf options as original script
	err := lpm.cmdRunner.RunWithInput(resolvConf.String(), "resolvconf", "-a", prefix+interfaceName, "-m", "0", "-x")
	if err != nil {
		// Check if resolvconf is available, otherwise warn but continue
		if _, whichErr := lpm.cmdRunner.RunWithOutput("which", "resolvconf"); whichErr != nil {
			lpm.logger.Warning("resolvconf not available, DNS configuration skipped")
			return nil
		}
		return fmt.Errorf("failed to configure DNS via resolvconf: %w", err)
	}

	lpm.dnsSet[interfaceName] = true
	return nil
}

// CleanupDNS cleans up DNS settings
func (lpm *LinuxPlatformManager) CleanupDNS(interfaceName string) {
	if !lpm.dnsSet[interfaceName] {
		return
	}

	prefix := lpm.getResolvconfIfacePrefix()
	if err := lpm.cmdRunner.Run("resolvconf", "-d", prefix+interfaceName, "-f"); err != nil {
		lpm.logger.Warning(fmt.Sprintf("Failed to cleanup DNS for %s: %v", interfaceName, err))
	}
	delete(lpm.dnsSet, interfaceName)
}

// GetCurrentDNS reads live DNS nameserver IPs from resolvconf.
// Matches original linux.bash save_config: resolvconf -l "PREFIX$INTERFACE"
func (lpm *LinuxPlatformManager) GetCurrentDNS(interfaceName string) []string {
	prefix := lpm.getResolvconfIfacePrefix()
	resolvName := prefix + interfaceName

	// Try resolvconf -l first, then fall back to reading the interface file directly
	// (matching original bash: resolvconf -l ... 2>/dev/null || cat /etc/resolvconf/run/interface/...)
	output, err := lpm.cmdRunner.RunWithOutput("resolvconf", "-l", resolvName)
	if err != nil {
		fallbackPath := fmt.Sprintf("/etc/resolvconf/run/interface/%s", resolvName)
		data, readErr := os.ReadFile(fallbackPath)
		if readErr != nil {
			return nil
		}
		output = data
	}

	return parseNameserversFromResolvconf(output)
}

// parseNameserversFromResolvconf extracts nameserver IPs from resolvconf output.
// Matches original bash regex: ^nameserver ([a-zA-Z0-9_=+:%.-]+)$
func parseNameserversFromResolvconf(data []byte) []string {
	re := regexp.MustCompile(`^nameserver\s+([a-zA-Z0-9_=+:%.-]+)$`)
	var nameservers []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		if matches := re.FindStringSubmatch(scanner.Text()); len(matches) > 1 {
			nameservers = append(nameservers, matches[1])
		}
	}
	return nameservers
}

// SetupRoutes configures routes
func (lpm *LinuxPlatformManager) SetupRoutes(interfaceName string, allowedIPs []net.IPNet, table string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error {
	if table == "off" {
		return nil
	}

	// Get allowed IPs from wg if not provided
	if len(allowedIPs) == 0 {
		var err error
		allowedIPs, err = lpm.getAllowedIPs(interfaceName, outputParser, lpm.cmdRunner)
		if err != nil {
			return err
		}
	}

	// Sort by mask size (more specific first)
	utils.SortAllowedIPsBySpecificity(allowedIPs)

	for _, allowedIP := range allowedIPs {
		if err := lpm.AddRoute(interfaceName, allowedIP, table); err != nil {
			return fmt.Errorf("failed to add route %s: %w", allowedIP.String(), err)
		}
	}

	return nil
}

// getAllowedIPs gets all allowed IPs from wg
func (lpm *LinuxPlatformManager) getAllowedIPs(interfaceName string, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) ([]net.IPNet, error) {
	output, err := utils.GetWireGuardInfo(interfaceName, "allowed-ips", cmdRunner)
	if err != nil {
		return nil, err
	}

	return utils.ParseAllowedIPsFromWgOutput(output, outputParser)
}

// AddRoute adds a route
func (lpm *LinuxPlatformManager) AddRoute(interfaceName string, route net.IPNet, table string) error {
	// Check if this is a default route
	if utils.IsDefaultRoute(route) {
		return lpm.AddDefaultRoute(interfaceName, route, 0, lpm.cmdRunner)
	}

	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return err
	}

	// Create route
	netlinkRoute := &netlink.Route{
		Dst:       &route,
		LinkIndex: link.Attrs().Index,
	}

	// Set table if specified
	if table != "" && table != "auto" {
		if tableID, err := strconv.Atoi(table); err == nil {
			netlinkRoute.Table = tableID
		}
	}

	if err := netlink.RouteAdd(netlinkRoute); err != nil {
		// Route already exists (e.g., connected route from another interface) — not fatal
		if errors.Is(err, syscall.EEXIST) {
			lpm.logger.Warning(fmt.Sprintf("Route %s already exists, skipping", route.String()))
			return nil
		}
		return err
	}
	return nil
}

// AddDefaultRoute adds default route with policy routing
func (lpm *LinuxPlatformManager) AddDefaultRoute(interfaceName string, route net.IPNet, fwmark int, cmdRunner runner.SystemCommandRunner) error {
	// CRITICAL: Add endpoint protection FIRST (like original script)
	if err := lpm.addEndpointProtection(interfaceName, cmdRunner); err != nil {
		lpm.logger.Warning(fmt.Sprintf("Failed to add endpoint protection: %v", err))
		// Continue anyway - this is non-fatal
	}

	// Get or create fwmark
	if fwmark == 0 {
		var err error
		fwmark, err = lpm.GetFwMark(interfaceName, cmdRunner)
		if err != nil {
			// Create new fwmark
			fwmark = 51820
			for lpm.TableInUse(fwmark, cmdRunner) {
				fwmark++
			}

			if err := cmdRunner.Run("wg", "set", interfaceName, "fwmark", strconv.Itoa(fwmark)); err != nil {
				return err
			}
		}
	}

	// Add routing rules using netlink
	var family int
	if route.IP.To4() != nil {
		family = netlink.FAMILY_V4
	} else {
		family = netlink.FAMILY_V6
	}

	// Rule: packets not marked with fwmark go to table fwmark
	rule1 := netlink.NewRule()
	rule1.Family = family
	rule1.Invert = true
	rule1.Mark = uint32(fwmark)
	rule1.Table = fwmark
	if err := netlink.RuleAdd(rule1); err != nil {
		return fmt.Errorf("failed to add fwmark rule: %w", err)
	}

	// Rule: suppress default route in main table
	rule2 := netlink.NewRule()
	rule2.Family = family
	rule2.Table = 254 // RT_TABLE_MAIN
	rule2.SuppressPrefixlen = 0
	if err := netlink.RuleAdd(rule2); err != nil {
		return fmt.Errorf("failed to add suppress_prefixlength rule: %w", err)
	}

	// Add route to separate table using netlink
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		return err
	}

	netlinkRoute := &netlink.Route{
		Dst:       &route,
		LinkIndex: link.Attrs().Index,
		Table:     fwmark,
	}

	if err := netlink.RouteAdd(netlinkRoute); err != nil {
		return err
	}

	// Track the table for cleanup on down
	lpm.activeTable[interfaceName] = fwmark

	// Setup firewall to prevent leaks
	return lpm.SetupFirewall(interfaceName, fwmark, nil, cmdRunner)
}

// cleanupPolicyRouting removes policy routing rules created by AddDefaultRoute.
// Matches the original linux.bash del_if() loop that removes all matching rules.
func (lpm *LinuxPlatformManager) cleanupPolicyRouting(interfaceName string) {
	table, exists := lpm.activeTable[interfaceName]
	if !exists {
		return
	}

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		// Delete all "lookup $table" rules (matching original: while ip rule show == *"lookup $TABLE"*)
		for {
			rules, err := netlink.RuleList(family)
			if err != nil {
				break
			}
			found := false
			for _, rule := range rules {
				if rule.Table == table {
					if err := netlink.RuleDel(&rule); err == nil {
						found = true
						break
					}
				}
			}
			if !found {
				break
			}
		}

		// Delete all "suppress_prefixlength 0" rules in main table
		for {
			rules, err := netlink.RuleList(family)
			if err != nil {
				break
			}
			found := false
			for _, rule := range rules {
				if rule.Table == 254 && rule.SuppressPrefixlen == 0 {
					if err := netlink.RuleDel(&rule); err == nil {
						found = true
						break
					}
				}
			}
			if !found {
				break
			}
		}
	}

	delete(lpm.activeTable, interfaceName)
}

// addEndpointProtection adds routes for WireGuard endpoints via original gateway
func (lpm *LinuxPlatformManager) addEndpointProtection(interfaceName string, cmdRunner runner.SystemCommandRunner) error {
	// Get default route info
	routes, err := netlink.RouteList(nil, netlink.FAMILY_ALL)
	if err != nil {
		return err
	}

	var defaultGateway net.IP
	for _, route := range routes {
		if route.Dst == nil && route.Gw != nil { // Default route
			defaultGateway = route.Gw
			break
		}
	}

	if defaultGateway == nil {
		return fmt.Errorf("no default gateway found")
	}

	// Get WireGuard endpoints
	endpoints, err := utils.GetWireGuardIPEndpoints(interfaceName, cmdRunner)
	if err != nil {
		return err
	}

	// Add route for each endpoint via original gateway
	for _, endpoint := range endpoints {
		host, err := utils.ParseEndpointHost(endpoint)
		if err != nil {
			continue
		}

		endpointIP := net.ParseIP(host)
		if endpointIP == nil {
			continue
		}

		// Create route to endpoint via default gateway
		route := &netlink.Route{
			Dst: &net.IPNet{
				IP:   endpointIP,
				Mask: net.CIDRMask(32, 32), // /32 for IPv4
			},
			Gw: defaultGateway,
		}

		if endpointIP.To4() == nil {
			route.Dst.Mask = net.CIDRMask(128, 128) // /128 for IPv6
		}

		if err := netlink.RouteAdd(route); err != nil {
			lpm.logger.Warning(fmt.Sprintf("Failed to add endpoint route for %s: %v", endpoint, err))
		} else {
			lpm.logger.Info(fmt.Sprintf("Added endpoint protection route: %s via %s", endpoint, defaultGateway))
		}
	}

	return nil
}

// GetFwMark gets current fwmark of interface
func (lpm *LinuxPlatformManager) GetFwMark(interfaceName string, cmdRunner runner.SystemCommandRunner) (int, error) {
	output, err := cmdRunner.RunWithOutput("wg", "show", interfaceName, "fwmark")
	if err != nil {
		return 0, err
	}

	fwmarkStr := strings.TrimSpace(string(output))
	if fwmarkStr == "off" || fwmarkStr == "" {
		return 0, errors.New("no fwmark set")
	}

	return strconv.Atoi(fwmarkStr)
}

// TableInUse checks if routing table is in use
func (lpm *LinuxPlatformManager) TableInUse(table int, cmdRunner runner.SystemCommandRunner) bool {
	// Check IPv4 routes
	routes4, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err == nil && len(routes4) > 0 {
		return true
	}

	// Check IPv6 routes
	routes6, err := netlink.RouteListFiltered(netlink.FAMILY_V6, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err == nil && len(routes6) > 0 {
		return true
	}

	return false
}

// SetupFirewall configures firewall rules
func (lpm *LinuxPlatformManager) SetupFirewall(interfaceName string, fwmark int, addresses []net.IPNet, cmdRunner runner.SystemCommandRunner) error {
	// Try nftables first, fallback to iptables
	if lpm.setupNftables(interfaceName, fwmark, addresses, cmdRunner) == nil {
		lpm.firewallSet[interfaceName] = true
		return nil
	}

	if lpm.setupIptables(interfaceName, fwmark, addresses, cmdRunner) == nil {
		lpm.firewallSet[interfaceName] = true
		return nil
	}

	return errors.New("failed to setup firewall rules")
}

// setupNftables configures nftables rules
func (lpm *LinuxPlatformManager) setupNftables(interfaceName string, fwmark int, addresses []net.IPNet, cmdRunner runner.SystemCommandRunner) error {
	tableName := fmt.Sprintf("wg-quick-%s", interfaceName)

	var nftScript strings.Builder

	// Create tables for IPv4 and IPv6
	for _, family := range []string{"ip", "ip6"} {
		nftScript.WriteString(fmt.Sprintf("add table %s %s\n", family, tableName))
		nftScript.WriteString(fmt.Sprintf("add chain %s %s preraw { type filter hook prerouting priority -300; }\n", family, tableName))
		nftScript.WriteString(fmt.Sprintf("add chain %s %s premangle { type filter hook prerouting priority -150; }\n", family, tableName))
		nftScript.WriteString(fmt.Sprintf("add chain %s %s postmangle { type filter hook postrouting priority -150; }\n", family, tableName))

		// Rules to prevent leaks
		for _, addr := range addresses {
			isIPv4 := addr.IP.To4() != nil
			if (family == "ip" && isIPv4) || (family == "ip6" && !isIPv4) {
				nftScript.WriteString(fmt.Sprintf("add rule %s %s preraw iifname != \"%s\" %s daddr %s fib saddr type != local drop\n",
					family, tableName, interfaceName, family, addr.IP.String()))
			}
		}

		// Packet marking rules
		nftScript.WriteString(fmt.Sprintf("add rule %s %s postmangle meta l4proto udp mark %d ct mark set mark\n", family, tableName, fwmark))
		nftScript.WriteString(fmt.Sprintf("add rule %s %s premangle meta l4proto udp meta mark set ct mark\n", family, tableName))
	}

	return cmdRunner.RunWithInput(nftScript.String(), "nft", "-f", "/dev/stdin")
}

// setupIptables configures iptables rules
func (lpm *LinuxPlatformManager) setupIptables(interfaceName string, fwmark int, addresses []net.IPNet, cmdRunner runner.SystemCommandRunner) error {
	marker := fmt.Sprintf("wg-quick(8) rule for %s", interfaceName)

	for _, iptables := range []string{"iptables", "ip6tables"} {
		var restore strings.Builder
		restore.WriteString("*raw\n")

		// Rules to prevent leaks
		for _, addr := range addresses {
			isIPv4 := addr.IP.To4() != nil
			if (iptables == "iptables" && isIPv4) || (iptables == "ip6tables" && !isIPv4) {
				restore.WriteString(fmt.Sprintf("-I PREROUTING ! -i %s -d %s -m addrtype ! --src-type LOCAL -j DROP -m comment --comment \"%s\"\n",
					interfaceName, addr.IP.String(), marker))
			}
		}

		restore.WriteString("COMMIT\n*mangle\n")
		restore.WriteString(fmt.Sprintf("-I POSTROUTING -m mark --mark %d -p udp -j CONNMARK --save-mark -m comment --comment \"%s\"\n", fwmark, marker))
		restore.WriteString(fmt.Sprintf("-I PREROUTING -p udp -j CONNMARK --restore-mark -m comment --comment \"%s\"\n", marker))
		restore.WriteString("COMMIT\n")

		if err := cmdRunner.RunWithInput(restore.String(), iptables+"-restore", "-n"); err != nil {
			return err
		}
	}

	// Enable src_valid_mark for IPv4
	_ = cmdRunner.Run("sysctl", "-q", "net.ipv4.conf.all.src_valid_mark=1")

	return nil
}

// CleanupFirewall cleans up firewall rules
func (lpm *LinuxPlatformManager) CleanupFirewall(interfaceName string, cmdRunner runner.SystemCommandRunner) {
	if !lpm.firewallSet[interfaceName] {
		return
	}

	// Cleanup nftables
	lpm.cleanupNftables(interfaceName, cmdRunner)

	// Cleanup iptables
	lpm.cleanupIptables(interfaceName, cmdRunner)

	delete(lpm.firewallSet, interfaceName)
}

// cleanupNftables cleans up nftables rules
func (lpm *LinuxPlatformManager) cleanupNftables(interfaceName string, cmdRunner runner.SystemCommandRunner) {
	tableName := fmt.Sprintf("wg-quick-%s", interfaceName)

	output, err := cmdRunner.RunWithOutput("nft", "list", "tables")
	if err != nil {
		return
	}

	var nftScript strings.Builder
	re := regexp.MustCompile(fmt.Sprintf(`(table \w+ %s)`, tableName))

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()
		matches := re.FindStringSubmatch(line)
		if len(matches) > 1 {
			nftScript.WriteString(fmt.Sprintf("delete %s\n", matches[1]))
		}
	}

	if nftScript.Len() > 0 {
		if err := cmdRunner.RunWithInput(nftScript.String(), "nft", "-f", "/dev/stdin"); err != nil {
			lpm.logger.Warning(fmt.Sprintf("Failed to cleanup nftables rules for %s: %v", interfaceName, err))
		}
	}
}

// cleanupIptables cleans up iptables rules
func (lpm *LinuxPlatformManager) cleanupIptables(interfaceName string, cmdRunner runner.SystemCommandRunner) {
	marker := fmt.Sprintf("wg-quick(8) rule for %s", interfaceName)

	for _, iptables := range []string{"iptables", "ip6tables"} {
		output, err := cmdRunner.RunWithOutput(iptables + "-save")
		if err != nil {
			continue
		}

		var restore strings.Builder
		found := false

		re := regexp.MustCompile(fmt.Sprintf(`(-A .* %s.*)`, regexp.QuoteMeta(marker)))
		scanner := bufio.NewScanner(strings.NewReader(string(output)))

		for scanner.Scan() {
			line := scanner.Text()
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				found = true
				// Replace -A with -D for deletion
				deleteRule := strings.Replace(matches[1], "-A", "-D", 1)
				restore.WriteString(deleteRule + "\n")
			}
		}

		if found {
			// Add table headers and commit
			fullRestore := "*raw\n" + restore.String() + "COMMIT\n*mangle\n" + restore.String() + "COMMIT\n"
			if err := cmdRunner.RunWithInput(fullRestore, iptables+"-restore", "-n"); err != nil {
				lpm.logger.Warning(fmt.Sprintf("Failed to cleanup %s rules for %s: %v", iptables, interfaceName, err))
			}
		}
	}
}

// ConfigureWireGuard configures WireGuard interface using `wg addconf`.
// Matches original linux.bash: cmd wg addconf "$INTERFACE" <(echo "$WG_CONFIG")
func (lpm *LinuxPlatformManager) ConfigureWireGuard(interfaceName string, config *config.Config, cmdRunner runner.SystemCommandRunner) error {
	return utils.ConfigureWireGuardAddconf(interfaceName, config.RawWGConfig, cmdRunner)
}

// GetWireGuardInterfaceName returns the interface name for WireGuard commands
func (lpm *LinuxPlatformManager) GetWireGuardInterfaceName(interfaceName string) string {
	// Linux uses the interface name directly
	return interfaceName
}

// GetRealInterfaceName returns the actual OS-level interface name.
// On Linux, real name equals the logical name.
func (lpm *LinuxPlatformManager) GetRealInterfaceName(interfaceName string) string {
	return interfaceName
}

// StartMonitor is a no-op on Linux (uses policy routing instead).
func (lpm *LinuxPlatformManager) StartMonitor(interfaceName string, config *config.Config, outputParser *utils.OutputParser, cmdRunner runner.SystemCommandRunner) error {
	return nil
}

// StopMonitor is a no-op on Linux.
func (lpm *LinuxPlatformManager) StopMonitor(interfaceName string) {}
