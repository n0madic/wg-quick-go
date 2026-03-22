package wireguard

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/n0madic/wg-quick-go/pkg/config"
	"github.com/n0madic/wg-quick-go/pkg/logger"
	"github.com/n0madic/wg-quick-go/pkg/platform"
	"github.com/n0madic/wg-quick-go/pkg/runner"
	"github.com/n0madic/wg-quick-go/pkg/utils"

	"gopkg.in/ini.v1"
)

// WireGuardManager manages WireGuard interfaces
type WireGuardManager struct {
	interfaceName string
	config        *config.Config
	configPath    string

	// Dependencies
	logger       logger.Logger
	cmdRunner    runner.SystemCommandRunner
	outputParser *utils.OutputParser
	platformMgr  platform.PlatformManager
}

// NewManager creates a new WireGuard manager
func NewManager(interfaceName string, log logger.Logger, cmdRunner runner.SystemCommandRunner) *WireGuardManager {
	if log == nil {
		log = &logger.DefaultLogger{}
	}
	if cmdRunner == nil {
		cmdRunner = runner.NewDefaultCommandRunner(log)
	}

	platformMgr := platform.NewPlatformManager(log)
	platformMgr.SetCommandRunner(cmdRunner)

	return &WireGuardManager{
		interfaceName: interfaceName,
		logger:        log,
		cmdRunner:     cmdRunner,
		outputParser:  utils.NewOutputParser(),
		platformMgr:   platformMgr,
	}
}

// ParseConfig parses configuration file
func (wg *WireGuardManager) ParseConfig(configPath string) error {
	cfg, actualPath, err := config.ParseFile(configPath)
	if err != nil {
		return err
	}

	wg.config = cfg
	wg.configPath = actualPath

	// Extract interface name from path
	filename := filepath.Base(actualPath)
	wg.interfaceName = strings.TrimSuffix(filename, ".conf")

	// Warn about insecure file permissions (like original bash script)
	wg.validateConfigFilePermissions(actualPath)

	// Perform universal validation (platform-independent)
	if err := wg.validateConfigUniversal(cfg); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}

// ParseConfigForDown parses configuration for down operation without address conflict validation
func (wg *WireGuardManager) ParseConfigForDown(configPath string) error {
	actualPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path: %w", err)
	}

	cfg, _, err := config.ParseFile(actualPath)
	if err != nil {
		return err
	}

	wg.config = cfg
	wg.configPath = actualPath

	// Extract interface name from path
	filename := filepath.Base(actualPath)
	wg.interfaceName = strings.TrimSuffix(filename, ".conf")

	// Warn about insecure file permissions (like original bash script)
	wg.validateConfigFilePermissions(actualPath)

	// For down operation, skip address conflict validation but do basic validation
	if err := wg.validateConfigBasic(cfg); err != nil {
		return fmt.Errorf("configuration validation failed: %w", err)
	}

	return nil
}

// validateConfigBasic performs basic validation without address conflict checks
func (wg *WireGuardManager) validateConfigBasic(cfg *config.Config) error {
	// Validate interface name
	if err := utils.ValidateInterfaceName(wg.interfaceName); err != nil {
		return err
	}

	// Validate private key
	if err := utils.ValidatePrivateKey(cfg.Interface.PrivateKey); err != nil {
		return err
	}

	// Validate listen port
	if cfg.Interface.ListenPort != nil {
		if *cfg.Interface.ListenPort < 1 || *cfg.Interface.ListenPort > 65535 {
			return fmt.Errorf("invalid listen port: %d (must be 1-65535)", *cfg.Interface.ListenPort)
		}
	}

	// Validate MTU
	if cfg.Interface.MTU != nil && *cfg.Interface.MTU > 0 {
		if err := utils.ValidateMTU(*cfg.Interface.MTU); err != nil {
			return err
		}
	}

	// Validate peers
	for i, peer := range cfg.Peers {
		// Validate public key
		if err := utils.ValidatePublicKey(peer.PublicKey); err != nil {
			return fmt.Errorf("peer %d: invalid public key: %w", i, err)
		}

		// Validate endpoint if present
		if peer.Endpoint != "" {
			if err := utils.ValidateEndpoint(peer.Endpoint); err != nil {
				return fmt.Errorf("peer %d: %w", i, err)
			}
		}

		// Validate allowed IPs
		if err := utils.ValidateAllowedIPs(peer.AllowedIPs); err != nil {
			return fmt.Errorf("peer %d: %w", i, err)
		}
	}

	return nil
}

// validateConfigFilePermissions checks configuration file permissions and logs
// a warning if the file is world-accessible. Matches the original bash behavior
// where this is a warning, not a fatal error.
func (wg *WireGuardManager) validateConfigFilePermissions(configPath string) {
	if warning, err := utils.CheckFilePermissions(configPath); err != nil {
		wg.logger.Warning(fmt.Sprintf("Cannot check permissions for %s: %v", configPath, err))
	} else if warning != "" {
		wg.logger.Warning(warning)
	}
}

// validateConfigUniversal performs universal configuration validation (all platforms)
func (wg *WireGuardManager) validateConfigUniversal(cfg *config.Config) error {
	// Validate interface name
	if err := utils.ValidateInterfaceName(wg.interfaceName); err != nil {
		return err
	}

	// Validate interface addresses
	if err := utils.ValidateInterfaceAddresses(cfg.Interface.Address); err != nil {
		return err
	}

	// Check for network conflicts with existing interfaces
	if err := utils.ValidateNoNetworkConflicts(cfg.Interface.Address); err != nil {
		return err
	}

	// Validate private key
	if cfg.Interface.PrivateKey != "" {
		if err := utils.ValidatePrivateKey(cfg.Interface.PrivateKey); err != nil {
			return fmt.Errorf("invalid private key: %w", err)
		}
	}

	// Validate listen port
	if cfg.Interface.ListenPort != nil {
		if *cfg.Interface.ListenPort < 1 || *cfg.Interface.ListenPort > 65535 {
			return fmt.Errorf("invalid listen port: %d (must be 1-65535)", *cfg.Interface.ListenPort)
		}
	}

	// Validate MTU if specified
	if cfg.Interface.MTU != nil {
		if err := utils.ValidateMTU(*cfg.Interface.MTU); err != nil {
			return err
		}
	}

	// Validate table if specified
	if cfg.Interface.Table != "" {
		if err := utils.ValidateTable(cfg.Interface.Table); err != nil {
			return err
		}
	}

	// Validate FwMark if specified
	if cfg.Interface.FwMark != nil {
		if err := utils.ValidateFwMark(*cfg.Interface.FwMark); err != nil {
			return err
		}
	}

	// Validate DNS addresses
	for _, dns := range cfg.Interface.DNS {
		if err := utils.ValidateDNSAddress(dns.String()); err != nil {
			return err
		}
	}

	// Collect all allowed IPs for conflict checking
	var allAllowedIPs []net.IPNet

	// Validate peer configurations
	for i, peer := range cfg.Peers {
		// Validate public key
		if err := utils.ValidatePublicKey(peer.PublicKey); err != nil {
			return fmt.Errorf("peer %d: invalid public key: %w", i, err)
		}

		// Validate preshared key if specified
		if peer.PresharedKey != "" {
			if err := utils.ValidatePrivateKey(peer.PresharedKey); err != nil {
				return fmt.Errorf("peer %d: invalid preshared key: %w", i, err)
			}
		}

		// Validate endpoint if specified
		if peer.Endpoint != "" {
			if err := utils.ValidateEndpoint(peer.Endpoint); err != nil {
				return fmt.Errorf("peer %d: %w", i, err)
			}
		}

		// Validate persistent keepalive
		if peer.PersistentKeepalive != nil {
			if *peer.PersistentKeepalive < 0 || *peer.PersistentKeepalive > 65535 {
				return fmt.Errorf("peer %d: invalid persistent keepalive: %d (must be 0-65535)", i, *peer.PersistentKeepalive)
			}
		}

		// Validate allowed IPs
		for _, allowedIP := range peer.AllowedIPs {
			if err := utils.ValidateIPNetwork(allowedIP.String()); err != nil {
				return fmt.Errorf("peer %d: invalid allowed IP %s: %w", i, allowedIP.String(), err)
			}
			allAllowedIPs = append(allAllowedIPs, allowedIP)
		}
	}

	// Check for route conflicts between allowed IPs
	if err := utils.ValidateRouteConflicts(allAllowedIPs); err != nil {
		return err
	}

	return nil
}

// Up brings up WireGuard interface
func (wg *WireGuardManager) Up(ctx context.Context) error {
	// Check platform requirements
	if err := wg.platformMgr.CheckRequirements(); err != nil {
		return fmt.Errorf("platform requirements not met: %w", err)
	}

	// Platform-specific validation (universal validation already done in ParseConfig)
	if err := wg.platformMgr.ValidateConfig(wg.config); err != nil {
		return fmt.Errorf("platform-specific validation failed: %w", err)
	}

	// Check if interface already exists (matching original bash: die if exists)
	if wg.platformMgr.InterfaceExists(wg.interfaceName) {
		realName := wg.platformMgr.GetRealInterfaceName(wg.interfaceName)
		if realName != wg.interfaceName {
			return fmt.Errorf("`%s' already exists as `%s'", wg.interfaceName, realName)
		}
		return fmt.Errorf("`%s' already exists", wg.interfaceName)
	}

	// Setup signal handling for cleanup
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		wg.logger.Info("Received termination signal, cleaning up...")
		_ = wg.Down(context.Background())
		os.Exit(0)
	}()

	// Create interface first (matching original bash: add_if → execute_hooks(PreUp) → set_config)
	if err := wg.platformMgr.CreateInterface(wg.interfaceName); err != nil {
		return fmt.Errorf("failed to create interface: %w", err)
	}

	// Cleanup on error
	var upErr error
	defer func() {
		if upErr != nil {
			_ = wg.Down(context.Background())
		}
	}()

	// Execute PreUp hooks AFTER interface creation (matching original bash order)
	if err := wg.executeHooks(ctx, wg.config.Interface.PreUp); err != nil {
		upErr = fmt.Errorf("PreUp hook failed: %w", err)
		return upErr
	}

	// Configure WireGuard
	if err := wg.platformMgr.ConfigureWireGuard(wg.interfaceName, wg.config, wg.cmdRunner); err != nil {
		upErr = fmt.Errorf("failed to configure WireGuard: %w", err)
		return upErr
	}

	// Add addresses
	for _, addr := range wg.config.Interface.Address {
		if err := wg.platformMgr.AddAddress(wg.interfaceName, addr); err != nil {
			upErr = fmt.Errorf("failed to add address %s: %w", addr.String(), err)
			return upErr
		}
	}

	// Set MTU and bring up
	mtu := 1420 // WireGuard default
	if wg.config.Interface.MTU != nil {
		mtu = *wg.config.Interface.MTU
	} else {
		// Auto-calculate MTU
		if calculatedMTU, err := wg.platformMgr.CalculateOptimalMTU(wg.interfaceName, wg.outputParser, wg.cmdRunner); err == nil {
			mtu = calculatedMTU
		}
	}

	if err := wg.platformMgr.SetMTUAndUp(wg.interfaceName, mtu); err != nil {
		upErr = fmt.Errorf("failed to set MTU and bring up interface: %w", err)
		return upErr
	}

	// On macOS, DNS is set AFTER routes (matching original bash: routes → endpoint → dns → monitor → PostUp).
	// On all other platforms, DNS is set BEFORE routes (matching original bash).
	if runtime.GOOS != "darwin" {
		if err := wg.platformMgr.SetupDNS(wg.interfaceName, wg.config.Interface.DNS, wg.config.Interface.DNSSearch); err != nil {
			upErr = fmt.Errorf("failed to setup DNS: %w", err)
			return upErr
		}
	}

	// Read AllowedIPs from the live WireGuard interface, matching original bash:
	//   while read -r _ AllowedIPs; do ... done < <(wg show "$INTERFACE" allowed-ips)
	// This ensures routes reflect the actual interface state after wg addconf,
	// not just the parsed config file.
	wgIfaceName := wg.platformMgr.GetWireGuardInterfaceName(wg.interfaceName)
	allowedIPs, err := utils.GetAllowedIPsFromInterface(wgIfaceName, wg.outputParser, wg.cmdRunner)
	if err != nil {
		upErr = fmt.Errorf("failed to get allowed IPs from interface: %w", err)
		return upErr
	}

	if err := wg.platformMgr.SetupRoutes(wg.interfaceName, allowedIPs, wg.config.Interface.Table, wg.outputParser, wg.cmdRunner); err != nil {
		upErr = fmt.Errorf("failed to setup routes: %w", err)
		return upErr
	}

	if runtime.GOOS == "darwin" {
		if err := wg.platformMgr.SetupDNS(wg.interfaceName, wg.config.Interface.DNS, wg.config.Interface.DNSSearch); err != nil {
			upErr = fmt.Errorf("failed to setup DNS: %w", err)
			return upErr
		}
	}

	// Start route monitor daemon BEFORE PostUp hooks (matching original bash for BSD platforms)
	if err := wg.platformMgr.StartMonitor(wg.interfaceName, wg.config, wg.outputParser, wg.cmdRunner); err != nil {
		wg.logger.Warning(fmt.Sprintf("Failed to start route monitor: %v", err))
	}

	// Execute PostUp hooks (fatal on failure, matching original bash set -e behavior)
	if err := wg.executeHooks(ctx, wg.config.Interface.PostUp); err != nil {
		upErr = fmt.Errorf("PostUp hook failed: %w", err)
		return upErr
	}

	wg.logger.Info(fmt.Sprintf("Interface %s is up", wg.interfaceName))
	return nil
}

// Down brings down WireGuard interface
func (wg *WireGuardManager) Down(ctx context.Context) error {
	if !wg.platformMgr.InterfaceExists(wg.interfaceName) {
		// If config says SaveConfig, still try to save it even if interface is gone
		if wg.config != nil && wg.config.Interface.SaveConfig {
			if err := wg.SaveConfig(); err != nil {
				wg.logger.Warning(fmt.Sprintf("Failed to save config: %v", err))
			}
		}
		return fmt.Errorf("interface %s does not exist", wg.interfaceName)
	}

	// Execute PreDown hooks
	if wg.config != nil {
		if err := wg.executeHooks(ctx, wg.config.Interface.PreDown); err != nil {
			wg.logger.Warning(fmt.Sprintf("PreDown hook failed: %v", err))
		}
	}

	// Save config if needed
	if wg.config != nil && wg.config.Interface.SaveConfig {
		if err := wg.SaveConfig(); err != nil {
			wg.logger.Warning(fmt.Sprintf("Failed to save config: %v", err))
		}
	}

	// Stop route monitor daemon before deleting interface
	wg.platformMgr.StopMonitor(wg.interfaceName)

	// Delete interface will also trigger cleanup of routes, etc.
	if err := wg.platformMgr.DeleteInterface(wg.interfaceName); err != nil {
		return fmt.Errorf("failed to delete interface: %w", err)
	}

	// Cleanup DNS and firewall
	wg.platformMgr.CleanupDNS(wg.interfaceName)
	wg.platformMgr.CleanupFirewall(wg.interfaceName, wg.cmdRunner)

	// Execute PostDown hooks
	if wg.config != nil {
		if err := wg.executeHooks(ctx, wg.config.Interface.PostDown); err != nil {
			wg.logger.Warning(fmt.Sprintf("PostDown hook failed: %v", err))
		}
	}

	wg.logger.Info(fmt.Sprintf("Interface %s is down", wg.interfaceName))
	return nil
}

// SaveConfig saves current configuration to INI file
func (wg *WireGuardManager) SaveConfig() error {
	if !wg.platformMgr.InterfaceExists(wg.interfaceName) {
		return fmt.Errorf("interface %s does not exist", wg.interfaceName)
	}

	// Get current WireGuard config using platform-specific interface name
	wgInterfaceName := wg.platformMgr.GetWireGuardInterfaceName(wg.interfaceName)
	wgOutput, err := wg.cmdRunner.RunWithOutput("wg", "showconf", wgInterfaceName)
	if err != nil {
		return fmt.Errorf("failed to get current config: %w", err)
	}

	// Parse current config
	currentCfg, err := ini.Load(wgOutput)
	if err != nil {
		return fmt.Errorf("failed to parse current config: %w", err)
	}

	// Update Interface section with runtime values
	interfaceSection := currentCfg.Section("Interface")

	// Add current addresses
	addresses := wg.platformMgr.GetCurrentAddresses(wg.interfaceName)
	if len(addresses) > 0 {
		interfaceSection.Key("Address").SetValue(strings.Join(addresses, ", "))
	}

	// Add current DNS.
	// Try live DNS from the system first (Linux/FreeBSD read from resolvconf),
	// fall back to parsed config values (macOS/OpenBSD, matching original bash TODO).
	if liveDNS := wg.platformMgr.GetCurrentDNS(wg.interfaceName); len(liveDNS) > 0 {
		interfaceSection.Key("DNS").SetValue(strings.Join(liveDNS, ", "))
	} else if len(wg.config.Interface.DNS) > 0 {
		var dnsStrings []string
		for _, dns := range wg.config.Interface.DNS {
			dnsStrings = append(dnsStrings, dns.String())
		}
		dnsStrings = append(dnsStrings, wg.config.Interface.DNSSearch...)
		interfaceSection.Key("DNS").SetValue(strings.Join(dnsStrings, ", "))
	}

	// Add current MTU
	if mtu := wg.platformMgr.GetCurrentMTU(wg.interfaceName); mtu > 0 {
		interfaceSection.Key("MTU").SetValue(strconv.Itoa(mtu))
	}

	// Add original configuration parameters
	if wg.config.Interface.Table != "" {
		interfaceSection.Key("Table").SetValue(wg.config.Interface.Table)
	}

	if wg.config.Interface.SaveConfig {
		interfaceSection.Key("SaveConfig").SetValue("true")
	}

	// Add hooks
	for _, hook := range wg.config.Interface.PreUp {
		_, _ = interfaceSection.NewKey("PreUp", hook)
	}
	for _, hook := range wg.config.Interface.PostUp {
		_, _ = interfaceSection.NewKey("PostUp", hook)
	}
	for _, hook := range wg.config.Interface.PreDown {
		_, _ = interfaceSection.NewKey("PreDown", hook)
	}
	for _, hook := range wg.config.Interface.PostDown {
		_, _ = interfaceSection.NewKey("PostDown", hook)
	}

	// Save to file atomically with restrictive permissions.
	// Matches original bash: umask 077 → write → sync → mv
	oldUmask := setUmask(0o077)
	defer setUmask(oldUmask)

	tempFile := wg.configPath + ".tmp"
	f, err := os.OpenFile(tempFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("failed to create temp config: %w", err)
	}

	if _, err := currentCfg.WriteTo(f); err != nil {
		_ = f.Close()
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to write config: %w", err)
	}

	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to sync config: %w", err)
	}

	if err := f.Close(); err != nil {
		_ = os.Remove(tempFile)
		return fmt.Errorf("failed to close config: %w", err)
	}

	return os.Rename(tempFile, wg.configPath)
}

// Strip outputs the raw WireGuard configuration (without wg-quick extensions).
// Matches original bash: cmd_strip() { echo "$WG_CONFIG"; }
// Unlike the previous implementation, this does NOT require a running interface.
func (wg *WireGuardManager) Strip() error {
	_, err := os.Stdout.WriteString(wg.config.RawWGConfig)
	return err
}

func (wg *WireGuardManager) executeHooks(ctx context.Context, hooks []string) error {
	// %i → real/OS-level interface name (utun5 on macOS, wg0 on OpenBSD, logical name on Linux/FreeBSD)
	// %I → logical interface name from config filename (always the config-derived name)
	realName := wg.platformMgr.GetRealInterfaceName(wg.interfaceName)
	for _, hook := range hooks {
		command := strings.ReplaceAll(hook, "%i", realName)
		command = strings.ReplaceAll(command, "%I", wg.interfaceName)
		wg.logger.Command("bash", "-c", command)
		cmd := exec.CommandContext(ctx, "bash", "-c", command)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("hook command failed: %s: %w", command, err)
		}
	}
	return nil
}
