package config

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/ini.v1"
)

// Config represents WireGuard interface configuration
type Config struct {
	Interface   InterfaceConfig
	Peers       []PeerConfig
	RawWGConfig string // Non-wg-quick lines for passing to `wg addconf` (like original bash $WG_CONFIG)
}

// InterfaceConfig contains interface settings
type InterfaceConfig struct {
	// Standard WireGuard parameters
	PrivateKey string `ini:"PrivateKey"`
	ListenPort *int   `ini:"ListenPort,omitempty"`
	FwMark     *int   `ini:"FwMark,omitempty"`

	// wg-quick specific parameters
	Address    []net.IPNet `ini:"-"`
	DNS        []net.IP    `ini:"-"`
	DNSSearch  []string    `ini:"-"`
	MTU        *int        `ini:"MTU,omitempty"`
	Table      string      `ini:"Table,omitempty"`
	SaveConfig bool        `ini:"SaveConfig,omitempty"`
	PreUp      []string    `ini:"-"`
	PostUp     []string    `ini:"-"`
	PreDown    []string    `ini:"-"`
	PostDown   []string    `ini:"-"`

	// Raw values for complex parsing
	AddressRaw  []string `ini:"Address"`
	DNSRaw      []string `ini:"DNS"`
	PreUpRaw    []string `ini:"PreUp"`
	PostUpRaw   []string `ini:"PostUp"`
	PreDownRaw  []string `ini:"PreDown"`
	PostDownRaw []string `ini:"PostDown"`
}

// PeerConfig contains peer settings
type PeerConfig struct {
	PublicKey           string      `ini:"PublicKey"`
	PresharedKey        string      `ini:"PresharedKey,omitempty"`
	Endpoint            string      `ini:"Endpoint,omitempty"`
	AllowedIPs          []net.IPNet `ini:"-"`
	PersistentKeepalive *int        `ini:"PersistentKeepalive,omitempty"`

	// Raw values for complex parsing
	AllowedIPsRaw []string `ini:"AllowedIPs"`
}

// ParseFile parses a WireGuard configuration file from the given path.
func ParseFile(configPath string) (*Config, string, error) {
	actualPath, err := findConfigFile(configPath)
	if err != nil {
		return nil, "", err
	}

	if err := checkConfigPermissions(actualPath); err != nil {
		// Log this as a warning instead of a hard error
		fmt.Fprintf(os.Stderr, "[WARNING] %v\n", err)
	}

	cfg, err := ini.Load(actualPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to load config file %s: %w", actualPath, err)
	}

	config := &Config{}

	if interfaceSection := cfg.Section("Interface"); interfaceSection != nil {
		if err := interfaceSection.MapTo(&config.Interface); err != nil {
			return nil, "", fmt.Errorf("failed to parse Interface section: %w", err)
		}
		if err := parseInterfaceComplexFields(&config.Interface); err != nil {
			return nil, "", fmt.Errorf("failed to parse interface complex fields: %w", err)
		}
	}

	for _, section := range cfg.Sections() {
		if strings.EqualFold(section.Name(), "Peer") {
			var peer PeerConfig
			if err := section.MapTo(&peer); err != nil {
				return nil, "", fmt.Errorf("failed to parse Peer section: %w", err)
			}
			if err := parsePeerComplexFields(&peer); err != nil {
				return nil, "", fmt.Errorf("failed to parse peer complex fields: %w", err)
			}
			config.Peers = append(config.Peers, peer)
		}
	}

	// Extract raw WireGuard config (non-wg-quick lines) for `wg addconf`.
	// This mirrors the original bash script's line-by-line accumulation of $WG_CONFIG.
	rawWGConfig, err := extractRawWGConfig(actualPath)
	if err != nil {
		return nil, "", fmt.Errorf("failed to extract raw WG config: %w", err)
	}
	config.RawWGConfig = rawWGConfig

	return config, actualPath, nil
}

func findConfigFile(configPath string) (string, error) {
	if filepath.IsAbs(configPath) || strings.Contains(configPath, string(os.PathSeparator)) {
		if _, err := os.Stat(configPath); err == nil {
			return configPath, nil
		}
		return "", fmt.Errorf("config file not found: %s", configPath)
	}

	searchPaths := []string{
		configPath,
		configPath + ".conf",
		filepath.Join("/etc/wireguard", configPath+".conf"),
		filepath.Join("/usr/local/etc/wireguard", configPath+".conf"),
	}

	for _, path := range searchPaths {
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}

	return "", fmt.Errorf("config file not found, tried: %s", strings.Join(searchPaths, ", "))
}

func checkConfigPermissions(configPath string) error {
	info, err := os.Stat(configPath)
	if err != nil {
		return err
	}
	if mode := info.Mode(); mode&0007 != 0 {
		return fmt.Errorf("config file %s is world accessible", configPath)
	}
	return nil
}

func parseInterfaceComplexFields(iface *InterfaceConfig) error {
	for _, addrStr := range iface.AddressRaw {
		addresses, err := parseAddresses(addrStr)
		if err != nil {
			return fmt.Errorf("invalid address %s: %w", addrStr, err)
		}
		iface.Address = append(iface.Address, addresses...)
	}

	for _, dnsStr := range iface.DNSRaw {
		dns, search, err := parseDNS(dnsStr)
		if err != nil {
			return fmt.Errorf("invalid DNS %s: %w", dnsStr, err)
		}
		iface.DNS = append(iface.DNS, dns...)
		iface.DNSSearch = append(iface.DNSSearch, search...)
	}

	iface.PreUp = append(iface.PreUp, iface.PreUpRaw...)
	iface.PostUp = append(iface.PostUp, iface.PostUpRaw...)
	iface.PreDown = append(iface.PreDown, iface.PreDownRaw...)
	iface.PostDown = append(iface.PostDown, iface.PostDownRaw...)

	return nil
}

func parsePeerComplexFields(peer *PeerConfig) error {
	for _, allowedIPStr := range peer.AllowedIPsRaw {
		allowedIPs, err := parseAllowedIPs(allowedIPStr)
		if err != nil {
			return fmt.Errorf("invalid AllowedIPs %s: %w", allowedIPStr, err)
		}
		peer.AllowedIPs = append(peer.AllowedIPs, allowedIPs...)
	}
	return nil
}

func parseAddresses(value string) ([]net.IPNet, error) {
	var addresses []net.IPNet
	for _, addr := range strings.Split(value, ",") {
		addr = strings.TrimSpace(addr)
		if addr == "" {
			continue
		}
		// Parse CIDR manually to preserve the original IP address
		if strings.Contains(addr, "/") {
			ip, ipnet, err := net.ParseCIDR(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR address: %s", addr)
			}
			// Use the original IP address, not the network address
			addresses = append(addresses, net.IPNet{IP: ip, Mask: ipnet.Mask})
		} else {
			ip := net.ParseIP(addr)
			if ip == nil {
				return nil, fmt.Errorf("invalid address: %s", addr)
			}
			var mask net.IPMask
			if ip.To4() != nil {
				mask = net.CIDRMask(32, 32)
			} else {
				mask = net.CIDRMask(128, 128)
			}
			addresses = append(addresses, net.IPNet{IP: ip, Mask: mask})
		}
	}
	return addresses, nil
}

func parseDNS(value string) ([]net.IP, []string, error) {
	var dns []net.IP
	var search []string
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if ip := net.ParseIP(item); ip != nil {
			dns = append(dns, ip)
		} else {
			search = append(search, item)
		}
	}
	return dns, search, nil
}

// wgQuickKeys are the [Interface] keys handled by wg-quick (not passed to wg).
// Matches the original bash case statement in parse_options().
var wgQuickKeys = map[string]bool{
	"address":    true,
	"dns":        true,
	"mtu":        true,
	"table":      true,
	"saveconfig": true,
	"preup":      true,
	"postup":     true,
	"predown":    true,
	"postdown":   true,
}

// extractRawWGConfig reads the config file line-by-line and builds the raw
// WireGuard configuration string, exactly mirroring the original bash script's
// $WG_CONFIG accumulation. Lines in [Interface] that are wg-quick extensions
// are excluded; everything else (including [Peer] sections, unknown keys,
// and non-wg-quick [Interface] keys like PrivateKey) is included verbatim.
func extractRawWGConfig(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	var wgConfig strings.Builder
	inInterfaceSection := false

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()

		// Strip comments for key detection (like original: stripped="${line%%\#*}")
		stripped := line
		if idx := strings.Index(stripped, "#"); idx >= 0 {
			stripped = stripped[:idx]
		}

		// Extract key from "key = value" (like original bash key extraction)
		key := strings.TrimSpace(stripped)
		if eqIdx := strings.Index(key, "="); eqIdx >= 0 {
			key = strings.TrimSpace(key[:eqIdx])
		}

		// Track section changes
		if strings.HasPrefix(key, "[") {
			inInterfaceSection = strings.EqualFold(key, "[Interface]")
		}

		// In [Interface] section, skip wg-quick extension keys
		if inInterfaceSection && wgQuickKeys[strings.ToLower(key)] {
			continue
		}

		wgConfig.WriteString(line)
		wgConfig.WriteByte('\n')
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return wgConfig.String(), nil
}

func parseAllowedIPs(value string) ([]net.IPNet, error) {
	var allowedIPs []net.IPNet
	for _, ip := range strings.Split(value, ",") {
		ip = strings.TrimSpace(ip)
		if ip == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(ip)
		if err != nil {
			return nil, fmt.Errorf("invalid allowed IP: %s", ip)
		}
		allowedIPs = append(allowedIPs, *ipnet)
	}
	return allowedIPs, nil
}
