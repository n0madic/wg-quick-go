# wg-quick-go

A Go implementation of [wg-quick](https://man7.org/linux/man-pages/man8/wg-quick.8.html) -- the standard utility for managing WireGuard VPN interfaces. Designed as a **drop-in replacement** for the original bash scripts with identical command-line interface and behavior.

## Why

The original `wg-quick` is a collection of platform-specific bash scripts (~400-500 lines each). This project replaces them with a single Go binary that:

- Works identically across **Linux**, **macOS**, **FreeBSD**, and **OpenBSD**
- Has no runtime dependency on bash
- Provides better error messages and input validation
- Uses native APIs where available (e.g., netlink on Linux instead of shelling out to `ip`)
- Ships as a single static binary per platform

## Installation

### From source

```bash
# Build for current platform
make build

# Install to /usr/local/bin (requires root)
sudo make install
```

### Cross-compilation

```bash
# Build for all supported platforms
make build-all

# Binaries appear in build/:
#   wg-quick-linux-amd64
#   wg-quick-darwin-amd64
#   wg-quick-darwin-arm64
#   wg-quick-freebsd-amd64
#   wg-quick-openbsd-amd64
```

### Requirements

**All platforms:**
- [wireguard-tools](https://www.wireguard.com/install/) (`wg` command)

**Linux:**
- Root privileges
- WireGuard kernel module **or** [wireguard-go](https://github.com/WireGuard/wireguard-go)
- `resolvconf` (optional, for DNS)

**macOS:**
- [wireguard-go](https://github.com/WireGuard/wireguard-go) (`brew install wireguard-go`)
- `ifconfig`, `route`, `networksetup` (included with macOS)

**FreeBSD:**
- Root privileges
- WireGuard kernel module (`if_wg`) **or** wireguard-go
- `ifconfig`, `route`, `netstat`

**OpenBSD:**
- Root privileges (or `doas`)
- wireguard-go
- `ifconfig`, `route`, `netstat`

## Usage

Commands are identical to the original `wg-quick`:

```bash
# Bring up a WireGuard interface
sudo wg-quick up /etc/wireguard/wg0.conf
sudo wg-quick up wg0     # shorthand: looks for /etc/wireguard/wg0.conf

# Bring down the interface
sudo wg-quick down wg0

# Save current runtime config back to file
sudo wg-quick save wg0

# Print stripped config (suitable for wg(8))
wg-quick strip wg0
```

### Force userspace implementation

```bash
sudo WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go wg-quick up wg0
```

## Configuration

Standard WireGuard configuration format. All fields supported by the original `wg-quick` are supported:

```ini
[Interface]
PrivateKey = <base64-encoded private key>
Address = 10.0.0.1/24, fd00::1/64
DNS = 1.1.1.1, 8.8.8.8, example.com
ListenPort = 51820
MTU = 1420
Table = auto
SaveConfig = false
FwMark = 0x1234

PreUp = echo "coming up"
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PreDown = echo "going down"
PostDown = iptables -D FORWARD -i %i -j ACCEPT

[Peer]
PublicKey = <base64-encoded public key>
PresharedKey = <base64-encoded preshared key>
Endpoint = 203.0.113.1:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
```

### Hook substitution

In `PreUp`, `PostUp`, `PreDown`, and `PostDown` commands:
- `%i` is replaced with the **real OS interface name** (e.g., `utun5` on macOS, `wg0` on OpenBSD/Linux)
- `%I` is replaced with the **logical interface name** from the config filename

## Compatibility with original wg-quick

This implementation matches the original bash scripts feature-for-feature:

| Feature | Linux | macOS | FreeBSD | OpenBSD |
|---|---|---|---|---|
| Interface creation (kernel + userspace fallback) | yes | yes | yes | yes |
| Address management (IPv4/IPv6) | yes | yes | yes | yes |
| Route setup with AllowedIPs | yes | yes | yes | yes |
| Default route override (0.0.0.0/0) | yes | yes | yes | yes |
| Policy routing + fwmark (Linux) | yes | -- | -- | -- |
| Split routing (BSD) | -- | yes | yes | yes |
| Endpoint protection routes | yes | yes | yes | yes |
| Route monitor daemon | -- | yes | yes | yes |
| Firewall rules (nftables/iptables) | yes | -- | -- | -- |
| DNS via resolvconf | yes | -- | yes | -- |
| DNS via networksetup | -- | yes | -- | -- |
| DNS via route nameserver / resolv.conf | -- | -- | -- | yes |
| MTU auto-detection | yes | yes | yes | yes |
| SaveConfig | yes | yes | yes | yes |
| Pre/PostUp/Down hooks | yes | yes | yes | yes |
| Table routing (off / auto / numeric) | yes | yes | yes | yes |
| Signal handling (SIGINT/SIGTERM) | yes | yes | yes | yes |
| Config file permission checks | yes | yes | yes | yes |

### MTU strategy per platform

Matches the original scripts:
- **Linux**: minimum MTU across all endpoint paths
- **macOS**: default route interface MTU
- **FreeBSD/OpenBSD**: maximum MTU across all endpoint paths

### Route monitor daemon

On macOS, FreeBSD, and OpenBSD, a background goroutine monitors `route -n monitor` for network changes (`RTM_*` events). When the network changes (e.g., switching from Wi-Fi to Ethernet), the monitor automatically:
- Refreshes endpoint protection routes via the new gateway
- Recalculates MTU if it was auto-detected
- Re-applies DNS settings (macOS only)

This matches the `monitor_daemon()` function in the original bash scripts.

## Architecture

```
wg-quick.go              Main entry point
pkg/
  app/app.go             CLI argument parsing and command dispatch
  config/config.go       INI configuration parsing and validation
  wireguard/
    wireguard.go         WireGuardManager: orchestrates up/down/save/strip
    wireguard_unix.go    Unix-specific syscall support (umask)
    wireguard_windows.go Windows syscall stubs
  platform/
    platform.go          PlatformManager interface (27 methods)
    factory.go           Platform-specific manager factory
    linux.go             Linux: netlink API, policy routing, nftables/iptables
    darwin.go            macOS: wireguard-go, utun, networksetup, route monitor
    freebsd.go           FreeBSD: kernel/userspace, resolvconf, route monitor
    openbsd.go           OpenBSD: dynamic wg slots, DNS daemons, route monitor
    stub.go              Stub for unsupported platforms
  utils/
    network.go           IP parsing, MTU calculation, gateway discovery
    wireguard.go         WireGuard command helpers, endpoint parsing
    validation.go        Config validation (keys, addresses, ports, etc.)
    routing.go           Shared BSD routing logic
    output.go            Command output parsing
    platform.go          Privilege checks, command validation, userspace cleanup
  runner/runner.go       Command execution abstraction
  logger/logger.go       Logging interface
```

## Development

```bash
# Download dependencies
make deps

# Run linter
make lint

# Format code
go fmt ./...

# Run unit tests
make test-unit

# Run integration tests (requires root + WireGuard tools)
sudo make test-integration

# Run connectivity tests only
sudo make test-connectivity

# Show system info and check requirements
make info
make check-linux    # or check-macos, check-freebsd, check-openbsd

# Build for all platforms and verify
make build-all
```

## License

This project implements the same functionality as the original `wg-quick` from the [WireGuard](https://www.wireguard.com/) project.
