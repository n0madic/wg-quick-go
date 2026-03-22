# WireGuard Integration Tests

This directory contains integration and unit tests for the wg-quick-go implementation.

## Test Files

| File | Tests | Root Required |
|------|-------|---------------|
| `integration_test.go` | Peer-to-peer connectivity | Yes |
| `validation_integration_test.go` | Config validation, error scenarios, cleanup | Partially |
| `platform_interface_test.go` | Platform manager interface mapping | No |
| `wireguard_command_test.go` | WireGuard command generation (mock runner) | No |

## Tests

### `TestIntegration_PeerToPeerConnectivity`

Full end-to-end test using `IntegrationTestSuite`. Requires root and `wg` tools.

**Subtests:** Setup, KeyGeneration, ConfigCreation, InterfaceCreation, Connectivity, WireGuardStats, Cleanup

**Topology:**

```
┌─────────────────────┐         ┌─────────────────────┐
│      wg-test1       │ ←────→  │      wg-test2       │
│  172.16.10.1/24     │         │  172.16.11.1/24     │
│  172.16.10.50/24    │         │  172.16.11.50/24    │
│  port :8001         │         │  port :8002         │
│                     │         │                     │
│  AllowedIPs:        │         │  AllowedIPs:        │
│  172.16.11.0/24     │         │  172.16.10.0/24     │
└─────────────────────┘         └─────────────────────┘
           │                              │
           └────── 127.0.0.1 ─────────────┘
```

Peer1 acts as server (no endpoint), peer2 connects to peer1 with `PersistentKeepalive = 2`.

### `TestIntegration_ConfigValidation`

Validates config parsing rejects invalid input. No root required.

**Subtests:** InvalidPrivateKey, InvalidAddress, InvalidEndpoint, InvalidMTU, InvalidListenPort, FilePermissions

### `TestIntegration_ErrorScenarios`

Tests error handling for runtime edge cases. Requires root.

**Subtests:** DuplicateInterface, InterfaceNotFound, NetworkConflicts

### `TestIntegration_CleanupScenarios`

Tests resource cleanup robustness. Requires root.

**Subtests:** NormalCleanup, ForceCleanup (interface removed externally), PartialCleanup

### `TestPlatformInterfaceMapping`

Verifies `GetWireGuardInterfaceName` and `ConfigureWireGuard` method availability. No root required.

### `TestWireGuardCommandGeneration`

Uses `MockCommandRunner` to verify that `ConfigureWireGuard` generates `wg addconf <iface> /dev/stdin` (not `wg set`) and passes raw config via stdin.

## Running Tests

```bash
# Unit tests only (no root)
go test -v ./test/ -run 'TestPlatformInterfaceMapping|TestPlatformMethodsExist|TestWireGuardCommandGeneration|TestIntegration_ConfigValidation'

# All tests (requires root + WireGuard tools)
sudo go test -v ./test/

# Specific test
sudo go test -v ./test/ -run TestIntegration_PeerToPeerConnectivity
```

## Prerequisites

- **Root privileges** for integration tests that create network interfaces
- **WireGuard tools** (`wg` command) for connectivity and cleanup tests
- **Platform-specific tools**:
  - Linux: `ip`, `iptables`/`nftables`, optionally `resolvconf`
  - macOS: `wireguard-go`, `ifconfig`, `route`, `networksetup`
  - FreeBSD: `ifconfig`, `route`, optionally `resolvconf`
  - OpenBSD: `ifconfig`, `route`

## Troubleshooting

**Permission Denied** — run with `sudo`.

**WireGuard Not Found** — install `wireguard-tools` for your platform.

**Interface Conflicts** — clean up leftover interfaces:

```bash
# List WireGuard interfaces
sudo wg show

# Remove test interfaces manually
# Linux:
sudo ip link delete wg-test1 2>/dev/null
sudo ip link delete wg-test2 2>/dev/null

# macOS:
sudo rm -f /var/run/wireguard/wg-test*.sock
sudo rm -f /var/run/wireguard/wg-test*.name
```

**Port Conflicts** — tests use ports 8001 and 8002. Kill conflicting processes or wait for them to release.
