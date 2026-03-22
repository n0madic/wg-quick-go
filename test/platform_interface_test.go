package test

import (
	"github.com/n0madic/wg-quick-go/pkg/config"
	"github.com/n0madic/wg-quick-go/pkg/logger"
	"github.com/n0madic/wg-quick-go/pkg/platform"
	"github.com/n0madic/wg-quick-go/pkg/runner"
	"testing"
)

// TestPlatformInterfaceMapping tests that platform managers correctly handle interface name mapping
func TestPlatformInterfaceMapping(t *testing.T) {
	logger := &logger.DefaultLogger{}
	cmdRunner := runner.NewDefaultCommandRunner(logger)

	// Create platform manager
	platformMgr := platform.NewPlatformManager(logger)
	platformMgr.SetCommandRunner(cmdRunner)

	// Test interface name mapping
	testInterfaceName := "wg-test-mapping"

	// Test GetWireGuardInterfaceName method
	wgInterfaceName := platformMgr.GetWireGuardInterfaceName(testInterfaceName)

	t.Logf("Logical interface name: %s", testInterfaceName)
	t.Logf("WireGuard interface name: %s", wgInterfaceName)

	// On macOS, the names might be different (e.g., wg-test-mapping -> utunX)
	// On Linux/FreeBSD/OpenBSD, they should be the same
	if wgInterfaceName == "" {
		t.Error("GetWireGuardInterfaceName returned empty string")
	}

	// Test that ConfigureWireGuard method exists and has correct signature
	// This is just a compilation test - we won't actually configure anything
	cfg := &config.Config{}
	err := platformMgr.ConfigureWireGuard(testInterfaceName, cfg, cmdRunner)
	if err == nil {
		t.Log("ConfigureWireGuard method is available (expected to fail without actual interface)")
	} else {
		t.Logf("ConfigureWireGuard failed as expected: %v", err)
	}
}

// TestPlatformMethodsExist verifies that all required platform methods are implemented
func TestPlatformMethodsExist(t *testing.T) {
	logger := &logger.DefaultLogger{}
	cmdRunner := runner.NewDefaultCommandRunner(logger)

	platformMgr := platform.NewPlatformManager(logger)
	platformMgr.SetCommandRunner(cmdRunner)

	// Test that all required methods exist
	testInterfaceName := "test-interface"

	// Test GetWireGuardInterfaceName
	wgName := platformMgr.GetWireGuardInterfaceName(testInterfaceName)
	if wgName == "" {
		t.Error("GetWireGuardInterfaceName returned empty string")
	}

	// Test ConfigureWireGuard (should not panic)
	cfg := &config.Config{}
	_ = platformMgr.ConfigureWireGuard(testInterfaceName, cfg, cmdRunner)

	t.Log("All platform methods are available")
}
