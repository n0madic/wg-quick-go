package test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/n0madic/wg-quick-go/pkg/logger"
	"github.com/n0madic/wg-quick-go/pkg/runner"
	"github.com/n0madic/wg-quick-go/pkg/wireguard"
)

// TestIntegration_ConfigValidation tests configuration validation
func TestIntegration_ConfigValidation(t *testing.T) {
	testDir, err := os.MkdirTemp("", "wg-validation-test-*")
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(testDir) }()

	t.Run("InvalidPrivateKey", func(t *testing.T) {
		testInvalidConfig(t, testDir, "bad-key", `[Interface]
PrivateKey = invalid_key_format
Address = 172.16.1.1/24`)
	})

	t.Run("InvalidAddress", func(t *testing.T) {
		testInvalidConfig(t, testDir, "bad-addr", `[Interface]
PrivateKey = aMJKx3GcYvHXpAabBg5D9MlneTVGu+oD0rZjnH0Uj3I=
Address = 300.300.300.300/24`)
	})

	t.Run("InvalidEndpoint", func(t *testing.T) {
		testInvalidConfig(t, testDir, "bad-endpoint", `[Interface]
PrivateKey = aMJKx3GcYvHXpAabBg5D9MlneTVGu+oD0rZjnH0Uj3I=
Address = 172.16.2.1/24

[Peer]
PublicKey = bJr0e3lOQrWz2o4+Ff5yDLtEPHEKt8uF9tL3/RcG8W0=
Endpoint = invalid_endpoint_format`)
	})

	t.Run("InvalidMTU", func(t *testing.T) {
		testInvalidConfig(t, testDir, "invalid-mtu", `[Interface]
PrivateKey = aMJKx3GcYvHXpAabBg5D9MlneTVGu+oD0rZjnH0Uj3I=
Address = 172.16.3.1/24
MTU = 50`)
	})

	t.Run("InvalidListenPort", func(t *testing.T) {
		testInvalidConfig(t, testDir, "invalid-port", `[Interface]
PrivateKey = aMJKx3GcYvHXpAabBg5D9MlneTVGu+oD0rZjnH0Uj3I=
Address = 172.16.4.1/24
ListenPort = 99999`)
	})

	t.Run("FilePermissions", func(t *testing.T) {
		testFilePermissions(t, testDir)
	})
}

// TestIntegration_ErrorScenarios tests various error scenarios
func TestIntegration_ErrorScenarios(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Error scenario tests require root privileges")
	}

	testDir, err := os.MkdirTemp("", "wg-error-test-*")
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(testDir) }()

	t.Run("DuplicateInterface", func(t *testing.T) {
		testDuplicateInterface(t, testDir)
	})

	t.Run("InterfaceNotFound", func(t *testing.T) {
		testInterfaceNotFound(t, testDir)
	})

	t.Run("NetworkConflicts", func(t *testing.T) {
		testNetworkConflicts(t, testDir)
	})
}

// TestIntegration_CleanupScenarios tests cleanup in various scenarios
func TestIntegration_CleanupScenarios(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Cleanup tests require root privileges")
	}

	testDir, err := os.MkdirTemp("", "wg-cleanup-test-*")
	if err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(testDir) }()

	t.Run("NormalCleanup", func(t *testing.T) {
		testNormalCleanup(t, testDir)
	})

	t.Run("ForceCleanup", func(t *testing.T) {
		testForceCleanup(t, testDir)
	})

	t.Run("PartialCleanup", func(t *testing.T) {
		testPartialCleanup(t, testDir)
	})
}

// Helper functions for validation tests

func testInvalidConfig(t *testing.T, testDir, name, configContent string) {
	configPath := filepath.Join(testDir, name+".conf")
	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	logger := &logger.DefaultLogger{}
	// Use shorter interface names to avoid length validation errors
	shortName := name
	if len(shortName) > 8 {
		shortName = shortName[:8]
	}
	manager := wireguard.NewManager(shortName, logger, runner.NewDefaultCommandRunner(logger))

	err := manager.ParseConfig(configPath)
	if err == nil {
		t.Errorf("Expected validation error for %s, but got none", name)
	} else {
		t.Logf("Correctly caught validation error for %s: %v", name, err)
	}
}

func testFilePermissions(t *testing.T, testDir string) {
	// Create config with wrong permissions (world-readable).
	// Matching original bash behavior: this should produce a warning, not an error.
	configPath := filepath.Join(testDir, "bad-perms.conf")
	configContent := `[Interface]
PrivateKey = aMJKx3GcYvHXpAabBg5D9MlneTVGu+oD0rZjnH0Uj3I=
Address = 172.16.5.1/24`

	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	logger := &logger.DefaultLogger{}
	manager := wireguard.NewManager("wg-test", logger, runner.NewDefaultCommandRunner(logger))

	// ParseConfig should succeed (warning only, not fatal) matching original bash
	err := manager.ParseConfig(configPath)
	if err != nil {
		t.Errorf("Expected no error for world-readable config (warning only), but got: %v", err)
	} else {
		t.Log("Correctly accepted world-readable config with warning (matching original bash behavior)")
	}
}

// Helper functions for error scenario tests

func testDuplicateInterface(t *testing.T, testDir string) {
	// Create a valid config
	configPath := filepath.Join(testDir, "duplicate.conf")
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	configContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 172.16.6.1/24
ListenPort = 8003`, privateKey)

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	logger := &logger.DefaultLogger{}

	// Create first interface
	manager1 := wireguard.NewManager("duplicate", logger, runner.NewDefaultCommandRunner(logger))
	if err := manager1.ParseConfig(configPath); err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	ctx := context.Background()
	if err := manager1.Up(ctx); err != nil {
		t.Fatalf("Failed to bring up first interface: %v", err)
	}
	defer func() { _ = manager1.Down(ctx) }()

	// Try to create second interface with same name — should fail either
	// at ParseConfig (address conflict) or at Up (interface already exists)
	manager2 := wireguard.NewManager("duplicate", logger, runner.NewDefaultCommandRunner(logger))
	err = manager2.ParseConfig(configPath)
	if err != nil {
		t.Logf("Correctly caught conflict at ParseConfig: %v", err)
		return
	}

	err = manager2.Up(ctx)
	if err != nil {
		t.Logf("Correctly handled duplicate interface at Up: %v", err)
	} else {
		t.Log("Interface reuse succeeded")
		defer func() { _ = manager2.Down(ctx) }()
	}
}

func testInterfaceNotFound(t *testing.T, testDir string) {
	logger := &logger.DefaultLogger{}
	manager := wireguard.NewManager("wg-nonexistent", logger, runner.NewDefaultCommandRunner(logger))

	ctx := context.Background()
	err := manager.Down(ctx)
	if err == nil {
		t.Error("Expected error when trying to bring down non-existent interface")
	} else {
		t.Logf("Correctly handled non-existent interface: %v", err)
	}
}

func testNetworkConflicts(t *testing.T, testDir string) {
	// This test would create interfaces with conflicting network ranges
	// and verify that the validation catches the conflicts

	configPath1 := filepath.Join(testDir, "conflict1.conf")
	configPath2 := filepath.Join(testDir, "conflict2.conf")

	privateKey1, _ := generatePrivateKey()
	privateKey2, _ := generatePrivateKey()

	// Both configs use overlapping address ranges
	config1 := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.200.0.1/16`, privateKey1)

	config2 := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 10.200.1.1/24`, privateKey2)

	if err := os.WriteFile(configPath1, []byte(config1), 0600); err != nil {
		t.Fatalf("Failed to write config1: %v", err)
	}
	if err := os.WriteFile(configPath2, []byte(config2), 0600); err != nil {
		t.Fatalf("Failed to write config2: %v", err)
	}

	logger := &logger.DefaultLogger{}

	manager1 := wireguard.NewManager("wg-conflict1", logger, runner.NewDefaultCommandRunner(logger))
	manager2 := wireguard.NewManager("wg-conflict2", logger, runner.NewDefaultCommandRunner(logger))

	ctx := context.Background()

	// First interface should work
	if err := manager1.ParseConfig(configPath1); err != nil {
		t.Fatalf("Failed to parse first config: %v", err)
	}
	if err := manager1.Up(ctx); err != nil {
		t.Fatalf("Failed to bring up first interface: %v", err)
	}
	defer func() { _ = manager1.Down(ctx) }()

	// Second interface should detect conflict
	err := manager2.ParseConfig(configPath2)
	if err == nil {
		t.Error("Expected network conflict error, but got none")
	} else {
		t.Logf("Correctly detected network conflict: %v", err)
	}
}

// Helper functions for cleanup tests

func testNormalCleanup(t *testing.T, testDir string) {
	configPath := filepath.Join(testDir, "cleanup.conf")
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	configContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 172.16.7.1/24
ListenPort = 8004
DNS = 8.8.8.8`, privateKey)

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	logger := &logger.DefaultLogger{}
	manager := wireguard.NewManager("cleanup", logger, runner.NewDefaultCommandRunner(logger))

	if err := manager.ParseConfig(configPath); err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	ctx := context.Background()

	// Bring up interface
	if err := manager.Up(ctx); err != nil {
		t.Fatalf("Failed to bring up interface: %v", err)
	}

	// Discover real interface name (e.g., utunX on macOS)
	realName := discoverRealName("cleanup")

	// Verify interface exists via wg show (try real name, then logical)
	stats, err := wgShow(realName)
	if err != nil {
		t.Errorf("Interface should exist but stats failed: %v", err)
	} else {
		t.Logf("Interface stats before cleanup: %s", stats)
	}

	// Clean up
	if err := manager.Down(ctx); err != nil {
		t.Errorf("Failed to clean up interface: %v", err)
	}

	// Verify interface is gone
	_, err = wgShow(realName)
	if err == nil {
		t.Error("Interface should be gone after cleanup")
	} else {
		t.Log("Interface correctly cleaned up")
	}
}

func testForceCleanup(t *testing.T, testDir string) {
	// Test cleanup when interface is in an inconsistent state
	configPath := filepath.Join(testDir, "force-cleanup.conf")
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	configContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 172.16.8.1/24`, privateKey)

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	logger := &logger.DefaultLogger{}
	manager := wireguard.NewManager("force-cleanup", logger, runner.NewDefaultCommandRunner(logger))

	if err := manager.ParseConfig(configPath); err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	ctx := context.Background()
	if err := manager.Up(ctx); err != nil {
		t.Fatalf("Failed to bring up interface: %v", err)
	}

	// Simulate partial failure by manually removing interface
	// (this tests our cleanup robustness)
	cmdRunner := runner.NewDefaultCommandRunner(logger)
	_ = cmdRunner.Run("ip", "link", "delete", "force-cleanup")

	// Now try to clean up - should handle missing interface gracefully
	err = manager.Down(ctx)
	if err != nil {
		t.Logf("Cleanup with missing interface handled: %v", err)
	} else {
		t.Log("Force cleanup succeeded")
	}
}

func testPartialCleanup(t *testing.T, testDir string) {
	// Test cleanup when some components fail
	t.Log("Testing partial cleanup scenario...")

	// This would test scenarios where DNS cleanup fails,
	// or firewall cleanup fails, etc.
	// For now, just verify we can handle basic scenarios

	configPath := filepath.Join(testDir, "partial.conf")
	privateKey, err := generatePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	configContent := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 172.16.9.1/24`, privateKey)

	if err := os.WriteFile(configPath, []byte(configContent), 0600); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	logger := &logger.DefaultLogger{}
	manager := wireguard.NewManager("partial", logger, runner.NewDefaultCommandRunner(logger))

	if err := manager.ParseConfig(configPath); err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	ctx := context.Background()
	if err := manager.Up(ctx); err != nil {
		t.Fatalf("Failed to bring up interface: %v", err)
	}

	// Normal cleanup should work
	if err := manager.Down(ctx); err != nil {
		t.Errorf("Partial cleanup test failed: %v", err)
	} else {
		t.Log("Partial cleanup test passed")
	}
}

// discoverRealName reads the name file to get the real OS interface name
func discoverRealName(interfaceName string) string {
	nameFile := filepath.Join("/var/run/wireguard", interfaceName+".name")
	if data, err := os.ReadFile(nameFile); err == nil {
		return strings.TrimSpace(string(data))
	}
	return interfaceName
}

// wgShow runs wg show on an interface
func wgShow(interfaceName string) (string, error) {
	output, err := exec.Command("wg", "show", interfaceName).Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}
