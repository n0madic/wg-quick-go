package test

import (
	"github.com/n0madic/wg-quick-go/pkg/logger"
	"github.com/n0madic/wg-quick-go/pkg/utils"
	"strings"
	"testing"
)

// MockCommandRunner captures commands instead of executing them
type MockCommandRunner struct {
	Commands []string
	Inputs   []string // Captured stdin inputs for RunWithInput calls
	logger   logger.Logger
}

func NewMockCommandRunner(logger logger.Logger) *MockCommandRunner {
	return &MockCommandRunner{
		Commands: make([]string, 0),
		Inputs:   make([]string, 0),
		logger:   logger,
	}
}

func (m *MockCommandRunner) Run(name string, args ...string) error {
	command := name + " " + strings.Join(args, " ")
	m.Commands = append(m.Commands, command)
	m.logger.Command(name, args...)
	return nil
}

func (m *MockCommandRunner) RunWithOutput(name string, args ...string) ([]byte, error) {
	command := name + " " + strings.Join(args, " ")
	m.Commands = append(m.Commands, command)
	m.logger.Command(name, args...)
	return []byte(""), nil
}

func (m *MockCommandRunner) RunWithInput(input string, name string, args ...string) error {
	command := name + " " + strings.Join(args, " ")
	m.Commands = append(m.Commands, command)
	m.Inputs = append(m.Inputs, input)
	m.logger.Command(name, args...)
	return nil
}

// TestWireGuardCommandGeneration tests that ConfigureWireGuardAddconf generates
// the correct `wg addconf <iface> /dev/stdin` command with raw config piped via
// stdin, matching the original bash behavior.
func TestWireGuardCommandGeneration(t *testing.T) {
	logger := &logger.DefaultLogger{}
	mockRunner := NewMockCommandRunner(logger)

	rawWGConfig := "[Interface]\nPrivateKey = test-private-key\nListenPort = 8001\n\n[Peer]\nPublicKey = test-public-key\nEndpoint = 127.0.0.1:8002\nAllowedIPs = 172.16.11.0/24\n"
	testInterfaceName := "wg-test-cmd"

	// Test ConfigureWireGuardAddconf directly — this is the shared function
	// all platforms use (darwin resolves utun first, then calls this)
	err := utils.ConfigureWireGuardAddconf(testInterfaceName, rawWGConfig, mockRunner)
	if err != nil {
		t.Fatalf("ConfigureWireGuardAddconf failed: %v", err)
	}

	// Check generated commands
	t.Logf("Generated commands:")
	for i, cmd := range mockRunner.Commands {
		t.Logf("  [%d] %s", i+1, cmd)
	}

	// Verify that WireGuard commands use `wg addconf` (not `wg set`)
	var wgAddconfCommand string
	for _, cmd := range mockRunner.Commands {
		if strings.HasPrefix(cmd, "wg addconf") {
			wgAddconfCommand = cmd
			break
		}
	}

	if wgAddconfCommand == "" {
		t.Error("No 'wg addconf' command found — expected wg addconf")
	} else {
		t.Logf("Found wg addconf command: %s", wgAddconfCommand)

		// Verify the command includes /dev/stdin for piped input
		if !strings.Contains(wgAddconfCommand, "/dev/stdin") {
			t.Errorf("wg addconf should use /dev/stdin, got: %s", wgAddconfCommand)
		}

		// Verify interface name is in the command
		if !strings.Contains(wgAddconfCommand, testInterfaceName) {
			t.Errorf("wg addconf should reference interface %s, got: %s", testInterfaceName, wgAddconfCommand)
		}
	}

	// Verify no `wg set` commands were generated (old behavior)
	for _, cmd := range mockRunner.Commands {
		if strings.HasPrefix(cmd, "wg set") {
			t.Errorf("Found unexpected 'wg set' command (should use wg addconf): %s", cmd)
		}
	}

	// Verify stdin input contains the raw WireGuard config
	if len(mockRunner.Inputs) == 0 {
		t.Fatal("No stdin input captured — raw config should be piped via stdin")
	}

	lastInput := mockRunner.Inputs[len(mockRunner.Inputs)-1]
	if !strings.Contains(lastInput, "PrivateKey") {
		t.Errorf("Expected raw WG config in stdin, got: %s", lastInput)
	}
	if !strings.Contains(lastInput, "test-public-key") {
		t.Errorf("Expected peer public key in stdin, got: %s", lastInput)
	}
	t.Logf("Raw config passed via stdin (%d bytes)", len(lastInput))
}
