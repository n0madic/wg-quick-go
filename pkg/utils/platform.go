package utils

import (
	"fmt"
	"github.com/n0madic/wg-quick-go/pkg/logger"
	"os"
	"path/filepath"
)

// CheckRootPrivileges verifies that the program is running with root privileges
func CheckRootPrivileges() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("this program must be run as root")
	}
	return nil
}

// CheckRequiredCommands validates that all required system commands are available
func CheckRequiredCommands(commands []string, cmdRunner interface {
	RunWithOutput(command string, args ...string) ([]byte, error)
}) error {
	for _, cmd := range commands {
		if _, err := cmdRunner.RunWithOutput("which", cmd); err != nil {
			return fmt.Errorf("required command '%s' not found", cmd)
		}
	}
	return nil
}

// CheckInterfaceExistsBSD checks if an interface exists using ifconfig (BSD-style)
func CheckInterfaceExistsBSD(interfaceName string, cmdRunner interface {
	Run(command string, args ...string) error
}) bool {
	err := cmdRunner.Run("ifconfig", interfaceName)
	return err == nil
}

// GetInterfaceMTUFromIfconfig gets interface MTU using ifconfig command
func GetInterfaceMTUFromIfconfig(interfaceName string, cmdRunner interface {
	RunWithOutput(command string, args ...string) ([]byte, error)
}) int {
	output, err := cmdRunner.RunWithOutput("ifconfig", interfaceName)
	if err != nil {
		return 0
	}

	if mtu, err := ParseMTUFromOutput(output); err == nil && mtu > 0 {
		return mtu
	}

	return 0
}

// CleanupUserspaceFiles cleans up userspace WireGuard files (socket and name files)
func CleanupUserspaceFiles(interfaceName, socketName string, logger logger.Logger) {
	runDir := "/var/run/wireguard"

	// Clean up socket file - this stops the userspace WireGuard process
	socketFile := filepath.Join(runDir, socketName+".sock")
	if err := os.Remove(socketFile); err != nil && !os.IsNotExist(err) {
		logger.Warning(fmt.Sprintf("Failed to remove socket file %s: %v", socketFile, err))
	} else if err == nil {
		logger.Info(fmt.Sprintf("Removed socket file: %s", socketFile))
	}

	// Clean up interface name file
	nameFile := filepath.Join(runDir, interfaceName+".name")
	if err := os.Remove(nameFile); err != nil && !os.IsNotExist(err) {
		logger.Warning(fmt.Sprintf("Failed to remove name file %s: %v", nameFile, err))
	}
}
