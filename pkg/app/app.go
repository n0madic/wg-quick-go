package app

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/n0madic/wg-quick-go/pkg/logger"
	"github.com/n0madic/wg-quick-go/pkg/wireguard"
)

func printUsage() {
	fmt.Fprintf(os.Stderr, `Usage: %s [ up | down | save | strip ] [ CONFIG_FILE | INTERFACE ]

  CONFIG_FILE is a configuration file, whose filename is the interface name
  followed by '.conf'. Otherwise, INTERFACE is an interface name, with
  configuration found at /etc/wireguard/INTERFACE.conf.

  Commands:
    up    - bring up the WireGuard interface
    down  - bring down the WireGuard interface
    save  - save current interface configuration
    strip - output stripped configuration suitable for wg(8)

See wg-quick(8) for more info and examples.
`, os.Args[0])
}

// wgUserspaceEnvVar is the environment variable for custom WireGuard userspace implementation.
const wgUserspaceEnvVar = "WG_QUICK_USERSPACE_IMPLEMENTATION"

// autoSu re-executes the program with elevated privileges if not already root.
// Matches original bash: auto_su() { [[ $UID == 0 ]] || exec sudo ... }
// On OpenBSD uses doas; on other platforms uses sudo.
// Unlike -E (which preserves all env vars), only WG_QUICK_USERSPACE_IMPLEMENTATION
// is selectively forwarded when set, matching the original bash behavior.
func autoSu(args []string) {
	if os.Getuid() == 0 {
		return
	}

	// Determine escalation command based on platform
	var sudoCmd string
	if runtime.GOOS == "openbsd" {
		sudoCmd = "doas"
	} else {
		sudoCmd = "sudo"
	}

	sudoPath, err := exec.LookPath(sudoCmd)
	if err != nil {
		// Cannot find sudo/doas — fall through, CheckRequirements will report the error
		return
	}

	var newArgs []string
	if runtime.GOOS == "openbsd" {
		// doas doesn't support -p, just re-exec directly
		newArgs = append([]string{sudoCmd, "--"}, args...)
	} else {
		// Matching original bash: sudo -p "prompt" -- [env VAR=val] command args...
		newArgs = []string{
			sudoCmd,
			"-p", fmt.Sprintf("%s must be run as root. Please enter the password for %%u to continue: ", args[0]),
			"--",
		}
		// Selectively preserve WG_QUICK_USERSPACE_IMPLEMENTATION through sudo
		// (original bash doesn't use -E; we forward only the WireGuard-relevant var)
		if val, ok := os.LookupEnv(wgUserspaceEnvVar); ok {
			newArgs = append(newArgs, "env", wgUserspaceEnvVar+"="+val)
		}
		newArgs = append(newArgs, args...)
	}

	// Replace the current process (like original bash: exec sudo ...)
	// If Exec fails, fall through and let CheckRequirements report the error.
	syscall.Exec(sudoPath, newArgs, os.Environ()) //nolint:errcheck
}

// Run is the main entrypoint for the wg-quick-go application.
func Run(ctx context.Context, args []string) error {
	if len(args) >= 2 {
		switch args[1] {
		case "help", "--help", "-h":
			printUsage()
			return nil
		}
	}

	if len(args) < 3 {
		printUsage()
		return fmt.Errorf("not enough arguments")
	}

	command := args[1]
	configFile := args[2]

	// Auto-escalate to root for commands that need it (matching original bash auto_su)
	switch command {
	case "up", "down", "save", "strip":
		autoSu(args)
	}

	log := &logger.DefaultLogger{}
	manager := wireguard.NewManager("", log, nil)

	// Use different parsing methods based on command
	switch command {
	case "up":
		if err := manager.ParseConfig(configFile); err != nil {
			return fmt.Errorf("error parsing config: %w", err)
		}
		return manager.Up(ctx)
	case "down":
		// For down operation, skip address conflict validation
		if err := manager.ParseConfigForDown(configFile); err != nil {
			return fmt.Errorf("error parsing config: %w", err)
		}
		return manager.Down(ctx)
	case "save":
		if err := manager.ParseConfig(configFile); err != nil {
			return fmt.Errorf("error parsing config: %w", err)
		}
		return manager.SaveConfig()
	case "strip":
		// strip only needs config file parsing, no root, no interface validation.
		if err := manager.ParseConfigForDown(configFile); err != nil {
			return fmt.Errorf("error parsing config: %w", err)
		}
		return manager.Strip()
	default:
		printUsage()
		return fmt.Errorf("unknown command: %s", command)
	}
}
