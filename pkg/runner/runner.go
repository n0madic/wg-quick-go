package runner

import (
	"os/exec"
	"strings"

	"github.com/n0madic/wg-quick-go/pkg/logger"
)

// SystemCommandRunner interface for running system commands
type SystemCommandRunner interface {
	Run(name string, args ...string) error
	RunWithOutput(name string, args ...string) ([]byte, error)
	RunWithInput(input string, name string, args ...string) error
}

// DefaultCommandRunner implements SystemCommandRunner
type DefaultCommandRunner struct {
	logger logger.Logger
}

// NewDefaultCommandRunner creates a new command runner
func NewDefaultCommandRunner(logger logger.Logger) *DefaultCommandRunner {
	return &DefaultCommandRunner{logger: logger}
}

// Run executes a command
func (r *DefaultCommandRunner) Run(name string, args ...string) error {
	r.logger.Command(name, args...)
	cmd := exec.Command(name, args...)
	return cmd.Run()
}

// RunWithOutput executes a command and returns output
func (r *DefaultCommandRunner) RunWithOutput(name string, args ...string) ([]byte, error) {
	cmd := exec.Command(name, args...)
	return cmd.Output()
}

// RunWithInput executes a command with stdin input
func (r *DefaultCommandRunner) RunWithInput(input string, name string, args ...string) error {
	r.logger.Command(name, args...)
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(input)
	return cmd.Run()
}
