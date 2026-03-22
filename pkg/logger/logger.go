package logger

import (
	"fmt"
	"os"
	"strings"
)

// Logger interface for logging
type Logger interface {
	Command(cmd string, args ...string)
	Info(msg string)
	Warning(msg string)
	Error(msg string)
}

// DefaultLogger simple logger implementation
type DefaultLogger struct{}

func (l DefaultLogger) Command(cmd string, args ...string) {
	fmt.Fprintf(os.Stderr, "[#] %s %s\n", cmd, strings.Join(args, " "))
}

func (l DefaultLogger) Info(msg string) {
	fmt.Fprintf(os.Stderr, "[INFO] %s\n", msg)
}

func (l DefaultLogger) Warning(msg string) {
	fmt.Fprintf(os.Stderr, "[WARNING] %s\n", msg)
}

func (l DefaultLogger) Error(msg string) {
	fmt.Fprintf(os.Stderr, "[ERROR] %s\n", msg)
}
