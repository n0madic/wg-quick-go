package platform

import "github.com/n0madic/wg-quick-go/pkg/logger"

// NewPlatformManager is a factory function that creates a platform-specific
// manager. The actual implementation is chosen at compile time based on build tags.
func NewPlatformManager(logger logger.Logger) PlatformManager {
	return newPlatformManager(logger)
}
