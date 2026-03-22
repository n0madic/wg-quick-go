//go:build windows

package wireguard

func setUmask(_ int) (oldMask int) {
	// Windows does not support umask; file permissions are set via OpenFile mode.
	return 0
}
