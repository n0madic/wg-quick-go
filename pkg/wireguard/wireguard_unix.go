//go:build !windows

package wireguard

import "syscall"

func setUmask(mask int) (oldMask int) {
	return syscall.Umask(mask)
}
