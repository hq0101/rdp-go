//go:build linux || darwin

package rdpdr

import (
	"os"
	"syscall"
)

// DirectoryDrive owns this open file description and holds its mutex throughout
// the transaction. O_APPEND makes EOF selection part of write, including against
// other independently opened local writers. The filesystem must implement that
// native guarantee (some network filesystems emulate append non-atomically).
// Control pins the descriptor through flag restoration; no pathname is reopened.
func directoryAppend(f *os.File, data []byte) (int, error) {
	var n int
	err := directoryWithFD(f, func(fd uintptr) error {
		var err error
		n, err = directoryAppendFlags(syscall.O_APPEND,
			func() (uintptr, error) { return directoryAppendFcntl(fd, syscall.F_GETFL, 0) },
			func(flags uintptr) error {
				_, err := directoryAppendFcntl(fd, syscall.F_SETFL, flags)
				return err
			},
			func() (int, error) {
				for {
					n, err := syscall.Write(int(fd), data)
					if n <= 0 && err == syscall.EINTR {
						continue // interrupted before transferring data
					}
					return max(n, 0), err // syscall returns -1 on failure
				}
			})
		return err
	})
	return n, err
}

func directoryAppendFcntl(fd, command, arg uintptr) (uintptr, error) {
	for {
		value, _, errno := syscall.Syscall(syscall.SYS_FCNTL, fd, command, arg)
		if errno == syscall.EINTR {
			continue
		}
		if errno != 0 {
			return 0, errno
		}
		return value, nil
	}
}
