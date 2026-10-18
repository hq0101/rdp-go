//go:build !windows && !linux && !darwin

package rdpdr

import "os"

// An append-only open already uses O_APPEND. General writable handles need a
// platform-specific atomic EOF write; do not approximate it by seeking first.
func directoryAppend(*os.File, []byte) (int, error) {
	return 0, ErrUnsupported
}
