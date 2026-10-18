//go:build linux && !amd64 && !arm64

package rdpdr

import (
	"os"
	"syscall"
)

// Other Linux ABIs still expose queries and normal file I/O. Do not pass a
// 64-bit timespec to a kernel ABI whose time layout has not been implemented.
func directoryMetadataAvailable() bool                       { return false }
func directorySetTimes(*os.File, [4]directoryUnixTime) error { return syscall.ENOTSUP }
