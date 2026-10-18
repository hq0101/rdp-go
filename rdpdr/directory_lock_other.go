//go:build !windows

package rdpdr

func directoryLockAvailable() bool                                { return false }
func directoryLockNative(*directoryFile, LockRegion, bool) uint32 { return StatusNotSupported }
func directoryUnlockNative(*directoryFile, LockRegion) uint32     { return StatusNotSupported }
