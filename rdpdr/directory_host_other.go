//go:build !windows && !linux && !darwin

package rdpdr

import "os"

func directoryOpenFlags() int                                { return 0 }
func directoryVolume(string, *os.File) (int64, int64, error) { return 0, 0, ErrUnsupported }
