//go:build !windows && !linux && !darwin

package rdp

import "os"

func fileLicenseSupported() bool              { return false }
func fileLicenseOpenFlags() int               { return 0 }
func lockFileLicense(*os.File) error          { return ErrLicenseStorePlatform }
func unlockFileLicense(*os.File) error        { return ErrLicenseStorePlatform }
func syncFileLicenseDirectory(*os.Root) error { return ErrLicenseStorePlatform }
