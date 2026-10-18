//go:build !windows

package rdpdr

import "os"

func directoryNamespaceAvailable() bool                   { return false }
func directoryRequestedFlags(uint32) int                  { return directoryOpenFlags() }
func directoryPrepareIdentity(*directoryFile) uint32      { return StatusNotSupported }
func directoryMarkDelete(*directoryFile) uint32           { return StatusNotSupported }
func directoryPrepareDeleteOnClose(*directoryFile) uint32 { return StatusNotSupported }
func (d *DirectoryDrive) openNativeWritable(string, *CreateRequest, uint32) (*os.File, bool, uint32, func() error) {
	return nil, false, StatusNotSupported, nil
}
func (d *DirectoryDrive) renameNamespace(*directoryFile, string, bool) (uint32, error) {
	return StatusNotSupported, nil
}

func (d *DirectoryDrive) refreshNamespacePaths() {}

func (d *DirectoryDrive) openNoRecall(string, *CreateRequest, uint32) (*os.File, bool, uint32, func() error) {
	return nil, false, StatusNotSupported, nil
}

func directoryOverwrite(f *directoryFile, _ *CreateRequest) uint32 {
	return directoryStatus(f.ioFile().Truncate(0))
}
