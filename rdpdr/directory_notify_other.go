//go:build !windows

package rdpdr

func newDirectoryNativeWatch(*directoryFile, NotifyRequest) (directoryNativeWatch, uint32) {
	return nil, StatusNotSupported
}
