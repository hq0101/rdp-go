//go:build !windows && !linux && !darwin

package rdpdr

import "io/fs"

func directoryMetadataAvailable() bool           { return false }
func directoryAllocation(info fs.FileInfo) int64 { return directoryFallbackAllocation(info) }
func directoryStandard(_ *directoryFile, info fs.FileInfo) (StandardInformation, uint32) {
	return StandardInformation{EndOfFile: directorySize(info), AllocationSize: directoryAllocation(info), Links: 1, Directory: info.IsDir()}, 0
}

func directoryBasicInfo(info fs.FileInfo) BasicInformation { return directoryFallbackBasic(info) }
func directoryBasicHandle(_ *directoryFile, info fs.FileInfo) (BasicInformation, uint32) {
	return directoryBasicInfo(info), 0
}
func directorySetMetadata(*directoryFile, SetInformation) uint32 { return StatusNotSupported }
