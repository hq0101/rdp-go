package rdpdr

import "os"

// The native identity handle, when present, is also the data handle. Native
// per-open timestamp suppression must affect subsequent reads/writes on the
// same FILE_OBJECT; setting a separate metadata-only open would be ineffective.
func (f *directoryFile) ioFile() *os.File {
	if f.identity != nil {
		return f.identity
	}
	return f.file
}

func (d *DirectoryDrive) setMetadata(f *directoryFile, set SetInformation) (uint32, FileResult, error) {
	empty := FileResult{}
	if !directoryMetadataAvailable() {
		return StatusNotSupported, empty, nil
	}
	if set.Class == FileBasicInformation {
		if f.access&0x100 == 0 {
			return StatusAccessDenied, empty, nil
		}
		b := set.Basic
		if b.CreationTime < -2 || b.LastAccessTime < -2 || b.LastWriteTime < -2 || b.ChangeTime < -2 {
			return StatusInvalidParameter, empty, nil
		}
		// Sparse/compressed/encrypted/reparse and cloud storage state need their
		// own controls, not a fabricated successful basic-attributes mutation.
		if b.Attributes&^uint32(0x31b7) != 0 {
			return StatusNotSupported, empty, nil
		}
		if b.Attributes&0x10 != 0 && !f.info.IsDir() {
			return StatusInvalidParameter, empty, nil
		}
	} else {
		if f.access&2 == 0 {
			return StatusAccessDenied, empty, nil
		}
		if f.info.IsDir() {
			return statusFileIsDirectory, empty, nil
		}
		if set.Size < 0 {
			return StatusInvalidParameter, empty, nil
		}
	}
	status := directorySetMetadata(f, set)
	if status == 0 && set.Class == FileAllocationInformation && f.writeThrough {
		status = directoryStatus(f.ioFile().Sync())
	}
	return status, empty, nil
}
