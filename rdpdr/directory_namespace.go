package rdpdr

import (
	"os"
	"strings"
)

const statusDeletePending uint32 = 0xc0000056

func directorySamePath(a, b string) bool { return strings.EqualFold(a, b) }

func (d *DirectoryDrive) setNamespace(f *directoryFile, set SetInformation) (uint32, FileResult, error) {
	empty := FileResult{}
	if !directoryNamespaceAvailable() {
		return StatusNotSupported, empty, nil
	}
	if f.access&0x10000 == 0 || f.path == "." {
		return StatusAccessDenied, empty, nil
	}
	if f.deletePending {
		return statusDeletePending, empty, nil
	}
	if set.Class == FileDispositionInformation {
		status := directoryMarkDelete(f)
		if status == 0 {
			f.deletePending = true
		}
		return status, empty, nil
	}
	name, err := directoryPath(set.Rename.Name)
	if err != nil || name == "." {
		return StatusAccessDenied, empty, nil
	}
	status, err := d.renameNamespace(f, name, set.Rename.Replace)
	if status == 0 && err == nil {
		old := f.path
		for _, other := range d.files {
			if os.SameFile(other.info, f.info) && directorySamePath(other.path, old) {
				other.path = name
			}
		}
		d.refreshNamespacePaths()

	}
	return status, empty, err
}
