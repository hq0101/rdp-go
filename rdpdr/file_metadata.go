package rdpdr

import (
	"encoding/binary"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	FileDirectoryInformation     = 1
	FileFullDirectoryInformation = 2
	FileBothDirectoryInformation = 3
	FileNamesInformation         = 12
	FileFsVolumeInformation      = 1
	FileFsSizeInformation        = 3
	FileFsDeviceInformation      = 4
	FileFsAttributeInformation   = 5
	FileFsFullSizeInformation    = 7
	MaxFileEntries               = 4096 // implementation budget per encoded batch
)

// DirectoryEntry is metadata supplied by a backend. Names are protocol text,
// never authorized local paths. Allocation granularity, attributes, EA/reparse
// tags and short-name generation remain the backend's responsibility.
type DirectoryEntry struct {
	FileIndex                 uint32
	Basic                     BasicInformation
	EndOfFile, AllocationSize int64
	EaSize                    uint32
	Name, ShortName           string
}

// EncodeDirectoryInformation encodes a complete batch in one of the four
// MS-RDPEFS directory classes. All classes align subsequent entries to 8 bytes.
// FileBothDirectoryInformation omits FSCC's reserved byte: its name begins at
// byte 93, not 94. No trailing alignment bytes follow the final entry.
// Empty input returns empty data; the caller chooses STATUS_NO_MORE_FILES.
// On error no partial batch is returned; do not advance an enumeration cursor.
func EncodeDirectoryInformation(class uint32, entries []DirectoryEntry) ([]byte, error) {
	fixed := 0
	switch class {
	case FileDirectoryInformation:
		fixed = 64
	case FileFullDirectoryInformation:
		fixed = 68
	case FileBothDirectoryInformation:
		fixed = 93
	case FileNamesInformation:
		fixed = 12
	default:
		return nil, ErrFileOperation
	}
	if len(entries) > MaxFileEntries {
		return nil, ErrLimit
	}
	var out []byte
	for i, e := range entries {
		name, err := encodeMetadataText(e.Name, MaxFilePathUnits, false)
		if err != nil {
			return nil, err
		}
		n := fixed + len(name)
		if i+1 < len(entries) {
			n = (n + 7) &^ 7
		}
		if n > MaxFileData-len(out) {
			return nil, ErrLimit
		}
		start := len(out)
		out = append(out, make([]byte, n)...)
		b := out[start:]
		if i+1 < len(entries) {
			binary.LittleEndian.PutUint32(b, uint32(n))
		}
		binary.LittleEndian.PutUint32(b[4:], e.FileIndex)
		if class == FileNamesInformation {
			binary.LittleEndian.PutUint32(b[8:], uint32(len(name)))
		} else {
			basic, err := EncodeBasicInformation(e.Basic)
			if err != nil {
				return nil, err
			}
			if e.EndOfFile < 0 || e.AllocationSize < 0 {
				return nil, ErrProtocol
			}
			copy(b[8:40], basic[:32])
			binary.LittleEndian.PutUint64(b[40:], uint64(e.EndOfFile))
			binary.LittleEndian.PutUint64(b[48:], uint64(e.AllocationSize))
			binary.LittleEndian.PutUint32(b[56:], e.Basic.Attributes)
			binary.LittleEndian.PutUint32(b[60:], uint32(len(name)))
			if class != FileDirectoryInformation {
				binary.LittleEndian.PutUint32(b[64:], e.EaSize)
			}
			if class == FileBothDirectoryInformation {
				short, err := encodeMetadataText(e.ShortName, 12, true)
				if err != nil {
					return nil, err
				}
				b[68] = byte(len(short))
				copy(b[69:93], short)
			}
		}
		copy(b[fixed:], name)
	}
	return out, nil
}

type NotificationEntry struct {
	Action uint32 // MS-FSCC FILE_ACTION_* values 1..11
	Name   string // name relative to the watched directory; not NUL terminated
}

// EncodeNotifyInformation encodes a complete notification batch, padding every
// entry (including the last) to 4 bytes. Rename old/new actions 4/5 must be
// adjacent pairs; overflow should instead complete with STATUS_NOTIFY_ENUM_DIR
// and empty data. This encoder does not create a filesystem watcher.
func EncodeNotifyInformation(entries []NotificationEntry) ([]byte, error) {
	if len(entries) > MaxFileEntries {
		return nil, ErrLimit
	}
	var out []byte
	for i, e := range entries {
		if e.Action < 1 || e.Action > 11 {
			return nil, ErrProtocol
		}
		if e.Action == 4 && (i+1 == len(entries) || entries[i+1].Action != 5) ||
			e.Action == 5 && (i == 0 || entries[i-1].Action != 4) {
			return nil, ErrProtocol
		}
		name, err := encodeMetadataText(e.Name, MaxFilePathUnits, false)
		if err != nil {
			return nil, err
		}
		n := (12 + len(name) + 3) &^ 3
		if n > MaxFileData-len(out) {
			return nil, ErrLimit
		}
		start := len(out)
		out = append(out, make([]byte, n)...)
		b := out[start:]
		if i+1 < len(entries) {
			binary.LittleEndian.PutUint32(b, uint32(n))
		}
		binary.LittleEndian.PutUint32(b[4:], e.Action)
		binary.LittleEndian.PutUint32(b[8:], uint32(len(name)))
		copy(b[12:], name)
	}
	return out, nil
}

type VolumeInformation struct {
	CreationTime    int64
	SerialNumber    uint32
	SupportsObjects bool
	// Supply a label already reduced to at most 32 UTF-16 units by the backend.
	// This helper rejects oversized labels instead of silently splitting text.
	Label string
}

// EncodeVolumeInformation uses RDPEFS's 17-byte prefix, omitting the FSCC
// reserved byte. The counted label is emitted without a NUL terminator.
func EncodeVolumeInformation(v VolumeInformation) ([]byte, error) {
	if v.CreationTime < 0 {
		return nil, ErrProtocol
	}
	label, err := encodeMetadataText(v.Label, 32, true)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 17, 17+len(label))
	binary.LittleEndian.PutUint64(b, uint64(v.CreationTime))
	binary.LittleEndian.PutUint32(b[8:], v.SerialNumber)
	binary.LittleEndian.PutUint32(b[12:], uint32(len(label)))
	if v.SupportsObjects {
		b[16] = 1
	}
	return append(b, label...), nil
}

type VolumeSizeInformation struct {
	TotalAllocationUnits, AvailableAllocationUnits int64
	SectorsPerAllocationUnit, BytesPerSector       uint32
}

func EncodeVolumeSizeInformation(v VolumeSizeInformation) ([]byte, error) {
	if v.TotalAllocationUnits < 0 || v.AvailableAllocationUnits < 0 || v.SectorsPerAllocationUnit == 0 || v.BytesPerSector == 0 {
		return nil, ErrProtocol
	}
	b := binary.LittleEndian.AppendUint64(nil, uint64(v.TotalAllocationUnits))
	b = binary.LittleEndian.AppendUint64(b, uint64(v.AvailableAllocationUnits))
	b = binary.LittleEndian.AppendUint32(b, v.SectorsPerAllocationUnit)
	return binary.LittleEndian.AppendUint32(b, v.BytesPerSector), nil
}

type VolumeFullSizeInformation struct {
	TotalAllocationUnits, CallerAvailableAllocationUnits, ActualAvailableAllocationUnits int64
	SectorsPerAllocationUnit, BytesPerSector                                             uint32
}

// Actual free units may exceed the caller's total when quotas apply.
func EncodeVolumeFullSizeInformation(v VolumeFullSizeInformation) ([]byte, error) {
	if v.TotalAllocationUnits < 0 || v.CallerAvailableAllocationUnits < 0 || v.ActualAvailableAllocationUnits < 0 || v.SectorsPerAllocationUnit == 0 || v.BytesPerSector == 0 {
		return nil, ErrProtocol
	}
	b := binary.LittleEndian.AppendUint64(nil, uint64(v.TotalAllocationUnits))
	b = binary.LittleEndian.AppendUint64(b, uint64(v.CallerAvailableAllocationUnits))
	b = binary.LittleEndian.AppendUint64(b, uint64(v.ActualAvailableAllocationUnits))
	b = binary.LittleEndian.AppendUint32(b, v.SectorsPerAllocationUnit)
	return binary.LittleEndian.AppendUint32(b, v.BytesPerSector), nil
}

func EncodeVolumeDeviceInformation(deviceType, characteristics uint32) ([]byte, error) {
	if deviceType != 2 && deviceType != 7 {
		return nil, ErrProtocol
	}
	b := binary.LittleEndian.AppendUint32(nil, deviceType)
	return binary.LittleEndian.AppendUint32(b, characteristics), nil
}

type VolumeAttributeInformation struct {
	Attributes             uint32
	MaximumComponentLength int32
	FileSystemName         string
}

func EncodeVolumeAttributeInformation(v VolumeAttributeInformation) ([]byte, error) {
	if v.MaximumComponentLength < 1 || v.MaximumComponentLength > 255 || v.Attributes&0x8010 == 0x8010 {
		return nil, ErrProtocol
	}
	name, err := encodeMetadataText(v.FileSystemName, MaxFilePathUnits, false)
	if err != nil {
		return nil, err
	}
	b := binary.LittleEndian.AppendUint32(nil, v.Attributes)
	b = binary.LittleEndian.AppendUint32(b, uint32(v.MaximumComponentLength))
	b = binary.LittleEndian.AppendUint32(b, uint32(len(name)))
	return append(b, name...), nil
}

// Count before allocating; invalid UTF-8 must not silently become U+FFFD.
func encodeMetadataText(s string, maxUnits int, empty bool) ([]byte, error) {
	// A valid UTF-8 string uses at most three bytes per UTF-16 code unit.
	if len(s) > maxUnits*3 {
		return nil, ErrLimit
	}
	if s == "" && !empty || !utf8.ValidString(s) {
		return nil, ErrProtocol
	}
	n := 0
	for _, r := range s {
		if r == 0 {
			return nil, ErrProtocol
		}
		n++
		if r > 0xffff {
			n++
		}
		if n > maxUnits {
			return nil, ErrLimit
		}
	}
	b := make([]byte, 0, n*2)
	for _, r := range s {
		if r > 0xffff {
			a, z := utf16.EncodeRune(r)
			b = binary.LittleEndian.AppendUint16(b, uint16(a))
			b = binary.LittleEndian.AppendUint16(b, uint16(z))
		} else {
			b = binary.LittleEndian.AppendUint16(b, uint16(r))
		}
	}
	return b, nil
}
