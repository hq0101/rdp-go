package rdpdr

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

const (
	MajorCreate           = 0x00
	MajorClose            = 0x02
	MajorRead             = 0x03
	MajorWrite            = 0x04
	MajorQueryInformation = 0x05
	MajorSetInformation   = 0x06
	MajorQueryVolume      = 0x0a
	MajorSetVolume        = 0x0b
	MajorDirectoryControl = 0x0c
	MajorDeviceControl    = 0x0e
	MajorLockControl      = 0x11
	MinorQueryDirectory   = 0x01
	MinorNotifyDirectory  = 0x02

	// Implementation budgets, not protocol limits. Read/output length fields
	// are preserved without allocation; actual responses are bounded separately.
	MaxFileData      = 1 << 20
	MaxFilePathUnits = 32767
	MaxFileLocks     = 4096
)

var ErrFileOperation = errors.New("rdpdr: unsupported file operation or information class")

type CreateRequest struct {
	DesiredAccess                                  uint32
	AllocationSize                                 uint64
	Attributes, SharedAccess, Disposition, Options uint32
	// Path is untrusted protocol text, not an authorized host filesystem path.
	// Empty is the root request used by Windows and the MS-RDPEFS 4.12 example.
	Path string
}
type ReadRequest struct {
	Length uint32
	Offset uint64
}
type WriteRequest struct {
	// Append means minor 13 interpreted the all-ones Offset as EOF. A backend
	// must select EOF with the write, not use a separate Stat/Seek then Write.
	// Offset is still preserved exactly. Minor 12 never sets Append.
	Append bool
	Offset uint64
	Data   []byte
}
type ControlRequest struct {
	OutputLength, Code uint32
	Input              []byte
}
type InformationRequest struct {
	Class uint32
	// Buffer is the exact query/set input, not a requested output capacity.
	// Query classes/selector semantics and backend support must be checked by
	// the caller. DecodeSetInformation/DecodeVolumeLabel parse known setters.
	Buffer []byte
}
type DirectoryRequest struct {
	Class   uint32
	Initial bool
	Path    string
}
type NotifyRequest struct {
	WatchTree bool
	Filter    uint32
}
type LockRegion struct{ Length, Offset uint64 }
type LockRequest struct {
	// Operation 2=shared, 3=exclusive, 4=unlock, 5=unlock multiple. Unknown
	// operations are preserved so the backend can fail the request explicitly.
	Operation uint32
	// Wait preserves the F bit as specified (set means wait). A backend may
	// explicitly select the observed Windows fail-immediately compatibility.
	Wait    bool
	Regions []LockRegion
}

// FileRequest is an owned decoded message. Exactly the pointer selected by
// Header is set; Close has none. It validates framing, not access masks, path
// confinement, FileID ownership, offset arithmetic or backend support. Never
// pass its Path directly to os.Open. No normalization or path cleaning occurs.
type FileRequest struct {
	Header      IOHeader
	Create      *CreateRequest
	Read        *ReadRequest
	Write       *WriteRequest
	Control     *ControlRequest
	Information *InformationRequest
	Directory   *DirectoryRequest
	Notify      *NotifyRequest
	Lock        *LockRequest
}

// DecodeFile returns a separate owned interpretation of the immutable request.
// Decoding a stale token is allowed; only DriveClient.CompleteFile consumes it.
func (r Request) DecodeFile() (FileRequest, error) {
	if r.entry == nil {
		return FileRequest{}, ErrRequest
	}
	return DecodeFileRequestVersion(r.entry.header, r.entry.body, r.entry.minor)
}

// DecodeFileRequest accepts the 24-byte header's fields and the remaining body.
// It uses minor version 12; use DecodeFileRequestVersion for negotiated minor 13.
// Reserved padding is ignored. Unknown major/minor functions return
// ErrFileOperation; unknown information classes remain available to the backend.
func DecodeFileRequest(h IOHeader, b []byte) (FileRequest, error) {
	return DecodeFileRequestVersion(h, b, 12)
}

// DecodeFileRequestVersion preserves framing and interprets version-dependent
// semantics. Minor must be 12 or 13 (zero selects 12), as advertised by the client.
func DecodeFileRequestVersion(h IOHeader, b []byte, minor uint16) (FileRequest, error) {
	if minor != 0 && minor != 12 && minor != 13 {
		return FileRequest{}, ErrUnsupported
	}
	var zero FileRequest
	if len(b) > MaxDeviceMessage-24 {
		return zero, ErrLimit
	}
	// MinorFunction is meaningful only for DIRECTORY_CONTROL (2.2.1.4).
	// Other operations SHOULD send zero, but it is not a required value.
	r := FileRequest{Header: h}
	switch h.MajorFunction {
	case MajorCreate:
		if len(b) < 32 || uint64(binary.LittleEndian.Uint32(b[28:])) != uint64(len(b)-32) {
			return zero, ErrProtocol
		}
		path, err := decodeFileText(b[32:], true, true)
		if err != nil {
			return zero, err
		}
		r.Create = &CreateRequest{DesiredAccess: binary.LittleEndian.Uint32(b), AllocationSize: binary.LittleEndian.Uint64(b[4:]), Attributes: binary.LittleEndian.Uint32(b[12:]), SharedAccess: binary.LittleEndian.Uint32(b[16:]), Disposition: binary.LittleEndian.Uint32(b[20:]), Options: binary.LittleEndian.Uint32(b[24:]), Path: path}
	case MajorClose:
		if len(b) != 32 {
			return zero, ErrProtocol
		}
	case MajorRead:
		if len(b) != 32 {
			return zero, ErrProtocol
		}
		r.Read = &ReadRequest{Length: binary.LittleEndian.Uint32(b), Offset: binary.LittleEndian.Uint64(b[4:])}
	case MajorWrite:
		if len(b) < 32 || uint64(binary.LittleEndian.Uint32(b)) != uint64(len(b)-32) {
			return zero, ErrProtocol
		}
		if len(b)-32 > MaxFileData {
			return zero, ErrLimit
		}
		offset := binary.LittleEndian.Uint64(b[4:])
		r.Write = &WriteRequest{Append: minor == 13 && offset == ^uint64(0), Offset: offset, Data: append([]byte(nil), b[32:]...)}
	case MajorDeviceControl:
		if len(b) < 32 || uint64(binary.LittleEndian.Uint32(b[4:])) != uint64(len(b)-32) {
			return zero, ErrProtocol
		}
		r.Control = &ControlRequest{OutputLength: binary.LittleEndian.Uint32(b), Code: binary.LittleEndian.Uint32(b[8:]), Input: append([]byte(nil), b[32:]...)}
	case MajorQueryInformation, MajorSetInformation, MajorQueryVolume, MajorSetVolume:
		if len(b) < 32 || uint64(binary.LittleEndian.Uint32(b[4:])) != uint64(len(b)-32) {
			return zero, ErrProtocol
		}
		r.Information = &InformationRequest{Class: binary.LittleEndian.Uint32(b), Buffer: append([]byte(nil), b[32:]...)}
	case MajorDirectoryControl:
		switch h.MinorFunction {
		case MinorQueryDirectory:
			if len(b) < 32 {
				return zero, ErrProtocol
			}
			q := &DirectoryRequest{Class: binary.LittleEndian.Uint32(b), Initial: b[4] != 0}
			if q.Initial {
				if uint64(binary.LittleEndian.Uint32(b[5:])) != uint64(len(b)-32) {
					return zero, ErrProtocol
				}
				path, err := decodeFileText(b[32:], true, false)
				if err != nil {
					return zero, err
				}
				q.Path = path
			}
			// For continuation queries the spec says to ignore Path contents
			// irrespective of PathLength. The outer message remains bounded.
			r.Directory = q
		case MinorNotifyDirectory:
			if len(b) != 32 {
				return zero, ErrProtocol
			}
			r.Notify = &NotifyRequest{WatchTree: b[0] != 0, Filter: binary.LittleEndian.Uint32(b[1:])}
		default:
			return zero, ErrFileOperation
		}
	case MajorLockControl:
		if len(b) < 32 {
			return zero, ErrProtocol
		}
		n := binary.LittleEndian.Uint32(b[8:])
		if n == 0 || uint64(n)*16 != uint64(len(b)-32) {
			return zero, ErrProtocol
		}
		if n > MaxFileLocks {
			return zero, ErrLimit
		}
		q := &LockRequest{Operation: binary.LittleEndian.Uint32(b), Wait: b[4]&1 != 0, Regions: make([]LockRegion, int(n))}
		for i := range q.Regions {
			p := b[32+i*16:]
			q.Regions[i] = LockRegion{Length: binary.LittleEndian.Uint64(p), Offset: binary.LittleEndian.Uint64(p[8:])}
		}
		r.Lock = q
	default:
		return zero, ErrFileOperation
	}
	return r, nil
}

// decodeFileText rejects invalid UTF-16 and embedded NULs instead of replacing
// them with U+FFFD or silently aliasing a name. It does not enforce path policy.
func decodeFileText(b []byte, terminated, emptyRoot bool) (string, error) {
	if len(b) == 0 && emptyRoot {
		return "", nil
	}
	if len(b)%2 != 0 {
		return "", ErrProtocol
	}
	if len(b)/2 > MaxFilePathUnits+1 {
		return "", ErrLimit
	}
	if terminated {
		if len(b) < 2 || binary.LittleEndian.Uint16(b[len(b)-2:]) != 0 {
			return "", ErrProtocol
		}
		b = b[:len(b)-2]
	}
	if len(b)/2 > MaxFilePathUnits {
		return "", ErrLimit
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[i*2:])
	}
	for i := 0; i < len(u); i++ {
		if u[i] == 0 {
			return "", ErrProtocol
		}
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 >= len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return "", ErrProtocol
			}
			i++
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			return "", ErrProtocol
		}
	}
	return string(utf16.Decode(u)), nil
}

const (
	FileBasicInformation        = 4
	FileStandardInformation     = 5
	FileRenameInformation       = 10
	FileDispositionInformation  = 13
	FileAllocationInformation   = 19
	FileEndOfFileInformation    = 20
	FileAttributeTagInformation = 35
)

// BasicInformation preserves Windows 100ns timestamps, including the -1/-2
// setter sentinels. Their effects on future operations belong to the backend.
type BasicInformation struct {
	CreationTime, LastAccessTime, LastWriteTime, ChangeTime int64
	Attributes                                              uint32
}
type RenameInformation struct {
	Replace bool
	Name    string
}
type SetInformation struct {
	Class         uint32
	Basic         *BasicInformation
	Rename        *RenameInformation
	Size          int64
	DeletePending bool
}

// DecodeSetInformation handles RDPEFS's setter layouts, including its compact
// rename and implicit delete. It does not rename, truncate or delete anything.
func DecodeSetInformation(class uint32, b []byte) (SetInformation, error) {
	r := SetInformation{Class: class}
	var zero SetInformation
	if len(b) > MaxDeviceMessage-56 {
		return zero, ErrLimit
	}
	switch class {
	case FileBasicInformation:
		// The RDPEFS 4.28 example uses 36 bytes. Also accept the FSCC reserved
		// tail when present in setters; query responses must omit that tail.
		if len(b) != 36 && len(b) != 40 {
			return zero, ErrProtocol
		}
		r.Basic = &BasicInformation{int64(binary.LittleEndian.Uint64(b)), int64(binary.LittleEndian.Uint64(b[8:])), int64(binary.LittleEndian.Uint64(b[16:])), int64(binary.LittleEndian.Uint64(b[24:])), binary.LittleEndian.Uint32(b[32:])}
	case FileRenameInformation:
		if len(b) < 6 || b[1] != 0 || uint64(binary.LittleEndian.Uint32(b[2:])) != uint64(len(b)-6) {
			return zero, ErrProtocol
		}
		// Windows 10 sends a single NUL included in FileNameLength. Accept
		// this observed RDPEFS form as well as the counted nonterminated form.
		// Exact length, embedded NUL and UTF-16 checks remain unchanged.
		terminated := len(b) >= 8 && binary.LittleEndian.Uint16(b[len(b)-2:]) == 0
		name, err := decodeFileText(b[6:], terminated, false)
		if err != nil {
			return zero, err
		}
		if name == "" {
			return zero, ErrProtocol
		}
		r.Rename = &RenameInformation{Replace: b[0] != 0, Name: name}
	case FileDispositionInformation:
		if len(b) != 0 {
			return zero, ErrProtocol
		}
		r.DeletePending = true
	case FileAllocationInformation, FileEndOfFileInformation:
		if len(b) != 8 {
			return zero, ErrProtocol
		}
		r.Size = int64(binary.LittleEndian.Uint64(b))
	default:
		return zero, ErrFileOperation
	}
	// Signed values are preserved; a backend must reject invalid times/sizes
	// using an operation failure rather than silently casting to unsigned.
	return r, nil
}

// DecodeVolumeLabel decodes FileFsLabelInformation (class 2). Its counted UTF-16
// name has no terminator; setting a label still requires explicit backend policy.
func DecodeVolumeLabel(b []byte) (string, error) {
	if len(b) < 4 || uint64(binary.LittleEndian.Uint32(b)) != uint64(len(b)-4) {
		return "", ErrProtocol
	}
	return decodeFileText(b[4:], false, false)
}
