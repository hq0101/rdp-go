package rdpdr

import (
	"encoding/binary"
	"errors"
)

const (
	StatusSuccess               uint32 = 0
	StatusPending               uint32 = 0x00000103
	StatusNotifyEnumDir         uint32 = 0x0000010c
	StatusBufferOverflow        uint32 = 0x80000005
	StatusNoMoreFiles           uint32 = 0x80000006
	StatusUnsuccessful          uint32 = 0xc0000001
	StatusInvalidInfoClass      uint32 = 0xc0000003
	StatusInvalidParameter      uint32 = 0xc000000d
	StatusNoSuchFile            uint32 = 0xc000000f
	StatusEndOfFile             uint32 = 0xc0000011
	StatusAccessDenied          uint32 = 0xc0000022
	StatusFileLockConflict      uint32 = 0xc0000054
	StatusLockNotGranted        uint32 = 0xc0000055
	StatusRangeNotLocked        uint32 = 0xc000007e
	StatusInsufficientResources uint32 = 0xc000009a
	StatusNotSupported          uint32 = 0xc00000bb
	StatusCancelled             uint32 = 0xc0000120
)

// FileResult supplies an operation's output, not its wire padding/lengths.
// CREATE uses FileID/Information (0, 1 or 3); WRITE uses Written; READ, queries,
// notifications and control use Data. CLOSE/SET/LOCK require a zero result.
// Query/notify/FSCTL Data must already use the requested FSCC structure; this
// encoder checks its length but does not interpret arbitrary class-specific data.
type FileResult struct {
	FileID      uint32
	Information byte
	Written     uint32
	Data        []byte
}

func (r FileResult) empty() bool {
	return r.FileID == 0 && r.Information == 0 && r.Written == 0 && len(r.Data) == 0
}

func fileResponsePayload(q FileRequest, status uint32, r FileResult) ([]byte, error) {
	if status == StatusPending {
		return nil, ErrProtocol
	}
	if len(r.Data) > MaxFileData {
		return nil, ErrLimit
	}
	// Error replies must not accidentally disclose a caller's previous buffer.
	// Warning statuses (e.g. BUFFER_OVERFLOW) can carry partial output.
	if status>>30 == 3 && len(r.Data) != 0 {
		return nil, ErrProtocol
	}
	var b []byte
	switch q.Header.MajorFunction {
	case MajorCreate:
		if q.Create == nil || r.Written != 0 || len(r.Data) != 0 || (r.Information != 0 && r.Information != 1 && r.Information != 3) {
			return nil, ErrProtocol
		}
		if status != StatusSuccess && (r.FileID != 0 || r.Information != 0) {
			return nil, ErrProtocol
		}
		b = binary.LittleEndian.AppendUint32(nil, r.FileID)
		b = append(b, r.Information)
	case MajorClose:
		if !r.empty() {
			return nil, ErrProtocol
		}
		b = make([]byte, 4)
	case MajorWrite:
		if q.Write == nil || r.FileID != 0 || r.Information != 0 || len(r.Data) != 0 || uint64(r.Written) > uint64(len(q.Write.Data)) {
			return nil, ErrProtocol
		}
		b = binary.LittleEndian.AppendUint32(nil, r.Written)
		b = append(b, 0) // permitted write-response padding
	case MajorSetInformation, MajorSetVolume:
		if q.Information == nil || !r.empty() {
			return nil, ErrProtocol
		}
		if len(q.Information.Buffer) > MaxDeviceMessage-56 {
			return nil, ErrLimit
		}
		// Required to echo the input length, including on failure; not zero and
		// not the length of an output structure.
		b = binary.LittleEndian.AppendUint32(nil, uint32(len(q.Information.Buffer)))
		if q.Header.MajorFunction == MajorSetInformation {
			b = append(b, 0)
		}
	case MajorLockControl:
		if q.Lock == nil || !r.empty() {
			return nil, ErrProtocol
		}
		b = make([]byte, 5)
	case MajorRead, MajorDeviceControl, MajorQueryInformation, MajorQueryVolume, MajorDirectoryControl:
		if r.FileID != 0 || r.Information != 0 || r.Written != 0 {
			return nil, ErrProtocol
		}
		switch q.Header.MajorFunction {
		case MajorRead:
			if q.Read == nil || uint64(len(r.Data)) > uint64(q.Read.Length) {
				return nil, ErrProtocol
			}
		case MajorDeviceControl:
			if q.Control == nil || uint64(len(r.Data)) > uint64(q.Control.OutputLength) {
				return nil, ErrProtocol
			}
		case MajorQueryInformation, MajorQueryVolume:
			if q.Information == nil {
				return nil, ErrProtocol
			}
		case MajorDirectoryControl:
			if q.Header.MinorFunction == MinorQueryDirectory {
				if q.Directory == nil {
					return nil, ErrProtocol
				}
			} else if q.Header.MinorFunction == MinorNotifyDirectory {
				if q.Notify == nil {
					return nil, ErrProtocol
				}
			} else {
				return nil, ErrFileOperation
			}
		}
		b = make([]byte, 4, 5+len(r.Data))
		binary.LittleEndian.PutUint32(b, uint32(len(r.Data)))
		b = append(b, r.Data...)
		if q.Header.MajorFunction == MajorDirectoryControl && len(r.Data) == 0 {
			b = append(b, 0)
		}
	default:
		return nil, ErrFileOperation
	}
	return b, nil
}

// EncodeFileCompletion encodes a reply for a decoded request. It performs no
// I/O and consumes no token. Use CompleteFile with DriveClient so correlation
// and limits come from the original immutable request, not a mutable copy.
func EncodeFileCompletion(q FileRequest, status uint32, r FileResult) ([]byte, error) {
	b, err := fileResponsePayload(q, status, r)
	if err != nil {
		return nil, err
	}
	return EncodeIOCompletion(q.Header.DeviceID, q.Header.CompletionID, status, b)
}

// CompleteFile validates the original operation and produces a final response,
// consuming its token once. Invalid results leave it pending. It does not close
// handles or cancel work. For an unknown major/directory-minor operation only
// an error status with a zero result is accepted, producing a common failure.
func (c *DriveClient) CompleteFile(request Request, status uint32, result FileResult) ([]byte, error) {
	if !c.initialized() || request.owner != c || request.entry == nil {
		return nil, ErrRequest
	}
	h := request.entry.header
	if c.pending[requestKey{h.DeviceID, h.CompletionID}] != request.entry {
		return nil, ErrRequest
	}
	q, err := request.DecodeFile()
	if err != nil {
		if errors.Is(err, ErrFileOperation) && status>>30 == 3 && result.empty() {
			return c.Complete(request, status, nil)
		}
		return nil, err
	}
	payload, err := fileResponsePayload(q, status, result)
	if err != nil {
		return nil, err
	}
	return c.Complete(request, status, payload)
}

// EncodeBasicInformation returns the 36-byte RDPEFS query representation,
// omitting FSCC's reserved tail. Query timestamps cannot be setter sentinels.
func EncodeBasicInformation(v BasicInformation) ([]byte, error) {
	if v.CreationTime < 0 || v.LastAccessTime < 0 || v.LastWriteTime < 0 || v.ChangeTime < 0 {
		return nil, ErrProtocol
	}
	b := make([]byte, 0, 36)
	for _, n := range []int64{v.CreationTime, v.LastAccessTime, v.LastWriteTime, v.ChangeTime} {
		b = binary.LittleEndian.AppendUint64(b, uint64(n))
	}
	return binary.LittleEndian.AppendUint32(b, v.Attributes), nil
}

type StandardInformation struct {
	AllocationSize, EndOfFile int64
	Links                     uint32
	DeletePending, Directory  bool
}

// EncodeStandardInformation returns 22 bytes; FSCC's 2-byte reserved tail is
// absent in RDPEFS. Allocation granularity is a backend/volume responsibility.
func EncodeStandardInformation(v StandardInformation) ([]byte, error) {
	if v.AllocationSize < 0 || v.EndOfFile < 0 {
		return nil, ErrProtocol
	}
	b := binary.LittleEndian.AppendUint64(nil, uint64(v.AllocationSize))
	b = binary.LittleEndian.AppendUint64(b, uint64(v.EndOfFile))
	b = binary.LittleEndian.AppendUint32(b, v.Links)
	b = append(b, 0, 0)
	if v.DeletePending {
		b[20] = 1
	}
	if v.Directory {
		b[21] = 1
	}
	return b, nil
}

func EncodeAttributeTagInformation(attributes, reparseTag uint32) []byte {
	b := binary.LittleEndian.AppendUint32(nil, attributes)
	return binary.LittleEndian.AppendUint32(b, reparseTag)
}
