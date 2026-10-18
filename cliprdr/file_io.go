package cliprdr

import (
	"encoding/binary"
	"io"
	"math"
)

// ReadFileContents services one SIZE or RANGE request using a caller-selected
// ReaderAt and its fixed, published size. It never opens a path, seeks, closes
// the source, or reads more than MaxFileChunk bytes. SIZE and empty ranges do
// not call source; source may be nil for these requests. Sources larger than
// math.MaxInt64 are rejected because ReaderAt uses signed offsets.
//
// Use this only after Handle returns FileContentsNeeded: select the source by
// the event's FileSet and Index, perform I/O outside the Client lock, then pass
// both returned values to CompleteFileRequest with the original token. This
// helper does not validate connection ownership or change the Client state.
// Keep the source bytes stable until RetainedFileSets releases the set AND all
// application reads have finished. The caller owns cancellation and closing.
//
// A range is clamped to the published EOF. An earlier EOF is io.ErrUnexpectedEOF,
// not a successful short transfer. On any error, no partial data is returned.
func ReadFileContents(source io.ReaderAt, size uint64, request FileContentsRequest) ([]byte, error) {
	if !request.valid() || size > math.MaxInt64 {
		return nil, ErrFile
	}
	if request.Length > MaxFileChunk {
		return nil, ErrFileLimit
	}
	if request.Flags == FileSizeRequest {
		return binary.LittleEndian.AppendUint64(nil, size), nil
	}
	if request.Offset > size {
		return nil, ErrFile
	}
	length := min(uint64(request.Length), size-request.Offset)
	if length == 0 {
		return []byte{}, nil
	}
	if source == nil {
		return nil, ErrFile
	}
	data := make([]byte, int(length))
	n, err := source.ReadAt(data, int64(request.Offset))
	if n < 0 || n > len(data) {
		return nil, ErrFile
	}
	if err != nil && err != io.EOF {
		return nil, err
	}
	if n != len(data) {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}
