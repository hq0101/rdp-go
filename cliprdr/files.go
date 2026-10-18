package cliprdr

import (
	"encoding/binary"
	"errors"
	"math"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	FileGroupDescriptorName = "FileGroupDescriptorW"
	FileDescriptorBytes     = 592
	MaxFiles                = 1024
	// A response including its clipboard header fits the default static-channel limit.
	MaxFileChunk                  = (1 << 20) - 12
	MaxFileRequests               = 64
	MaxFileRequestBytes           = 8 << 20
	MaxFileSets                   = 8
	FileSizeRequest        uint32 = 1
	FileRangeRequest       uint32 = 2
	FileAttributesValid    uint32 = 0x04
	FileWriteTimeValid     uint32 = 0x20
	FileSizeValid          uint32 = 0x40
	FileShowProgress       uint32 = 0x4000
	FileAttributeDirectory uint32 = 0x10
	capLong                uint32 = 2
	capFiles               uint32 = 4
	capNoPaths             uint32 = 8
	capLock                uint32 = 16
	capHuge                uint32 = 32
)

var (
	ErrFile          = errors.New("cliprdr: invalid file descriptor, range, or response")
	ErrFileStreaming = errors.New("cliprdr: required file streaming capability unavailable")
	ErrFileLimit     = errors.New("cliprdr: file transfer resource limit exceeded")
)

// FileDescriptor is metadata, never a filesystem instruction. Name may contain
// relative directory components. DecodeFileList preserves it verbatim; a caller
// saving files MUST separately enforce its destination/path and collision policy.
// Flags determine which metadata fields are valid. WriteTime is a Windows FILETIME.
type FileDescriptor struct {
	Flags      uint32
	Attributes uint32
	WriteTime  uint64
	Size       uint64
	Name       string
}

func (d FileDescriptor) IsDirectory() bool {
	return d.Flags&FileAttributesValid != 0 && d.Attributes&FileAttributeDirectory != 0
}

func EncodeFileList(files []FileDescriptor) ([]byte, error) {
	if len(files) > MaxFiles {
		return nil, ErrFileLimit
	}
	for _, d := range files {
		if d.Name == "" || !utf8.ValidString(d.Name) || strings.ContainsRune(d.Name, 0) || len(d.Name) > 4*259 || len(utf16.Encode([]rune(d.Name))) > 259 {
			return nil, ErrFile
		}
	}
	b := make([]byte, 4+len(files)*FileDescriptorBytes)
	binary.LittleEndian.PutUint32(b, uint32(len(files)))
	for i, d := range files {
		p := b[4+i*FileDescriptorBytes:]
		binary.LittleEndian.PutUint32(p, d.Flags)
		binary.LittleEndian.PutUint32(p[36:], d.Attributes)
		binary.LittleEndian.PutUint64(p[56:], d.WriteTime)
		binary.LittleEndian.PutUint32(p[64:], uint32(d.Size>>32))
		binary.LittleEndian.PutUint32(p[68:], uint32(d.Size))
		for j, u := range utf16.Encode([]rune(d.Name)) {
			binary.LittleEndian.PutUint16(p[72+j*2:], u)
		}
	}
	return b, nil
}

func DecodeFileList(b []byte) ([]FileDescriptor, error) {
	if len(b) < 4 {
		return nil, ErrFile
	}
	n := uint64(binary.LittleEndian.Uint32(b))
	if n > MaxFiles {
		return nil, ErrFileLimit
	}
	if uint64(len(b)) != 4+n*FileDescriptorBytes {
		return nil, ErrFile
	}
	files := make([]FileDescriptor, int(n))
	for i := range files {
		p := b[4+i*FileDescriptorBytes : 4+(i+1)*FileDescriptorBytes]
		name, err := decodeName(p[72:], false)
		if err != nil || name == "" {
			return nil, ErrFile
		}
		files[i] = FileDescriptor{Flags: binary.LittleEndian.Uint32(p), Attributes: binary.LittleEndian.Uint32(p[36:]), WriteTime: binary.LittleEndian.Uint64(p[56:]), Size: uint64(binary.LittleEndian.Uint32(p[64:]))<<32 | uint64(binary.LittleEndian.Uint32(p[68:])), Name: name}
	}
	return files, nil
}

// FileContentsRequest carries a complete wire request. Locked distinguishes an
// absent clipDataId from the valid numeric ID zero. Codec methods do not perform
// capability, known-file-size, ownership, or application resource checks.
type FileContentsRequest struct {
	StreamID   uint32
	Index      int32
	Flags      uint32
	Offset     uint64
	Length     uint32
	Locked     bool
	ClipDataID uint32
}

// DecodeFileContentsRequest validates exactly one complete request PDU.
func DecodeFileContentsRequest(b []byte) (FileContentsRequest, error) {
	var err error
	b, err = clipboardPacket(b)
	if err != nil || binary.LittleEndian.Uint16(b) != 8 || binary.LittleEndian.Uint16(b[2:]) != 0 {
		return FileContentsRequest{}, ErrProtocol
	}
	return decodeFileRequest(b[8:])
}

func (r FileContentsRequest) valid() bool {
	return r.Index >= 0 && ((r.Flags == FileSizeRequest && r.Offset == 0 && r.Length == 8) || (r.Flags == FileRangeRequest && uint64(r.Length) <= math.MaxUint64-r.Offset))
}
func EncodeFileContentsRequest(r FileContentsRequest) ([]byte, error) {
	if !r.valid() {
		return nil, ErrFile
	}
	b := binary.LittleEndian.AppendUint32(nil, r.StreamID)
	b = binary.LittleEndian.AppendUint32(b, uint32(r.Index))
	b = binary.LittleEndian.AppendUint32(b, r.Flags)
	b = binary.LittleEndian.AppendUint64(b, r.Offset)
	b = binary.LittleEndian.AppendUint32(b, r.Length)
	if r.Locked {
		b = binary.LittleEndian.AppendUint32(b, r.ClipDataID)
	}
	return packet(8, 0, b), nil
}
func decodeFileRequest(body []byte) (FileContentsRequest, error) {
	if len(body) != 24 && len(body) != 28 {
		return FileContentsRequest{}, ErrProtocol
	}
	r := FileContentsRequest{StreamID: binary.LittleEndian.Uint32(body), Index: int32(binary.LittleEndian.Uint32(body[4:])), Flags: binary.LittleEndian.Uint32(body[8:]), Offset: binary.LittleEndian.Uint64(body[12:]), Length: binary.LittleEndian.Uint32(body[20:]), Locked: len(body) == 28}
	if r.Locked {
		r.ClipDataID = binary.LittleEndian.Uint32(body[24:])
	}
	if !r.valid() {
		return r, ErrFile
	}
	return r, nil
}

// FileSet and FileRequestToken are opaque connection-bound handles. A handle from
// an old/reset Client cannot address a new transfer even if wire IDs are reused.
type FileSet struct {
	owner  *fileState
	id     uint64
	remote bool
}
type FileRequestToken struct {
	owner *fileState
	id    uint64
}
type FileList struct {
	Set         FileSet
	Descriptors []FileDescriptor
	Locked      bool
}
type FileRequest struct {
	Token   FileRequestToken
	Set     FileSet
	Request FileContentsRequest
}
type FileResult struct {
	Set     FileSet
	Request FileContentsRequest
	Size    uint64
	Data    []byte
}
type FileStatus struct {
	Enabled, Streaming, Locking, HugeFiles                bool
	Incoming, Outgoing, LocalSets, RemoteSets, LocalLocks int
	IncomingBytes, OutgoingBytes                          uint64
}
type fileSnapshot struct {
	key                         FileSet
	files                       []FileDescriptor
	version                     uint64
	locked                      bool
	lockID                      uint32
	released, rejected, invalid bool
}
type fileTransfer struct {
	request   FileContentsRequest
	set       *fileSnapshot
	token     FileRequestToken
	abandoned bool
}
type fileState struct {
	negotiated           uint32
	nextSet, nextToken   uint64
	nextStream, nextLock uint64
	current              *fileSnapshot
	offer                *fileSnapshot
	local                map[uint64]*fileSnapshot
	remote               map[uint64]*fileSnapshot
	locks                map[uint32]*fileSnapshot
	in                   map[uint32]*fileTransfer
	out                  map[uint32]*fileTransfer
	inBytes, outBytes    uint64
	read                 *fileSnapshot
}

// EnableFileStreaming opts in before receiving any capability/ready PDU. The
// caller must service FileContentsNeeded events explicitly. No file is opened,
// no system clipboard is accessed, and no temporary share is advertised.
func (c *Client) EnableFileStreaming() error {
	if c.ready || c.capsSeen {
		return ErrNotReady
	}
	if c.files == nil {
		c.files = &fileState{local: map[uint64]*fileSnapshot{}, remote: map[uint64]*fileSnapshot{}, locks: map[uint32]*fileSnapshot{}, in: map[uint32]*fileTransfer{}, out: map[uint32]*fileTransfer{}}
	}
	return nil
}
func (c *Client) FileStatus() FileStatus {
	f := c.files
	if f == nil {
		return FileStatus{}
	}
	return FileStatus{true, c.ready && f.negotiated&capFiles != 0, c.ready && f.negotiated&capLock != 0, c.ready && f.negotiated&capHuge != 0, len(f.in), len(f.out), len(f.local), len(f.remote), len(f.locks), f.inBytes, f.outBytes}
}
func (c *Client) filesReady() error {
	if !c.ready {
		return ErrNotReady
	}
	if c.files == nil || c.files.negotiated&capFiles == 0 || !c.longNames {
		return ErrFileStreaming
	}
	return nil
}
func (f *fileState) newSet(remote bool) *fileSnapshot {
	f.nextSet++
	return &fileSnapshot{key: FileSet{f, f.nextSet, remote}}
}
func (c *Client) fileOwnershipChanged() {
	if c.files == nil {
		return
	}
	c.files.current = nil
	c.files.collect()
}
func (f *fileState) collect() {
	keep := map[*fileSnapshot]bool{}
	keep[f.current] = true
	for _, s := range f.locks {
		keep[s] = true
	}
	for _, r := range f.in {
		keep[r.set] = true
	}
	for id, s := range f.local {
		if !keep[s] {
			delete(f.local, id)
		}
	}
}

// RetainedFileSets lists the caller-owned sources still needed by the protocol.
// Reconcile after EVERY Handle, Publish, and CompleteFileRequest. Locks and
// outstanding replies retain old sources; Reset releases all handles.
func (c *Client) RetainedFileSets() []FileSet {
	var out []FileSet
	if c.files != nil {
		for _, s := range c.files.local {
			out = append(out, s.key)
		}
	}
	return out
}

// PublishFiles publishes metadata only. Callers keep immutable, explicitly
// selected sources keyed by the returned FileSet and answer FileContentsNeeded.
// The library never dereferences descriptor names. Additional representations
// (for example text) may be published in the same clipboard offer.
func (c *Client) PublishFiles(formatID uint32, files []FileDescriptor, additional []Data) ([]byte, FileSet, error) {
	if err := c.filesReady(); err != nil {
		return nil, FileSet{}, err
	}
	f := c.files
	if formatID < 0xc000 || f.nextSet == math.MaxUint64 {
		return nil, FileSet{}, ErrFile
	}
	if len(f.local) >= MaxFileSets {
		return nil, FileSet{}, ErrFileLimit
	}
	// NO_FILE_PATHS forbids source paths, but permits relative subtree names.
	for _, d := range files {
		if strings.HasPrefix(d.Name, "\\") || strings.HasPrefix(d.Name, "/") || strings.Contains(d.Name, ":") {
			return nil, FileSet{}, ErrFile
		}
		for _, part := range strings.FieldsFunc(d.Name, func(r rune) bool { return r == '/' || r == '\\' }) {
			if part == "." || part == ".." {
				return nil, FileSet{}, ErrFile
			}
		}
		if d.Flags&FileSizeValid != 0 && d.Size > math.MaxUint32 && f.negotiated&capHuge == 0 {
			return nil, FileSet{}, ErrFileStreaming
		}
	}
	data, err := EncodeFileList(files)
	if err != nil {
		return nil, FileSet{}, err
	}
	all := append([]Data{{Format{formatID, FileGroupDescriptorName}, data}}, additional...)
	b, err := c.Publish(all)
	if err != nil {
		return nil, FileSet{}, err
	}
	s := f.newSet(false)
	s.files = append([]FileDescriptor(nil), files...)
	f.current = s
	f.offer = s
	f.local[s.key.id] = s
	return b, s.key, nil
}

// RequestFiles obtains the current remote list. With lock=true it first sends
// LOCK and later includes that ID in file requests. Send every returned PDU in
// order. FileListResult completes this untagged operation; a timeout must drain
// it. Failed/stale lists automatically produce an UNLOCK reply.
func (c *Client) RequestFiles(lock bool) ([][]byte, error) {
	if err := c.filesReady(); err != nil {
		return nil, err
	}
	f := c.files
	if lock && f.negotiated&capLock == 0 {
		return nil, ErrFileStreaming
	}
	if len(f.remote) >= MaxFileSets || f.nextSet == math.MaxUint64 || (lock && f.nextLock >= math.MaxUint32) {
		return nil, ErrFileLimit
	}
	b, err := c.Request(Format{Name: FileGroupDescriptorName})
	if err != nil {
		return nil, err
	}
	s := f.newSet(true)
	s.version = c.remoteVersion
	s.locked = lock
	var replies [][]byte
	if lock {
		f.nextLock++
		s.lockID = uint32(f.nextLock)
		replies = append(replies, packet(10, 0, binary.LittleEndian.AppendUint32(nil, s.lockID)))
	}
	f.read = s
	return append(replies, b), nil
}

func (c *Client) finishFileList(e *Event) [][]byte {
	f := c.files
	s := f.read
	f.read = nil
	e.Kind = FileListResult
	if e.Err == nil {
		var err error
		s.files, err = DecodeFileList(e.Data)
		e.Err = err
		if err == nil {
			for _, d := range s.files {
				if d.Flags&FileSizeValid != 0 && d.Size > math.MaxUint32 && f.negotiated&capHuge == 0 {
					e.Err = ErrFileStreaming
					break
				}
			}
		}
	}
	e.Data = nil
	if e.Err != nil {
		if s.locked {
			return [][]byte{packet(11, 0, binary.LittleEndian.AppendUint32(nil, s.lockID))}
		}
		return nil
	}
	f.remote[s.key.id] = s
	e.Files = &FileList{s.key, append([]FileDescriptor(nil), s.files...), s.locked}
	return nil
}
func (c *Client) remoteFileSet(key FileSet) (*fileSnapshot, error) {
	if err := c.filesReady(); err != nil {
		return nil, err
	}
	if key.owner != c.files || !key.remote {
		return nil, ErrChanged
	}
	s := c.files.remote[key.id]
	if s == nil || s.released || s.invalid || (!s.locked && s.version != c.remoteVersion) {
		return nil, ErrChanged
	}
	return s, nil
}

func (c *Client) RequestFileSize(set FileSet, index uint32) ([]byte, error) {
	return c.requestFile(set, index, FileSizeRequest, 0, 8)
}

// LockRemoteFiles retains a previously obtained, still-current list. It may be
// used after RequestFiles(false) when a peer instantiates file streams lazily.
// No read may be pending for this set: changing retention cannot retroactively
// turn an unlocked in-flight request into a locked one.
func (c *Client) LockRemoteFiles(key FileSet) ([]byte, error) {
	s, err := c.remoteFileSet(key)
	if err != nil {
		return nil, err
	}
	f := c.files
	if f.negotiated&capLock == 0 {
		return nil, ErrFileStreaming
	}
	if s.locked {
		return nil, ErrBusy
	}
	for _, r := range f.out {
		if r.set == s {
			return nil, ErrBusy
		}
	}
	if f.nextLock >= math.MaxUint32 {
		return nil, ErrFileLimit
	}
	f.nextLock++
	s.lockID = uint32(f.nextLock)
	s.locked = true
	return packet(10, 0, binary.LittleEndian.AppendUint32(nil, s.lockID)), nil
}
func (c *Client) RequestFileRange(set FileSet, index uint32, offset uint64, length uint32) ([]byte, error) {
	return c.requestFile(set, index, FileRangeRequest, offset, length)
}
func (c *Client) requestFile(key FileSet, index, kind uint32, offset uint64, length uint32) ([]byte, error) {
	s, err := c.remoteFileSet(key)
	if err != nil {
		return nil, err
	}
	f := c.files
	if index >= uint32(len(s.files)) || s.files[index].IsDirectory() {
		return nil, ErrFile
	}
	d := s.files[index]
	if length > MaxFileChunk {
		return nil, ErrFileLimit
	}
	if kind == FileRangeRequest && (d.Flags&FileSizeValid == 0 || offset > d.Size || uint64(length) > d.Size-offset) {
		return nil, ErrFile
	}
	if len(f.out) >= MaxFileRequests || f.outBytes+uint64(length) > MaxFileRequestBytes || f.nextStream >= math.MaxUint32 {
		return nil, ErrFileLimit
	}
	r := FileContentsRequest{StreamID: uint32(f.nextStream + 1), Index: int32(index), Flags: kind, Offset: offset, Length: length, Locked: s.locked, ClipDataID: s.lockID}
	b, err := EncodeFileContentsRequest(r)
	if err != nil {
		return nil, err
	}
	f.nextStream++
	f.out[r.StreamID] = &fileTransfer{request: r, set: s}
	f.outBytes += uint64(length)
	return b, nil
}

// ReleaseRemoteFiles invalidates a remote handle and abandons its outstanding
// reads. Their IDs remain reserved until replies are drained; no wire ID is ever
// reused on this connection. UNLOCK follows already-sent requests in wire order.
func (c *Client) ReleaseRemoteFiles(key FileSet) ([][]byte, error) {
	if c.files == nil || key.owner != c.files || !key.remote {
		return nil, ErrChanged
	}
	s := c.files.remote[key.id]
	if s == nil || s.released {
		return nil, ErrChanged
	}
	s.released = true
	delete(c.files.remote, key.id)
	for _, r := range c.files.out {
		if r.set == s {
			r.abandoned = true
		}
	}
	if s.locked {
		return [][]byte{packet(11, 0, binary.LittleEndian.AppendUint32(nil, s.lockID))}, nil
	}
	return nil, nil
}

func fileResponse(id uint32, ok bool, data []byte) []byte {
	flags := uint16(2)
	if ok {
		flags = 1
	}
	return packet(9, flags, append(binary.LittleEndian.AppendUint32(nil, id), data...))
}

func (c *Client) handleFilePDU(typ, flags uint16, body []byte) ([][]byte, Event, error) {
	var e Event
	if c.filesReady() != nil {
		return nil, e, ErrProtocol
	}
	f := c.files
	switch typ {
	case 10, 11:
		if flags != 0 || len(body) != 4 || f.negotiated&capLock == 0 {
			return nil, e, ErrProtocol
		}
		id := binary.LittleEndian.Uint32(body)
		if typ == 10 {
			if _, ok := f.locks[id]; ok {
				return nil, e, ErrProtocol
			}
			if len(f.locks) >= MaxFileSets {
				return nil, e, ErrFileLimit
			}
			// Even an empty clipboard can be tagged. A future offer must never
			// become the target of a lock made against that empty clipboard.
			f.locks[id] = f.current
		} else {
			if _, ok := f.locks[id]; !ok {
				return nil, e, ErrProtocol
			}
			delete(f.locks, id)
			f.collect()
		}
		e.Kind = FileRetentionChanged
	case 8:
		if flags != 0 {
			return nil, e, ErrProtocol
		}
		r, err := decodeFileRequest(body)
		if err == ErrProtocol {
			return nil, e, err
		}
		if _, ok := f.in[r.StreamID]; ok {
			return nil, e, ErrProtocol
		}
		fail := func() ([][]byte, Event, error) { return [][]byte{fileResponse(r.StreamID, false, nil)}, e, nil }
		if err != nil || r.Length > MaxFileChunk || len(f.in) >= MaxFileRequests || f.inBytes+uint64(r.Length) > MaxFileRequestBytes || f.nextToken == math.MaxUint64 {
			return fail()
		}
		s := f.current
		if r.Locked {
			if f.negotiated&capLock == 0 {
				return nil, e, ErrProtocol
			}
			s = f.locks[r.ClipDataID]
		}
		if s == nil || s.rejected || int(r.Index) >= len(s.files) || s.files[r.Index].IsDirectory() {
			return fail()
		}
		d := s.files[r.Index]
		// Windows IStream consumers request their full block size at EOF.
		// cbRequested is a maximum: permit the final short read (including
		// zero bytes exactly at EOF), but never an offset beyond the file.
		if r.Flags == FileRangeRequest && (d.Flags&FileSizeValid == 0 || r.Offset > d.Size) {
			return fail()
		}
		if f.negotiated&capHuge == 0 && r.Offset > math.MaxUint32 {
			return fail()
		}
		f.nextToken++
		token := FileRequestToken{f, f.nextToken}
		f.in[r.StreamID] = &fileTransfer{request: r, set: s, token: token}
		f.inBytes += uint64(r.Length)
		e.Kind = FileContentsNeeded
		e.FileRequest = &FileRequest{token, s.key, r}
	case 9:
		if len(body) < 4 || (flags != 1 && flags != 2) || (flags == 2 && len(body) != 4) {
			return nil, e, ErrProtocol
		}
		id := binary.LittleEndian.Uint32(body)
		r := f.out[id]
		if r == nil {
			return nil, e, ErrProtocol
		}
		data := body[4:]
		if flags == 1 && ((r.request.Flags == FileSizeRequest && len(data) != 8) || (r.request.Flags == FileRangeRequest && uint64(len(data)) > uint64(r.request.Length))) {
			return nil, e, ErrProtocol
		}
		delete(f.out, id)
		f.outBytes -= uint64(r.request.Length)
		e.Kind = FileContentsResult
		e.FileResult = &FileResult{Set: r.set.key, Request: r.request}
		if r.abandoned || r.set.invalid || (!r.set.locked && r.set.version != c.remoteVersion) {
			e.Err = ErrChanged
		} else if flags == 2 {
			e.Err = ErrRejected
		} else if r.request.Flags == FileSizeRequest {
			size := binary.LittleEndian.Uint64(data)
			d := &r.set.files[r.request.Index]
			if f.negotiated&capHuge == 0 && size > math.MaxUint32 {
				e.Err = ErrFileStreaming
			} else if d.Flags&FileSizeValid != 0 && d.Size != size {
				e.Err = ErrChanged
				r.set.invalid = true
			} else {
				d.Size = size
				d.Flags |= FileSizeValid
				e.FileResult.Size = size
			}
		} else {
			e.FileResult.Data = append([]byte{}, data...)
		}
	default:
		return nil, e, ErrProtocol
	}
	return nil, e, nil
}

// CompleteFileRequest answers one FileContentsNeeded. data is exactly 8 bytes
// little-endian for SIZE, or at most Length bytes for RANGE. A read error sends
// FAIL with no data. The caller may do asynchronous I/O outside its Client lock;
// the opaque token prevents a late completion answering a newer reused stream ID.
// Invalid local data leaves the request pending so it can be explicitly failed.
func (c *Client) CompleteFileRequest(token FileRequestToken, data []byte, readErr error) ([]byte, error) {
	f := c.files
	if f == nil || token.owner != f {
		return nil, ErrChanged
	}
	var id uint32
	var r *fileTransfer
	for k, v := range f.in {
		if v.token == token {
			id = k
			r = v
			break
		}
	}
	if r == nil {
		return nil, ErrChanged
	}
	if r.set.rejected || (!r.request.Locked && f.current != r.set) {
		readErr = ErrChanged
	}
	if readErr == nil {
		if r.request.Flags == FileSizeRequest {
			if len(data) != 8 {
				return nil, ErrFile
			}
			size := binary.LittleEndian.Uint64(data)
			d := &r.set.files[r.request.Index]
			if f.negotiated&capHuge == 0 && size > math.MaxUint32 {
				return nil, ErrFileStreaming
			}
			if d.Flags&FileSizeValid != 0 && d.Size != size {
				return nil, ErrChanged
			}
			d.Size = size
			d.Flags |= FileSizeValid
		} else {
			d := r.set.files[r.request.Index]
			if uint64(len(data)) > uint64(r.request.Length) || r.request.Offset > d.Size || uint64(len(data)) > d.Size-r.request.Offset {
				return nil, ErrFile
			}
		}
	} else {
		data = nil
	}
	delete(f.in, id)
	f.inBytes -= uint64(r.request.Length)
	f.collect()
	return fileResponse(id, readErr == nil, data), nil
}
