package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/hq0101/rdp-go/cliprdr"
)

const uploadChunkBytes = 256 << 10

type uploadEntry struct {
	Name      string `json:"name"`
	Size      uint64 `json:"size"`
	Directory bool   `json:"directory,omitempty"`
}
type uploadStatus struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	Total     uint64 `json:"total"`
	Received  uint64 `json:"received"`
	Files     int    `json:"files"`
	Completed int    `json:"completed"`
}

// ioMu owns all disk handles and the transfer of cleanup responsibility. mu
// protects only public progress. No HTTP body or disk access holds clipMu.
type uploadJob struct {
	ioMu        sync.Mutex
	mu          sync.Mutex
	status      uploadStatus
	generation  string
	sources     *clipboardSources
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	files       []cliprdr.FileDescriptor
	offsets     []uint64
	ready       []bool
	handles     []*os.File
	paths       []string
	root        string
	identity    os.FileInfo
	transferred bool
}

func (j *uploadJob) snapshot() uploadStatus { j.mu.Lock(); defer j.mu.Unlock(); return j.status }
func (j *uploadJob) state(state string, err error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.status.State = state
	if err != nil {
		j.status.Error = fileJobError(err)
	}
}
func (j *uploadJob) cleanup() error { // ioMu held
	if j.root == "" {
		return nil
	}
	var result error
	for i, f := range j.handles {
		if f != nil {
			result = errors.Join(result, f.Close())
			j.handles[i] = nil
		}
	}
	info, err := os.Lstat(j.root)
	if err != nil {
		return errors.Join(result, err)
	}
	if j.identity == nil && len(j.paths) == 0 {
		return errors.Join(result, os.Remove(j.root))
	}
	if !info.IsDir() || j.identity == nil || !os.SameFile(info, j.identity) {
		return errors.Join(result, cliprdr.ErrChanged)
	}
	for _, path := range j.paths {
		result = errors.Join(result, os.Remove(path))
	}
	result = errors.Join(result, os.Remove(j.root))
	if result == nil {
		j.root = ""
		j.paths = nil
	}
	return result
}
func (j *uploadJob) release() error {
	j.ioMu.Lock()
	defer j.ioMu.Unlock()
	err := j.cleanup()
	if err != nil {
		j.mu.Lock()
		j.status.State, j.status.Error = "finished", "cleanup_failed"
		j.mu.Unlock()
	} else {
		j.state("released", nil)
	}
	return err
}
func (v *viewer) runUpload(j *uploadJob) {
	defer close(j.done)
	defer func() { <-v.clipHTTPGate }()
	<-j.ctx.Done()
	j.ioMu.Lock()
	defer j.ioMu.Unlock()
	if !j.transferred {
		if j.snapshot().Error == "" {
			j.state("finished", j.ctx.Err())
		}
		if err := j.cleanup(); err != nil {
			j.sources.failed.Store(true)
			j.mu.Lock()
			j.status.State, j.status.Error = "finished", "cleanup_failed"
			j.mu.Unlock()
		}
	}
}

func uploadDescriptors(entries []uploadEntry) ([]cliprdr.FileDescriptor, uint64, error) {
	if len(entries) == 0 || len(entries) > viewerFileCount {
		return nil, 0, cliprdr.ErrFileLimit
	}
	files := make([]cliprdr.FileDescriptor, len(entries))
	for i, e := range entries {
		if e.Directory && e.Size != 0 {
			return nil, 0, cliprdr.ErrFile
		}
		files[i] = cliprdr.FileDescriptor{Name: e.Name, Size: e.Size, Flags: cliprdr.FileAttributesValid | cliprdr.FileSizeValid, Attributes: 0x80}
		if e.Directory {
			files[i].Attributes = cliprdr.FileAttributeDirectory
		}
	}
	plan, err := cliprdr.PlanFileOffer(files, cliprdr.FilePlanOptions{MaxFileSize: viewerFileBytes, MaxTotalSize: viewerFileBytes})
	if err != nil {
		return nil, 0, err
	}
	if len(plan.Entries()) > viewerFileCount {
		return nil, 0, cliprdr.ErrFileLimit
	}
	// HTTP file indices remain those of the browser manifest. Add implicit
	// parents after them, then order the published descriptors by the tree plan.
	for _, entry := range plan.Entries() {
		if entry.Index < 0 {
			files = append(files, cliprdr.FileDescriptor{Name: entry.Path, Flags: cliprdr.FileAttributesValid, Attributes: cliprdr.FileAttributeDirectory})
		}
	}
	return files, plan.TotalSize(), nil
}

func uploadError(w http.ResponseWriter, err error) {
	code := 409
	if errors.Is(err, cliprdr.ErrFilePath) || errors.Is(err, cliprdr.ErrFileCollision) || errors.Is(err, cliprdr.ErrFile) {
		code = 400
	}
	if errors.Is(err, cliprdr.ErrFileLimit) {
		code = 413
	}
	if errors.Is(err, context.DeadlineExceeded) {
		code = 504
	}
	if errors.Is(err, errClipboardTransport) {
		code = 502
	}
	// Never expose private spool names or filesystem error text.
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": fileJobError(err)})
}

func (v *viewer) serveClipboardUpload(w http.ResponseWriter, r *http.Request) {
	generation := r.Header.Get("X-RdpGo-Generation")
	if !v.clipboardGeneration(generation) {
		uploadError(w, errConnectionChanged)
		return
	}
	w.Header().Set("X-RdpGo-Generation", generation)
	if r.URL.Path == "/clipboard/upload/data" {
		v.serveUploadChunk(w, r, generation)
		return
	}
	if r.Method == http.MethodGet {
		j := v.findUpload(generation, r.URL.Query().Get("id"))
		if j == nil {
			http.Error(w, "unknown upload", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(j.snapshot())
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		w.WriteHeader(415)
		return
	}
	var req struct {
		Action string        `json:"action"`
		ID     string        `json:"id"`
		Files  []uploadEntry `json:"files"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10))
	d.DisallowUnknownFields()
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid upload", 400)
		return
	}
	if req.Action == "create" && req.ID == "" {
		v.createUpload(w, r, generation, req.Files)
		return
	}
	if len(req.Files) != 0 {
		http.Error(w, "invalid upload", 400)
		return
	}
	j := v.findUpload(generation, req.ID)
	if j == nil {
		http.Error(w, "unknown upload", 404)
		return
	}
	switch req.Action {
	case "cancel":
		// Cancellation stops preparation; after publication the source must obey
		// protocol ownership/locks. Clearing the page does not revoke a paste.
		if state := j.snapshot().State; state == "published" || state == "released" {
			w.WriteHeader(204)
			return
		}
		j.cancel()
		w.WriteHeader(204)
	case "publish":
		v.publishUpload(w, r, j)
	default:
		http.Error(w, "invalid upload action", 400)
	}
}
func (v *viewer) findUpload(generation, id string) *uploadJob {
	v.clipMu.Lock()
	defer v.clipMu.Unlock()
	j := v.uploadJob
	if j == nil || j.generation != generation || j.status.ID != id {
		return nil
	}
	return j
}

func (v *viewer) createUpload(w http.ResponseWriter, r *http.Request, generation string, entries []uploadEntry) {
	files, total, err := uploadDescriptors(entries)
	if err != nil {
		uploadError(w, err)
		return
	}
	var id [16]byte
	if _, err = rand.Read(id[:]); err != nil {
		uploadError(w, err)
		return
	}
	v.connectionMu.RLock()
	v.clipMu.Lock()
	unlock := func() { v.clipMu.Unlock(); v.connectionMu.RUnlock() }
	if !v.clipboardGeneration(generation) || v.clip == nil || !v.fileClipboardEnabled || !v.clip.FileStatus().Streaming {
		unlock()
		uploadError(w, errConnectionChanged)
		return
	}
	if v.clip.Status().Busy {
		unlock()
		uploadError(w, cliprdr.ErrBusy)
		return
	}
	if j := v.uploadJob; j != nil {
		select {
		case <-j.done:
		default:
			unlock()
			uploadError(w, cliprdr.ErrBusy)
			return
		}
	}
	s, err := v.ensureSources()
	if err != nil {
		unlock()
		uploadError(w, err)
		return
	}
	st := s.store.Status()
	if s.failed.Load() || st.Failed != 0 || st.Stopped || st.Sets >= 8 || uint64(viewerFileBytes)-st.Bytes < total || viewerFileCount-st.Files < len(files) {
		unlock()
		uploadError(w, cliprdr.ErrFileLimit)
		return
	}
	select {
	case v.clipHTTPGate <- struct{}{}:
	default:
		unlock()
		uploadError(w, cliprdr.ErrBusy)
		return
	}
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Minute)
	j := &uploadJob{generation: generation, sources: s, ctx: ctx, cancel: cancel, done: make(chan struct{}), files: files, offsets: make([]uint64, len(files)), ready: make([]bool, len(files)), handles: make([]*os.File, len(files)), status: uploadStatus{ID: hex.EncodeToString(id[:]), State: "uploading", Total: total, Files: len(files)}}
	j.ioMu.Lock()
	v.uploadJob = j
	unlock()
	go v.runUpload(j)
	j.root, err = os.MkdirTemp("", "rdpgo-upload-")
	if err == nil {
		var dir *os.File
		dir, err = os.Open(j.root)
		if err == nil {
			j.identity, err = dir.Stat()
			err = errors.Join(err, dir.Close())
		}
	}
	if err == nil {
		j.mu.Lock()
		for i, f := range files {
			if f.IsDirectory() {
				j.ready[i] = true
				j.status.Completed++
			}
		}
		j.mu.Unlock()
	}
	if err == nil {
		err = r.Context().Err()
	}
	if err == nil {
		err = j.ctx.Err()
	}
	if err != nil {
		j.state("finished", err)
		j.cancel()
	}
	j.ioMu.Unlock()
	if err != nil {
		uploadError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	_ = json.NewEncoder(w).Encode(j.snapshot())
}

func (v *viewer) serveUploadChunk(w http.ResponseWriter, r *http.Request, generation string) {
	if err := r.Context().Err(); err != nil {
		uploadError(w, err)
		return
	}
	if r.Method != http.MethodPut {
		w.WriteHeader(405)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/octet-stream" {
		w.WriteHeader(415)
		return
	}
	j := v.findUpload(generation, r.URL.Query().Get("id"))
	if j == nil {
		http.Error(w, "unknown upload", 404)
		return
	}
	index, e1 := strconv.Atoi(r.URL.Query().Get("index"))
	offset, e2 := strconv.ParseUint(r.URL.Query().Get("offset"), 10, 64)
	if e1 != nil || e2 != nil || index < 0 || index >= len(j.files) {
		uploadError(w, cliprdr.ErrFile)
		return
	}
	if !j.ioMu.TryLock() {
		uploadError(w, cliprdr.ErrBusy)
		return
	}
	defer j.ioMu.Unlock()
	if j.ctx.Err() != nil || j.transferred || j.ready[index] || j.offsets[index] != offset {
		uploadError(w, cliprdr.ErrChanged)
		return
	}
	remaining := j.files[index].Size - offset
	want := uint64(uploadChunkBytes)
	if remaining < want {
		want = remaining
	}
	if r.ContentLength >= 0 && uint64(r.ContentLength) != want {
		uploadError(w, cliprdr.ErrFile)
		return
	}
	// A bounded chunk is fully read before touching disk. Cancellation interrupts
	// a blocked network body, not an arbitrary filesystem operation.
	controller := http.NewResponseController(w)
	if err = controller.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil && !errors.Is(err, http.ErrNotSupported) {
		uploadError(w, err)
		return
	}
	interrupted := make(chan struct{})
	stop := context.AfterFunc(j.ctx, func() { defer close(interrupted); _ = controller.SetReadDeadline(time.Now()); _ = r.Body.Close() })
	defer func() {
		if !stop() {
			<-interrupted
		}
	}()
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, int64(want)+1))
	if err == nil {
		err = r.Context().Err()
	}
	if err == nil && uint64(len(data)) != want {
		err = cliprdr.ErrFile
	}
	if err == nil {
		err = j.ctx.Err()
	}
	if err == nil && !v.clipboardGeneration(generation) {
		err = errConnectionChanged
	}
	if err != nil {
		j.state("finished", err)
		j.cancel()
		uploadError(w, err)
		return
	}
	path := filepath.Join(j.root, fmt.Sprintf("source-%03d.bin", index))
	flags := os.O_WRONLY
	if offset == 0 {
		flags |= os.O_CREATE | os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0600)
	if err == nil {
		if offset == 0 {
			j.paths = append(j.paths, path)
		}
		var n int
		n, err = f.WriteAt(data, int64(offset))
		if err == nil && n != len(data) {
			err = io.ErrShortWrite
		}
		if err == nil && want == remaining {
			err = f.Sync()
		}
		err = errors.Join(err, f.Close())
	}
	if err == nil && want == remaining {
		j.handles[index], err = os.Open(path)
	}
	if err == nil {
		err = j.ctx.Err()
	}
	if err != nil {
		j.state("finished", err)
		j.cancel()
		uploadError(w, err)
		return
	}
	j.offsets[index] += want
	j.mu.Lock()
	j.status.Received += want
	if want == remaining {
		j.ready[index] = true
		j.status.Completed++
	}
	j.mu.Unlock()
	w.WriteHeader(204)
}

func (v *viewer) publishUpload(w http.ResponseWriter, r *http.Request, j *uploadJob) {
	if !j.ioMu.TryLock() {
		uploadError(w, cliprdr.ErrBusy)
		return
	}
	defer j.ioMu.Unlock()
	if err := r.Context().Err(); err != nil {
		j.cancel()
		uploadError(w, err)
		return
	}
	if j.ctx.Err() != nil || j.transferred {
		uploadError(w, cliprdr.ErrChanged)
		return
	}
	for _, ready := range j.ready {
		if !ready {
			uploadError(w, cliprdr.ErrFileIncomplete)
			return
		}
	}
	v.connectionMu.RLock()
	v.clipMu.Lock()
	if v.clip != j.sources.client || v.sources != j.sources || !v.clipboardGeneration(j.generation) || j.ctx.Err() != nil || r.Context().Err() != nil {
		v.clipMu.Unlock()
		v.connectionMu.RUnlock()
		uploadError(w, errConnectionChanged)
		return
	}
	plan, err := cliprdr.PlanFileOffer(j.files, cliprdr.FilePlanOptions{MaxFileSize: viewerFileBytes, MaxTotalSize: viewerFileBytes})
	if err != nil {
		v.clipMu.Unlock()
		v.connectionMu.RUnlock()
		uploadError(w, err)
		return
	}
	files := make([]cliprdr.FileDescriptor, 0, len(j.files))
	readers := make([]io.ReaderAt, 0, len(j.files))
	for _, entry := range plan.Entries() {
		files = append(files, j.files[entry.Index])
		var reader io.ReaderAt
		if f := j.handles[entry.Index]; f != nil {
			reader = f
		}
		readers = append(readers, reader)
	}
	b, _, err := j.sources.store.Publish(0xc003, cliprdr.FileSourceOffer{Files: files, Readers: readers, Release: j.release, Additional: []cliprdr.Data{{Format: cliprdr.Format{ID: 0xc013, Name: "Preferred DropEffect"}, Bytes: []byte{1, 0, 0, 0}}}})
	if err != nil {
		v.clipMu.Unlock()
		v.connectionMu.RUnlock()
		uploadError(w, err)
		return
	}
	j.transferred = true
	j.state("publishing", nil)
	wait := make(chan clipResult, 1)
	v.clipWait = wait
	ctx, cancel := context.WithTimeout(j.ctx, 8*time.Second)
	defer cancel()
	err = v.remote.(channelRemote).WriteChannel(ctx, v.clipChannel, b)
	if err != nil {
		v.closeFailedClipboardTransport()
	}
	v.reconcileSources()
	v.clipMu.Unlock()
	v.connectionMu.RUnlock()
	defer func() {
		v.clipMu.Lock()
		if v.clipWait == wait {
			v.clipWait = nil
		}
		v.clipMu.Unlock()
		j.cancel()
	}()
	if err == nil {
		select {
		case result := <-wait:
			err = result.err
		case <-ctx.Done():
			err = ctx.Err()
		case <-r.Context().Done():
			err = r.Context().Err()
		}
	}
	if err == nil && !v.clipboardGeneration(j.generation) {
		err = errConnectionChanged
	}
	if err != nil {
		j.state("finished", err)
		uploadError(w, err)
		return
	}
	j.state("published", nil)
	w.WriteHeader(204)
}

func uploadPath(path string) bool {
	return path == "/clipboard/upload" || path == "/clipboard/upload/data"
}

// Wait outside all connection/clipboard locks before installing new sources.
func (v *viewer) finishSources() error {
	v.clipMu.Lock()
	s, j := v.sources, v.uploadJob
	v.clipMu.Unlock()
	if s != nil {
		if s.ctx.Err() == nil {
			return errors.New("upload sources still active")
		}
		<-s.done
	}
	if j != nil {
		<-j.done
	}
	if s != nil && s.failed.Load() {
		return errors.New("upload source cleanup failed")
	}
	return nil
}
