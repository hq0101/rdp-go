package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hq0101/rdp-go/cliprdr"
)

const viewerFileBytes = 64 << 20
const viewerArchiveBytes = viewerFileBytes + 4<<20
const viewerFileCount = 128

type fileJobStatus struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	Error     string `json:"error,omitempty"`
	Files     int    `json:"files"`
	Completed int    `json:"completed"`
	Total     uint64 `json:"total"`
	Received  uint64 `json:"received"`
}

// One explicitly requested download per viewer. The worker owns disk I/O and
// cleanup. clipMu protects client/set/waiting and event routing; mu protects
// HTTP-visible progress and the archive lease. No disk I/O holds clipMu.
type fileJob struct {
	mu          sync.Mutex
	status      fileJobStatus
	generation  string
	client      *cliprdr.Client
	set         cliprdr.FileSet
	waiting     bool
	events      chan cliprdr.Event
	ctx         context.Context
	cancel      context.CancelFunc
	done        chan struct{}
	archive     *os.File
	archiveSize int64
	serving     bool
	readers     sync.WaitGroup
}

func (j *fileJob) snapshot() fileJobStatus { j.mu.Lock(); defer j.mu.Unlock(); return j.status }
func (j *fileJob) progress(state string, received uint64, completed int) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.status.State, j.status.Received, j.status.Completed = state, received, completed
}

// Called before the first channel packet, including on private ARC candidates.
func (v *viewer) configureFileClipboard(enabled bool) error {
	v.fileClipboardRequested = enabled
	v.fileClipboardEnabled = false
	if !enabled || !v.gatewayPolicy.ClipboardAllowed() {
		return nil
	}
	if v.clip == nil {
		return cliprdr.ErrNotReady
	}
	if err := v.clip.EnableFileStreaming(); err != nil {
		return err
	}
	v.fileClipboardEnabled = true
	return nil
}

// Caller holds connectionMu and clipMu. Canceled/late lists still need UNLOCK.
func (v *viewer) routeFileEvent(event cliprdr.Event) ([][]byte, error) {
	j := v.fileJob
	if event.Kind == cliprdr.FileListResult {
		if j != nil && j.client == v.clip && j.waiting {
			j.waiting = false
			if event.Files != nil {
				j.set = event.Files.Set
			}
			if j.ctx.Err() == nil {
				select {
				case j.events <- event:
					return nil, nil
				default:
					return nil, cliprdr.ErrFileLimit
				}
			}
		}
		if event.Files != nil {
			b, err := v.clip.ReleaseRemoteFiles(event.Files.Set)
			if j != nil && j.set == event.Files.Set {
				j.set = cliprdr.FileSet{}
			}
			return b, err
		}
	}
	if event.Kind == cliprdr.FileContentsResult && event.FileResult != nil && j != nil && j.client == v.clip && j.set == event.FileResult.Set && j.ctx.Err() == nil {
		select {
		case j.events <- event:
		default:
			return nil, cliprdr.ErrFileLimit
		}
	}
	return nil, nil
}

// Check the generation and client together while holding the connection lock.
func (v *viewer) fileOperation(j *fileJob, op func(*cliprdr.Client) ([][]byte, error)) error {
	v.connectionMu.RLock()
	defer v.connectionMu.RUnlock()
	if err := j.ctx.Err(); err != nil {
		return err
	}
	if !v.clipboardGeneration(j.generation) {
		return errConnectionChanged
	}
	v.clipMu.Lock()
	defer v.clipMu.Unlock()
	if v.clip != j.client || v.fileJob != j {
		return errConnectionChanged
	}
	packets, err := op(v.clip)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(j.ctx, 8*time.Second)
	defer cancel()
	for _, b := range packets {
		if b == nil {
			continue
		}
		if err := v.remote.(channelRemote).WriteChannel(ctx, v.clipChannel, b); err != nil {
			// A partially written channel message cannot be retried on this stream.
			v.closeFailedClipboardTransport()
			return errClipboardTransport
		}
	}
	return nil
}

func (v *viewer) waitFileEvent(j *fileJob) (cliprdr.Event, error) {
	timeout := time.NewTimer(30 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-j.ctx.Done():
			return cliprdr.Event{}, j.ctx.Err()
		case <-timeout.C:
			return cliprdr.Event{}, context.DeadlineExceeded
		case <-tick.C:
			if !v.clipboardGeneration(j.generation) {
				return cliprdr.Event{}, errConnectionChanged
			}
		case e := <-j.events:
			if !v.clipboardGeneration(j.generation) {
				return cliprdr.Event{}, errConnectionChanged
			}
			return e, e.Err
		}
	}
}

func (v *viewer) releaseFileJob(j *fileJob) error {
	v.connectionMu.RLock()
	defer v.connectionMu.RUnlock()
	v.clipMu.Lock()
	defer v.clipMu.Unlock()
	if v.clip != j.client || j.set == (cliprdr.FileSet{}) {
		return nil
	}
	b, err := v.clip.ReleaseRemoteFiles(j.set)
	j.set = cliprdr.FileSet{}
	if err != nil {
		return err
	}
	if b != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		for _, packet := range b {
			if err := v.remote.(channelRemote).WriteChannel(ctx, v.clipChannel, packet); err != nil {
				v.closeFailedClipboardTransport()
				return errClipboardTransport
			}
		}
	}
	return nil
}

func fileJobError(err error) string {
	switch {
	case errors.Is(err, context.Canceled):
		return "cancelled"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, cliprdr.ErrFileLimit):
		return "limit"
	case errors.Is(err, cliprdr.ErrFilePath), errors.Is(err, cliprdr.ErrFileCollision):
		return "names"
	case errors.Is(err, errConnectionChanged), errors.Is(err, cliprdr.ErrChanged):
		return "changed"
	case errors.Is(err, cliprdr.ErrRejected):
		return "rejected"
	default:
		return "failed"
	}
}

// Independent of the initiating HTTP request, with a bounded lifetime. Cancel,
// generation loss, reset, reply timeout and viewer shutdown all stop the worker.
func (v *viewer) runFileJob(j *fileJob) {
	defer close(j.done)
	defer j.cancel()
	gateHeld := true
	releaseGate := func() {
		if gateHeld {
			<-v.clipHTTPGate
			gateHeld = false
		}
	}
	defer releaseGate()
	var batch *cliprdr.FileBatch
	var root string
	var result error
	defer func() {
		j.mu.Lock()
		j.status.State = "finished"
		if result != nil {
			j.status.Error = fileJobError(result)
		}
		j.mu.Unlock()
		j.cancel() // stop any archive reader before closing its handle
		j.readers.Wait()
		var cleanupErr error
		if batch != nil {
			cleanupErr = batch.Close()
		}
		if j.archive != nil {
			cleanupErr = errors.Join(cleanupErr, j.archive.Close())
		}
		if root != "" {
			// Only fixed files in our generated directory; no recursive removal.
			if err := os.Remove(filepath.Join(root, "received.zip")); err != nil && !os.IsNotExist(err) {
				cleanupErr = errors.Join(cleanupErr, err)
			}
			cleanupErr = errors.Join(cleanupErr, os.Remove(root))
		}
		cleanupErr = errors.Join(cleanupErr, v.releaseFileJob(j))
		if cleanupErr != nil {
			j.mu.Lock()
			j.status.Error = "cleanup_failed"
			j.mu.Unlock()
		}
	}()
	result = v.fileOperation(j, func(c *cliprdr.Client) ([][]byte, error) {
		p, e := c.RequestFiles(true)
		if e == nil {
			j.waiting = true
		}
		return p, e
	})
	if result != nil {
		return
	}
	e, err := v.waitFileEvent(j)
	if err != nil {
		result = err
		return
	}
	if e.Files == nil || len(e.Files.Descriptors) == 0 {
		result = cliprdr.ErrFile
		return
	}
	if len(e.Files.Descriptors) > viewerFileCount {
		result = cliprdr.ErrFileLimit
		return
	}
	set := e.Files.Set
	for i, d := range e.Files.Descriptors {
		if d.IsDirectory() || d.Flags&cliprdr.FileSizeValid != 0 {
			continue
		}
		result = v.fileOperation(j, func(c *cliprdr.Client) ([][]byte, error) {
			b, e := c.RequestFileSize(set, uint32(i))
			return [][]byte{b}, e
		})
		if result != nil {
			return
		}
		e, err = v.waitFileEvent(j)
		if err != nil {
			result = err
			return
		}
		if e.FileResult == nil || e.FileResult.Set != set || e.FileResult.Request.Index != int32(i) || e.FileResult.Request.Flags != cliprdr.FileSizeRequest {
			result = cliprdr.ErrProtocol
			return
		}
	}
	var plan *cliprdr.FilePlan
	result = v.fileOperation(j, func(c *cliprdr.Client) ([][]byte, error) {
		var e error
		plan, e = c.PlanFiles(set, cliprdr.FilePlanOptions{MaxFileSize: viewerFileBytes, MaxTotalSize: viewerFileBytes})
		if e == nil && len(plan.Entries()) > viewerFileCount {
			return nil, cliprdr.ErrFileLimit
		}
		return nil, e
	})
	if result != nil {
		return
	}
	j.mu.Lock()
	j.status.Files = len(plan.Entries())
	j.status.Total = plan.TotalSize()
	j.mu.Unlock()
	root, result = os.MkdirTemp("", "openrdp-download-")
	if result != nil {
		return
	}
	batch, result = cliprdr.NewFileBatch(root, plan, cliprdr.FileBatchOptions{MaxOpenFiles: 1})
	if result != nil {
		return
	}
	var received uint64
	completed := 0
	for _, entry := range plan.Entries() {
		if entry.Directory {
			completed++
			continue
		}
		target, err := batch.OpenFile(uint32(entry.Index))
		if err != nil {
			result = err
			return
		}
		var download *cliprdr.FileDownload
		result = v.fileOperation(j, func(c *cliprdr.Client) ([][]byte, error) {
			var e error
			download, e = c.NewFileDownload(set, uint32(entry.Index), target, cliprdr.FileDownloadOptions{MaxSize: entry.Size, ChunkSize: 64 << 10, Window: 4})
			return nil, e
		})
		if result != nil {
			return
		}
		for !download.Status().Complete {
			for {
				var packet []byte
				result = v.fileOperation(j, func(c *cliprdr.Client) ([][]byte, error) {
					var e error
					packet, e = download.Next(c)
					return [][]byte{packet}, e
				})
				if result != nil {
					download.Cancel(result)
					return
				}
				if packet == nil {
					break
				}
			}
			e, result = v.waitFileEvent(j)
			if result != nil {
				download.Cancel(result)
				return
			}
			var handled bool
			handled, result = download.Accept(e) // disk I/O outside connectionMu/clipMu
			if result != nil {
				return
			}
			if !handled {
				result = cliprdr.ErrProtocol
				return
			}
			j.progress("receiving", received+download.Status().Written, completed)
		}
		result = batch.CompleteFile(uint32(entry.Index), download)
		if result != nil {
			return
		}
		received += entry.Size
		completed++
		j.progress("receiving", received, completed)
	}
	result = v.releaseFileJob(j)
	if result != nil {
		return
	}
	j.progress("packing", received, completed)
	j.archive, result = os.OpenFile(filepath.Join(root, "received.zip"), os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if result != nil {
		return
	}
	result = batch.WriteZIP(j.ctx, &archiveLimitWriter{w: j.archive, left: viewerArchiveBytes})
	if result == nil {
		result = j.archive.Sync()
	}
	if result != nil {
		return
	}
	info, err := j.archive.Stat()
	if err != nil {
		result = err
		return
	}
	result = batch.Close()
	if result != nil {
		return
	}
	batch = nil
	if !v.clipboardGeneration(j.generation) {
		result = errConnectionChanged
		return
	}
	j.mu.Lock()
	j.archiveSize = info.Size()
	j.status.State = "ready"
	j.mu.Unlock()
	releaseGate()
	expires := time.NewTimer(5 * time.Minute)
	defer expires.Stop()
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-j.ctx.Done():
			result = j.ctx.Err()
			return
		case <-expires.C:
			result = context.DeadlineExceeded
			return
		case <-tick.C:
			if !v.clipboardGeneration(j.generation) {
				result = errConnectionChanged
				return
			}
		}
	}
}

type archiveLimitWriter struct {
	w    io.Writer
	left int
}

func (w *archiveLimitWriter) Write(p []byte) (int, error) {
	if len(p) > w.left {
		return 0, cliprdr.ErrFileLimit
	}
	n, e := w.w.Write(p)
	w.left -= n
	return n, e
}

func (v *viewer) serveClipboardFiles(w http.ResponseWriter, r *http.Request) {
	generation := r.Header.Get("X-OpenRDP-Generation")
	if !v.clipboardGeneration(generation) {
		clipboardError(w, errConnectionChanged)
		return
	}
	w.Header().Set("X-OpenRDP-Generation", generation)
	if r.URL.Path == "/clipboard/files/archive" {
		v.serveFileArchive(w, r, generation)
		return
	}
	if r.Method == http.MethodGet {
		v.clipMu.Lock()
		j := v.fileJob
		v.clipMu.Unlock()
		if j == nil || j.generation != generation || j.status.ID != r.URL.Query().Get("id") {
			http.Error(w, "unknown transfer", 404)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(j.snapshot())
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
	var request struct {
		Action string `json:"action"`
		ID     string `json:"id"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid transfer request", 400)
		return
	}
	v.connectionMu.RLock()
	defer v.connectionMu.RUnlock()
	if !v.clipboardGeneration(generation) {
		clipboardError(w, errConnectionChanged)
		return
	}
	v.clipMu.Lock()
	defer v.clipMu.Unlock()
	if request.Action == "cancel" {
		j := v.fileJob
		if j == nil || j.generation != generation || j.status.ID != request.ID {
			http.Error(w, "unknown transfer", 404)
			return
		}
		j.cancel()
		w.WriteHeader(204)
		return
	}
	if request.Action != "download" || request.ID != "" {
		http.Error(w, "invalid transfer action", 400)
		return
	}
	if !v.fileClipboardEnabled || v.clip == nil || !v.clip.FileStatus().Locking || !v.clip.FileStatus().Streaming {
		clipboardError(w, cliprdr.ErrNotReady)
		return
	}
	if old := v.fileJob; old != nil {
		select {
		case <-old.done:
		default:
			clipboardError(w, cliprdr.ErrBusy)
			return
		}
		if old.snapshot().Error == "cleanup_failed" {
			clipboardError(w, cliprdr.ErrBusy)
			return
		}
	}
	if v.clip.Status().Busy {
		clipboardError(w, cliprdr.ErrBusy)
		return
	}
	found := false
	for _, f := range v.clip.RemoteFormatList() {
		if f.ID >= 0xc000 && strings.EqualFold(f.Name, cliprdr.FileGroupDescriptorName) {
			found = true
		}
	}
	if !found {
		clipboardError(w, cliprdr.ErrNoFormat)
		return
	}
	select {
	case v.clipHTTPGate <- struct{}{}:
	default:
		clipboardError(w, cliprdr.ErrBusy)
		return
	}
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		<-v.clipHTTPGate
		http.Error(w, "cannot start transfer", 500)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	j := &fileJob{generation: generation, client: v.clip, events: make(chan cliprdr.Event, 8), ctx: ctx, cancel: cancel, done: make(chan struct{}), status: fileJobStatus{ID: hex.EncodeToString(id[:]), State: "listing"}}
	v.fileJob = j
	go v.runFileJob(j)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(202)
	json.NewEncoder(w).Encode(j.snapshot())
}

type checkedArchiveReader struct {
	v   *viewer
	j   *fileJob
	r   io.Reader
	ctx context.Context
}

func (r *checkedArchiveReader) Read(p []byte) (int, error) {
	if e := r.ctx.Err(); e != nil {
		return 0, e
	}
	if e := r.j.ctx.Err(); e != nil {
		return 0, e
	}
	if !r.v.clipboardGeneration(r.j.generation) {
		return 0, errConnectionChanged
	}
	return r.r.Read(p)
}

func (v *viewer) serveFileArchive(w http.ResponseWriter, r *http.Request, generation string) {
	if r.Method != http.MethodGet {
		w.WriteHeader(405)
		return
	}
	v.clipMu.Lock()
	j := v.fileJob
	v.clipMu.Unlock()
	if j == nil || j.generation != generation || j.status.ID != r.URL.Query().Get("id") {
		http.Error(w, "unknown transfer", 404)
		return
	}
	j.mu.Lock()
	if j.status.State != "ready" || j.ctx.Err() != nil || j.serving {
		j.mu.Unlock()
		clipboardError(w, cliprdr.ErrBusy)
		return
	}
	j.serving = true
	j.readers.Add(1)
	f, size := j.archive, j.archiveSize
	j.mu.Unlock()
	defer func() { j.mu.Lock(); j.serving = false; j.mu.Unlock(); j.readers.Done() }()
	// Keep a slow browser from retaining a file handle indefinitely.
	err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(30 * time.Second))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		http.Error(w, "download unavailable", 500)
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="rdp-go-files.zip"`)
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	reader := &checkedArchiveReader{v: v, j: j, r: io.NewSectionReader(f, 0, size), ctx: r.Context()}
	if _, err = io.CopyBuffer(w, reader, make([]byte, 64<<10)); err != nil {
		// Content-Length makes truncation detectable; never append an error page.
		return
	}
}
