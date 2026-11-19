package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hq0101/rdp-go/cliprdr"
)

type channelRemote interface {
	ChannelID(string) (uint16, bool)
	WriteChannel(context.Context, uint16, []byte) error
}
type clipResult struct {
	text    string
	err     error
	data    []byte
	format  cliprdr.Format
	version uint64
	hasText bool
}
type clipboardStatus struct {
	Enabled bool `json:"enabled"`
	cliprdr.Status
	Served       uint64 `json:"served"`
	RemoteHTML   bool   `json:"remote_html"`
	RemoteImage  bool   `json:"remote_image"`
	FileDownload bool   `json:"file_download"`
	FileUpload   bool   `json:"file_upload"`
	RemoteFiles  bool   `json:"remote_files"`
	FileBusy     bool   `json:"file_busy"`
}

func imageClipboardFormat(formats []cliprdr.Format) (cliprdr.Format, bool) {
	for _, want := range []cliprdr.Format{{Name: cliprdr.PNGName}, {ID: cliprdr.DIBV5}, {ID: cliprdr.DIB}} {
		for _, f := range formats {
			if want.Name != "" && f.ID >= 0xc000 && strings.EqualFold(want.Name, f.Name) || want.ID != 0 && want.ID == f.ID {
				return f, true
			}
		}
	}
	return cliprdr.Format{}, false
}

func (v *viewer) clipboardStatus() clipboardStatus {
	v.clipMu.Lock()
	defer v.clipMu.Unlock()
	if v.clip == nil {
		return clipboardStatus{}
	}
	s := clipboardStatus{Enabled: true, Status: v.clip.Status(), Served: v.clipServed}
	fs := v.clip.FileStatus()
	s.FileDownload = v.fileClipboardEnabled && fs.Streaming && fs.Locking
	s.FileUpload = v.fileClipboardEnabled && fs.Streaming && (v.sources == nil || !v.sources.failed.Load())
	if v.uploadJob != nil {
		select {
		case <-v.uploadJob.done:
		default:
			s.FileBusy = true
		}
	}
	if v.fileJob != nil {
		select {
		case <-v.fileJob.done:
		default:
			s.FileBusy = true
		}
	}
	formats := v.clip.RemoteFormatList()
	for _, f := range formats {
		if f.ID >= 0xc000 && strings.EqualFold(f.Name, cliprdr.FileGroupDescriptorName) {
			s.RemoteFiles = true
		}
		if f.ID >= 0xc000 && strings.EqualFold(f.Name, cliprdr.HTMLName) {
			s.RemoteHTML = true
		}
	}
	_, s.RemoteImage = imageClipboardFormat(formats)
	return s
}
func (v *viewer) receiveClipboard(ctx context.Context, chunk []byte) error {
	v.clipMu.Lock()
	defer v.clipMu.Unlock()
	b, complete, err := v.clipDecoder.Feed(chunk)
	if err != nil || !complete {
		return err
	}
	replies, event, err := v.clip.Handle(b)
	v.reconcileSources()
	if err != nil {
		return err
	}
	fileReplies, err := v.routeFileEvent(event)
	if err != nil {
		return err
	}
	replies = append(replies, fileReplies...)
	sourceReplies, err := v.routeSourceEvent(event)
	if err != nil {
		return err
	}
	replies = append(replies, sourceReplies...)
	writeCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	for _, reply := range replies {
		if err := v.remote.(channelRemote).WriteChannel(writeCtx, v.clipChannel, reply); err != nil {
			return writeFailure(err)
		}
	}
	if event.Kind == cliprdr.TextServed || event.Kind == cliprdr.DataServed {
		v.clipServed++
	}
	if v.clipWait != nil && (event.Kind == cliprdr.TextResult || event.Kind == cliprdr.DataResult || event.Kind == cliprdr.OfferResult) {
		v.clipWait <- clipResult{text: event.Text, err: event.Err, data: event.Data, format: event.Format}
		v.clipWait = nil
	}
	return nil
}

func (v *viewer) clipboardGeneration(generation string) bool {
	v.frameMu.Lock()
	defer v.frameMu.Unlock()
	return !v.stopping.Load() && v.active && v.reconnection.Phase == "connected" && generation == strconv.FormatUint(v.generation, 10)
}

var errClipboardTransport = errors.New("clipboard transport failed")

// Never hold connectionMu across the reply wait or image conversion. A second
// representation must have the same remote ownership version as the first.
func (v *viewer) clipboardExchange(r *http.Request, offer *[]cliprdr.Data, format string, version *uint64) (clipResult, error) {
	var result clipResult
	v.connectionMu.RLock()
	locked := true
	unlock := func() {
		if locked {
			v.connectionMu.RUnlock()
			locked = false
		}
	}
	defer unlock()
	generation := r.Header.Get("X-RdpGo-Generation")
	if !v.clipboardGeneration(generation) {
		return result, errConnectionChanged
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	v.clipMu.Lock()
	if v.clip == nil {
		v.clipMu.Unlock()
		return result, cliprdr.ErrNotReady
	}
	state := v.clip.Status()
	if version != nil && *version != state.RemoteVersion {
		v.clipMu.Unlock()
		return result, cliprdr.ErrChanged
	}
	var b []byte
	var err error
	switch {
	case offer != nil:
		b, err = v.clip.Publish(*offer)
		v.reconcileSources()
	case format == "text":
		b, err = v.clip.RequestText()
	case format == "html":
		b, err = v.clip.Request(cliprdr.Format{Name: cliprdr.HTMLName})
	case format == "image":
		f, found := imageClipboardFormat(v.clip.RemoteFormatList())
		if !found {
			err = cliprdr.ErrNoFormat
		} else {
			b, err = v.clip.Request(f)
		}
	default:
		err = cliprdr.ErrFormat
	}
	if err != nil {
		v.clipMu.Unlock()
		return result, err
	}
	wait := make(chan clipResult, 1)
	v.clipWait = wait
	err = v.remote.(channelRemote).WriteChannel(ctx, v.clipChannel, b)
	v.clipMu.Unlock()
	defer func() {
		v.clipMu.Lock()
		if v.clipWait == wait {
			v.clipWait = nil
		}
		v.clipMu.Unlock()
	}()
	if err != nil {
		if v.writeInterrupted("clipboard transport write failed") {
			return result, errConnectionChanged
		}
		return result, errClipboardTransport
	}
	unlock()
	select {
	case result = <-wait:
		if !v.clipboardGeneration(generation) {
			return clipResult{}, errConnectionChanged
		}
		result.version, result.hasText = state.RemoteVersion, state.RemoteText
		return result, result.err
	case <-ctx.Done():
		// Pending protocol state remains until its untagged response is drained.
		return result, ctx.Err()
	}
}

// Explicit authenticated actions only. Status contains availability, never
// content or registered private format names. One HTTP operation owns the large
// decode/encode budget; a timed-out wire request remains busy until drained.
func (v *viewer) serveClipboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	select {
	case v.clipHTTPGate <- struct{}{}:
		defer func() { <-v.clipHTTPGate }()
	default:
		clipboardError(w, cliprdr.ErrBusy)
		return
	}
	generation := r.Header.Get("X-RdpGo-Generation")
	if !v.clipboardGeneration(generation) {
		clipboardError(w, errConnectionChanged)
		return
	}
	w.Header().Set("X-RdpGo-Generation", generation)
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	var request struct {
		Action string  `json:"action"`
		Format string  `json:"format"`
		Text   *string `json:"text"`
		HTML   string  `json:"html"`
	}
	var offer []cliprdr.Data
	if r.URL.Path == "/clipboard/image" {
		if media != "image/png" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		b, e := io.ReadAll(http.MaxBytesReader(w, r.Body, cliprdr.MaxDataBytes))
		if e != nil {
			http.Error(w, "image exceeds clipboard limit", 413)
			return
		}
		img, e := cliprdr.DecodePNG(b)
		if e != nil {
			clipboardError(w, e)
			return
		}
		dib, e := cliprdr.EncodeDIBV5(img)
		if e != nil {
			clipboardError(w, e)
			return
		}
		png, e := cliprdr.EncodePNG(img) // normalize away ancillary metadata
		if e != nil {
			clipboardError(w, e)
			return
		}
		offer = []cliprdr.Data{{Format: cliprdr.Format{ID: 0xc002, Name: cliprdr.PNGName}, Bytes: png}, {Format: cliprdr.Format{ID: cliprdr.DIBV5}, Bytes: dib}}
		request.Action = "set"
	} else {
		if media != "application/json" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		// JSON escaping can cost six bytes per character. Content limits remain
		// independent; only one handler can allocate this body at a time.
		d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 6*(cliprdr.MaxHTMLBytes+cliprdr.MaxTextBytes)+1024))
		d.DisallowUnknownFields()
		if err := d.Decode(&request); err != nil {
			http.Error(w, "invalid clipboard request", 400)
			return
		}
		if d.Decode(new(any)) != io.EOF {
			http.Error(w, "invalid clipboard request", 400)
			return
		}
		if request.Format == "" {
			request.Format = "text"
		}
		if (request.Action != "set" && request.Action != "get") || (request.Format != "text" && request.Format != "html" && request.Format != "image") || (request.Action == "get" && (request.HTML != "" || request.Text != nil && *request.Text != "")) || (request.Format != "html" && request.HTML != "") || (request.Action == "set" && request.Format == "image") {
			http.Error(w, "invalid clipboard action", 400)
			return
		}
		if request.Action == "set" {
			if request.Format == "html" {
				b, e := cliprdr.EncodeHTML(request.HTML)
				if e != nil {
					clipboardError(w, e)
					return
				}
				offer = append(offer, cliprdr.Data{Format: cliprdr.Format{ID: 0xc001, Name: cliprdr.HTMLName}, Bytes: b})
			}
			if request.Text != nil || request.Format == "text" {
				text := ""
				if request.Text != nil {
					text = *request.Text
				}
				b, e := cliprdr.EncodeText(text)
				if e != nil {
					clipboardError(w, e)
					return
				}
				offer = append(offer, cliprdr.Data{Format: cliprdr.Format{ID: cliprdr.UnicodeText}, Bytes: b})
			}
		}
	}
	if request.Action == "set" {
		_, err = v.clipboardExchange(r, &offer, "", nil)
		if err != nil {
			clipboardError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	result, err := v.clipboardExchange(r, nil, request.Format, nil)
	if err != nil {
		clipboardError(w, err)
		return
	}
	var body any
	var png []byte
	switch request.Format {
	case "text":
		body = struct {
			Text string `json:"text"`
		}{result.text}
	case "html":
		h, e := cliprdr.DecodeHTML(result.data)
		if e != nil {
			clipboardError(w, e)
			return
		}
		plain := ""
		if result.hasText {
			p, e := v.clipboardExchange(r, nil, "text", &result.version)
			if e != nil {
				clipboardError(w, e)
				return
			}
			plain = p.text
		}
		body = struct {
			HTML    string `json:"html"`
			Text    string `json:"text"`
			HasText bool   `json:"has_text"`
		}{h.Fragment, plain, result.hasText}
	case "image":
		if result.format.ID == cliprdr.DIB || result.format.ID == cliprdr.DIBV5 {
			img, e := cliprdr.DecodeDIB(result.data)
			if e != nil {
				clipboardError(w, e)
				return
			}
			png, err = cliprdr.EncodePNG(img)
		} else {
			img, e := cliprdr.DecodePNG(result.data)
			if e != nil {
				clipboardError(w, e)
				return
			}
			png, err = cliprdr.EncodePNG(img)
		}
		if err != nil {
			clipboardError(w, err)
			return
		}
	}
	if !v.clipboardGeneration(generation) {
		clipboardError(w, errConnectionChanged)
		return
	}
	if png != nil {
		w.Header().Set("Content-Type", "image/png")
		w.Write(png)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(body)
}
func clipboardError(w http.ResponseWriter, err error) {
	code := http.StatusConflict
	if errors.Is(err, cliprdr.ErrText) || errors.Is(err, cliprdr.ErrFormat) || errors.Is(err, cliprdr.ErrHTML) || errors.Is(err, cliprdr.ErrImage) {
		code = http.StatusBadRequest
	}
	if errors.Is(err, cliprdr.ErrRejected) {
		code = http.StatusUnprocessableEntity
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		code = http.StatusGatewayTimeout
	}
	if errors.Is(err, errClipboardTransport) {
		code = http.StatusBadGateway
	}
	http.Error(w, err.Error(), code)
}
