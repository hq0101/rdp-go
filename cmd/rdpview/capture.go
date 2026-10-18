package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/hq0101/rdp-go/audin"
	"github.com/hq0101/rdp-go/dynvc"
)

const captureLease = 5 * time.Second
const captureWindow = 200 * time.Millisecond

type captureChunk struct {
	data []byte
	at   time.Time
}
type viewerCapture struct {
	client                                    *audin.Client
	id                                        uint32
	request                                   *audin.Request
	owner                                     string
	deadline, next                            time.Time
	queue                                     []captureChunk
	bytes                                     int
	primed                                    bool
	sequence                                  uint64
	ignored                                   int
	submitted, sent, silence, dropped, resets uint64
}
type captureStatus struct {
	Enabled         bool   `json:"enabled"`
	Epoch           string `json:"epoch"`
	Recording       bool   `json:"recording"`
	Ready           bool   `json:"ready"`
	Channels        uint16 `json:"channels"`
	SampleRate      uint32 `json:"sample_rate"`
	FramesPerPacket uint32 `json:"frames_per_packet"`
	BufferedBytes   int    `json:"buffered_bytes"`
	Submitted       uint64 `json:"submitted_frames"`
	Sent            uint64 `json:"sent_frames"`
	Silence         uint64 `json:"silence_frames"`
	Dropped         uint64 `json:"dropped_frames"`
	Resets          uint64 `json:"pacing_resets"`
}

func (v *viewer) captureStatus() captureStatus {
	v.captureMu.Lock()
	defer v.captureMu.Unlock()
	return v.captureStatusLocked()
}
func (v *viewer) captureStatusLocked() captureStatus {
	s := captureStatus{Epoch: strconv.FormatUint(v.captureEpoch, 10)}
	if a := v.capture; a != nil {
		s.Enabled = true
		s.Recording = a.owner != ""
		s.Ready = a.request != nil
		if a.request != nil {
			s.Channels = a.request.Format.Channels
			s.SampleRate = a.request.Format.SampleRate
			s.FramesPerPacket = a.request.FramesPerPacket
		}
		s.BufferedBytes = a.bytes
		s.Submitted = a.submitted
		s.Sent = a.sent
		s.Silence = a.silence
		s.Dropped = a.dropped
		s.Resets = a.resets
	}
	return s
}
func (a *viewerCapture) clearQueue() {
	if a.request != nil {
		a.dropped += uint64(a.bytes / a.request.Format.BlockAlign())
	}
	for _, b := range a.queue {
		clear(b.data)
	}
	a.queue = nil
	a.bytes = 0
	a.primed = false
}

// connectionMu is held by callers. Invalidation never writes on an old session.
func (v *viewer) resetCapture() {
	v.captureMu.Lock()
	defer v.captureMu.Unlock()
	v.captureEpoch++
	if a := v.capture; a != nil {
		a.clearQueue()
		if a.client != nil {
			a.client.Close()
		}
	}
	v.capture = nil
}
func (v *viewer) captureChanged(a *viewerCapture) { a.clearQueue(); a.sequence = 0; v.captureEpoch++ }
func (v *viewer) captureStop(a *viewerCapture) {
	v.captureChanged(a)
	a.owner = ""
	a.deadline = time.Time{}
}

// The opt-in virtual device supplies silence until a browser source is granted.
// Muting stops physical capture, but leaves the remote application device open.
// connectionMu is held; this lock never requires display/frame/input locks.
func (v *viewer) receiveCapture(ctx context.Context, e dynvc.Event) error {
	v.captureMu.Lock()
	defer v.captureMu.Unlock()
	a := v.capture
	if a == nil {
		return dynvc.ErrChannel
	}
	switch e.Kind {
	case dynvc.Opened:
		if a.client != nil {
			return dynvc.ErrProtocol
		}
		r := v.remote.(managedDynamicRemote)
		id := e.ID
		var formats []audin.Format
		for _, rate := range []uint32{8000, 11025, 16000, 22050, 32000, 44100, 48000, 64000, 88200, 96000} {
			for _, ch := range []uint16{1, 2} {
				formats = append(formats, audin.Format{Channels: ch, SampleRate: rate})
			}
		}
		c, err := audin.New(audin.Config{Formats: formats}, func(ctx context.Context, b []byte) error { return r.SendDynamic(ctx, id, b) })
		if err != nil {
			return err
		}
		v.captureChanged(a)
		a.client = c
		a.id = id
		a.request = nil
	case dynvc.Data:
		if a.client == nil || a.id != e.ID {
			return dynvc.ErrChannel
		}
		ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		result, err := a.client.Handle(ctx, e.Data)
		if errors.Is(err, audin.ErrProtocol) || errors.Is(err, audin.ErrSequence) || errors.Is(err, audin.ErrLimit) {
			a.ignored++
			if a.ignored <= 16 {
				return nil
			}
			return err
		}
		if err != nil {
			return writeFailure(err)
		}
		if q := result.Request; q != nil {
			v.captureChanged(a)
			if time.Duration(q.FramesPerPacket)*time.Second/time.Duration(q.Format.SampleRate) > captureWindow {
				if !q.Change {
					if err := a.client.CompleteOpen(ctx, q.Token, 0x80004005); err != nil {
						return writeFailure(err)
					}
				}
				a.client.Close()
				a.client = nil
				a.request = nil
				return writeFailure(v.remote.(interface {
					CloseDynamic(context.Context, uint32) error
				}).CloseDynamic(ctx, e.ID))
			}
			// The bounded PCM/silence source is ready before the Open reply.
			a.request = q
			a.next = time.Now()
			if q.Change {
				err = a.client.ConfirmFormat(ctx, q.Token)
			} else {
				err = a.client.CompleteOpen(ctx, q.Token, 0)
			}
			if err != nil {
				return writeFailure(err)
			}
		}
	case dynvc.Closed:
		v.captureChanged(a)
		if a.client != nil {
			a.client.Close()
		}
		a.client = nil
		a.request = nil
	}
	return nil
}

// captureTick owns the sole capture clock. Each invocation writes at most four
// frames; a stalled clock drops queued audio instead of replaying an old backlog.
func (v *viewer) captureTick(ctx context.Context, now time.Time) error {
	v.connectionMu.RLock()
	defer v.connectionMu.RUnlock()
	v.captureMu.Lock()
	defer v.captureMu.Unlock()
	a := v.capture
	if a == nil {
		return nil
	}
	if a.owner != "" && !now.Before(a.deadline) {
		v.captureStop(a)
	}
	q := a.request
	if a.client == nil || q == nil {
		return nil
	}
	d := time.Duration(q.FramesPerPacket) * time.Second / time.Duration(q.Format.SampleRate)
	if !a.next.IsZero() && now.Sub(a.next) > captureWindow {
		a.clearQueue()
		a.resets++
		a.next = now
	}
	for len(a.queue) > 0 && now.Sub(a.queue[0].at) > captureWindow {
		old := a.queue[0]
		a.dropped += uint64(len(old.data) / q.Format.BlockAlign())
		a.bytes -= len(old.data)
		clear(old.data)
		a.queue[0] = captureChunk{}
		a.queue = a.queue[1:]
	}
	for burst := 0; burst < 4 && !now.Before(a.next); burst++ {
		pcm := make([]byte, q.PacketBytes())
		if !a.primed && a.bytes >= min(q.PacketBytes()*2, int(q.Format.SampleRate)*q.Format.BlockAlign()/5) {
			a.primed = true
		}
		voiced := a.owner != "" && a.primed && a.bytes >= len(pcm)
		if voiced {
			for pos := 0; pos < len(pcm); {
				chunk := &a.queue[0]
				n := copy(pcm[pos:], chunk.data)
				clear(chunk.data[:n])
				chunk.data = chunk.data[n:]
				pos += n
				a.bytes -= n
				if len(chunk.data) == 0 {
					a.queue[0] = captureChunk{}
					a.queue = a.queue[1:]
				}
			}
		} else if a.primed {
			a.clearQueue()
		}
		x, cancel := context.WithTimeout(ctx, 3*time.Second)
		err := a.client.WritePCM(x, q.Token, pcm)
		cancel()
		clear(pcm)
		if err != nil {
			v.captureChanged(a)
			a.client.Close()
			a.client = nil
			a.request = nil
			if errors.Is(err, dynvc.ErrChannel) {
				return nil
			}
			return writeFailure(err)
		}
		if voiced {
			a.sent += uint64(q.FramesPerPacket)
		} else {
			a.silence += uint64(q.FramesPerPacket)
		}
		a.next = a.next.Add(d)
	}
	if !now.Before(a.next) {
		a.clearQueue()
		a.resets++
		a.next = now.Add(d)
	}
	return nil
}
func (v *viewer) watchCapture(ctx context.Context) {
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			if err := v.captureTick(ctx, now); err != nil {
				v.connectionMu.RLock()
				v.writeInterrupted("microphone transport interrupted")
				v.connectionMu.RUnlock()
			}
		}
	}
}

type captureRequest struct {
	Action   string `json:"action"`
	Client   string `json:"client"`
	Epoch    string `json:"epoch"`
	Sequence uint64 `json:"sequence,omitempty"`
	Data     []byte `json:"data,omitempty"`
}

func (v *viewer) serveCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" {
		w.WriteHeader(415)
		return
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 65536))
	d.DisallowUnknownFields()
	var req captureRequest
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF || !validAudioClient(req.Client) || (req.Action != "start" && req.Action != "stop" && req.Action != "poll" && req.Action != "data") || (req.Action != "data" && (len(req.Data) != 0 || req.Sequence != 0)) {
		http.Error(w, "invalid microphone request", 400)
		return
	}
	defer clear(req.Data)
	v.connectionMu.RLock()
	defer v.connectionMu.RUnlock()
	v.frameMu.Lock()
	connected := v.reconnection.Phase == "connected"
	v.frameMu.Unlock()
	v.captureMu.Lock()
	defer v.captureMu.Unlock()
	a := v.capture
	now := time.Now()
	if a == nil || !connected {
		http.Error(w, "microphone connection changed", 409)
		return
	}
	if a.owner != "" && !now.Before(a.deadline) {
		v.captureStop(a)
	}
	// Stop's unique owner nonce also cleans up a lost Start response. It cannot
	// cancel a different browser, including a new lease in the same page.
	if req.Action == "stop" {
		if a.owner == req.Client {
			v.captureStop(a)
		}
		w.WriteHeader(204)
		return
	}
	if req.Action == "start" {
		if req.Epoch != strconv.FormatUint(v.captureEpoch, 10) || (a.owner != "" && a.owner != req.Client) {
			http.Error(w, "microphone already owned or changed", 409)
			return
		}
		if a.owner == "" {
			v.captureChanged(a)
			a.owner = req.Client
		}
	} else if a.owner != req.Client {
		http.Error(w, "microphone source changed", 409)
		return
	}
	if req.Action == "data" {
		q := a.request
		if req.Epoch != strconv.FormatUint(v.captureEpoch, 10) || q == nil || req.Sequence != a.sequence+1 {
			http.Error(w, "microphone stream changed", 409)
			return
		}
		align := q.Format.BlockAlign()
		limit := int(q.Format.SampleRate) * align / 5
		if len(req.Data) == 0 || len(req.Data)%align != 0 || len(req.Data) > int(q.Format.SampleRate)*align/20 {
			http.Error(w, "invalid microphone block", 400)
			return
		}
		if len(a.queue) >= 32 || a.bytes+len(req.Data) > limit {
			http.Error(w, "microphone queue full", 429)
			return
		}
		a.queue = append(a.queue, captureChunk{append([]byte(nil), req.Data...), now})
		a.bytes += len(req.Data)
		a.sequence++
		a.submitted += uint64(len(req.Data) / align)
	}
	a.deadline = now.Add(captureLease)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v.captureStatusLocked())
}
