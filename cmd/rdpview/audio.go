package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/hq0101/rdp-go/rdpdr"
	"github.com/hq0101/rdp-go/rdpsnd"
	"github.com/hq0101/rdp-go/vchan"
)

const (
	audioLease       = 10 * time.Second
	audioQueueTime   = time.Second
	audioQueueBytes  = 1 << 20 // decoded float32, not base64 JSON
	audioQueueBlocks = 32
)

type audioBlock struct {
	Token      string `json:"token"`
	Channels   uint16 `json:"channels"`
	SampleRate uint32 `json:"sample_rate"`
	Data       []byte `json:"data"` // little-endian float32, interleaved
	id         uint64
	duration   time.Duration
	delivered  bool
}

type audioMessage struct {
	data     []byte
	received time.Time
}
type viewerAudio struct {
	client                                *rdpsnd.Client
	device                                rdpdr.CoreClient
	channel, deviceChannel                uint16
	decoder, deviceDecoder                vchan.Decoder
	owner                                 string
	deadline                              time.Time
	changed                               chan struct{}
	polling                               bool
	blocks                                []*audioBlock
	bytes                                 int
	duration                              time.Duration
	deferred                              []audioMessage
	deferredBytes                         int
	completed                             map[string]bool
	completedOrder                        []string
	negotiated, streamClosed, deviceReady bool
	formats                               []rdpsnd.Format
	received, played, dropped, ignored    uint64
}

type audioStatus struct {
	Enabled       bool   `json:"enabled"`
	Epoch         string `json:"epoch"`
	Playing       bool   `json:"playing"`
	Negotiated    bool   `json:"negotiated"`
	StreamClosed  bool   `json:"stream_closed"`
	DeviceReady   bool   `json:"device_ready"`
	Pending       int    `json:"pending"`
	BufferedBytes int    `json:"buffered_bytes"`
	Received      uint64 `json:"received"`
	Played        uint64 `json:"played"`
	Dropped       uint64 `json:"dropped"`
	Ignored       uint64 `json:"ignored"`
}

func newViewerAudio(r channelRemote) (*viewerAudio, error) {
	id, ok := r.ChannelID(rdpsnd.ChannelName)
	if !ok {
		return nil, errors.New("audio requires rdpsnd")
	}
	deviceID, ok := r.ChannelID(rdpdr.ChannelName)
	if !ok {
		return nil, errors.New("Windows audio requires rdpdr")
	}
	// Web Audio guarantees support for this sample-rate range. The browser
	// resamples each AudioBuffer to its output device rate, without OS bindings.
	var formats []rdpsnd.Format
	for _, rate := range []uint32{8000, 11025, 12000, 16000, 22050, 24000, 32000, 44100, 48000, 64000, 88200, 96000} {
		for _, channels := range []uint16{1, 2} {
			for _, bits := range []uint16{8, 16, 24, 32} {
				formats = append(formats, rdpsnd.Format{Channels: channels, SampleRate: rate, BitsPerSample: bits})
			}
		}
	}
	c, err := rdpsnd.New(rdpsnd.Config{Quality: rdpsnd.HighQuality, Codecs: []rdpsnd.Encoding{rdpsnd.PCM, rdpsnd.MSADPCM, rdpsnd.IMAADPCM}, Formats: formats, MaxPending: 128, MaxPendingBytes: 8 << 20})
	if err != nil {
		return nil, err
	}
	return &viewerAudio{client: c, channel: id, deviceChannel: deviceID, changed: make(chan struct{}), completed: make(map[string]bool)}, nil
}

func (v *viewer) audioStatus() audioStatus {
	v.audioMu.Lock()
	defer v.audioMu.Unlock()
	s := audioStatus{Epoch: strconv.FormatUint(v.audioEpoch, 10)}
	if a := v.audio; a != nil {
		s.Enabled = true
		s.Playing = a.owner != ""
		s.Negotiated = a.negotiated
		s.StreamClosed = a.streamClosed
		s.DeviceReady = a.deviceReady
		s.Pending = len(a.blocks)
		s.BufferedBytes = a.bytes
		s.Received = a.received
		s.Played = a.played
		s.Dropped = a.dropped
		s.Ignored = a.ignored
	}
	return s
}

func (a *viewerAudio) signal() { close(a.changed); a.changed = make(chan struct{}) }

// Caller holds connectionMu; taking audioMu never requires frame/input locks.
// No confirmation is sent on a dead transport or from a discarded candidate.
func (v *viewer) resetAudio() {
	v.audioMu.Lock()
	defer v.audioMu.Unlock()
	v.audioEpoch++
	if a := v.audio; a != nil {
		a.client.Close()
		for _, b := range a.blocks {
			clear(b.Data)
		}
		for _, m := range a.deferred {
			clear(m.data)
		}
		a.blocks = nil
		a.deferred = nil
		a.owner = ""
		a.bytes = 0
		a.duration = 0
		a.signal()
	}
	v.audio = nil
}

// Caller holds connectionMu.RLock and audioMu. Network writes have a total
// bound per operation; a write failure is eligible for the existing recovery.
func (v *viewer) audioWrite(ctx context.Context, channel uint16, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return writeFailure(v.remote.(channelRemote).WriteChannel(ctx, channel, data))
}

func (v *viewer) confirmAudio(ctx context.Context, a *viewerAudio, id uint64, now time.Time) error {
	reply, err := a.client.Confirm(id, now)
	if err != nil {
		return err
	}
	return v.audioWrite(ctx, a.channel, reply)
}

func (v *viewer) consumeAudio(ctx context.Context, a *viewerAudio, index int, played, remember bool, now time.Time) error {
	b := a.blocks[index]
	if err := v.confirmAudio(ctx, a, b.id, now); err != nil {
		return err
	}
	a.bytes -= len(b.Data)
	a.duration -= b.duration
	clear(b.Data)
	b.Data = nil
	copy(a.blocks[index:], a.blocks[index+1:])
	a.blocks[len(a.blocks)-1] = nil
	a.blocks = a.blocks[:len(a.blocks)-1]
	if played {
		a.played++
	} else {
		a.dropped++
	}
	if remember {
		a.completed[b.Token] = true
		a.completedOrder = append(a.completedOrder, b.Token)
		if len(a.completedOrder) > 64 {
			delete(a.completed, a.completedOrder[0])
			a.completedOrder = a.completedOrder[1:]
		}
	}
	return nil
}

func (v *viewer) stopAudio(ctx context.Context, a *viewerAudio, now time.Time) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	// The browser stops nodes before requesting this. Lease expiry also abandons
	// the old sink, whose scheduled window is bounded, rather than claiming play.
	a.owner = ""
	a.polling = false
	a.deadline = time.Time{}
	v.audioEpoch++
	a.signal()
	for len(a.blocks) > 0 {
		if err := v.consumeAudio(ctx, a, 0, false, false, now); err != nil {
			return err
		}
	}
	clear(a.completed)
	a.completedOrder = nil
	return v.drainAudio(ctx, a)
}

func (v *viewer) handleAudioMessage(ctx context.Context, a *viewerAudio, m audioMessage) error {
	result, err := a.client.Handle(m.data, m.received)
	if err != nil {
		if errors.Is(err, rdpsnd.ErrPending) {
			return err
		}
		a.ignored++
		if a.ignored > 16 {
			return err
		}
		return nil
	}
	for _, reply := range result.Replies {
		if err := v.audioWrite(ctx, a.channel, reply); err != nil {
			return err
		}
	}
	if result.Negotiated {
		a.negotiated = true
		a.formats = result.Formats
		a.streamClosed = false
	}
	if result.StreamClosed {
		a.streamClosed = true
	}
	if frame := result.Frame; frame != nil {
		a.received++
		duration, _ := frame.Format.Duration(len(frame.PCM))
		floatBytes := len(frame.PCM) / (int(frame.Format.BitsPerSample) / 8) * 4
		// Allow a single long valid block; never stack further blocks behind it.
		// Ordinary output is bounded to one second / 1 MiB / 32 blocks, including
		// delivered blocks whose browser completion has not arrived yet.
		if a.owner == "" || len(a.blocks) >= audioQueueBlocks || floatBytes > audioQueueBytes-a.bytes || (len(a.blocks) > 0 && a.duration+duration > audioQueueTime) {
			clear(frame.PCM)
			a.dropped++
			if err := v.confirmAudio(ctx, a, frame.Token, time.Now()); err != nil {
				return err
			}
		} else {
			samples, err := rdpsnd.DecodePCM(frame.Format, frame.PCM)
			clear(frame.PCM)
			if err != nil {
				return err
			}
			data := make([]byte, len(samples)*4)
			for i, x := range samples {
				binary.LittleEndian.PutUint32(data[i*4:], math.Float32bits(x))
			}
			clear(samples)
			a.blocks = append(a.blocks, &audioBlock{Token: strconv.FormatUint(frame.Token, 10), Channels: frame.Format.Channels, SampleRate: frame.Format.SampleRate, Data: data, id: frame.Token, duration: duration})
			a.bytes += len(data)
			a.duration += duration
		}
	}
	a.signal()
	return nil
}

func (v *viewer) deferAudio(a *viewerAudio, m audioMessage) error {
	if len(a.deferred) >= 16 || len(m.data) > 1<<20-a.deferredBytes {
		return errors.New("audio negotiation queue exceeded")
	}
	a.deferred = append(a.deferred, m)
	a.deferredBytes += len(m.data)
	return nil
}

func (v *viewer) drainAudio(ctx context.Context, a *viewerAudio) error {
	for len(a.deferred) > 0 {
		m := a.deferred[0]
		err := v.handleAudioMessage(ctx, a, m)
		if errors.Is(err, rdpsnd.ErrPending) {
			return nil
		}
		if err != nil {
			return err
		}
		a.deferredBytes -= len(m.data)
		clear(m.data)
		a.deferred[0] = audioMessage{}
		a.deferred = a.deferred[1:]
	}
	return nil
}

func (v *viewer) receiveAudio(ctx context.Context, channel uint16, chunk []byte) error {
	v.audioMu.Lock()
	defer v.audioMu.Unlock()
	a := v.audio
	if a == nil {
		return nil
	}
	if channel == a.deviceChannel {
		data, complete, err := a.deviceDecoder.Feed(chunk)
		if err != nil || !complete {
			return err
		}
		result, err := a.device.Handle(data)
		if err != nil {
			a.ignored++
			if a.ignored > 16 {
				return err
			}
			return nil
		}
		for _, reply := range result.Replies {
			if err := v.audioWrite(ctx, channel, reply); err != nil {
				return err
			}
		}
		a.deviceReady = result.Ready
		return nil
	}
	data, complete, err := a.decoder.Feed(chunk)
	if err != nil || !complete {
		return err
	}
	now := time.Now()
	if a.owner != "" && !now.Before(a.deadline) {
		if err := v.stopAudio(ctx, a, now); err != nil {
			return err
		}
	}
	m := audioMessage{data, now}
	if len(a.deferred) > 0 {
		return v.deferAudio(a, m)
	}
	if err := v.handleAudioMessage(ctx, a, m); errors.Is(err, rdpsnd.ErrPending) {
		return v.deferAudio(a, m)
	} else {
		return err
	}
}

func (v *viewer) expireAudio(ctx context.Context, now time.Time) error {
	v.connectionMu.RLock()
	defer v.connectionMu.RUnlock()
	v.audioMu.Lock()
	defer v.audioMu.Unlock()
	if a := v.audio; a != nil && a.owner != "" && !now.Before(a.deadline) {
		return v.stopAudio(ctx, a, now)
	}
	return nil
}

func (v *viewer) watchAudio(ctx context.Context) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := v.expireAudio(ctx, now); err != nil {
				v.connectionMu.RLock()
				v.writeInterrupted("audio confirmation failed")
				v.connectionMu.RUnlock()
			}
		}
	}
}

type audioRequest struct {
	Action string   `json:"action"`
	Client string   `json:"client"`
	Epoch  string   `json:"epoch"`
	Tokens []string `json:"tokens,omitempty"`
}
type audioResponse struct {
	Epoch        string        `json:"epoch"`
	Blocks       []*audioBlock `json:"blocks,omitempty"`
	StreamClosed bool          `json:"stream_closed"`
}

func validAudioClient(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, b := range []byte(s) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

// Uses the common host/origin/token checks. Long polling never holds the
// connection lock while waiting, so it cannot obstruct a session replacement.
func (v *viewer) serveAudio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		w.WriteHeader(415)
		return
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
	d.DisallowUnknownFields()
	var req audioRequest
	if d.Decode(&req) != nil || d.Decode(new(any)) != io.EOF || !validAudioClient(req.Client) || (req.Action != "start" && req.Action != "stop" && req.Action != "poll" && req.Action != "ack") || len(req.Tokens) > 32 || (req.Action == "ack" && len(req.Tokens) == 0) || (req.Action != "ack" && len(req.Tokens) != 0) {
		http.Error(w, "invalid audio request", 400)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	var polling *viewerAudio
	defer func() {
		if polling != nil {
			v.audioMu.Lock()
			if v.audio == polling && polling.owner == req.Client && strconv.FormatUint(v.audioEpoch, 10) == req.Epoch {
				polling.polling = false
			}
			v.audioMu.Unlock()
		}
	}()
	waited := false
	for {
		v.connectionMu.RLock()
		v.audioMu.Lock()
		unlock := func() { v.audioMu.Unlock(); v.connectionMu.RUnlock() }
		a := v.audio
		epoch := strconv.FormatUint(v.audioEpoch, 10)
		if a == nil || v.stopping.Load() {
			unlock()
			http.Error(w, "audio unavailable", 409)
			return
		}
		if a.owner != "" && !time.Now().Before(a.deadline) {
			if err := v.stopAudio(ctx, a, time.Now()); err != nil {
				v.writeInterrupted("audio lease cleanup failed")
				unlock()
				http.Error(w, "audio transport failed", 502)
				return
			}
			epoch = strconv.FormatUint(v.audioEpoch, 10)
		}
		if req.Action == "start" {
			v.frameMu.Lock()
			connected := v.reconnection.Phase == "connected"
			v.frameMu.Unlock()
			if !connected || (a.owner != "" && a.owner != req.Client) || (a.owner == "" && req.Epoch != epoch) {
				unlock()
				http.Error(w, "audio occupied or connection changed", 409)
				return
			}
			if a.owner == "" {
				v.audioEpoch++
				epoch = strconv.FormatUint(v.audioEpoch, 10)
				a.owner = req.Client
				clear(a.completed)
				a.completedOrder = nil
				a.signal()
			}
			a.deadline = time.Now().Add(audioLease)
			unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(audioResponse{Epoch: epoch})
			return
		}
		// Stop is also compensation for a lost Start response. Client nonces are
		// unique per Start; an old page can never stop a different owner's lease.
		if a.owner != req.Client || (req.Action != "stop" && epoch != req.Epoch) {
			unlock()
			http.Error(w, "audio lease changed", 409)
			return
		}
		a.deadline = time.Now().Add(audioLease)
		if req.Action == "stop" {
			err := v.stopAudio(ctx, a, time.Now())
			if err != nil {
				v.writeInterrupted("audio stop failed")
			}
			unlock()
			if err != nil {
				http.Error(w, "audio transport failed", 502)
			} else {
				w.WriteHeader(204)
			}
			return
		}
		if req.Action == "ack" {
			seen := make(map[string]bool, len(req.Tokens))
			valid := true
			for _, token := range req.Tokens {
				if seen[token] {
					valid = false
					break
				}
				seen[token] = true
				if a.completed[token] {
					continue
				}
				found := false
				for _, b := range a.blocks {
					if b.Token == token && b.delivered {
						found = true
						break
					}
				}
				if !found {
					valid = false
					break
				}
			}
			if !valid {
				unlock()
				http.Error(w, "unknown audio completion", 409)
				return
			}
			var err error
			for _, token := range req.Tokens {
				for i, b := range a.blocks {
					if b.Token == token {
						err = v.consumeAudio(ctx, a, i, true, true, time.Now())
						break
					}
				}
				if err != nil {
					break
				}
			}
			if err == nil {
				err = v.drainAudio(ctx, a)
			}
			a.signal()
			if err != nil {
				v.writeInterrupted("audio acknowledgement failed")
			}
			unlock()
			if err != nil {
				http.Error(w, "audio transport failed", 502)
			} else {
				w.WriteHeader(204)
			}
			return
		}
		if polling == nil {
			if a.polling {
				unlock()
				http.Error(w, "audio poll already active", 409)
				return
			}
			a.polling = true
			polling = a
		}
		out := audioResponse{Epoch: epoch, StreamClosed: a.streamClosed}
		for _, b := range a.blocks {
			if !b.delivered {
				copyBlock := *b
				out.Blocks = append(out.Blocks, &copyBlock)
				b.delivered = true
				a.bytes -= len(b.Data)
				b.Data = nil
			}
		}
		if len(out.Blocks) > 0 || waited {
			a.polling = false
			polling = nil
			unlock()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(out)
			for _, b := range out.Blocks {
				clear(b.Data)
			}
			return
		}
		changed := a.changed
		unlock()
		timer := time.NewTimer(600 * time.Millisecond)
		select {
		case <-changed:
		case <-timer.C:
			waited = true
		case <-ctx.Done():
			timer.Stop()
			return
		}
		timer.Stop()
	}
}
