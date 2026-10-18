// Package audin implements MS-RDPEAI audio input on the AUDIO_INPUT dynamic
// channel. It has no microphone, file, resampling or operating-system effects.
// Only caller-supplied, interleaved signed 16-bit little-endian PCM is sent.
package audin

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

const ChannelName = "AUDIO_INPUT"
const MaxMessage = 1 << 20
const MaxFormats = 256

var (
	// Invalid, unknown and out-of-sequence server messages are discarded without
	// state changes, as required by section 3.1.5. The caller may log the category.
	ErrProtocol = errors.New("audin: malformed or unsupported message")
	ErrSequence = errors.New("audin: unexpected message or stale stream token")
	ErrLimit    = errors.New("audin: resource limit exceeded")
)

type Format struct {
	Channels   uint16
	SampleRate uint32
}

func (f Format) valid() bool {
	return (f.Channels == 1 || f.Channels == 2) && f.SampleRate >= 8000 && f.SampleRate <= 192000
}
func (f Format) BlockAlign() int { return int(f.Channels) * 2 }

// WaveFormat is the server's advisory capture-device format, which may differ
// from the negotiated wire format. Extra is owned and bounded. The caller can
// capture directly in Request.Format or convert before calling WritePCM.
type WaveFormat struct {
	Tag, Channels              uint16
	SampleRate, BytesPerSecond uint32
	BlockAlign, BitsPerSample  uint16
	Extra                      []byte
}
type Config struct {
	// Formats is an explicit source capability list. Empty accepts all supported
	// 16-bit PCM formats; advertise only formats the source can supply/convert.
	Formats []Format
	// MaxPacketBytes defaults to 256 KiB; range 2..MaxMessage-1.
	MaxPacketBytes int
}
type Request struct {
	// Token is unique to this Client's open/format request. It must accompany
	// every PCM block; a format change invalidates previous source callbacks.
	Token           uint64
	FormatIndex     uint32
	Format          Format
	FramesPerPacket uint32
	CaptureFormat   WaveFormat
	Change          bool
}

func (r Request) PacketBytes() int { return int(r.FramesPerPacket) * r.Format.BlockAlign() }

type Result struct {
	ServerVersion uint32
	Negotiated    bool
	Formats       []Format
	Request       *Request
}
type State struct {
	ServerVersion      uint32
	Negotiated, Closed bool
	Formats            []Format
	Pending, Stream    *Request
	Packets, PCMBytes  uint64 // successfully written, not server/application acknowledgment
}

// SendFunc sends exactly one complete DVC message, honoring context cancellation.
// It must not reenter Client. The client serializes all callbacks, including
// Incoming/Data pairs and format acknowledgments. Any callback error is terminal:
// the caller must close the DVC (or connection), never retry uncertain audio.
type SendFunc func(context.Context, []byte) error

type phase uint8

const (
	initial phase = iota
	versioned
	negotiated
	opening
	streaming
	changing
	rejected
)

// Client is safe for concurrent calls. Use one Client per opened DVC, never reuse
// it after DVC close/reconnect. Close cancels in-flight writes and waiting calls;
// the owner separately closes the DVC using Session.CloseDynamic.
type Client struct {
	gate   chan struct{}
	mu     sync.Mutex
	life   context.Context
	cancel context.CancelFunc
	send   SendFunc
	config Config
	phase  phase
	next   uint64
	state  State
}

func New(config Config, send SendFunc) (*Client, error) {
	if send == nil {
		return nil, ErrProtocol
	}
	if config.MaxPacketBytes == 0 {
		config.MaxPacketBytes = 256 << 10
	}
	if config.MaxPacketBytes < 2 || config.MaxPacketBytes >= MaxMessage || len(config.Formats) > MaxFormats {
		return nil, ErrLimit
	}
	for _, f := range config.Formats {
		if !f.valid() {
			return nil, ErrProtocol
		}
	}
	config.Formats = append([]Format(nil), config.Formats...)
	life, cancel := context.WithCancel(context.Background())
	return &Client{gate: make(chan struct{}, 1), life: life, cancel: cancel, config: config, send: send}, nil
}
func cloneRequest(r *Request) *Request {
	if r == nil {
		return nil
	}
	n := *r
	n.CaptureFormat.Extra = append([]byte(nil), r.CaptureFormat.Extra...)
	return &n
}
func (c *Client) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.state
	s.Closed = c.life.Err() != nil
	s.Formats = append([]Format(nil), s.Formats...)
	s.Pending = cloneRequest(s.Pending)
	s.Stream = cloneRequest(s.Stream)
	return s
}
func (c *Client) Close() {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()
	c.state.Pending, c.state.Stream = nil, nil
}
func (c *Client) enter(ctx context.Context) (context.Context, func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-c.life.Done():
		return nil, nil, net.ErrClosed
	case c.gate <- struct{}{}:
	}
	if c.life.Err() != nil || ctx.Err() != nil {
		<-c.gate
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}
		return nil, nil, net.ErrClosed
	}
	work, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.life, cancel)
	return work, func() { stop(); cancel(); <-c.gate }, nil
}
func (c *Client) write(ctx context.Context, packets ...[]byte) error {
	for _, p := range packets {
		if err := ctx.Err(); err != nil {
			c.Close()
			return err
		}
		if err := c.send(ctx, p); err != nil {
			c.Close()
			return err
		}
	}
	if c.life.Err() != nil {
		return net.ErrClosed
	}
	return nil
}
func number(kind byte, n uint32) []byte { return binary.LittleEndian.AppendUint32([]byte{kind}, n) }
func parseFormat(b []byte) (WaveFormat, int, error) {
	if len(b) < 18 {
		return WaveFormat{}, 0, ErrProtocol
	}
	n := 18 + int(binary.LittleEndian.Uint16(b[16:]))
	if len(b) < n {
		return WaveFormat{}, 0, ErrProtocol
	}
	f := WaveFormat{Tag: binary.LittleEndian.Uint16(b), Channels: binary.LittleEndian.Uint16(b[2:]), SampleRate: binary.LittleEndian.Uint32(b[4:]), BytesPerSecond: binary.LittleEndian.Uint32(b[8:]), BlockAlign: binary.LittleEndian.Uint16(b[12:]), BitsPerSample: binary.LittleEndian.Uint16(b[14:]), Extra: append([]byte(nil), b[18:n]...)}
	if f.Tag == 0xfffe && len(f.Extra) != 22 {
		return WaveFormat{}, 0, ErrProtocol
	}
	return f, n, nil
}
func (c *Client) supports(w WaveFormat) bool {
	f := Format{Channels: w.Channels, SampleRate: w.SampleRate}
	if w.Tag != 1 || w.BitsPerSample != 16 || len(w.Extra) != 0 || !f.valid() || int(w.BlockAlign) != f.BlockAlign() || uint64(w.BytesPerSecond) != uint64(f.SampleRate)*uint64(f.BlockAlign()) {
		return false
	}
	if len(c.config.Formats) == 0 {
		return true
	}
	for _, x := range c.config.Formats {
		if x == f {
			return true
		}
	}
	return false
}

// Handle accepts a complete server DVC message, not a fragment. Open and format
// requests require explicit completion before data can be sent. Returned slices
// and snapshots are independent from internal state and from the input buffer.
func (c *Client) Handle(ctx context.Context, b []byte) (Result, error) {
	ctx, leave, err := c.enter(ctx)
	if err != nil {
		return Result{}, err
	}
	defer leave()
	if len(b) == 0 {
		return Result{}, ErrProtocol
	}
	if len(b) > MaxMessage {
		return Result{}, ErrLimit
	}
	s := c.State()
	if s.Closed {
		return Result{}, net.ErrClosed
	}
	switch b[0] {
	case 1:
		if c.phase != initial {
			return Result{}, ErrSequence
		}
		if len(b) != 5 || binary.LittleEndian.Uint32(b[1:]) == 0 {
			return Result{}, ErrProtocol
		}
		v := binary.LittleEndian.Uint32(b[1:])
		if err = c.write(ctx, number(1, min(v, 2))); err != nil {
			return Result{}, err
		}
		c.mu.Lock()
		c.state.ServerVersion = v
		c.phase = versioned
		c.mu.Unlock()
		return Result{ServerVersion: v}, nil
	case 2:
		if c.phase != versioned {
			return Result{}, ErrSequence
		}
		if len(b) < 9 {
			return Result{}, ErrProtocol
		}
		n := binary.LittleEndian.Uint32(b[1:])
		if n > MaxFormats {
			return Result{}, ErrLimit
		}
		// Server cbSizeFormatsPacket is reserved; trailing ExtraData is ignored.
		formats := []Format{}
		reply := make([]byte, 9)
		reply[0] = 2
		rest := b[9:]
		for i := uint32(0); i < n; i++ {
			w, size, e := parseFormat(rest)
			if e != nil {
				return Result{}, e
			}
			if c.supports(w) {
				formats = append(formats, Format{Channels: w.Channels, SampleRate: w.SampleRate})
				reply = append(reply, rest[:size]...)
			}
			rest = rest[size:]
		}
		binary.LittleEndian.PutUint32(reply[1:], uint32(len(formats)))
		binary.LittleEndian.PutUint32(reply[5:], uint32(len(reply)))
		if err = c.write(ctx, []byte{5}, reply); err != nil {
			return Result{}, err
		}
		c.mu.Lock()
		c.state.Formats = formats
		c.state.Negotiated = true
		c.phase = negotiated
		c.mu.Unlock()
		return Result{Negotiated: true, Formats: append([]Format(nil), formats...)}, nil
	case 3, 7:
		change := b[0] == 7
		if (!change && c.phase != negotiated) || (change && c.phase != streaming) {
			return Result{}, ErrSequence
		}
		var r Request
		if change {
			if len(b) != 5 {
				return Result{}, ErrProtocol
			}
			r = *cloneRequest(s.Stream)
			r.Change = true
			r.FormatIndex = binary.LittleEndian.Uint32(b[1:])
		} else {
			if len(b) < 27 {
				return Result{}, ErrProtocol
			}
			w, n, e := parseFormat(b[9:])
			if e != nil {
				return Result{}, e
			}
			if n != len(b)-9 {
				return Result{}, ErrProtocol
			}
			r = Request{FramesPerPacket: binary.LittleEndian.Uint32(b[1:]), FormatIndex: binary.LittleEndian.Uint32(b[5:]), CaptureFormat: w}
		}
		if uint64(r.FormatIndex) >= uint64(len(s.Formats)) {
			return Result{}, ErrProtocol
		}
		r.Format = s.Formats[r.FormatIndex]
		if r.FramesPerPacket == 0 || uint64(r.FramesPerPacket)*uint64(r.Format.BlockAlign()) > uint64(c.config.MaxPacketBytes) {
			return Result{}, ErrLimit
		}
		c.next++
		r.Token = c.next
		c.mu.Lock()
		if c.life.Err() != nil {
			c.mu.Unlock()
			return Result{}, net.ErrClosed
		}
		c.state.Stream = nil
		c.state.Pending = &r
		if change {
			c.phase = changing
		} else {
			c.phase = opening
		}
		c.mu.Unlock()
		return Result{Request: cloneRequest(&r)}, nil
	default:
		return Result{}, ErrProtocol
	}
}

// CompleteOpen sends Format Change followed by Open Reply. Pass zero only after
// the source is ready; a failure HRESULT (high bit set) reports refusal/failure.
// A rejected open cannot send samples; close its DVC after sending the reply.
func (c *Client) CompleteOpen(ctx context.Context, token uint64, hresult uint32) error {
	return c.complete(ctx, token, hresult, false)
}

// ConfirmFormat acknowledges a pending format switch after the source has been
// reconfigured. Discard partial/queued old-format audio. There is no negative
// format-change reply: close the DVC if the source cannot supply the new format.
func (c *Client) ConfirmFormat(ctx context.Context, token uint64) error {
	return c.complete(ctx, token, 0, true)
}
func (c *Client) complete(ctx context.Context, token uint64, result uint32, change bool) error {
	ctx, leave, err := c.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	s := c.State()
	r := s.Pending
	if r == nil || r.Token != token || r.Change != change {
		return ErrSequence
	}
	if result != 0 && result&0x80000000 == 0 {
		return ErrProtocol
	}
	replies := [][]byte{number(7, r.FormatIndex)}
	if !change {
		replies = append(replies, number(4, result))
	}
	if err = c.write(ctx, replies...); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.life.Err() != nil {
		return net.ErrClosed
	}
	c.state.Pending = nil
	if result == 0 {
		c.state.Stream = r
		c.phase = streaming
	} else {
		c.phase = rejected
	}
	return nil
}

// WritePCM sends one exact FramesPerPacket block. It neither buffers nor paces:
// the source supplies real-time audio and bounds its own queue. It does not pad,
// silently drop, resample or record. Tokens from an earlier format are rejected.
func (c *Client) WritePCM(ctx context.Context, token uint64, pcm []byte) error {
	ctx, leave, err := c.enter(ctx)
	if err != nil {
		return err
	}
	defer leave()
	s := c.State()
	r := s.Stream
	if r == nil || r.Token != token {
		return ErrSequence
	}
	if len(pcm) != r.PacketBytes() {
		return ErrProtocol
	}
	p := make([]byte, len(pcm)+1)
	p[0] = 6
	copy(p[1:], pcm)
	if err = c.write(ctx, []byte{5}, p); err != nil {
		return err
	}
	c.mu.Lock()
	c.state.Packets++
	c.state.PCMBytes += uint64(len(pcm))
	c.mu.Unlock()
	return nil
}
