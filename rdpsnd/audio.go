// Package rdpsnd implements MS-RDPEA PCM and ADPCM audio output on the reliable static
// rdpsnd channel. It has no operating-system audio or recording side effects.
// Feed complete virtual-channel messages, not MCS fragments, to Client.Handle.
package rdpsnd

import (
	"encoding/binary"
	"errors"
	"math"
	"net"
	"sync"
	"time"
)

const ChannelName = "rdpsnd"

var (
	// The specification requires ignoring malformed, unknown and out-of-sequence
	// PDUs. These errors report a discarded message; they do not close the client.
	ErrProtocol = errors.New("rdpsnd: malformed or unsupported message")
	ErrSequence = errors.New("rdpsnd: out-of-sequence message or confirmation")
	ErrLimit    = errors.New("rdpsnd: resource limit exceeded")
	// ErrPending requires the caller to finish/cancel pending audio and retry
	// this Formats message before reading further messages from the channel.
	// It prevents old block confirmations from being mistaken for a new stream.
	ErrPending = errors.New("rdpsnd: drain previous stream before retrying formats")
)

// Format describes integer, little-endian WAVE_FORMAT_PCM. Supported formats
// have 1 or 2 channels, 8..192 kHz, and 8, 16, 24 or 32 bits per sample. Eight-bit
// samples are unsigned; all others are signed. No extra format bytes are used.
type Format struct {
	Channels      uint16
	SampleRate    uint32
	BitsPerSample uint16
}

func (f Format) valid() bool {
	return (f.Channels == 1 || f.Channels == 2) && f.SampleRate >= 8000 && f.SampleRate <= 192000 &&
		(f.BitsPerSample == 8 || f.BitsPerSample == 16 || f.BitsPerSample == 24 || f.BitsPerSample == 32)
}

func (f Format) BlockAlign() int { return int(f.Channels) * int(f.BitsPerSample) / 8 }

// Duration reports the duration of an integral number of interleaved PCM frames.
func (f Format) Duration(bytes int) (time.Duration, error) {
	if !f.valid() || bytes < 0 || bytes > MaxPCMFrame || bytes%f.BlockAlign() != 0 {
		return 0, ErrProtocol
	}
	return time.Duration(bytes/f.BlockAlign()) * time.Second / time.Duration(f.SampleRate), nil
}

// DecodePCM returns owned interleaved samples in [-1,1]. It does not resample,
// adjust volume, play audio, or acknowledge consumption. Input is bounded to one
// decoded protocol audio block (MaxPCMFrame bytes). Positive full-scale 32-bit PCM can round to 1 in float32.
func DecodePCM(f Format, data []byte) ([]float32, error) {
	if _, err := f.Duration(len(data)); err != nil {
		return nil, err
	}
	step := int(f.BitsPerSample) / 8
	out := make([]float32, len(data)/step)
	for i := range out {
		b := data[i*step:]
		switch step {
		case 1:
			out[i] = float32(int(b[0])-128) / 128
		case 2:
			out[i] = float32(int16(binary.LittleEndian.Uint16(b))) / 32768
		case 3:
			v := int32(b[0]) | int32(b[1])<<8 | int32(b[2])<<16
			out[i] = float32(v<<8>>8) / 8388608
		case 4:
			out[i] = float32(int32(binary.LittleEndian.Uint32(b))) / 2147483648
		}
	}
	return out, nil
}

type Quality uint16

const (
	DynamicQuality Quality = iota
	MediumQuality
	HighQuality
)

type Config struct {
	// Version defaults to 8. Versions 2..7 exercise the legacy WaveInfo/Wave path.
	Version uint16
	Quality Quality
	// Formats restricts decoded PCM output to this list. Empty accepts every
	// supported output format; server order is retained. Copied by New.
	Formats []Format
	// Codecs selects wire encodings. Empty preserves PCM-only negotiation.
	// MSADPCM and IMAADPCM produce 16-bit PCM; the server's offered format
	// bytes are returned unchanged, with indexes into the client intersection.
	Codecs []Encoding
	// Volume advertises that the caller will apply Result.Volume to its sink.
	// Pitch and UDP audio are never advertised.
	Volume bool
	// MaxPending defaults to 32, range 1..128. MaxPendingBytes defaults to 1 MiB,
	// range 4..8 MiB. Includes delivered blocks awaiting explicit confirmation.
	MaxPending      int
	MaxPendingBytes int
}

type Volume struct{ Left, Right uint16 }

type Frame struct {
	// Token belongs to the originating Client. Pass it to Confirm only after the
	// sink has completed, canceled or deliberately dropped this entire block.
	Token       uint64
	Format      Format
	FormatIndex uint16
	Block       byte
	Timestamp   uint16
	// AudioTimestamp is server uptime in milliseconds, present only for Wave2.
	AudioTimestamp uint32
	Wave2          bool
	// PCM is owned decoded data; Encoding/EncodedBytes identify the wire input.
	PCM          []byte
	Encoding     Encoding
	EncodedBytes int
}

type Result struct {
	// Replies are separate complete rdpsnd PDUs, to send in order on this channel.
	Replies       [][]byte
	Negotiated    bool
	ServerVersion uint16
	Formats       []Format   // decoded output formats
	Encodings     []Encoding // wire encodings at matching indexes
	Trained       bool
	Frame         *Frame
	StreamClosed  bool
	Volume        *Volume
}

type pending struct {
	timestamp uint16
	block     byte
	received  time.Time
	bytes     int
}
type waveInfo struct {
	timestamp, format uint16
	block             byte
	size              int
	first             [4]byte
}

// Client is safe for concurrent Handle/Confirm calls. Deliver frames and replies
// in wire order; use one reader for Handle. Close before discarding a channel or
// reconnecting, and create a new Client for the new channel. It never retains PCM
// after returning a Frame (only bounded confirmation metadata).
type Client struct {
	mu                                   sync.Mutex
	config                               Config
	formats                              []Format
	sources                              []sourceFormat
	serverVersion                        uint16
	negotiated, trained, stopped, closed bool
	partial                              *waveInfo
	pending                              map[uint64]pending
	blocks                               [256]uint64
	bytes                                int
	next                                 uint64
}

func New(config Config) (*Client, error) {
	if config.Version == 0 {
		config.Version = 8
	}
	if config.MaxPending == 0 {
		config.MaxPending = 32
	}
	if config.MaxPendingBytes == 0 {
		config.MaxPendingBytes = 1 << 20
	}
	if config.Version < 2 || config.Version > 8 || config.Quality > HighQuality ||
		config.MaxPending < 1 || config.MaxPending > 128 || config.MaxPendingBytes < 4 ||
		config.MaxPendingBytes > 8<<20 || len(config.Formats) > 256 {
		return nil, ErrLimit
	}
	for _, f := range config.Formats {
		if !f.valid() {
			return nil, ErrProtocol
		}
	}
	if len(config.Codecs) == 0 {
		config.Codecs = []Encoding{PCM}
	}
	if len(config.Codecs) > 3 {
		return nil, ErrLimit
	}
	for _, encoding := range config.Codecs {
		if encoding != PCM && encoding != MSADPCM && encoding != IMAADPCM {
			return nil, ErrProtocol
		}
	}
	config.Codecs = append([]Encoding(nil), config.Codecs...)
	config.Formats = append([]Format(nil), config.Formats...)
	return &Client{config: config, pending: make(map[uint64]pending)}, nil
}

// Pending reports outstanding confirmations and their aggregate PCM byte count.
func (c *Client) Pending() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.pending), c.bytes
}

// Close invalidates all outstanding tokens and clears partial audio. This is
// permanent and distinct from the server's restartable streaming Close PDU.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	c.formats, c.sources, c.partial = nil, nil, nil
	clear(c.pending)
	clear(c.blocks[:])
	c.bytes = 0
}

func packet(kind byte, body []byte) []byte {
	b := []byte{kind, 0, byte(len(body)), byte(len(body) >> 8)}
	return append(b, body...)
}

// Handle accepts one reassembled virtual-channel message and its receipt time.
// A successful audio receipt returns a Frame, never a Wave Confirm. On error the
// message is ignored without changing state. In particular, a malformed legacy
// Wave does not consume the pending WaveInfo; Close tears down an abandoned pair.
// ErrPending is an exception to discard-on-error: retain that one Formats PDU,
// drain/cancel all previously delivered frames, then retry it in channel order.
func (c *Client) Handle(data []byte, now time.Time) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var out Result
	if c.closed {
		return out, net.ErrClosed
	}
	if c.partial != nil {
		w := c.partial
		if len(data) != w.size || len(data) < 4 || binary.LittleEndian.Uint32(data) != 0 {
			return out, ErrProtocol
		}
		encoded := append([]byte(nil), data...)
		copy(encoded, w.first[:])
		frame, err := c.frame(w.format, w.block, w.timestamp, 0, false, encoded, now)
		if err != nil {
			return out, err
		}
		c.partial = nil
		out.Frame = frame
		return out, nil
	}
	if len(data) < 4 || len(data) > 65539 {
		return out, ErrProtocol
	}
	size := int(binary.LittleEndian.Uint16(data[2:]))
	if data[0] == 2 {
		if !c.trained || c.stopped {
			return out, ErrSequence
		}
		if len(data) != 16 || size < 12 {
			return out, ErrProtocol
		}
		w := &waveInfo{timestamp: binary.LittleEndian.Uint16(data[4:]), format: binary.LittleEndian.Uint16(data[6:]), block: data[8], size: size - 8}
		if _, err := c.checkFrame(w.format, w.block, w.size); err != nil {
			return out, err
		}
		copy(w.first[:], data[12:16])
		c.partial = w
		return out, nil
	}
	if size != len(data)-4 {
		return out, ErrProtocol
	}
	body := data[4:]
	switch data[0] {
	case 7:
		return c.negotiate(body)
	case 6:
		if !c.negotiated {
			return out, ErrSequence
		}
		if len(body) < 4 {
			return out, ErrProtocol
		}
		packSize := int(binary.LittleEndian.Uint16(body[2:]))
		if (len(body) == 4 && packSize != 0) || (len(body) > 4 && packSize != len(data)) {
			return out, ErrProtocol
		}
		out.Replies = [][]byte{packet(6, body[:4])}
		out.Trained = true
		if !c.stopped {
			c.trained = true
		}
	case 13:
		if !c.trained || c.stopped || c.config.Version < 8 || c.serverVersion < 8 {
			return out, ErrSequence
		}
		if len(body) < 12 {
			return out, ErrProtocol
		}
		frame, err := c.frame(binary.LittleEndian.Uint16(body[2:]), body[4], binary.LittleEndian.Uint16(body), binary.LittleEndian.Uint32(body[8:]), true, body[12:], now)
		if err != nil {
			return out, err
		}
		out.Frame = frame
	case 1:
		if len(body) != 0 {
			return out, ErrProtocol
		}
		if !c.negotiated || c.stopped {
			return out, ErrSequence
		}
		c.stopped = true
		c.trained = false
		out.StreamClosed = true
	case 3, 4:
		if len(body) != 4 {
			return out, ErrProtocol
		}
		if !c.trained || c.stopped {
			return out, ErrSequence
		}
		if data[0] == 3 && c.config.Volume {
			out.Volume = &Volume{binary.LittleEndian.Uint16(body), binary.LittleEndian.Uint16(body[2:])}
		} // Pitch must be ignored, per MS-RDPEA 3.2.5.3.1.2.
	default:
		return out, ErrProtocol
	}
	return out, nil
}

func (c *Client) negotiate(body []byte) (Result, error) {
	var out Result
	if len(body) < 20 {
		return out, ErrProtocol
	}
	count, version := int(binary.LittleEndian.Uint16(body[14:])), binary.LittleEndian.Uint16(body[17:])
	if count > 256 {
		return out, ErrLimit
	}
	if version < 2 {
		return out, ErrProtocol
	}
	remaining := body[20:]
	var formats []Format
	var sources []sourceFormat
	var encodings []Encoding
	var wire []byte
	for i := 0; i < count; i++ {
		if len(remaining) < 18 {
			return out, ErrProtocol
		}
		n := 18 + int(binary.LittleEndian.Uint16(remaining[16:]))
		if n > len(remaining) {
			return out, ErrProtocol
		}
		source, valid := parseAudioFormat(remaining[:n])
		f := source.output
		supported := false
		for _, encoding := range c.config.Codecs {
			if valid && source.encoding == encoding {
				supported = true
			}
		}
		if supported && len(c.config.Formats) > 0 {
			supported = false
			for _, allowed := range c.config.Formats {
				if f == allowed {
					supported = true
					break
				}
			}
		}
		if supported {
			formats = append(formats, f)
			sources = append(sources, source)
			encodings = append(encodings, source.encoding)
			wire = append(wire, remaining[:n]...)
		}
		remaining = remaining[n:]
	}
	if len(remaining) != 0 {
		return out, ErrProtocol
	}
	// Validate the entire offer first. Even without a preceding Close, do not
	// recycle block identifiers while the previous stream is still draining.
	if len(c.pending) != 0 {
		return out, ErrPending
	}
	b := make([]byte, 20, 20+len(wire))
	b[0] = 1 // ALIVE; no UDP, pitch control, or unsupported codecs.
	if c.config.Volume {
		b[0] |= 2
	}
	binary.LittleEndian.PutUint32(b[4:], 0xffffffff)
	binary.LittleEndian.PutUint32(b[8:], 0x10000)
	binary.LittleEndian.PutUint16(b[14:], uint16(len(formats)))
	binary.LittleEndian.PutUint16(b[17:], c.config.Version)
	out.Replies = [][]byte{packet(7, append(b, wire...))}
	if c.config.Version >= 6 && version >= 6 {
		out.Replies = append(out.Replies, packet(12, []byte{byte(c.config.Quality), 0, 0, 0}))
	}
	out.Negotiated = true
	out.ServerVersion = version
	out.Formats = append([]Format(nil), formats...)
	out.Encodings = append([]Encoding(nil), encodings...)
	c.formats, c.sources, c.serverVersion = formats, sources, version
	c.negotiated, c.trained, c.stopped = true, false, false
	return out, nil
}

func (c *Client) checkFrame(index uint16, block byte, encodedBytes int) (int, error) {
	if int(index) >= len(c.sources) {
		return 0, ErrProtocol
	}
	decodedBytes, err := c.sources[index].decodedSize(encodedBytes)
	if err != nil {
		return 0, err
	}
	if c.blocks[block] != 0 {
		return 0, ErrSequence
	}
	if len(c.pending) >= c.config.MaxPending || decodedBytes > c.config.MaxPendingBytes-c.bytes || c.next == math.MaxUint64 {
		return 0, ErrLimit
	}
	return decodedBytes, nil
}

func (c *Client) frame(index uint16, block byte, timestamp uint16, audioTime uint32, wave2 bool, data []byte, now time.Time) (*Frame, error) {
	decodedBytes, err := c.checkFrame(index, block, len(data))
	if err != nil {
		return nil, err
	}
	pcm, err := c.sources[index].decode(data)
	if err != nil {
		return nil, err
	}
	// Decoding can reject a malformed predictor/index late in a block. No
	// confirmation token or byte budget is committed until all blocks succeed.
	c.next++
	c.pending[c.next] = pending{timestamp, block, now, decodedBytes}
	c.blocks[block] = c.next
	c.bytes += decodedBytes
	return &Frame{Token: c.next, Format: c.formats[index], FormatIndex: index, Block: block, Timestamp: timestamp, AudioTimestamp: audioTime, Wave2: wave2, PCM: pcm, Encoding: c.sources[index].encoding, EncodedBytes: len(data)}, nil
}

// Confirm consumes a token exactly once and returns a Wave Confirm for the same
// channel. Call only after the sink completes, cancels or drops the whole block,
// not on enqueue. A failed network send requires channel/session teardown; never
// reuse its tokens. Receipt-to-consumption milliseconds are added modulo 65536.
func (c *Client) Confirm(token uint64, now time.Time) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, net.ErrClosed
	}
	p, ok := c.pending[token]
	if !ok || now.Before(p.received) {
		return nil, ErrSequence
	}
	timestamp := p.timestamp + uint16(now.Sub(p.received)/time.Millisecond)
	b := packet(5, []byte{byte(timestamp), byte(timestamp >> 8), p.block, 0})
	delete(c.pending, token)
	c.blocks[p.block] = 0
	c.bytes -= p.bytes
	return b, nil
}
