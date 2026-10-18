package dtls

import "encoding/binary"

const (
	HandshakeHeader      = 12
	MaxHandshakeMessage  = 1 << 20
	MaxHandshakeBuffered = 4 << 20
	MaxHandshakeMessages = 32
	MaxFragments         = 4096
)

type Message struct {
	Type     uint8
	Sequence uint16
	Body     []byte
}

func (m Message) String() string   { return "dtls.Message{private body}" }
func (m Message) GoString() string { return m.String() }

type fragment struct {
	typ           uint8
	seq           uint16
	total, offset int
	data          []byte
}

func uint24(b []byte) int   { return int(b[0])<<16 | int(b[1])<<8 | int(b[2]) }
func put24(b []byte, n int) { b[0], b[1], b[2] = byte(n>>16), byte(n>>8), byte(n) }

func marshalFragment(m Message, offset, n int) []byte {
	b := make([]byte, HandshakeHeader+n)
	b[0] = m.Type
	put24(b[1:4], len(m.Body))
	binary.BigEndian.PutUint16(b[4:6], m.Sequence)
	put24(b[6:9], offset)
	put24(b[9:12], n)
	copy(b[12:], m.Body[offset:offset+n])
	return b
}

// Canonical returns the unfragmented DTLS handshake encoding for transcript
// hashing. The handshake owner decides which messages belong to the transcript
// (in particular, the initial ClientHello/HelloVerifyRequest are excluded when
// a cookie exchange occurs). It must not hash retransmissions a second time.
func (m Message) Canonical() ([]byte, error) {
	if len(m.Body) > MaxHandshakeMessage {
		return nil, ErrLimit
	}
	return marshalFragment(m, 0, len(m.Body)), nil
}

// FragmentMessage returns record payloads, preserving message_seq on every
// fragment. maxPayload includes the 12-byte handshake header but excludes
// record header/encryption expansion; subtract both from the transport MTU.
func FragmentMessage(m Message, maxPayload int) ([][]byte, error) {
	if len(m.Body) > MaxHandshakeMessage {
		return nil, ErrLimit
	}
	if maxPayload < HandshakeHeader || maxPayload > MaxPlaintext || maxPayload == HandshakeHeader && len(m.Body) > 0 {
		return nil, ErrInvalid
	}
	if len(m.Body) == 0 {
		return [][]byte{marshalFragment(m, 0, 0)}, nil
	}
	n := maxPayload - HandshakeHeader
	count := (len(m.Body) + n - 1) / n
	if count > MaxFragments {
		return nil, ErrLimit
	}
	out := make([][]byte, 0, count)
	for offset := 0; offset < len(m.Body); offset += n {
		out = append(out, marshalFragment(m, offset, min(n, len(m.Body)-offset)))
	}
	return out, nil
}

func parseFragments(b []byte) ([]fragment, error) {
	if len(b) == 0 {
		return nil, ErrInvalid
	}
	if len(b) > MaxPlaintext {
		return nil, ErrLimit
	}
	var out []fragment
	for len(b) > 0 {
		if len(out) == MaxRecords {
			return nil, ErrLimit
		}
		if len(b) < HandshakeHeader {
			return nil, ErrInvalid
		}
		total, offset, n := uint24(b[1:4]), uint24(b[6:9]), uint24(b[9:12])
		if total > MaxHandshakeMessage {
			return nil, ErrLimit
		}
		if offset > total || n > total-offset || n > len(b)-12 || n == 0 && total != 0 {
			return nil, ErrInvalid
		}
		out = append(out, fragment{b[0], binary.BigEndian.Uint16(b[4:6]), total, offset, b[12 : 12+n]})
		b = b[12+n:]
	}
	return out, nil
}

type ReassemblyLimits struct {
	MaxMessage, MaxBuffered, MaxMessages int
}

type partialMessage struct {
	typ        uint8
	data, bits []byte
	received   int
}

// Reassembler is a serial handshake-owner component, not a concurrent socket.
// Buffered limits declared message lengths, not only bytes already received.
// Bitmaps add at most one eighth plus seven bytes per message; atomic Push may
// temporarily clone the touched buffers. No datagram can allocate past these
// bounded budgets. Old message_seq values are ignored, never delivered twice.
type Reassembler struct {
	limits   ReassemblyLimits
	next     uint32 // 65536 is an exhausted sentinel, not a wrapped zero
	buffered int
	pending  map[uint16]*partialMessage
	closed   bool
}

type ReassemblyStats struct {
	NextSequence       uint32
	Buffered, Messages int
}

func NewReassembler(next uint16, limits ReassemblyLimits) (*Reassembler, error) {
	if limits.MaxMessage == 0 {
		limits.MaxMessage = 256 << 10
	}
	if limits.MaxBuffered == 0 {
		limits.MaxBuffered = 1 << 20
	}
	if limits.MaxMessages == 0 {
		limits.MaxMessages = 8
	}
	if limits.MaxMessage < 1 || limits.MaxMessage > MaxHandshakeMessage || limits.MaxBuffered < limits.MaxMessage || limits.MaxBuffered > MaxHandshakeBuffered || limits.MaxMessages < 1 || limits.MaxMessages > MaxHandshakeMessages {
		return nil, ErrInvalid
	}
	return &Reassembler{limits: limits, next: uint32(next), pending: make(map[uint16]*partialMessage)}, nil
}

func (r *Reassembler) Stats() ReassemblyStats {
	return ReassemblyStats{r.next, r.buffered, len(r.pending)}
}
func (r *Reassembler) String() string   { return "dtls.Reassembler{private state}" }
func (r *Reassembler) GoString() string { return r.String() }

// Push validates and commits one complete handshake record atomically. Identical
// overlaps (including changed retransmission fragment sizes) are accepted;
// conflicts, malformed tails or budget failures leave all prior state intact.
// Returned bodies are owned by the caller and ordered by message_seq.
func (r *Reassembler) Push(payload []byte) ([]Message, error) {
	if r.closed {
		return nil, ErrClosed
	}
	fragments, err := parseFragments(payload)
	if err != nil {
		return nil, err
	}
	work := make(map[uint16]*partialMessage, len(r.pending))
	for seq, p := range r.pending {
		work[seq] = p
	}
	touched := make(map[uint16]bool)
	buffered := r.buffered
	for _, f := range fragments {
		if uint32(f.seq) < r.next {
			continue
		}
		if uint32(f.seq)-r.next >= uint32(r.limits.MaxMessages) {
			return nil, ErrLimit
		}
		if f.total > r.limits.MaxMessage {
			return nil, ErrLimit
		}
		p := work[f.seq]
		if p == nil {
			if len(work) == r.limits.MaxMessages || f.total > r.limits.MaxBuffered-buffered {
				return nil, ErrLimit
			}
			p = &partialMessage{typ: f.typ, data: make([]byte, f.total), bits: make([]byte, (f.total+7)/8)}
			work[f.seq], touched[f.seq] = p, true
			buffered += f.total
		} else {
			if p.typ != f.typ || len(p.data) != f.total {
				return nil, ErrConflict
			}
			if !touched[f.seq] {
				p = &partialMessage{p.typ, append([]byte(nil), p.data...), append([]byte(nil), p.bits...), p.received}
				work[f.seq], touched[f.seq] = p, true
			}
		}
		for j, v := range f.data {
			i := f.offset + j
			mask := byte(1 << (i % 8))
			if p.bits[i/8]&mask != 0 {
				if p.data[i] != v {
					return nil, ErrConflict
				}
			} else {
				p.data[i] = v
				p.bits[i/8] |= mask
				p.received++
			}
		}
	}
	var out []Message
	next := r.next
	for next <= 65535 {
		p := work[uint16(next)]
		if p == nil || p.received != len(p.data) {
			break
		}
		out = append(out, Message{p.typ, uint16(next), p.data})
		buffered -= len(p.data)
		delete(work, uint16(next))
		clear(p.bits)
		next++
	}
	r.pending, r.buffered, r.next = work, buffered, next
	return out, nil
}

func (r *Reassembler) Close() {
	for _, p := range r.pending {
		clear(p.data)
		clear(p.bits)
	}
	clear(r.pending)
	r.buffered, r.closed = 0, true
}
