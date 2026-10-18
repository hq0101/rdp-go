package rdpemt

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

var (
	ErrLimit    = errors.New("rdpemt: message exceeds configured limit")
	ErrSequence = errors.New("rdpemt: unexpected tunnel action")
)

// ResponseError is a server rejection, not proof that the main session failed.
type ResponseError struct{ Code uint32 }

func (e *ResponseError) Error() string {
	return fmt.Sprintf("rdpemt: tunnel rejected (HRESULT %#08x)", e.Code)
}

type TunnelOptions struct {
	MaxPayload  int           // zero uses 65535; application messages only
	BindTimeout time.Duration // zero uses 10 seconds; must be positive
	// HandleNetworkProbes makes ReadMessage process reliable-tunnel bandwidth
	// requests/results, send results on this tunnel, and skip empty probe PDUs.
	// Returned messages contain only nonempty application data. It rejects
	// unsupported subheader types. False preserves the raw message interface.
	HandleNetworkProbes bool
}

// Message preserves the exact tunnel message and optional extension boundaries
// in raw mode. With HandleNetworkProbes, ReadMessage consumes known subheaders
// and returns only nonempty application Data; otherwise the owner handles them.
type Message struct {
	Data       []byte
	SubHeaders []SubHeader
}

func (m Message) String() string   { return "rdpemt.Message{private payload}" }
func (m Message) GoString() string { return m.String() }

// Tunnel owns a TLS or DTLS sideband after successful cookie/ID binding.
// It does not own the main RDP connection or perform Soft-Sync, DVC migration,
// UDP initialization or reconnection. If Soft-Sync was negotiated, the owner must
// complete that exchange before using application data on this tunnel.
// One reader and one writer can proceed concurrently. Cancellation after an I/O
// starts closes the entire sideband because partial framing cannot be resumed.
type Tunnel struct {
	conn                net.Conn
	abort               func() error
	datagramLimit       int // nonzero for DTLS; outgoing plaintext record capacity
	maxPayload          int
	readGate, writeGate chan struct{}
	done                chan struct{}
	once                sync.Once
	mu                  sync.Mutex
	terminal            error
	closeErr            error
	handleNetwork       bool           // immutable after binding
	detector            tunnelDetector // protected by mu; updated by readGate owner
	probeResponses      uint64         // mu; successfully written response subheaders
}

func (t *Tunnel) String() string   { return "rdpemt.Tunnel{private connection}" }
func (t *Tunnel) GoString() string { return t.String() }

// BindReliable takes ownership of secure, completes TLS and verifies identity,
// then sends the cookie/ID from the authenticated main connection. It returns
// only after a successful Tunnel Create Response. No application data is sent
// before that response. Every failure closes the underlying sideband, including
// invalid local options; the main connection is never closed by this function.
// secure must wrap a reliable RDP-UDP Conn, not DatagramConn. The main transport
// must have negotiated multitransport and drdynvc; the owner validates bootstrap
// channel/protocol and targets the main transport's actual remote address.
func BindReliable(ctx context.Context, secure *tls.Conn, identity ServerIdentity, request InitiateRequest, opts TunnelOptions) (_ *Tunnel, err error) {
	defer clear(request.Cookie[:])
	if secure == nil {
		return nil, ErrInvalid
	}
	t := newTunnel(secure, secure.NetConn().Close)
	ok := false
	defer func() {
		if !ok {
			t.fail(err)
		}
	}()
	if ctx == nil || request.Protocol != ReliableUDP || opts.MaxPayload < 0 || opts.MaxPayload > MaxPayload || opts.BindTimeout < 0 {
		return nil, ErrInvalid
	}
	if !identity.valid {
		return nil, ErrIdentity
	}
	if opts.MaxPayload == 0 {
		opts.MaxPayload = MaxPayload
	}
	if opts.BindTimeout == 0 {
		opts.BindTimeout = 10 * time.Second
	}
	t.maxPayload = opts.MaxPayload
	t.handleNetwork = opts.HandleNetworkProbes
	ctx, cancel := context.WithTimeout(ctx, opts.BindTimeout)
	defer cancel()
	err = t.run(ctx, func() error {
		if err := secure.HandshakeContext(ctx); err != nil {
			return err
		}
		if err := identity.verify(secure.ConnectionState(), time.Now()); err != nil {
			return err
		}
		b, err := CreateRequest(request)
		if err != nil {
			return err
		}
		defer clear(b)
		if err = writeAll(secure, b); err != nil {
			return err
		}
		p, err := ReadPacket(secure, 4)
		if err != nil {
			return err
		}
		defer clear(p.Payload)
		if p.Action != ActionCreateResponse {
			return ErrSequence
		}
		code := binary.LittleEndian.Uint32(p.Payload)
		if code&0x80000000 != 0 {
			return &ResponseError{Code: code}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	ok = true
	return t, nil
}

func newTunnel(conn net.Conn, abort func() error) *Tunnel {
	return &Tunnel{conn: conn, abort: abort, readGate: make(chan struct{}, 1), writeGate: make(chan struct{}, 1), done: make(chan struct{})}
}

// Close immediately closes the underlying connection without flushing TLS
// close-notify or queued UDP writes. It unblocks pending reads/writes and joins
// any workers owned by the underlying RDP-UDP Conn. It is idempotent.
func (t *Tunnel) Close() error {
	if t == nil || t.conn == nil {
		return nil
	}
	t.fail(net.ErrClosed)
	return t.closeErr
}
func (t *Tunnel) fail(err error) {
	t.once.Do(func() {
		if err == nil {
			err = net.ErrClosed
		}
		t.mu.Lock()
		t.terminal = err
		close(t.done)
		t.mu.Unlock()
		t.closeErr = t.abort()
	})
}
func (t *Tunnel) Err() error {
	if t == nil || t.conn == nil {
		return net.ErrClosed
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.terminal
}
func (t *Tunnel) acquire(ctx context.Context, gate chan struct{}) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.done:
		return t.Err()
	case gate <- struct{}{}:
		if err := ctx.Err(); err != nil {
			<-gate
			return err
		}
		if err := t.Err(); err != nil {
			<-gate
			return err
		}
		return nil
	}
}
func (t *Tunnel) run(ctx context.Context, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	finished := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { t.fail(ctx.Err()); close(finished) })
	err := fn()
	if !stop() {
		<-finished
	}
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		t.fail(err)
	}
	return err
}

// ReadMessage reads one message. With HandleNetworkProbes it first answers any
// measurement requests on the same tunnel, consumes probe-only messages and
// returns application data with processed subheaders removed. Replies can wait
// behind a concurrent writer; ctx bounds that wait and any actual write.
func (t *Tunnel) ReadMessage(ctx context.Context) (Message, error) {
	if t == nil || t.conn == nil {
		return Message{}, net.ErrClosed
	}
	if err := t.acquire(ctx, t.readGate); err != nil {
		return Message{}, err
	}
	defer func() { <-t.readGate }()
	for skipped := 0; ; skipped++ {
		if t.datagramLimit != 0 && skipped == 4096 {
			t.fail(ErrLimit)
			return Message{}, ErrLimit
		}
		var p Packet
		err := t.run(ctx, func() error {
			var err error
			if t.datagramLimit != 0 {
				p, err = readDatagramPacket(t.conn, t.maxPayload)
			} else {
				p, err = ReadPacket(t.conn, t.maxPayload)
			}
			if err != nil {
				return err
			}
			if t.datagramLimit != 0 && p.Action == ActionCreateResponse && binary.LittleEndian.Uint32(p.Payload)&0x80000000 == 0 {
				return nil // successful reply to a retransmitted bind request
			}
			if p.Action != ActionData {
				return ErrSequence
			}
			return nil
		})
		if err != nil {
			clear(p.Payload)
			return Message{}, err
		}
		if p.Action == ActionCreateResponse {
			clear(p.Payload)
			continue
		}
		m := Message{Data: p.Payload, SubHeaders: p.SubHeaders}
		if !t.handleNetwork {
			return m, nil
		}
		t.mu.Lock()
		replies, err := t.detector.handle(m, time.Now())
		t.mu.Unlock()
		if err != nil {
			clear(m.Data)
			t.fail(err)
			return Message{}, err
		}
		for _, reply := range replies {
			if err = t.WriteMessage(ctx, reply); err != nil {
				// Even cancellation while waiting for the write gate is terminal
				// here: the incoming request was already consumed, not retryable.
				clear(m.Data)
				t.fail(err)
				return Message{}, err
			}
			t.mu.Lock()
			t.probeResponses += uint64(len(reply.SubHeaders))
			t.mu.Unlock()
		}
		if len(m.Data) != 0 {
			return Message{Data: m.Data}, nil
		}
	}
}

// WriteMessage preserves one message boundary. Success means accepted by the
// reliable stream, not peer receipt. A local validation error leaves it usable.
// Callers must not mutate Data/SubHeaders until this call returns.
func (t *Tunnel) WriteMessage(ctx context.Context, m Message) error {
	if t == nil || t.conn == nil {
		return net.ErrClosed
	}
	if ctx == nil {
		return ErrInvalid
	}
	if len(m.Data) > t.maxPayload {
		return ErrLimit
	}
	if err := t.acquire(ctx, t.writeGate); err != nil {
		return err
	}
	defer func() { <-t.writeGate }()
	b, err := (Packet{Action: ActionData, SubHeaders: m.SubHeaders, Payload: m.Data}).Marshal()
	if err != nil {
		return err
	}
	defer clear(b)
	if t.datagramLimit != 0 {
		if len(b) > t.datagramLimit {
			return ErrLimit
		}
		return t.run(ctx, func() error { return writeDatagram(t.conn, b) })
	}
	return t.run(ctx, func() error { return writeAll(t.conn, b) })
}

// PayloadLimit is the maximum application payload with no optional subheaders.
// In lossy mode subheaders reduce the available outgoing message space.
func (t *Tunnel) PayloadLimit() int {
	if t == nil {
		return 0
	}
	if t.datagramLimit != 0 {
		return min(t.maxPayload, t.datagramLimit-4)
	}
	return t.maxPayload
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
