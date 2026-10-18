package rdpudp

import (
	"context"
	"encoding/binary"
	"errors"
	"github.com/hq0101/rdp-go/rdpudp2"
	"io"
	"net"
	"os"
	"sync"
	"time"
)

// DialConfig configures an RDP-UDP transport, not TLS/DTLS or an RDP session.
// Version3 selects UDP2 if agreed, or falls back to the negotiated v1/v2 engine.
// Version3 requires the hash of the main connection's security cookie. The caller must establish
// the RDP-authorized sideband and verify TLS/DTLS identity and tunnel binding
// before using application traffic. No certificate validation is bypassed here.
type DialConfig struct {
	Initialization InitConfig
	Endpoint       EndpointConfig
}

// Conn implements net.Conn over reliable RDP-UDP. Writes enqueue copied stream
// bytes with bounded backpressure; success does not mean peer acknowledgment.
// Read/Write/Close/deadlines/Stats may be called concurrently. A Read/Write
// deadline does not stop protocol timers or destroy the connection. Close does
// not flush pending writes; it closes the socket and joins both worker goroutines.
// This is an unauthenticated transport suitable for wrapping with crypto/tls.
type Conn struct{ *connBase }

// DatagramConn preserves one nonempty UDP-L source per Write and an ordered
// subsequence of these sources per Read. Oversized writes fail atomically.
// A short read buffer returns io.ErrShortBuffer without consuming the retained
// datagram, so the caller can retry with a larger buffer. Use DTLS, not TLS, on
// this lossy transport. The concurrency/deadline rules are the same as Conn.
type DatagramConn struct{ *connBase }

// PayloadLimit returns the largest data message accepted by Write, including
// any FEC reservation. It returns zero after Close. TLS/DTLS overhead is not
// included; a DTLS caller uses this value as its outgoing record MTU.
func (c *DatagramConn) PayloadLimit() int {
	if c == nil || c.connBase == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ep.PayloadLimit()
}

var _ net.Conn = (*Conn)(nil)
var _ net.Conn = (*DatagramConn)(nil)

type ConnStats struct {
	Endpoint          EndpointStats
	UDP2              rdpudp2.Stats // populated only for negotiated Version3
	RejectedDatagrams uint64
	Rejections        RejectionStats
}

type dataEngine interface {
	Queue([]byte) error
	Read() ([]byte, error)
	Receive([]byte, time.Time) error
	Next(time.Time) ([]byte, error)
	Deadline() time.Time
	Close()
	PayloadLimit() int
	Available() int
}

type connBase struct {
	socket                      net.Conn
	local, remote               net.Addr
	parameters                  Parameters
	mu                          sync.Mutex
	readMu, writeMu             sync.Mutex
	ep                          dataEngine
	handshake                   *Initializer
	readBuffer                  []byte
	readDeadline, writeDeadline time.Time
	terminal                    error
	changed                     chan struct{}
	wake                        chan struct{}
	done                        chan struct{}
	wg                          sync.WaitGroup
	duplicateACK                []byte // coalesced duplicate SYN+ACK response, at most one
	rejected                    uint64
	rejections                  RejectionStats
}

// DialContext performs a bounded UDP initialization, restricted to a connected
// chosen-peer socket. network is udp, udp4 or udp6. ctx applies only to dialing
// and initialization; canceling it after return does not close the connection.
func DialContext(ctx context.Context, network, address string, config DialConfig) (*Conn, error) {
	if config.Initialization.Lossy {
		return nil, ErrInvalid
	}
	b, err := dialTransport(ctx, network, address, config)
	if err != nil {
		return nil, err
	}
	return &Conn{b}, nil
}

func DialDatagramContext(ctx context.Context, network, address string, config DialConfig) (*DatagramConn, error) {
	config.Initialization.Lossy = true
	b, err := dialTransport(ctx, network, address, config)
	if err != nil {
		return nil, err
	}
	return &DatagramConn{b}, nil
}

func dialTransport(ctx context.Context, network, address string, c DialConfig) (*connBase, error) {
	if ctx == nil || network != "udp" && network != "udp4" && network != "udp6" || c.Initialization.MaxVersion != 0 && !versionOK(c.Initialization.MaxVersion) || c.Initialization.ReceiveWindow > MaxWindowPackets {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h, err := NewInitializer(c.Initialization)
	if err != nil {
		return nil, err
	}
	// Validate all local engine options before opening a socket or sending SYN.
	probe, err := NewEndpoint(Parameters{Version: min(h.maxVersion, Version2), Lossy: h.lossy, LocalWindow: h.receiveWindow, RemoteWindow: 64, SendMTU: h.upMTU, ReceiveMTU: h.downMTU}, c.Endpoint, time.Now())
	if err != nil {
		h.Close()
		return nil, err
	}
	probe.Close()
	udp, err := (&net.Dialer{}).DialContext(ctx, network, address)
	if err != nil {
		h.Close()
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			h.Close()
			_ = udp.Close()
		}
	}()
	interruptDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = udp.SetDeadline(time.Now()); close(interruptDone) })
	stopInterrupt := func() {
		if !stop() {
			<-interruptDone
		}
	}
	// Stop and join the cancellation callback before clearing socket deadlines
	// and handing the connection to workers. It must never affect the live Conn.
	p, err := initializeSocket(ctx, udp, h)
	stopInterrupt()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		return nil, connectionError("dial", udp.LocalAddr(), udp.RemoteAddr(), err)
	}
	if err = udp.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	e, err := newDataEngine(p, c.Endpoint, h.RoundTrip(), time.Now())
	if err != nil {
		return nil, err
	}
	b := startConnection(udp, h, e, p)
	ok = true
	return b, nil
}

func initializeSocket(ctx context.Context, socket net.Conn, h *Initializer) (Parameters, error) {
	// A full UDP-size read avoids platform-specific message-too-large errors
	// before our smaller protocol datagram limit can be enforced.
	buffer := make([]byte, 65536)
	for {
		if err := ctx.Err(); err != nil {
			return Parameters{}, err
		}
		out, err := h.Next(time.Now())
		if err != nil {
			return Parameters{}, err
		}
		deadline := h.Deadline()
		if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
			deadline = d
		}
		if err = socket.SetDeadline(deadline); err != nil {
			return Parameters{}, err
		}
		// Cancellation may have fired just before SetDeadline. Recheck after
		// setting it so a future deadline cannot overwrite the wake-up and leave
		// a canceled dial blocked in Read until the next handshake retry.
		if err = ctx.Err(); err != nil {
			return Parameters{}, err
		}
		if out != nil {
			if err = writeDatagram(socket, out); err != nil {
				return Parameters{}, contextOrError(ctx, err)
			}
		}
		n, err := socket.Read(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return Parameters{}, ctx.Err()
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return Parameters{}, err
		}
		if n > MaxDatagram {
			continue
		}
		out, err = h.Handle(buffer[:n], time.Now())
		if err != nil {
			if errors.Is(err, ErrInvalid) || errors.Is(err, ErrLimit) {
				continue
			}
			return Parameters{}, err
		}
		if out == nil {
			continue
		}
		if err = writeDatagram(socket, out); err != nil {
			return Parameters{}, contextOrError(ctx, err)
		}
		p, ok := h.Parameters()
		if !ok {
			return Parameters{}, ErrState
		}
		return p, nil
	}
}

func contextOrError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
func writeDatagram(c net.Conn, p []byte) error {
	n, err := c.Write(p)
	if err == nil && n != len(p) {
		return io.ErrShortWrite
	}
	return err
}

func startConnection(socket net.Conn, h *Initializer, e dataEngine, p Parameters) *connBase {
	b := &connBase{socket: socket, local: copyAddr(socket.LocalAddr()), remote: copyAddr(socket.RemoteAddr()), parameters: p, ep: e, handshake: h, changed: make(chan struct{}), wake: make(chan struct{}, 1), done: make(chan struct{})}
	b.wg.Add(2)
	go func() { defer b.wg.Done(); b.receiveLoop() }()
	go func() { defer b.wg.Done(); b.sendLoop() }()
	return b
}

func copyAddr(a net.Addr) net.Addr {
	if u, ok := a.(*net.UDPAddr); ok {
		return &net.UDPAddr{IP: append(net.IP(nil), u.IP...), Port: u.Port, Zone: u.Zone}
	}
	return a
}

func (b *connBase) kick() {
	select {
	case b.wake <- struct{}{}:
	default:
	}
}
func (b *connBase) notifyLocked() { close(b.changed); b.changed = make(chan struct{}) }

func (b *connBase) fail(err error) {
	b.mu.Lock()
	if b.terminal != nil {
		b.mu.Unlock()
		return
	}
	b.terminal = err
	b.ep.Close()
	if b.handshake != nil {
		b.handshake.Close()
	}
	b.readBuffer, b.duplicateACK = nil, nil
	close(b.done)
	b.notifyLocked()
	b.mu.Unlock()
	_ = b.socket.Close()
}

func (b *connBase) sendLoop() {
	for {
		b.mu.Lock()
		if b.terminal != nil {
			b.mu.Unlock()
			return
		}
		packet, err := b.ep.Next(time.Now())
		if packet == nil && err == nil && b.duplicateACK != nil {
			packet = b.duplicateACK
			b.duplicateACK = nil
		}
		deadline := b.ep.Deadline()
		b.notifyLocked() // timer expiry can make lossy receive data readable
		b.mu.Unlock()
		if err != nil {
			b.fail(err)
			return
		}
		if packet != nil {
			// Application deadlines govern queue operations, not ACK/keepalive
			// socket I/O. Bound a blocked kernel write independently.
			if err = b.socket.SetWriteDeadline(time.Now().Add(5 * time.Second)); err == nil {
				err = writeDatagram(b.socket, packet)
			}
			if err != nil {
				b.fail(err)
				return
			}
			continue
		}
		timer := time.NewTimer(max(0, time.Until(deadline)))
		select {
		case <-timer.C:
		case <-b.wake:
		case <-b.done:
			timer.Stop()
			return
		}
		timer.Stop()
	}
}

func (b *connBase) receiveLoop() {
	buffer := make([]byte, 65536)
	for {
		n, err := b.socket.Read(buffer)
		if err != nil {
			b.fail(err)
			return
		}
		b.mu.Lock()
		if b.terminal != nil {
			b.mu.Unlock()
			return
		}
		if n > MaxDatagram {
			b.rejectLocked("datagram-size")
			b.mu.Unlock()
			continue
		}
		initialization := n >= 8 && binary.BigEndian.Uint16(buffer[6:])&FlagSYN != 0
		if initialization {
			if b.handshake == nil {
				err = ErrInvalid
			} else {
				var reply []byte
				reply, err = b.handshake.Handle(buffer[:n], time.Now())
				if err == nil && reply != nil {
					b.duplicateACK = reply
				}
			}
		} else {
			err = b.ep.Receive(buffer[:n], time.Now())
		}
		if err != nil {
			if errors.Is(err, ErrInvalid) || errors.Is(err, ErrLimit) || errors.Is(err, rdpudp2.ErrInvalid) || errors.Is(err, rdpudp2.ErrLimit) {
				reason := rdpudp2.RejectionReason(err)
				if initialization {
					reason = "initialization"
				} else if errors.Is(err, ErrInvalid) {
					reason = "legacy-invalid"
				} else if errors.Is(err, ErrLimit) {
					reason = "legacy-limit"
				}
				b.rejectLocked(reason)
				b.mu.Unlock()
				continue
			}
			b.mu.Unlock()
			b.fail(err)
			return
		}
		b.notifyLocked()
		b.mu.Unlock()
		b.kick()
	}
}

func (b *connBase) String() string   { return "rdpudp.Conn{private transport state}" }
func (b *connBase) GoString() string { return b.String() }
func (b *connBase) LocalAddr() net.Addr {
	if b == nil {
		return nil
	}
	return copyAddr(b.local)
}
func (b *connBase) RemoteAddr() net.Addr {
	if b == nil {
		return nil
	}
	return copyAddr(b.remote)
}
func (b *connBase) Parameters() Parameters {
	if b == nil {
		return Parameters{}
	}
	return b.parameters
}
func (b *connBase) Stats() ConnStats {
	if b == nil {
		return ConnStats{Endpoint: EndpointStats{Closed: true}}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	s := ConnStats{RejectedDatagrams: b.rejected, Rejections: b.rejections}
	switch e := b.ep.(type) {
	case *Endpoint:
		s.Endpoint = e.Stats()
	case *rdpudp2.Endpoint:
		s.UDP2 = e.Stats()
		v := s.UDP2
		s.Endpoint = EndpointStats{SourcesSent: v.SourcesSent, SourcesReceived: v.SourcesReceived, Retransmitted: v.Retransmitted, Acknowledged: v.Acknowledged, Duplicates: v.Duplicates, Queued: v.Queued, InFlight: v.Pending, Buffered: v.Buffered, CongestionWindow: int(v.CongestionWindow), RTT: v.RoundTrip, RTO: v.RetransmitTimeout, Closed: v.Closed}
	}
	return s
}
func (b *connBase) Err() error {
	if b == nil {
		return net.ErrClosed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.terminal
}
func (b *connBase) Close() error {
	if b == nil {
		return nil
	}
	b.fail(net.ErrClosed)
	b.wg.Wait()
	return nil
}

func (b *connBase) SetDeadline(t time.Time) error { return b.setDeadlines(t, t, true, true) }
func (b *connBase) SetReadDeadline(t time.Time) error {
	return b.setDeadlines(t, time.Time{}, true, false)
}
func (b *connBase) SetWriteDeadline(t time.Time) error {
	return b.setDeadlines(time.Time{}, t, false, true)
}
func (b *connBase) setDeadlines(r, w time.Time, read, write bool) error {
	if b == nil {
		return net.ErrClosed
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminal != nil {
		return net.ErrClosed
	}
	if read {
		b.readDeadline = r
	}
	if write {
		b.writeDeadline = w
	}
	b.notifyLocked()
	return nil
}

func (c *Conn) Read(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	return c.connBase.read(p, false)
}
func (c *Conn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	return c.connBase.write(p, false)
}
func (c *DatagramConn) Read(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	return c.connBase.read(p, true)
}
func (c *DatagramConn) Write(p []byte) (int, error) {
	if c == nil {
		return 0, net.ErrClosed
	}
	return c.connBase.write(p, true)
}

func (b *connBase) read(p []byte, datagram bool) (int, error) {
	if b == nil {
		return 0, net.ErrClosed
	}
	b.readMu.Lock()
	defer b.readMu.Unlock()
	for {
		b.mu.Lock()
		if err := b.operationErrorLocked("read", b.readDeadline); err != nil {
			b.mu.Unlock()
			return 0, err
		}
		if len(p) == 0 && !datagram {
			b.mu.Unlock()
			return 0, nil
		}
		if b.readBuffer == nil {
			var err error
			b.readBuffer, err = b.ep.Read()
			if err != nil {
				b.mu.Unlock()
				return 0, connectionError("read", b.local, b.remote, err)
			}
			if b.readBuffer != nil {
				b.kick()
			}
		}
		if b.readBuffer != nil {
			if datagram && len(p) < len(b.readBuffer) {
				b.mu.Unlock()
				return 0, io.ErrShortBuffer
			}
			n := copy(p, b.readBuffer)
			b.readBuffer = b.readBuffer[n:]
			if len(b.readBuffer) == 0 {
				b.readBuffer = nil
			}
			b.mu.Unlock()
			return n, nil
		}
		changed, deadline := b.changed, b.readDeadline
		b.mu.Unlock()
		waitChange(changed, deadline)
	}
}

func (b *connBase) write(p []byte, datagram bool) (int, error) {
	if b == nil {
		return 0, net.ErrClosed
	}
	b.writeMu.Lock()
	defer b.writeMu.Unlock()
	written := 0
	for {
		b.mu.Lock()
		if err := b.operationErrorLocked("write", b.writeDeadline); err != nil {
			b.mu.Unlock()
			return written, err
		}
		limit := b.ep.PayloadLimit()
		if datagram && (len(p) == 0 || len(p) > limit) {
			b.mu.Unlock()
			if len(p) == 0 {
				return 0, ErrInvalid
			}
			return 0, ErrLimit
		}
		if written == len(p) {
			b.mu.Unlock()
			return written, nil
		}
		available := b.ep.Available()
		if available > 0 {
			n := min(len(p)-written, available*limit)
			if err := b.ep.Queue(p[written : written+n]); err != nil {
				b.mu.Unlock()
				return written, err
			}
			written += n
			b.mu.Unlock()
			b.kick()
			continue
		}
		changed, deadline := b.changed, b.writeDeadline
		b.mu.Unlock()
		waitChange(changed, deadline)
	}
}

func waitChange(changed <-chan struct{}, deadline time.Time) {
	if deadline.IsZero() {
		<-changed
		return
	}
	timer := time.NewTimer(max(0, time.Until(deadline)))
	defer timer.Stop()
	select {
	case <-changed:
	case <-timer.C:
	}
}

func (b *connBase) operationErrorLocked(op string, deadline time.Time) error {
	if b.terminal != nil {
		return connectionError(op, b.local, b.remote, b.terminal)
	}
	if !deadline.IsZero() && !time.Now().Before(deadline) {
		return connectionError(op, b.local, b.remote, os.ErrDeadlineExceeded)
	}
	return nil
}

type transportTimeout struct{ cause error }

func (e transportTimeout) Error() string   { return e.cause.Error() }
func (e transportTimeout) Unwrap() error   { return e.cause }
func (e transportTimeout) Timeout() bool   { return true }
func (e transportTimeout) Temporary() bool { return false }
func connectionError(op string, local, remote net.Addr, err error) error {
	if errors.Is(err, ErrTimeout) || errors.Is(err, ErrDataTimeout) || errors.Is(err, rdpudp2.ErrTimeout) {
		err = transportTimeout{err}
	}
	return &net.OpError{Op: op, Net: "rdpudp", Source: copyAddr(local), Addr: copyAddr(remote), Err: err}
}
