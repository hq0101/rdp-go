package rdghttp

import (
	"context"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Streams carries RDG packets, not bare RDP bytes. The caller drives Client,
// handles consent and applies policy before opening a target channel. Reading
// and writing may run concurrently; calls within each direction are serialized.
// No background reader, application queue, automatic retry or keepalive is used.
type Streams struct {
	pair       *HTTPPair
	r          io.Reader
	w          io.Writer
	rmu, wmu   sync.Mutex
	writeEnded bool // protected by wmu
	inRead     atomic.Bool
}

// OpenStreams consumes this pair exactly once. This initial supported profile
// uses HTTP/1.1, unframed final 200 bodies, exactly ten initial seed bytes per
// connection, no OUT resubmission, and a new chunked IN request on the existing
// authenticated connection. The seed is discarded by length, never scanned for
// a plausible packet header. This profile was corroborated by an independent
// client against a local peer; it is not a claim of real RD Gateway validation.
// Framed bodies, other seed sizes, HTTP/1.0 and reconnect/resubmit variants are
// not inferred or retried. MS-TSGU's general 100-byte seed limit does not specify
// a discoverable boundary for an unframed body.
//
// Setup has a 20-second ceiling, shortened by ctx. An error closes both sockets.
// After success ctx is detached and deadlines cleared; use Streams deadlines
// or Close for ongoing I/O. Close aborts immediately; it does not negotiate a
// protocol close or wait for a response to the indefinitely streaming IN body.
func (p *HTTPPair) OpenStreams(ctx context.Context) (stream *Streams, err error) {
	if p == nil || ctx == nil || p.out == nil || p.in == nil {
		return nil, ErrInvalid
	}
	if p.closed.Load() {
		return nil, net.ErrClosed
	}
	if !p.opened.CompareAndSwap(false, true) {
		return nil, ErrState
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { p.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		err = httpContextResult(ctx, err)
		if err == nil && p.closed.Load() {
			err = net.ErrClosed
		}
		if err != nil {
			p.Close()
			stream = nil
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	for _, ch := range []*httpChannel{p.out, p.in} {
		if err = streamResponse(ch.response); err != nil {
			return nil, err
		}
		if deadline, ok := ctx.Deadline(); ok {
			if err = ch.raw.SetDeadline(deadline); err != nil {
				return nil, err
			}
		}
	}
	for _, ch := range []*httpChannel{p.out, p.in} {
		var seed [10]byte
		if _, err = io.ReadFull(ch.response.Body, seed[:]); err != nil {
			return nil, err
		}
	}
	if err = writeHTTPHeader(p.in.conn, methodIn, p.host, p.id, "", true); err != nil {
		return nil, err
	}
	for _, ch := range []*httpChannel{p.out, p.in} {
		if err = ch.raw.SetDeadline(time.Time{}); err != nil {
			return nil, err
		}
	}
	return &Streams{pair: p, r: p.out.response.Body, w: p.in.conn}, nil
}

func streamResponse(r *http.Response) error {
	if r == nil || r.StatusCode != 200 || r.Body == nil {
		return ErrHTTP
	}
	if r.ProtoMajor != 1 || r.ProtoMinor != 1 || r.ContentLength != -1 || len(r.TransferEncoding) != 0 {
		return ErrUnsupported
	}
	for _, v := range r.Header.Values("Connection") {
		for _, token := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(token), "close") {
				return ErrUnsupported
			}
		}
	}
	// net/http sets Response.Close for an unframed entity even with keep-alive.
	// Its Body correctly exposes the raw continuing entity; don't drain/Close it.
	return nil
}

func (s *Streams) ReadFrame() (Frame, error) {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if s.pair.closed.Load() {
		return Frame{}, net.ErrClosed
	}
	f, err := ReadFrame(s.r)
	if err != nil {
		s.Close()
		return Frame{}, err
	}
	return f, nil
}

// WriteFrame emits one complete packet as an HTTP chunk. HTTP chunk boundaries
// are not packet boundaries on receive. A partial/error write closes both sides
// to prohibit replay on a now misaligned stream. Invalid local frames emit none.
func (s *Streams) WriteFrame(f Frame) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.pair.closed.Load() || s.writeEnded {
		return net.ErrClosed
	}
	b, err := f.MarshalBinary()
	if err != nil {
		return err
	}
	defer clear(b)
	if err = writeHTTPChunk(s.w, b); err != nil {
		s.Close()
	}
	return err
}

func writeHTTPChunk(w io.Writer, b []byte) error {
	if len(b) < HeaderSize || len(b) > MaxPacketSize {
		return ErrLimit
	}
	header := strconv.AppendInt(make([]byte, 0, 16), int64(len(b)), 16)
	header = append(header, '\r', '\n')
	if err := writeHTTPAll(w, header); err != nil {
		return err
	}
	if err := writeHTTPAll(w, b); err != nil {
		return err
	}
	return writeHTTPAll(w, []byte{'\r', '\n'})
}

// FinishWrite terminates only the HTTP IN request, after the caller has sent
// all binary protocol close packets. OUT remains readable. It is idempotent;
// any send failure is terminal for the pair, and future writes cannot replay it.
func (s *Streams) FinishWrite() error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	if s.pair.closed.Load() {
		return net.ErrClosed
	}
	if s.writeEnded {
		return nil
	}
	s.writeEnded = true
	err := writeHTTPAll(s.w, []byte("0\r\n\r\n"))
	if err != nil {
		s.Close()
	}
	return err
}

func (s *Streams) Close() error   { return s.pair.Close() }
func (*Streams) String() string   { return "rdghttp.Streams{private connections}" }
func (*Streams) GoString() string { return "rdghttp.Streams{private connections}" }

// ReadINStatus is a one-shot observer of the streaming IN request's final
// response. It owns the IN reader after OpenStreams consumed its seed. It
// never drains a body, follows a redirect or repeats authentication. Close
// interrupts a blocked call. An early response is terminal for a byte adapter.
func (s *Streams) ReadINStatus() (int, error) {
	if !s.inRead.CompareAndSwap(false, true) {
		return 0, ErrState
	}
	r, err := readHTTPResponse(s.pair.in.reader, methodIn)
	if err != nil {
		return 0, err
	}
	return r.StatusCode, nil
}

type streamAddress struct{ network, value string }

func (a streamAddress) Network() string { return a.network }
func (a streamAddress) String() string  { return a.value }
func (s *Streams) LocalAddr() net.Addr {
	a := s.pair.out.raw.LocalAddr()
	return streamAddress{a.Network(), a.String()}
}
func (s *Streams) GatewayAddr() net.Addr {
	a := s.pair.out.raw.RemoteAddr()
	return streamAddress{a.Network(), a.String()}
}

// Deadlines can interrupt pending calls without acquiring the read/write locks.
// Unlike a byte-oriented net.Conn, any I/O error is terminal: a packet may have
// been partly consumed/sent. Clearing a deadline cannot restart a failed stream.
func (s *Streams) SetReadDeadline(t time.Time) error {
	if s.pair.closed.Load() {
		return net.ErrClosed
	}
	return s.pair.out.raw.SetReadDeadline(t)
}
func (s *Streams) SetWriteDeadline(t time.Time) error {
	if s.pair.closed.Load() {
		return net.ErrClosed
	}
	return s.pair.in.raw.SetWriteDeadline(t)
}
func (s *Streams) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}
