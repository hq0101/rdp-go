package rdgateway

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hq0101/rdp-go/internal/rdghttp"
)

type packetStream interface {
	ReadFrame() (rdghttp.Frame, error)
	WriteFrame(rdghttp.Frame) error
	ReadINStatus() (int, error)
	FinishWrite() error
	SetWriteDeadline(time.Time) error
	Close() error
	LocalAddr() net.Addr
	GatewayAddr() net.Addr
}

type address struct{ network, value string }

func (a address) Network() string { return a.network }
func (a address) String() string  { return a.value }

// Conn is a concurrent target byte stream. The zero value is not usable.
// Read timeouts are recoverable, even during a partial RDG packet. An error
// while actually sending a packet is terminal: its delivery is ambiguous.
// Close aborts both HTTPS sockets and joins the two background readers.
// Call Shutdown for bounded, graceful binary/HTTP close instead.
type Conn struct {
	stream                      packetStream
	engine                      *rdghttp.Client
	engineMu                    sync.Mutex
	mu                          sync.Mutex
	wg                          sync.WaitGroup
	gate                        chan struct{}
	done, changed, inDone       chan struct{}
	terminal                    error
	buf                         []byte
	start, size                 int
	services                    [][]byte
	serviceBytes                int
	readDeadline, writeDeadline time.Time
	// writing: 0 idle, 1 user, 2 control; protected by mu. Physical IN write
	// deadline changes are serialized with this state, never with engineMu.
	writing             uint8
	shutting, finishing bool
	controlTimeout      time.Duration
	info                Info
	target              address
}

var _ net.Conn = (*Conn)(nil)

func newConn(s packetStream, e *rdghttp.Client, capacity int, control time.Duration) *Conn {
	return &Conn{stream: s, engine: e, gate: make(chan struct{}, 1), done: make(chan struct{}), changed: make(chan struct{}), inDone: make(chan struct{}), buf: make([]byte, capacity), controlTimeout: control}
}
func (*Conn) String() string        { return "rdgateway.Conn{private connections}" }
func (*Conn) GoString() string      { return "rdgateway.Conn{private connections}" }
func (c *Conn) Info() Info          { return c.info }
func (c *Conn) LocalAddr() net.Addr { return c.stream.LocalAddr() }

// RemoteAddr identifies the first requested resource, not a resolved server or
// the gateway TCP peer. It must not be used to open a direct UDP side channel.
func (c *Conn) RemoteAddr() net.Addr  { return c.target }
func (c *Conn) GatewayAddr() net.Addr { return c.stream.GatewayAddr() }

func (c *Conn) wake() { close(c.changed); c.changed = make(chan struct{}) }

func (c *Conn) stop(err error, discard bool) {
	c.mu.Lock()
	first := c.terminal == nil
	if first {
		c.terminal = publicError(err)
		close(c.done)
	}
	if discard {
		clear(c.buf)
		c.start, c.size = 0, 0
		for _, b := range c.services {
			clear(b)
		}
		c.services = nil
		c.serviceBytes = 0
	}
	c.wake()
	c.mu.Unlock()
	if first {
		c.stream.Close()
		c.engineMu.Lock()
		c.engine.Abort()
		c.engineMu.Unlock()
	}
}

func (c *Conn) Close() error {
	c.stop(net.ErrClosed, true)
	c.wg.Wait()
	return nil
}

// waitChange does not hold a mutex. The caller always rechecks its predicate;
// changing or clearing a deadline wakes it and invalidates the previous timer.
func waitChange(ch <-chan struct{}, deadline time.Time) {
	if deadline.IsZero() {
		<-ch
		return
	}
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case <-ch:
	case <-t.C:
	}
}
func expired(t time.Time) bool { return !t.IsZero() && !time.Now().Before(t) }

func (c *Conn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		// After termination no wait is possible: drain preserved bytes, then
		// return the terminal cause. A stale deadline must not hide both.
		if c.terminal == nil && expired(c.readDeadline) {
			return 0, os.ErrDeadlineExceeded
		}
		if c.size != 0 {
			n := min(len(p), c.size)
			first := min(n, len(c.buf)-c.start)
			copy(p, c.buf[c.start:c.start+first])
			copy(p[first:n], c.buf[:n-first])
			clear(c.buf[c.start : c.start+first])
			clear(c.buf[:n-first])
			c.start = (c.start + n) % len(c.buf)
			c.size -= n
			c.wake()
			return n, nil
		}
		if c.terminal != nil {
			return 0, c.terminal
		}
		if len(p) == 0 {
			return 0, nil
		}
		ch, deadline := c.changed, c.readDeadline
		c.mu.Unlock()
		waitChange(ch, deadline)
		c.mu.Lock()
	}
}

func (c *Conn) pushData(p []byte) error {
	defer clear(p)
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.buf)-c.size < len(p) && c.terminal == nil && !c.shutting {
		ch := c.changed
		c.mu.Unlock()
		<-ch
		c.mu.Lock()
	}
	if c.terminal != nil {
		return c.terminal
	}
	if c.shutting {
		return nil
	} // Shutdown must still reach a queued close ack.
	end := (c.start + c.size) % len(c.buf)
	n := copy(c.buf[end:], p)
	copy(c.buf, p[n:])
	c.size += len(p)
	c.wake()
	return nil
}

func (c *Conn) pushService(p []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		clear(p)
		return c.terminal
	}
	if len(c.services) >= 16 || len(p) > 256*1024-c.serviceBytes {
		clear(p)
		return ErrLimit
	}
	c.services = append(c.services, p)
	c.serviceBytes += len(p)
	c.wake()
	return nil
}

// ReadService returns one owned opaque gateway service message. It is separate
// from target bytes and read deadlines. At most 16 messages / 256 KiB queue;
// overflow is terminal. Consume these if the gateway sends service messages.
func (c *Conn) ReadService(ctx context.Context) ([]byte, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if len(c.services) > 0 {
			p := c.services[0]
			c.services[0] = nil
			c.services = c.services[1:]
			c.serviceBytes -= len(p)
			return p, nil
		}
		if c.terminal != nil {
			return nil, c.terminal
		}
		ch := c.changed
		c.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
		}
		c.mu.Lock()
	}
}

func (c *Conn) acquireUser() error {
	for {
		c.mu.Lock()
		err, d, ch := c.terminal, c.writeDeadline, c.changed
		if err == nil && c.shutting {
			err = net.ErrClosed
		}
		c.mu.Unlock()
		if err != nil {
			return err
		}
		if expired(d) {
			return os.ErrDeadlineExceeded
		}
		var timer *time.Timer
		var timeout <-chan time.Time
		if !d.IsZero() {
			timer = time.NewTimer(time.Until(d))
			timeout = timer.C
		}
		select {
		case c.gate <- struct{}{}:
			if timer != nil {
				timer.Stop()
			}
			return nil
		case <-ch:
		case <-timeout:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	if err := c.acquireUser(); err != nil {
		return 0, err
	}
	defer func() { <-c.gate }()
	n := 0
	for {
		c.mu.Lock()
		err := c.terminal
		if err == nil && c.shutting {
			err = net.ErrClosed
		}
		if err == nil && expired(c.writeDeadline) {
			err = os.ErrDeadlineExceeded
		}
		deadlineFailure := false
		if err == nil && len(p) > 0 {
			c.writing = 1
			err = c.stream.SetWriteDeadline(c.writeDeadline)
			deadlineFailure = err != nil
			if deadlineFailure {
				c.writing = 0
			}
		}
		c.mu.Unlock()
		if err != nil {
			if deadlineFailure {
				c.stop(err, false)
			}
			return n, err
		}
		if len(p) == 0 {
			return n, nil
		}
		count := min(len(p), rdghttp.MaxDataSize)
		c.engineMu.Lock()
		f, err := c.engine.SendData(p[:count])
		closing := c.engine.State() == rdghttp.Closed || c.engine.State() == rdghttp.Closing
		c.engineMu.Unlock()
		if err != nil && closing {
			c.mu.Lock()
			c.writing = 0
			c.mu.Unlock()
			return n, net.ErrClosed
		}
		if err == nil {
			err = c.stream.WriteFrame(f)
		}
		clear(f.Body)
		c.mu.Lock()
		c.writing = 0
		c.mu.Unlock()
		if err != nil {
			c.stop(err, false)
			return n, publicError(err)
		}
		n += count
		p = p[count:]
	}
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		return net.ErrClosed
	}
	c.readDeadline = t
	c.wake()
	return nil
}
func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		return net.ErrClosed
	}
	c.writeDeadline = t
	c.wake()
	if c.writing == 1 {
		return c.stream.SetWriteDeadline(t)
	}
	return nil
}
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *Conn) watchIN() {
	defer c.wg.Done()
	defer close(c.inDone)
	code, err := c.stream.ReadINStatus()
	c.mu.Lock()
	ended, finishing := c.terminal != nil, c.finishing
	c.mu.Unlock()
	if ended {
		return
	}
	if finishing && (err == io.EOF || err == nil && code == 200) {
		return
	}
	if err == nil {
		err = &INStatusError{code}
	} else if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	c.stop(err, false)
}

func (c *Conn) readOUT() {
	defer c.wg.Done()
	for {
		f, err := c.stream.ReadFrame()
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			c.stop(err, false)
			return
		}
		c.engineMu.Lock()
		step, err := c.engine.Receive(f)
		c.engineMu.Unlock()
		clear(f.Body)
		if err != nil {
			c.stop(err, false)
			return
		}
		switch step.Event {
		case rdghttp.ReceivedData:
			err = c.pushData(step.Data)
		case rdghttp.ReceivedService:
			err = c.pushService(step.Data)
		case rdghttp.Disconnected:
			ctx, cancel := context.WithTimeout(context.Background(), c.controlTimeout)
			err = c.control(ctx, step.Outbound, true, false)
			cancel()
			if err == nil {
				err = io.EOF
				if step.Status != 0 {
					err = &StatusError{uint16(f.Type), step.Status}
				}
			}
			c.stop(err, false)
			return
		}
		if err != nil {
			c.stop(err, false)
			return
		}
	}
}

// control serializes protocol writes with user writes without holding engineMu
// across I/O. Context cancellation interrupts an active control write, too.
func (c *Conn) control(ctx context.Context, frames []rdghttp.Frame, finish, begin bool) (err error) {
	defer func() {
		for _, f := range frames {
			clear(f.Body)
		}
	}()
	select {
	case c.gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		c.mu.Lock()
		err = c.terminal
		c.mu.Unlock()
		return err
	}
	defer func() { <-c.gate }()
	if err = ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.terminal != nil {
		err = c.terminal
		c.mu.Unlock()
		return err
	}
	c.writing = 2
	d, _ := ctx.Deadline()
	err = c.stream.SetWriteDeadline(d)
	if finish {
		c.finishing = true
	}
	c.mu.Unlock()
	if err != nil {
		return err
	}
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.stop(ctx.Err(), false); close(callbackDone) })
	defer func() {
		if !stop() {
			<-callbackDone
		}
		c.mu.Lock()
		c.writing = 0
		c.mu.Unlock()
		if ctx.Err() != nil {
			err = ctx.Err()
		} else if d, ok := ctx.Deadline(); ok && expired(d) {
			err = context.DeadlineExceeded
		}
	}()
	if begin {
		c.engineMu.Lock()
		if c.engine.State() == rdghttp.Closed {
			c.engineMu.Unlock()
			return nil
		}
		var step rdghttp.Step
		step, err = c.engine.BeginClose()
		frames = step.Outbound
		c.engineMu.Unlock()
		if err != nil {
			return err
		}
	}
	for _, f := range frames {
		if err = c.stream.WriteFrame(f); err != nil {
			return err
		}
	}
	if finish {
		err = c.stream.FinishWrite()
		if err == nil {
			select {
			case <-c.inDone:
			case <-c.done:
			case <-ctx.Done():
				return ctx.Err()
			}
			c.mu.Lock()
			err = c.terminal
			c.mu.Unlock()
		}
	}
	return err
}

// Shutdown initiates or waits for a graceful protocol close, bounded by ctx and
// ControlTimeout. Pending target data is discarded from the wire to reach the
// acknowledgement; bytes already queued remain readable. Timeout aborts both
// sockets. Concurrent Shutdown calls send only one close request.
func (c *Conn) Shutdown(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, c.controlTimeout)
	defer cancel()
	c.mu.Lock()
	start := !c.shutting && c.terminal == nil
	c.shutting = true
	c.wake()
	c.mu.Unlock()
	if start {
		if err := c.control(ctx, nil, false, true); err != nil {
			c.stop(err, false)
		}
	}
	select {
	case <-c.done:
	case <-ctx.Done():
		c.stop(ctx.Err(), false)
	}
	c.wg.Wait()
	c.mu.Lock()
	err := c.terminal
	c.mu.Unlock()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}
