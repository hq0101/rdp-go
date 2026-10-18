package dtls

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"
)

// Conn preserves one application record per Read/Write. It neither retransmits
// application data nor joins records into a stream. A short Read retains the
// entire application record. One reader and one writer may run concurrently.
// Close aborts I/O immediately, without sending or waiting for close_notify.
type Conn struct {
	raw                 net.Conn
	reader              *RecordReader
	writer              *RecordWriter
	mtu                 int
	state               ConnectionState
	readMu, writeMu, mu sync.Mutex
	once                sync.Once
	err                 error
	records             []Record
	pending             []byte
	hasPending          bool
}

var _ net.Conn = (*Conn)(nil)

func (c *Conn) String() string   { return "dtls.Conn{private connection}" }
func (c *Conn) GoString() string { return c.String() }
func (c *Conn) ConnectionState() ConnectionState {
	s := c.state
	s.PeerCertificates = append(s.PeerCertificates[:0:0], s.PeerCertificates...)
	return s
}
func (c *Conn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
func (c *Conn) terminal() error                    { c.mu.Lock(); defer c.mu.Unlock(); return c.err }
func (c *Conn) fail(err error) {
	if err == nil {
		err = net.ErrClosed
	}
	c.once.Do(func() {
		c.mu.Lock()
		c.err = err
		c.mu.Unlock()
		c.raw.Close()
		if c.reader != nil {
			c.reader.Close()
		}
		if c.writer != nil {
			c.writer.Close()
		}
	})
}
func (c *Conn) Close() error { c.fail(net.ErrClosed); return nil }

func parseAlert(b []byte) error {
	if len(b) != 2 || b[0] != 1 && b[0] != 2 {
		return ErrInvalid
	}
	if b[1] == 0 {
		return io.EOF
	}
	return errors.New("dtls: peer terminated the secure connection")
}

func (c *Conn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if err := c.terminal(); err != nil {
		return 0, err
	}
	if len(p) > c.mtu-RecordHeader-GCMExpansion || len(p) > MaxPlaintext {
		return 0, ErrLimit
	}
	b, err := c.writer.Seal(ApplicationData, p)
	if err != nil {
		c.fail(err)
		return 0, err
	}
	n, err := c.raw.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	if err != nil {
		c.fail(err)
		return 0, err
	}
	return len(p), nil
}

func (c *Conn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	buffer := make([]byte, MaxDatagram+1)
	for discarded := 0; discarded < 4096; discarded++ {
		if err := c.terminal(); err != nil {
			return 0, err
		}
		if c.hasPending {
			if len(p) < len(c.pending) {
				return 0, io.ErrShortBuffer
			}
			n := copy(p, c.pending)
			clear(c.pending)
			c.pending = nil
			c.hasPending = false
			return n, nil
		}
		if len(c.records) == 0 {
			n, err := c.raw.Read(buffer)
			if err != nil {
				var ne net.Error
				if !errors.As(err, &ne) || !ne.Timeout() {
					c.fail(err)
				}
				return 0, err
			}
			c.records, err = ParseDatagram(buffer[:n])
			if err != nil {
				continue
			}
		}
		r := c.records[0]
		c.records[0] = Record{}
		c.records = c.records[1:]
		if r.Epoch != 1 {
			continue
		} // old unauthenticated alerts cannot terminate data
		plain, err := c.reader.Open(r)
		if err != nil {
			continue
		}
		switch r.Type {
		case ApplicationData:
			c.pending = plain
			c.hasPending = true
		case Alert:
			err := parseAlert(plain)
			clear(plain)
			c.fail(err)
			return 0, err
		case Handshake:
			fs, err := parseFragments(plain)
			valid := err == nil && len(fs) > 0
			for _, f := range fs {
				valid = valid && f.typ == finishedMessage && f.total == 12
			}
			clear(plain)
			if !valid {
				c.fail(ErrUnsupported)
				return 0, ErrUnsupported
			} // no renegotiation
		default:
			clear(plain)
			c.fail(ErrHandshake)
			return 0, ErrHandshake
		}
	}
	c.fail(ErrLimit)
	return 0, ErrLimit
}
