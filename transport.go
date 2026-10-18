package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/hq0101/rdp-go/mcs"
	"github.com/hq0101/rdp-go/tpkt"
	"github.com/hq0101/rdp-go/x224"
)

var ErrInvalidFrame = errors.New("rdp: invalid frame")

type FrameKind uint8

const (
	FrameMCS FrameKind = iota
	FrameFastPath
)

// Frame contains owned packet data. MCS frames exclude TPKT and X.224 headers;
// fast-path frames exclude their length/header bytes but are NOT decoded graphics.
type Frame struct {
	Kind               FrameKind
	Data               []byte
	fastPathHeaderSize int // retained for continuous network-byte accounting
}

// Transport is an established TLS transport, optionally with NLA completed, NOT
// an active desktop session. Construct it with DialTLS or DialNLA, or obtain an
// RDSTLS transport through redirected Session establishment. One read and one
// write can run concurrently. Additional callers wait with context cancellation.
// An I/O/framing error closes the transport because a packet boundary may be lost.
type Transport struct {
	gatewayDynamic      *DynamicChannelOptions // immutable snapshot for gateway channel checks
	raw                 net.Conn
	conn                *tls.Conn
	negotiation         x224.Confirm
	maxSize             int
	readGate, writeGate chan struct{}
	closed              chan struct{}
	closeOnce           sync.Once
	closeErr            error
	failureMu           sync.Mutex
	failure             error // first terminal I/O cause; nil for deliberate Close
	requested           x224.Protocol
	nla                 NLAState
	rdstls              RDSTLSState
	certificatePinned   bool
	channelsStarted     bool // protected by both I/O gates
	mcsLimit            int  // read under either I/O gate; writes require both gates
}

func newTransport(raw net.Conn, conn *tls.Conn, c x224.Confirm, max int) *Transport {
	return &Transport{raw: raw, conn: conn, negotiation: c, maxSize: max, requested: x224.ProtocolTLS, mcsLimit: max - 7,
		readGate: make(chan struct{}, 1), writeGate: make(chan struct{}, 1), closed: make(chan struct{})}
}

// Close immediately closes the underlying socket and unblocks pending I/O.
// It does not send an RDP disconnect PDU or wait for a TLS close-notify.
func (t *Transport) Close() error {
	return t.closeWithCause(nil)
}
func (t *Transport) closeWithCause(cause error) error {
	t.closeOnce.Do(func() {
		t.failureMu.Lock()
		t.failure = cause
		t.failureMu.Unlock()
		close(t.closed)
		t.closeErr = t.raw.Close()
	})
	return t.closeErr
}

func (t *Transport) failedNetwork() bool {
	t.failureMu.Lock()
	defer t.failureMu.Unlock()
	return reconnectableNetworkError(t.failure)
}

// Negotiation returns the recorded pre-TLS selection. OpenChannels verifies the
// negotiation replay in the GCC server core data before joining any channels.
func (t *Transport) Negotiation() x224.Confirm { return t.negotiation }

func (t *Transport) TLSState() tls.ConnectionState { return t.conn.ConnectionState() }

// CertificatePinned reports whether the TLS handshake verified the explicitly
// configured leaf fingerprint. TLSState.VerifiedChains is empty in this mode.
func (t *Transport) CertificatePinned() bool { return t.certificatePinned }

// LocalAddr and RemoteAddr return owned address snapshots of the main transport.
// A sideband must target this established peer, rather than resolving the
// original hostname again and potentially selecting a different server. Gateway
// RemoteAddr is logical; gateway routes do not support a direct UDP sideband.
func (t *Transport) LocalAddr() net.Addr {
	if t == nil || t.raw == nil {
		return nil
	}
	return transportAddr(t.raw.LocalAddr())
}
func (t *Transport) RemoteAddr() net.Addr {
	if t == nil || t.raw == nil {
		return nil
	}
	return transportAddr(t.raw.RemoteAddr())
}
func transportAddr(a net.Addr) net.Addr {
	switch a := a.(type) {
	case *net.TCPAddr:
		return &net.TCPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
	case *net.UDPAddr:
		return &net.UDPAddr{IP: append(net.IP(nil), a.IP...), Port: a.Port, Zone: a.Zone}
	default:
		return a
	}
}

// NLAState distinguishes credential delegation from explicit early authorization.
// These authentication flags do not mean that an RDP desktop session is active.
type NLAState struct {
	CredentialsDelegated, EarlyAuthorizationConfirmed bool
	// SPNEGO reports completed negotiation using the configured mechanism.
	SPNEGO bool
	// Kerberos reports verified Kerberos mutual authentication and TLS binding.
	Kerberos bool
}

func (t *Transport) NLAState() NLAState { return t.nla }

func (t *Transport) acquire(ctx context.Context, gate chan struct{}) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.closed:
		return net.ErrClosed
	case gate <- struct{}{}:
	}
	select {
	case <-t.closed:
		<-gate
		return net.ErrClosed
	default:
	}
	if err := ctx.Err(); err != nil {
		<-gate
		return err
	}
	return nil
}

// WriteMCS sends one already-encoded MCS PDU as TPKT/X.224. It does not encode
// MCS messages or perform the required RDP session state transitions for you.
func (t *Transport) WriteMCS(ctx context.Context, pdu []byte) error {
	if len(pdu) > t.maxSize-7 {
		return fmt.Errorf("%w: outgoing packet exceeds limit", ErrInvalidFrame)
	}
	if err := checkMCSDataSize(pdu); err != nil {
		return err
	}
	b, err := x224.MarshalData(pdu)
	if err != nil {
		return err
	}
	if err := t.acquire(ctx, t.writeGate); err != nil {
		return err
	}
	defer func() { <-t.writeGate }()
	if len(pdu) > t.mcsLimit {
		return fmt.Errorf("%w: outgoing MCS PDU exceeds server limit", ErrInvalidFrame)
	}
	err = runIO(ctx, t.conn.SetWriteDeadline, func() error { return tpkt.Write(t.conn, b) })
	if err != nil {
		t.closeWithCause(err)
		return fmt.Errorf("rdp write: %w", err)
	}
	return nil
}

// ReadFrame reads a slow-path MCS frame or an unencrypted fast-path output frame
// inside TLS. Context cancellation during I/O closes the transport, including if
// only part of a packet was consumed. Cancellation while queued leaves it intact.
func (t *Transport) ReadFrame(ctx context.Context) (Frame, error) {
	var f Frame
	if err := t.acquire(ctx, t.readGate); err != nil {
		return f, err
	}
	defer func() { <-t.readGate }()
	err := runIO(ctx, t.conn.SetReadDeadline, func() error {
		var err error
		f, err = readFrame(t.conn, t.maxSize)
		if err == nil && f.Kind == FrameMCS && len(f.Data) > t.mcsLimit {
			clear(f.Data)
			err = fmt.Errorf("%w: incoming MCS PDU exceeds negotiated limit", ErrInvalidFrame)
		}
		return err
	})
	if err != nil {
		t.closeWithCause(err)
		return Frame{}, fmt.Errorf("rdp read: %w", err)
	}
	return f, nil
}

func readFrame(r io.Reader, maxSize int) (Frame, error) {
	var f Frame
	var h [3]byte
	if _, err := io.ReadFull(r, h[:1]); err != nil {
		return f, err
	}
	if h[0] == 3 {
		b, err := tpkt.Read(io.MultiReader(bytes.NewReader(h[:1]), r), maxSize)
		if err != nil {
			return f, err
		}
		pdu, err := x224.ParseData(b)
		if err != nil {
			return f, err
		}
		if err := checkMCSDataSize(pdu); err != nil {
			clear(pdu)
			return f, err
		}
		return Frame{Kind: FrameMCS, Data: pdu}, nil
	}
	// Fast-path server output reserves bits 2..5. Bits 6..7 are Standard
	// Security flags; reject double encryption on a TLS transport (3.2.5.9.3).
	if h[0] != 0 {
		return f, fmt.Errorf("%w: fast-path action, reserved or security bits 0x%02x", ErrInvalidFrame, h[0])
	}
	if _, err := io.ReadFull(r, h[1:2]); err != nil {
		return f, err
	}
	length, headerSize := int(h[1]), 2
	if h[1]&0x80 != 0 {
		if _, err := io.ReadFull(r, h[2:3]); err != nil {
			return f, err
		}
		length, headerSize = int(h[1]&0x7f)<<8|int(h[2]), 3
	}
	if length <= headerSize || length > maxSize {
		return f, fmt.Errorf("%w: fast-path length %d", ErrInvalidFrame, length)
	}
	b := make([]byte, length-headerSize)
	if _, err := io.ReadFull(r, b); err != nil {
		return f, err
	}
	return Frame{Kind: FrameFastPath, Data: b, fastPathHeaderSize: headerSize}, nil
}

// Only Send Data PDUs have the RDP 16 KiB profile bound. BER connection
// structures and fast-path output have separate limits. Low-level framing
// remains opaque; semantic/header validation belongs to the MCS parser.
func checkMCSDataSize(pdu []byte) error {
	if len(pdu) > mcs.MaxDataPDUSize && (pdu[0]>>2 == 25 || pdu[0]>>2 == 26) {
		return fmt.Errorf("%w: %w", ErrInvalidFrame, mcs.ErrDataSize)
	}
	return nil
}
