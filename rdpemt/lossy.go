package rdpemt

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/hq0101/rdp-go/internal/dtls"
	"github.com/hq0101/rdp-go/rdpudp"
)

// LossyTunnelOptions bounds one DTLS handshake and Tunnel Create exchange.
// There is no implicit fallback to weaker security or a different identity.
type LossyTunnelOptions struct {
	MaxPayload              int           // application receive/send limit; zero uses protocol maximum
	BindTimeout             time.Duration // default 10s, at most 2m, including DTLS
	RetryInterval           time.Duration // create-request retry; default 200ms, 10ms..5s
	MaxAttempts             int           // create-request attempts; default 5, 1..16
	AllowLegacyMasterSecret bool          // explicit DTLS EMS compatibility option
}

// BindLossy takes ownership of an initialized UDP-L connection, performs DTLS
// with the exact authenticated main connection identity, and sends the secret
// cookie only after both certificate/signature and Finished verification.
// Any failure closes this sideband; it never closes the main RDP connection.
// The caller must validate bootstrap channel/protocol and use the main peer's
// address. Applications must finish negotiated Soft-Sync before using the tunnel.
// Application PDUs occupy one complete DTLS record; they are not retransmitted.
// Network-probe subheaders are preserved for the owner, not processed here.
func BindLossy(ctx context.Context, transport *rdpudp.DatagramConn, identity ServerIdentity, request InitiateRequest, opts LossyTunnelOptions) (*Tunnel, error) {
	defer clear(request.Cookie[:])
	if transport == nil {
		return nil, ErrInvalid
	}
	return bindLossy(ctx, transport, transport.PayloadLimit(), identity, request, opts)
}

// The transport-neutral helper is private: production callers must supply an
// initialized RDP-UDP datagram connection with its real FEC-aware payload limit.
func bindLossy(ctx context.Context, raw net.Conn, mtu int, identity ServerIdentity, request InitiateRequest, opts LossyTunnelOptions) (_ *Tunnel, err error) {
	defer clear(request.Cookie[:])
	if raw == nil {
		return nil, ErrInvalid
	}
	ok := false
	var secure *dtls.Conn
	defer func() {
		if !ok {
			if secure != nil {
				secure.Close()
			} else {
				raw.Close()
			}
		}
	}()
	if ctx == nil || request.Protocol != LossyUDP || opts.MaxPayload < 0 || opts.MaxPayload > MaxPayload || opts.BindTimeout < 0 || opts.BindTimeout > 2*time.Minute || opts.RetryInterval < 0 || opts.MaxAttempts < 0 || opts.MaxAttempts > 16 || mtu < 256 {
		return nil, ErrInvalid
	}
	if !identity.valid {
		return nil, ErrIdentity
	}
	if opts.BindTimeout == 0 {
		opts.BindTimeout = 10 * time.Second
	}
	if opts.RetryInterval == 0 {
		opts.RetryInterval = 200 * time.Millisecond
	}
	if opts.RetryInterval < 10*time.Millisecond || opts.RetryInterval > 5*time.Second {
		return nil, ErrInvalid
	}
	if opts.MaxAttempts == 0 {
		opts.MaxAttempts = 5
	}
	if opts.MaxPayload == 0 {
		opts.MaxPayload = MaxPayload
	}
	ctx, cancel := context.WithTimeout(ctx, opts.BindTimeout)
	defer cancel()
	mtu = min(mtu, dtls.MaxPlaintext+dtls.RecordHeader)
	secure, err = dtls.Client(ctx, raw, dtls.Config{
		MTU: mtu, HandshakeTimeout: opts.BindTimeout,
		AllowLegacyMasterSecret: opts.AllowLegacyMasterSecret,
		VerifyPeerCertificates:  func(certs []*x509.Certificate) error { return identity.verifyCertificates(certs, time.Now()) },
	})
	if err != nil {
		return nil, err
	}
	state := secure.ConnectionState()
	if !state.HandshakeComplete || state.Version != dtls.Version12 {
		return nil, ErrIdentity
	}
	if err = identity.verifyCertificates(state.PeerCertificates, time.Now()); err != nil {
		return nil, err
	}
	t := newTunnel(secure, secure.Close)
	t.maxPayload = opts.MaxPayload
	t.datagramLimit = min(dtls.MaxPlaintext, mtu-dtls.RecordHeader-dtls.GCMExpansion)
	create, err := CreateRequest(request)
	if err != nil {
		return nil, err
	}
	defer clear(create)
	err = t.run(ctx, func() error { return exchangeLossyCreate(ctx, secure, create, opts) })
	if err != nil {
		return nil, err
	}
	ok = true
	return t, nil
}

// Retrying the same request ID/cookie is a bounded client policy for UDP loss.
// Each Write seals a fresh DTLS record/nonce. Application data is never replayed.
func exchangeLossyCreate(ctx context.Context, conn net.Conn, create []byte, opts LossyTunnelOptions) error {
	deadline, _ := ctx.Deadline()
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return err
	}
	interval := opts.RetryInterval
	for attempt := 0; attempt < opts.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := writeDatagram(conn, create); err != nil {
			return err
		}
		next := time.Now().Add(interval)
		if deadline.Before(next) {
			next = deadline
		}
		if err := conn.SetReadDeadline(next); err != nil {
			return err
		}
		p, err := readDatagramPacket(conn, 4)
		if err == nil {
			defer clear(p.Payload)
			if p.Action != ActionCreateResponse {
				return ErrSequence
			}
			code := binary.LittleEndian.Uint32(p.Payload)
			if code&0x80000000 != 0 {
				return &ResponseError{Code: code}
			}
			return conn.SetDeadline(time.Time{})
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var ne net.Error
		if !errors.As(err, &ne) || !ne.Timeout() {
			return err
		}
		if !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
		interval = min(interval*2, max(opts.RetryInterval, 2*time.Second))
	}
	return ErrLimit
}

func readDatagramPacket(conn net.Conn, limit int) (Packet, error) {
	// DTLS itself bounds plaintext. The extra byte also detects excess input in
	// transport-level tests without interpreting any truncated prefix as a PDU.
	b := make([]byte, dtls.MaxPlaintext+1)
	defer clear(b)
	n, err := conn.Read(b)
	if err != nil {
		return Packet{}, err
	}
	if n > dtls.MaxPlaintext {
		return Packet{}, ErrLimit
	}
	if limit < 0 || limit > MaxPayload {
		return Packet{}, ErrInvalid
	}
	if limit == 0 {
		limit = MaxPayload
	}
	_, payload, err := packetLengths(b[:n], MaxPayload)
	if err != nil {
		return Packet{}, err
	}
	// The configurable limit applies to application data, not a delayed
	// four-byte binding response (which may exceed a tiny application budget).
	if b[0] == ActionData && payload > limit {
		return Packet{}, ErrLimit
	}
	return ParsePacket(b[:n])
}

func writeDatagram(conn net.Conn, b []byte) error {
	n, err := conn.Write(b)
	if err != nil {
		return err
	}
	if n != len(b) {
		return io.ErrShortWrite
	}
	return nil
}
