package dtls

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"time"
)

type Config struct {
	ServerName string
	RootCAs    *x509.CertPool
	// VerifyPeerCertificates replaces CA/name verification, for an explicit
	// trusted pin from the authenticated main connection. Expiry, key usage,
	// key-exchange signature and Finished checks still run. Never trust a new
	// self-signed certificate merely because this callback is available.
	// The callback runs synchronously and must return promptly; cancellation
	// closes transport but cannot interrupt caller-supplied callback code.
	VerifyPeerCertificates func([]*x509.Certificate) error
	// MTU is the underlying datagram payload capacity, excluding UDP headers.
	MTU               int           // default 1200, range 256..16384+13
	HandshakeTimeout  time.Duration // default 30s, at most 2m
	InitialRetransmit time.Duration // default 1s; 10ms..10s for bounded test tuning
	MaxRetransmits    int           // default 5; 1..8
	// Legacy master-secret derivation is opt-in; no session resumption or
	// renegotiation is implemented, whether or not this option is enabled.
	AllowLegacyMasterSecret bool
}

type ConnectionState struct {
	Version, CipherSuite                    uint16
	HandshakeComplete, ExtendedMasterSecret bool
	PeerCertificates                        []*x509.Certificate // immutable certificate objects
}

type flightRecord struct {
	typ     uint8
	epoch   uint16
	payload []byte
}

type clientHandshakeState struct {
	c             *Conn
	config        Config
	random        [32]byte
	server        serverParameters
	assembler     *Reassembler
	transcript    []byte
	flight        []flightRecord
	plainSeq      uint64
	clientSeq     uint16
	cookie        []byte
	challenges    int
	phase         uint8
	public        *ecdh.PublicKey
	certs         []*x509.Certificate
	master        []byte
	ccs, finished bool
}

// Client takes ownership of one connected datagram-preserving transport and
// returns only after a full certificate-authenticated DTLS 1.2 handshake.
// Failure/cancellation closes transport. ctx controls only the handshake; after
// success the caller owns deadlines and Close. TCP/stream transports are invalid.
func Client(ctx context.Context, transport net.Conn, config Config) (_ *Conn, err error) {
	if transport == nil {
		return nil, ErrInvalid
	}
	c := &Conn{raw: transport}
	ok := false
	defer func() {
		if !ok {
			c.fail(err)
		}
	}()
	if ctx == nil {
		return nil, ErrInvalid
	}
	if config.MTU == 0 {
		config.MTU = 1200
	}
	if config.HandshakeTimeout == 0 {
		config.HandshakeTimeout = 30 * time.Second
	}
	if config.InitialRetransmit == 0 {
		config.InitialRetransmit = time.Second
	}
	if config.MaxRetransmits == 0 {
		config.MaxRetransmits = 5
	}
	if config.MTU < 256 || config.MTU > MaxPlaintext+RecordHeader || config.HandshakeTimeout <= 0 || config.HandshakeTimeout > 2*time.Minute || config.InitialRetransmit < 10*time.Millisecond || config.InitialRetransmit > 10*time.Second || config.MaxRetransmits < 1 || config.MaxRetransmits > 8 || config.VerifyPeerCertificates == nil && config.ServerName == "" {
		return nil, ErrInvalid
	}
	if config.RootCAs != nil {
		config.RootCAs = config.RootCAs.Clone()
	}
	c.mtu = config.MTU
	ctx, cancel := context.WithTimeout(ctx, config.HandshakeTimeout)
	defer cancel()
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { transport.Close(); close(done) })
	settled := false
	settle := func() {
		if !settled {
			if !stop() {
				<-done
			}
			settled = true
		}
	}
	defer settle()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h := &clientHandshakeState{c: c, config: config}
	defer func() {
		if !ok && ctx.Err() == nil {
			h.reject(err)
		}
	}()
	h.assembler, _ = NewReassembler(0, ReassemblyLimits{})
	defer func() {
		h.assembler.Close()
		clear(h.master)
		clear(h.cookie)
		clear(h.transcript)
		for _, r := range h.flight {
			clear(r.payload)
		}
	}()
	if _, err := io.ReadFull(rand.Reader, h.random[:]); err != nil {
		return nil, err
	}
	if err := h.makeHello(); err != nil {
		return nil, err
	}
	deadline, _ := ctx.Deadline()
	if err := transport.SetWriteDeadline(deadline); err != nil {
		return nil, err
	}
	if err := h.sendFlight(); err != nil {
		return nil, err
	}
	interval := config.InitialRetransmit
	next := time.Now().Add(interval)
	retries, bytesRead := 0, 0
	buffer := make([]byte, MaxDatagram+1)
	for reads := 0; reads < 4096; reads++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := transport.SetReadDeadline(minTime(next, deadline)); err != nil {
			return nil, err
		}
		n, err := transport.Read(buffer)
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			var ne net.Error
			if !errors.As(err, &ne) || !ne.Timeout() {
				return nil, err
			}
			if !time.Now().Before(deadline) {
				return nil, context.DeadlineExceeded
			}
			if retries == config.MaxRetransmits {
				return nil, ErrLimit
			}
			if err := h.sendFlight(); err != nil {
				return nil, err
			}
			retries++
			interval = min(interval*2, 60*time.Second)
			next = time.Now().Add(interval)
			continue
		}
		bytesRead += n
		if bytesRead > 4<<20 {
			return nil, ErrLimit
		}
		records, err := ParseDatagram(buffer[:n])
		if err != nil {
			continue
		}
		oldFlight := h.clientSeq
		for _, r := range records {
			if err := h.receive(r); err != nil {
				return nil, err
			}
		}
		if h.finished && h.ccs {
			settle()
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := transport.SetDeadline(time.Time{}); err != nil {
				return nil, err
			}
			c.state = ConnectionState{Version12, h.server.cipher, true, h.server.ems, append([]*x509.Certificate(nil), h.certs...)}
			ok = true
			return c, nil
		}
		if oldFlight != h.clientSeq {
			retries = 0
			interval = config.InitialRetransmit
			next = time.Now().Add(interval)
		}
	}
	return nil, ErrLimit
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

// Protocol/authentication rejection gets a bounded fatal alert. Cancellation,
// closed sockets and network errors take the immediate-abort path instead.
func (h *clientHandshakeState) reject(cause error) {
	var network net.Error
	if errors.As(cause, &network) || errors.Is(cause, net.ErrClosed) || errors.Is(cause, io.EOF) || errors.Is(cause, context.Canceled) || errors.Is(cause, context.DeadlineExceeded) {
		return
	}
	if h.c.raw.SetWriteDeadline(time.Now().Add(100*time.Millisecond)) != nil {
		return
	}
	var b []byte
	var err error
	if h.c.writer != nil {
		b, err = h.c.writer.Seal(Alert, []byte{2, 40})
	} else {
		b, err = (Record{Alert, Version12, 0, h.plainSeq, []byte{2, 40}}).Marshal()
	}
	if err == nil {
		h.c.raw.Write(b)
	}
}

func (h *clientHandshakeState) addTranscript(m Message) error {
	b, err := m.Canonical()
	if err != nil {
		return err
	}
	if len(h.transcript)+len(b) > 1<<20 {
		return ErrLimit
	}
	h.transcript = append(h.transcript, b...)
	return nil
}

func (h *clientHandshakeState) setFlight(records []flightRecord) {
	for _, r := range h.flight {
		clear(r.payload)
	}
	h.flight = records
}

func (h *clientHandshakeState) makeHello() error {
	b, err := helloBody(h.random, h.cookie, h.config.ServerName)
	if err != nil {
		return err
	}
	m := Message{clientHello, h.clientSeq, b}
	clear(h.transcript)
	h.transcript = nil
	if err := h.addTranscript(m); err != nil {
		return err
	}
	parts, err := FragmentMessage(m, h.config.MTU-RecordHeader)
	if err != nil {
		return err
	}
	var flight []flightRecord
	for _, p := range parts {
		flight = append(flight, flightRecord{Handshake, 0, p})
	}
	h.setFlight(flight)
	return nil
}

func (h *clientHandshakeState) sendFlight() error {
	for _, r := range h.flight {
		var b []byte
		var err error
		if r.epoch == 0 {
			if h.plainSeq > MaxSequence {
				return ErrSequence
			}
			b, err = (Record{r.typ, Version12, 0, h.plainSeq, r.payload}).Marshal()
			h.plainSeq++
		} else {
			b, err = h.c.writer.Seal(r.typ, r.payload)
		}
		if err != nil {
			return err
		}
		if len(b) > h.config.MTU {
			return ErrLimit
		}
		n, err := h.c.raw.Write(b)
		if err != nil {
			return err
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func (h *clientHandshakeState) receive(r Record) error {
	var payload []byte
	if r.Epoch == 0 {
		payload = r.Payload
		if r.Type == ChangeCipherSpec {
			if h.phase != 4 {
				return nil
			} // unauthenticated early CCS cannot change keys
			if !bytes.Equal(payload, []byte{1}) {
				return ErrHandshake
			}
			h.ccs = true
			return nil
		}
		if r.Type == Handshake && h.phase == 0 {
			fs, err := parseFragments(payload)
			if err == nil && len(fs) == 1 && fs[0].typ == helloVerify {
				f := fs[0]
				if f.offset != 0 || len(f.data) != f.total || f.total < 3 || int(f.data[2]) != f.total-3 || f.seq > h.clientSeq {
					return ErrHandshake
				}
				v := uint16(f.data[0])<<8 | uint16(f.data[1])
				if v != Version10 && v != Version12 {
					return ErrVersion
				}
				cookie := f.data[3:]
				if h.challenges == 0 || !bytes.Equal(cookie, h.cookie) {
					if h.challenges == 3 {
						return ErrLimit
					}
					h.challenges++
					h.clientSeq++
					clear(h.cookie)
					h.cookie = bytes.Clone(cookie)
					h.assembler.Close()
					h.assembler, _ = NewReassembler(f.seq+1, ReassemblyLimits{})
					if err := h.makeHello(); err != nil {
						return err
					}
				}
				return h.sendFlight()
			}
		}
		if h.phase == 4 { // old flight remains acceptable, never unhashed Finished
			if r.Type == Handshake {
				return nil
			}
		}
	} else if r.Epoch == 1 && h.c.reader != nil {
		var err error
		payload, err = h.c.reader.Open(r)
		if err != nil {
			return nil
		} // forged/replayed DTLS records are discarded
	} else {
		return nil
	}
	if r.Type == Alert {
		return parseAlert(payload)
	}
	if r.Type != Handshake {
		return nil
	} // no application data before Finished
	if r.Epoch == 1 && h.phase != 4 {
		return ErrHandshake
	}
	ms, err := h.assembler.Push(payload)
	if err != nil {
		return err
	}
	for _, m := range ms {
		if err := h.message(m); err != nil {
			return err
		}
	}
	return nil
}

func (h *clientHandshakeState) message(m Message) error {
	switch h.phase {
	case 0:
		if m.Type != serverHello {
			return ErrHandshake
		}
		p, err := parseServerHello(m.Body, h.config.ServerName != "" && net.ParseIP(h.config.ServerName) == nil, h.config.AllowLegacyMasterSecret)
		if err != nil {
			return err
		}
		h.server = p
		h.phase = 1
	case 1:
		if m.Type != certificateMessage {
			return ErrHandshake
		}
		certs, err := parseCertificates(m.Body)
		if err != nil {
			return err
		}
		if err := h.verifyCertificates(certs); err != nil {
			return err
		}
		h.certs = certs
		h.phase = 2
	case 2:
		if m.Type != serverKeyExchange {
			return ErrHandshake
		}
		pub, err := verifyKeyExchange(m.Body, h.certs[0], h.server.cipher, h.random, h.server.random)
		if err != nil {
			return err
		}
		h.public = pub
		h.phase = 3
	case 3:
		if m.Type != serverHelloDone || len(m.Body) != 0 {
			return ErrUnsupported
		}
		if err := h.addTranscript(m); err != nil {
			return err
		}
		return h.makeFinalFlight()
	case 4:
		if m.Type != finishedMessage || len(m.Body) != 12 || h.finished {
			return ErrHandshake
		}
		digest := sha256.Sum256(h.transcript)
		want := tlsPRF(h.master, "server finished", digest[:], 12)
		defer clear(want)
		if !hmac.Equal(want, m.Body) {
			return ErrAuthentication
		}
		h.finished = true
		return nil
	default:
		return ErrHandshake
	}
	return h.addTranscript(m)
}

func (h *clientHandshakeState) verifyCertificates(certs []*x509.Certificate) error {
	leaf := certs[0]
	now := time.Now()
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) || len(leaf.UnhandledCriticalExtensions) > 0 || leaf.KeyUsage != 0 && leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return ErrAuthentication
	}
	if len(leaf.ExtKeyUsage) > 0 || len(leaf.UnknownExtKeyUsage) > 0 {
		allowed := false
		for _, u := range leaf.ExtKeyUsage {
			allowed = allowed || u == x509.ExtKeyUsageAny || u == x509.ExtKeyUsageServerAuth
		}
		if !allowed {
			return ErrAuthentication
		}
	}
	if h.config.VerifyPeerCertificates != nil {
		return h.config.VerifyPeerCertificates(certs)
	}
	pool := x509.NewCertPool()
	for _, c := range certs[1:] {
		pool.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{DNSName: h.config.ServerName, Roots: h.config.RootCAs, Intermediates: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func (h *clientHandshakeState) makeFinalFlight() error {
	private, err := h.public.Curve().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	secret, err := private.ECDH(h.public)
	if err != nil {
		return err
	}
	defer clear(secret)
	pub := private.PublicKey().Bytes()
	h.clientSeq++
	m := Message{clientKeyExchange, h.clientSeq, append([]byte{byte(len(pub))}, pub...)}
	if err := h.addTranscript(m); err != nil {
		return err
	}
	if h.server.ems {
		digest := sha256.Sum256(h.transcript)
		h.master = tlsPRF(secret, "extended master secret", digest[:], 48)
	} else {
		h.master = tlsPRF(secret, "master secret", append(h.random[:], h.server.random[:]...), 48)
	}
	keys := tlsPRF(h.master, "key expansion", append(h.server.random[:], h.random[:]...), 40)
	defer clear(keys)
	h.c.writer, err = NewRecordWriter(1, keys[:16], keys[32:36])
	if err != nil {
		return err
	}
	h.c.reader, err = NewRecordReader(1, keys[16:32], keys[36:40])
	if err != nil {
		return err
	}
	var flight []flightRecord
	parts, err := FragmentMessage(m, h.config.MTU-RecordHeader)
	if err != nil {
		return err
	}
	for _, p := range parts {
		flight = append(flight, flightRecord{Handshake, 0, p})
	}
	flight = append(flight, flightRecord{ChangeCipherSpec, 0, []byte{1}})
	digest := sha256.Sum256(h.transcript)
	h.clientSeq++
	m = Message{finishedMessage, h.clientSeq, tlsPRF(h.master, "client finished", digest[:], 12)}
	if err := h.addTranscript(m); err != nil {
		return err
	}
	parts, err = FragmentMessage(m, h.config.MTU-RecordHeader-GCMExpansion)
	if err != nil {
		return err
	}
	for _, p := range parts {
		flight = append(flight, flightRecord{Handshake, 1, p})
	}
	h.setFlight(flight)
	h.phase = 4
	return h.sendFlight()
}
