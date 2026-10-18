package kerberos

import (
	"bytes"
	"context"
	"crypto/md5" // RFC 4121 channel-binding digest, not message integrity.
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/hq0101/rdp-go/internal/der"
	"github.com/hq0101/rdp-go/internal/krbcrypto"
)

var (
	ErrContext  = errors.New("kerberos: unusable GSS context")
	ErrSequence = errors.New("kerberos: unexpected GSS sequence")
	ErrExpired  = errors.New("kerberos: expired GSS context")
)

// Mutual, replay, sequence, confidentiality and integrity; no delegation.
const gssContextFlags uint32 = 2 | 4 | 8 | 16 | 32

var kerberosOID = []byte{6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 1, 2, 2}

// ChannelBindings supplies the RFC 2744 address types and binding bytes.
// Nil means GSS_C_NO_CHANNEL_BINDINGS; a non-nil empty value has a different
// digest. The API transmits the binding; acceptor policy determines enforcement.
// For GSS_C_AF_NULLADDR use 255; zero represents GSS_C_AF_UNSPEC.
type ChannelBindings struct {
	InitiatorType, AcceptorType                        uint32
	InitiatorAddress, AcceptorAddress, ApplicationData []byte
}

func channelBindingHash(binding *ChannelBindings) ([16]byte, error) {
	if binding == nil {
		return [16]byte{}, nil
	}
	if len(binding.InitiatorAddress) > 64<<10 || len(binding.AcceptorAddress) > 64<<10 || len(binding.ApplicationData) > 64<<10 {
		return [16]byte{}, ErrInvalid
	}
	b := binary.LittleEndian.AppendUint32(nil, binding.InitiatorType)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(binding.InitiatorAddress)))
	b = append(b, binding.InitiatorAddress...)
	b = binary.LittleEndian.AppendUint32(b, binding.AcceptorType)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(binding.AcceptorAddress)))
	b = append(b, binding.AcceptorAddress...)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(binding.ApplicationData)))
	b = append(b, binding.ApplicationData...)
	defer clear(b)
	return md5.Sum(b), nil
}
func gssToken(kind byte, body []byte) []byte {
	return der.Wrap(0x60, kerberosOID, []byte{kind, 0}, body)
}
func parseGSSToken(b []byte) (byte, []byte, error) {
	if len(b) > MaxMessage {
		return 0, nil, ErrInvalid
	}
	b, err := unwrap(b, 0x60)
	if err != nil {
		return 0, nil, err
	}
	_, oid, err := take(&b, 6)
	if err != nil || !bytes.Equal(oid, kerberosOID) {
		return 0, nil, ErrUnsupported
	}
	if len(b) < 3 || b[1] != 0 || (b[0] != 1 && b[0] != 2 && b[0] != 3) {
		return 0, nil, ErrInvalid
	}
	return b[0], b[2:], nil
}
func parseAPReply(b []byte) (encryptedData, error) {
	f := readFields(b, 0x6f, 7, 7)
	if f.int32(0) != 5 || f.int32(1) != 15 {
		f.reject(ErrInvalid)
	}
	e, err := parseEncrypted(f.raw[2])
	f.reject(err)
	return e, f.err
}

type apReplyPart struct {
	Time                time.Time
	Microseconds        int32
	KeyType             krbcrypto.Enctype
	Key                 []byte
	Sequence            uint32
	HasKey, HasSequence bool
}

func parseAPReplyPart(b []byte) (apReplyPart, error) {
	f := readFields(b, 0x7b, 15, 3)
	r := apReplyPart{Time: f.timestamp(0), Microseconds: f.microseconds(1), HasKey: f.has(2), HasSequence: f.has(3)}
	if r.HasKey {
		k := readFields(f.raw[2], 0, 3, 3)
		r.KeyType = krbcrypto.Enctype(k.int32(0))
		r.Key = k.get(1, 4)
		f.reject(k.err)
	}
	if r.HasSequence {
		r.Sequence = f.uint32(3)
	}
	return r, f.err
}

// ServiceContext is a connection-oriented Kerberos GSS initiator. It requires
// mutual authentication, then enforces exact receive order for Wrap and MIC
// together. Methods and Close are safe concurrently; wire writes must preserve
// the order of the returned tokens. Value copies share the same lifetime.
type ServiceContext struct{ material *gssMaterial }
type gssMaterial struct {
	mu                              sync.Mutex
	state                           uint8 // 1 awaiting AP-REP; 2 established; 3 closed/failed
	info                            TicketInfo
	now                             func() time.Time
	pending                         context.Context
	cancel                          context.CancelFunc
	stamp                           time.Time
	offered                         []krbcrypto.Enctype
	session, initiator, key         *krbcrypto.Key
	acceptorSubkey                  bool
	send, receive                   uint64
	sendExhausted, receiveExhausted bool
}
type ServiceInfo struct {
	Ticket                      TicketInfo
	Established, AcceptorSubkey bool
	Enctype                     krbcrypto.Enctype
}

func (ServiceContext) String() string   { return "[redacted Kerberos GSS context]" }
func (ServiceContext) GoString() string { return "[redacted Kerberos GSS context]" }

// BeginService consumes a private snapshot of a same-realm service ticket and
// produces a GSS-framed AP-REQ. No socket is opened. The caller sends the token,
// supplies the returned server token to Finish, and always closes the context.
// The input context and Config.Timeout bound the pending authentication.
func (c *Client) BeginService(ctx context.Context, ticket *Ticket, binding *ChannelBindings) (result *ServiceContext, token []byte, err error) {
	ctx, cancel, err := c.operation(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			cancel()
		}
	}()
	digest, err := channelBindingHash(binding)
	if err != nil {
		return nil, nil, err
	}
	info, raw, session, err := ticket.snapshot()
	if err != nil {
		return nil, nil, err
	}
	defer clear(raw)
	defer func() {
		if err != nil {
			session.Clear()
		}
	}()
	now := c.now().UTC()
	if info.Realm != c.config.Realm || len(info.Server.Components) == 0 || info.Server.Components[0] == "krbtgt" {
		return nil, nil, ErrIdentity
	}
	if info.StartTime.After(now.Add(clockSkew)) || !info.EndTime.After(now) {
		return nil, nil, ErrExpired
	}
	if !c.offers(session.Type()) {
		return nil, nil, ErrUnsupported
	}
	secret := make([]byte, keySize(session.Type()))
	defer clear(secret)
	if _, err = io.ReadFull(c.random, secret); err != nil {
		return nil, nil, err
	}
	subkey, err := krbcrypto.NewKey(session.Type(), secret)
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		if err != nil {
			subkey.Clear()
		}
	}()
	sequenceNumber, err := c.nonce()
	if err != nil {
		return nil, nil, err
	}
	stamp, err := c.authTimestamp()
	if err != nil {
		return nil, nil, err
	}
	checksum := binary.LittleEndian.AppendUint32(nil, 16)
	checksum = append(checksum, digest[:]...)
	checksum = binary.LittleEndian.AppendUint32(checksum, gssContextFlags)
	encodedKey := sequence(contextField(0, integer(uint32(subkey.Type()))), contextField(1, octets(secret)))
	defer clear(encodedKey)
	auth := application(2, contextField(0, integer(5)), contextField(1, generalString(info.Realm)), contextField(2, info.Client.marshal()), contextField(3, marshalChecksum(0x8003, checksum)), contextField(4, integer(uint32(stamp.Nanosecond()/1000))), contextField(5, kerberosTime(stamp)), contextField(6, encodedKey), contextField(7, integer(sequenceNumber)))
	defer clear(auth)
	sealed, err := session.Encrypt(11, auth)
	if err != nil {
		return nil, nil, err
	}
	ap := application(14, contextField(0, integer(5)), contextField(1, integer(14)), contextField(2, bitFlags(1<<(31-2))), contextField(3, raw), contextField(4, encryptedData{Type: int32(session.Type()), Cipher: sealed}.marshal()))
	token = gssToken(1, ap)
	if len(token) > MaxMessage {
		return nil, nil, ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return nil, nil, err
	}
	m := &gssMaterial{state: 1, info: info, now: c.now, pending: ctx, cancel: cancel, stamp: stamp, offered: append([]krbcrypto.Enctype(nil), c.config.Enctypes...), session: session, initiator: subkey, send: uint64(sequenceNumber)}
	return &ServiceContext{material: m}, token, nil
}

func (s *ServiceContext) Close() {
	if s == nil || s.material == nil {
		return
	}
	m := s.material
	m.mu.Lock()
	defer m.mu.Unlock()
	m.close()
}
func (m *gssMaterial) close() {
	if m.cancel != nil {
		m.cancel()
	}
	m.cancel = nil
	m.pending = nil
	m.session.Clear()
	m.initiator.Clear()
	m.key.Clear()
	m.session = nil
	m.initiator = nil
	m.key = nil
	m.info = TicketInfo{}
	m.stamp = time.Time{}
	m.offered = nil
	m.state = 3
}
func (m *gssMaterial) fail(err error) error { m.close(); return err }
func (m *gssMaterial) usable() error {
	if m.state != 2 {
		return ErrContext
	}
	if !m.info.EndTime.After(m.now()) {
		return m.fail(ErrExpired)
	}
	return nil
}
func (s *ServiceContext) Info() (ServiceInfo, error) {
	if s == nil || s.material == nil {
		return ServiceInfo{}, ErrContext
	}
	m := s.material
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state == 3 {
		return ServiceInfo{}, ErrContext
	}
	return ServiceInfo{Ticket: cloneInfo(m.info), Established: m.state == 2, AcceptorSubkey: m.acceptorSubkey, Enctype: m.key.Type()}, nil
}

// Finish verifies the peer's AP-REP using the service ticket key (usage 12),
// its exact echoed time and its initial sequence number. A rejected token makes
// the context unusable and clears every key; no message protection is available
// until this method succeeds. Kerberos errors are unauthenticated diagnostics.
func (s *ServiceContext) Finish(token []byte) error {
	if s == nil || s.material == nil {
		return ErrContext
	}
	m := s.material
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.state != 1 {
		return m.fail(ErrContext)
	}
	if err := m.pending.Err(); err != nil {
		return m.fail(err)
	}
	if !m.info.EndTime.After(m.now()) {
		return m.fail(ErrExpired)
	}
	kind, body, err := parseGSSToken(token)
	if err != nil {
		return m.fail(err)
	}
	if kind == 3 {
		kerr, err := parseError(body)
		if err != nil {
			return m.fail(err)
		}
		return m.fail(kerr)
	}
	if kind != 2 {
		return m.fail(ErrInvalid)
	}
	e, err := parseAPReply(body)
	if err != nil {
		return m.fail(err)
	}
	if e.Type != int32(m.session.Type()) {
		return m.fail(ErrUnsupported)
	}
	plain, err := m.session.Decrypt(12, e.Cipher)
	if err != nil {
		return m.fail(err)
	}
	defer clear(plain)
	r, err := parseAPReplyPart(plain)
	if err != nil {
		return m.fail(err)
	}
	if !r.Time.Equal(m.stamp.Truncate(time.Second)) || r.Microseconds != int32(m.stamp.Nanosecond()/1000) || !r.HasSequence {
		return m.fail(ErrReply)
	}
	if r.HasKey {
		allowed := false
		for _, e := range m.offered {
			if e == r.KeyType {
				allowed = true
			}
		}
		if !allowed {
			return m.fail(ErrUnsupported)
		}
		m.key, err = krbcrypto.NewKey(r.KeyType, r.Key)
		if err != nil {
			return m.fail(err)
		}
		m.acceptorSubkey = true
		m.initiator.Clear()
		m.initiator = nil
	} else {
		m.key = m.initiator
		m.initiator = nil
	}
	if err = m.pending.Err(); err != nil {
		return m.fail(err)
	}
	m.receive = uint64(r.Sequence)
	m.session.Clear()
	m.session = nil
	m.cancel()
	m.cancel = nil
	m.pending = nil
	m.offered = nil
	m.stamp = time.Time{}
	m.state = 2
	return nil
}
