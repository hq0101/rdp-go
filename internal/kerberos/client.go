package kerberos

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hq0101/rdp-go/internal/krbcrypto"
	"github.com/hq0101/rdp-go/kdcproxy"
)

const clockSkew = 5 * time.Minute
const flagInitial uint32 = 1 << (31 - 9)
const flagEncPARep uint32 = 1 << (31 - 15)
const allowedTicketFlags = flagInitial | 1<<(31-10) | 1<<(31-11) | 1<<(31-12) | 1<<(31-13) | flagEncPARep

var ErrClosed = errors.New("kerberos: ticket has been cleared")

// Config uses an explicit KDC address and exact realm. Discovery, referrals,
// canonicalization, FAST and operating-system credential caches are not enabled.
type Config struct {
	Realm     string
	KDC       string            // host:port; normally port 88
	Proxy     *kdcproxy.Options // explicit HTTPS alternative; excludes KDC/Network
	Network   string            // tcp (default), or udp with one TCP retry on error 52
	Timeout   time.Duration     // whole exchange, including preauthentication
	Lifetime  time.Duration
	Enctypes  []krbcrypto.Enctype
	WorkLimit uint32 // password-derivation iterations; zero uses krbcrypto's cap
}

// Client keeps immutable configuration and a synchronized authenticator clock.
// Value copies share that clock and support independent concurrent requests.
type Client struct {
	config Config
	proxy  *kdcproxy.Client
	now    func() time.Time
	random io.Reader
	stamps *authClock
}

type authClock struct {
	mu   sync.Mutex
	last time.Time
}

func New(config Config) (*Client, error) {
	if !validName(config.Realm, 1024) {
		return nil, ErrInvalid
	}
	var proxy *kdcproxy.Client
	if config.Proxy != nil {
		if config.KDC != "" || config.Network != "" {
			return nil, ErrInvalid
		}
		config.Proxy = config.Proxy.Clone()
		var err error
		proxy, err = kdcproxy.New(*config.Proxy)
		if err != nil {
			return nil, err
		}
	} else {
		if !validName(config.KDC, 1024) {
			return nil, ErrInvalid
		}
		host, port, err := net.SplitHostPort(config.KDC)
		n, portErr := strconv.Atoi(port)
		if err != nil || host == "" || portErr != nil || n < 1 || n > 65535 {
			return nil, ErrInvalid
		}
		if config.Network == "" {
			config.Network = "tcp"
		}
		if config.Network != "tcp" && config.Network != "udp" {
			return nil, ErrUnsupported
		}
	}
	if config.Timeout == 0 {
		config.Timeout = 15 * time.Second
	}
	if config.Lifetime == 0 {
		config.Lifetime = 8 * time.Hour
	}
	if config.Timeout <= 0 || config.Timeout > 2*time.Minute || config.Lifetime < time.Minute || config.Lifetime > 24*time.Hour || config.WorkLimit > krbcrypto.MaxIterations {
		return nil, ErrInvalid
	}
	if len(config.Enctypes) == 0 {
		config.Enctypes = []krbcrypto.Enctype{20, 19, 18, 17}
	}
	if len(config.Enctypes) > 4 {
		return nil, ErrInvalid
	}
	seen := map[krbcrypto.Enctype]bool{}
	for _, e := range config.Enctypes {
		if keySize(e) == 0 || seen[e] {
			return nil, ErrUnsupported
		}
		seen[e] = true
	}
	config.Enctypes = append([]krbcrypto.Enctype(nil), config.Enctypes...)
	return &Client{config: config, proxy: proxy, now: time.Now, random: rand.Reader, stamps: &authClock{}}, nil
}

func keySize(e krbcrypto.Enctype) int {
	switch e {
	case 17, 19:
		return 16
	case 18, 20:
		return 32
	}
	return 0
}
func (c *Client) offers(e krbcrypto.Enctype) bool {
	for _, v := range c.config.Enctypes {
		if v == e {
			return true
		}
	}
	return false
}

// Credentials are used only during AcquireTGT, never retained by Client.
// A Go string cannot be reliably erased; the caller controls its own lifetime.
type Credentials struct {
	Client   Principal
	Password string `json:"-"`
}

func (Credentials) String() string   { return "[redacted Kerberos credentials]" }
func (Credentials) GoString() string { return "[redacted Kerberos credentials]" }

type TicketInfo struct {
	Realm                        string
	Client, Server               Principal
	SessionEnctype               krbcrypto.Enctype
	Flags                        uint32
	AuthTime, StartTime, EndTime time.Time
	RequestBound                 bool // RFC 6806 full-request checksum was verified
}

// Ticket owns a private ticket and session key. Value copies share lifetime.
// Clear invalidates new users and erases owned buffers. Already-started requests
// have private snapshots; cancel their contexts to stop them as well.
type Ticket struct{ material *ticketMaterial }
type ticketMaterial struct {
	mu   sync.RWMutex
	info TicketInfo
	raw  []byte
	key  *krbcrypto.Key
}

func (Ticket) String() string   { return "[redacted Kerberos ticket]" }
func (Ticket) GoString() string { return "[redacted Kerberos ticket]" }
func cloneInfo(info TicketInfo) TicketInfo {
	info.Client = info.Client.clone()
	info.Server = info.Server.clone()
	return info
}
func (t *Ticket) Info() (TicketInfo, error) {
	if t == nil || t.material == nil {
		return TicketInfo{}, ErrClosed
	}
	m := t.material
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.key == nil {
		return TicketInfo{}, ErrClosed
	}
	return cloneInfo(m.info), nil
}
func (t *Ticket) Clear() {
	if t == nil || t.material == nil {
		return
	}
	m := t.material
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.raw)
	m.raw = nil
	m.key.Clear()
	m.key = nil
	m.info = TicketInfo{}
}
func (t *Ticket) snapshot() (TicketInfo, []byte, *krbcrypto.Key, error) {
	if t == nil || t.material == nil {
		return TicketInfo{}, nil, nil, ErrClosed
	}
	m := t.material
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.key == nil {
		return TicketInfo{}, nil, nil, ErrClosed
	}
	b := m.key.Bytes()
	defer clear(b)
	key, err := krbcrypto.NewKey(m.key.Type(), b)
	if err != nil {
		return TicketInfo{}, nil, nil, err
	}
	return cloneInfo(m.info), append([]byte(nil), m.raw...), key, nil
}

func (c *Client) operation(ctx context.Context) (context.Context, context.CancelFunc, error) {
	if c == nil || c.now == nil || c.random == nil || c.stamps == nil || ctx == nil {
		return nil, nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	return ctx, cancel, nil
}
func (c *Client) nonce() (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(c.random, b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]) & 0x7fffffff, nil
}

// Kerberos replay caches can identify authenticators by client/time alone.
// Keep microseconds unique even when the OS clock has a coarser resolution or
// requests run concurrently. A substantial clock rollback is an error, not an
// unbounded fabricated timestamp or an instruction to change the system clock.
func (c *Client) authTimestamp() (time.Time, error) {
	c.stamps.mu.Lock()
	defer c.stamps.mu.Unlock()
	now := c.now().UTC().Truncate(time.Microsecond)
	stamp := now
	if !stamp.After(c.stamps.last) {
		stamp = c.stamps.last.Add(time.Microsecond)
	}
	if stamp.Year() < 1 || stamp.Year() > 9999 || stamp.After(now.Add(clockSkew)) {
		return time.Time{}, ErrReply
	}
	c.stamps.last = stamp
	return stamp, nil
}
func tgtName(realm string) Principal { return Principal{2, []string{"krbtgt", realm}} }
func (c *Client) passwordKey(ctx context.Context, creds Credentials, h etypeHint) (*krbcrypto.Key, error) {
	if !c.offers(h.Type) {
		return nil, ErrUnsupported
	}
	salt := h.Salt
	if !h.HasSalt {
		salt = []byte(c.config.Realm + strings.Join(creds.Client.Components, ""))
		defer clear(salt)
	}
	return krbcrypto.StringToKey(ctx, h.Type, creds.Password, salt, h.Params, c.config.WorkLimit)
}

// AcquireTGT makes at most two AS requests: one metadata probe and, if required,
// one encrypted timestamp. It never retries a rejected password or follows a
// referral. Password-derived replies are not application-server authentication.
func (c *Client) AcquireTGT(ctx context.Context, creds Credentials) (*Ticket, error) {
	ctx, cancel, err := c.operation(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if !creds.Client.valid() || len(creds.Password) > krbcrypto.MaxPasswordBytes || !utf8.ValidString(creds.Password) {
		return nil, ErrInvalid
	}
	creds.Client = creds.Client.clone()
	nonce, err := c.nonce()
	if err != nil {
		return nil, err
	}
	now := c.now().UTC()
	till := now.Add(c.config.Lifetime).Truncate(time.Second)
	server := tgtName(c.config.Realm)
	body := marshalBody(&creds.Client, c.config.Realm, server, till, nonce, c.config.Enctypes)
	pa := []paData{pacRequest(), {149, nil}}
	request := marshalRequest(10, body, pa)
	response, err := c.exchange(ctx, request)
	if err != nil {
		return nil, err
	}
	var key *krbcrypto.Key
	defer func() { key.Clear() }()
	if len(response) > 0 && response[0] == 0x7e {
		kerr, err := parseError(response)
		if err != nil {
			return nil, err
		}
		if kerr.Code != 25 {
			return nil, kerr
		}
		if kerr.serverRealm != c.config.Realm || !kerr.server.equal(server) {
			return nil, ErrIdentity
		}
		methods, err := parsePA(kerr.data)
		if err != nil {
			return nil, err
		}
		_, hasTimestamp, err := uniquePA(methods, 2)
		if err != nil {
			return nil, err
		}
		if !hasTimestamp {
			return nil, ErrUnsupported
		}
		encodedHints, ok, err := uniquePA(methods, 19)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrUnsupported
		}
		hints, err := parseEtypeInfo(encodedHints)
		if err != nil {
			return nil, err
		}
		var selected etypeHint
		found := false
		for _, e := range c.config.Enctypes {
			for _, h := range hints {
				if h.Type == e {
					selected = h
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return nil, ErrUnsupported
		}
		key, err = c.passwordKey(ctx, creds, selected)
		if err != nil {
			return nil, err
		}
		stamp, err := c.authTimestamp()
		if err != nil {
			return nil, err
		}
		timestamp := marshalTimestamp(stamp)
		defer clear(timestamp)
		cipher, err := key.Encrypt(1, timestamp)
		if err != nil {
			return nil, err
		}
		pa = append(pa, paData{2, encryptedData{Type: int32(key.Type()), Cipher: cipher}.marshal()})
		cookie, hasCookie, err := uniquePA(methods, 133)
		if err != nil {
			return nil, err
		}
		if hasCookie {
			pa = append(pa, paData{133, cookie})
		}
		request = marshalRequest(10, body, pa)
		response, err = c.exchange(ctx, request)
		if err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(response) > 0 && response[0] == 0x7e {
		kerr, err := parseError(response)
		if err != nil {
			return nil, err
		}
		return nil, kerr
	}
	reply, err := parseReply(response, 11)
	if err != nil {
		return nil, err
	}
	if reply.ClientRealm != c.config.Realm || !reply.Client.equal(creds.Client) {
		return nil, ErrIdentity
	}
	if key == nil {
		hint := etypeHint{Type: krbcrypto.Enctype(reply.Encrypted.Type)}
		encoded, ok, err := uniquePA(reply.PA, 19)
		if err != nil {
			return nil, err
		}
		if ok {
			hints, err := parseEtypeInfo(encoded)
			if err != nil {
				return nil, err
			}
			found := false
			for _, h := range hints {
				if h.Type == hint.Type {
					hint = h
					found = true
				}
			}
			if !found {
				return nil, ErrUnsupported
			}
		}
		key, err = c.passwordKey(ctx, creds, hint)
		if err != nil {
			return nil, err
		}
	}
	return c.acceptReply(ctx, reply, key, request, nonce, till, creds.Client, server, nil)
}

// AcquireService requests an exact same-realm SPN (for example, the two
// components TERMSRV and server.example.test). DNS canonicalization and
// cross-realm referrals are intentionally not inferred from the KDC response.
func (c *Client) AcquireService(ctx context.Context, tgt *Ticket, service Principal) (*Ticket, error) {
	ctx, cancel, err := c.operation(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	if !service.valid() || service.equal(tgtName(c.config.Realm)) {
		return nil, ErrInvalid
	}
	service = service.clone()
	info, raw, key, err := tgt.snapshot()
	if err != nil {
		return nil, err
	}
	defer key.Clear()
	defer clear(raw)
	now := c.now().UTC()
	if info.Realm != c.config.Realm || !info.Server.equal(tgtName(c.config.Realm)) {
		return nil, ErrIdentity
	}
	if now.Add(clockSkew).Before(info.StartTime) || !now.Before(info.EndTime) {
		return nil, ErrReply
	}
	nonce, err := c.nonce()
	if err != nil {
		return nil, err
	}
	till := now.Add(c.config.Lifetime).Truncate(time.Second)
	if till.After(info.EndTime) {
		till = info.EndTime
	}
	body := marshalBody(nil, c.config.Realm, service, till, nonce, c.config.Enctypes)
	sum, err := key.Checksum(6, body)
	if err != nil {
		return nil, err
	}
	defer clear(sum)
	secret := make([]byte, keySize(key.Type()))
	defer clear(secret)
	if _, err = io.ReadFull(c.random, secret); err != nil {
		return nil, err
	}
	subkey, err := krbcrypto.NewKey(key.Type(), secret)
	if err != nil {
		return nil, err
	}
	defer subkey.Clear()
	encodedKey := sequence(contextField(0, integer(uint32(key.Type()))), contextField(1, octets(secret)))
	defer clear(encodedKey)
	stamp, err := c.authTimestamp()
	if err != nil {
		return nil, err
	}
	auth := application(2, contextField(0, integer(5)), contextField(1, generalString(info.Realm)), contextField(2, info.Client.marshal()), contextField(3, marshalChecksum(key.ChecksumType(), sum)), contextField(4, integer(uint32(stamp.Nanosecond()/1000))), contextField(5, kerberosTime(stamp)), contextField(6, encodedKey))
	defer clear(auth)
	sealed, err := key.Encrypt(7, auth)
	if err != nil {
		return nil, err
	}
	ap := application(14, contextField(0, integer(5)), contextField(1, integer(14)), contextField(2, bitFlags(0)), contextField(3, raw), contextField(4, encryptedData{Type: int32(key.Type()), Cipher: sealed}.marshal()))
	request := marshalRequest(12, body, []paData{{1, ap}})
	response, err := c.exchange(ctx, request)
	if err != nil {
		return nil, err
	}
	if len(response) > 0 && response[0] == 0x7e {
		kerr, err := parseError(response)
		if err != nil {
			return nil, err
		}
		return nil, kerr
	}
	reply, err := parseReply(response, 13)
	if err != nil {
		return nil, err
	}
	return c.acceptReply(ctx, reply, subkey, request, nonce, till, info.Client, service, &info)
}

func (c *Client) acceptReply(ctx context.Context, r kdcReply, key *krbcrypto.Key, request []byte, nonce uint32, till time.Time, client, server Principal, tgt *TicketInfo) (*Ticket, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if r.ClientRealm != c.config.Realm || !r.Client.equal(client) || r.Ticket.Realm != c.config.Realm || !r.Ticket.Server.equal(server) {
		return nil, ErrIdentity
	}
	if r.Encrypted.Type != int32(key.Type()) || r.Ticket.Encrypted.Type <= 0 {
		return nil, ErrUnsupported
	}
	usage := uint32(3)
	tag := int32(25)
	if tgt != nil {
		usage = 9
		tag = 26
	}
	plain, err := key.Decrypt(usage, r.Encrypted.Cipher)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	// RFC 4120 section 5.4.2 explicitly permits AS replies tagged as TGS parts.
	if tgt == nil && len(plain) > 0 && plain[0] == 0x7a {
		tag = 26
	}
	p, err := parseReplyPart(plain, tag)
	if err != nil {
		return nil, err
	}
	if p.Realm != c.config.Realm || !p.Server.equal(server) {
		return nil, ErrIdentity
	}
	now := c.now().UTC()
	if p.Nonce != nonce || !c.offers(p.KeyType) || p.Addresses || p.Flags & ^uint32(allowedTicketFlags) != 0 || !p.RenewTill.IsZero() || p.StartTime.Before(p.AuthTime) || !p.EndTime.After(p.StartTime) || !p.EndTime.After(now) || p.EndTime.After(till) || p.StartTime.After(now.Add(clockSkew)) {
		return nil, ErrReply
	}
	if tgt == nil {
		if p.Flags&flagInitial == 0 || p.AuthTime.Before(now.Add(-clockSkew)) || p.AuthTime.After(now.Add(clockSkew)) {
			return nil, ErrReply
		}
	} else if p.Flags&flagInitial != 0 || !p.AuthTime.Equal(tgt.AuthTime) || p.EndTime.After(tgt.EndTime) {
		return nil, ErrReply
	}
	bound := false
	if tgt != nil {
		if len(p.PA) > 0 {
			return nil, ErrReply
		}
	} else {
		encoded, ok, err := uniquePA(p.PA, 149)
		if err != nil {
			return nil, err
		}
		if !ok && p.Flags&flagEncPARep != 0 {
			return nil, ErrReply
		}
		if ok {
			typeID, sum, err := parseChecksum(encoded)
			if err != nil {
				return nil, err
			}
			if typeID != key.ChecksumType() {
				return nil, ErrReply
			}
			if err = key.VerifyChecksum(56, request, sum); err != nil {
				return nil, err
			}
			bound = true
		}
	}
	sessionKey, err := krbcrypto.NewKey(p.KeyType, p.Key)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		sessionKey.Clear()
		return nil, err
	}
	info := TicketInfo{Realm: p.Realm, Client: client.clone(), Server: server.clone(), SessionEnctype: p.KeyType, Flags: p.Flags, AuthTime: p.AuthTime, StartTime: p.StartTime, EndTime: p.EndTime, RequestBound: bound}
	return &Ticket{material: &ticketMaterial{info: info, raw: append([]byte(nil), r.Ticket.Raw...), key: sessionKey}}, nil
}
