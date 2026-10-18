package licensing

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"io"
	"sync"
	"time"
)

type Config struct {
	redacted
	// Names are already encoded in the caller's selected ANSI code page, without
	// a terminating NUL. No implicit UTF-8/code-page or machine-name conversion.
	UserName, MachineName []byte
	PlatformID            uint32
	ClientType            uint16
	// Caller supplies a stable identity; the library never fingerprints hardware.
	HardwareID [16]byte
}
type State uint8

const (
	Await State = iota
	NeedKey
	AwaitServer
	AwaitLicense
	Complete
	Failed
	Closed
)

type Status struct {
	State                     State
	Messages, Resends, Resets int
	Issued, Upgraded, Cached  bool
}
type Result struct {
	redacted
	Reply               []byte   // Caller owns the packet and must discard it after sending.
	Request             *Request // Caller must authenticate its certificate before Start.
	License             *License // MAC-verified new CAL; caller owns it and chooses storage.
	Done, Reset, Resent bool
}

func (r *Result) Clear() {
	if r == nil {
		return
	}
	clear(r.Reply)
	r.Request.Clear()
	r.License.Clear()
	*r = Result{}
}

// Client serializes its in-memory state; no callbacks, file or network I/O run
// under the lock. Start is a deliberate boundary for external certificate/store
// work. Close is terminal and wipes retained material. Never copy a Client.
type Client struct {
	redacted
	mu      sync.Mutex
	config  Config
	status  Status
	request *Request
	keys    keys
	hwid    [20]byte
	last    []byte
	random  io.Reader // crypto/rand by default; test injection stays package-private.
}

func New(config Config) (*Client, error) {
	validName := func(b []byte) bool { return len(b) > 0 && len(b) < MaxText && bytes.IndexByte(b, 0) < 0 }
	if !validName(config.UserName) || !validName(config.MachineName) || config.HardwareID == ([16]byte{}) {
		return nil, ErrInvalid
	}
	if config.ClientType == 0 {
		config.ClientType = 0xff00
	}
	if config.ClientType != 0x100 && config.ClientType != 0x200 && config.ClientType != 0x300 && config.ClientType != 0xff00 {
		return nil, ErrInvalid
	}
	config.UserName = bytes.Clone(config.UserName)
	config.MachineName = bytes.Clone(config.MachineName)
	c := &Client{config: config, random: rand.Reader}
	binary.LittleEndian.PutUint32(c.hwid[:4], config.PlatformID)
	copy(c.hwid[4:], config.HardwareID[:])
	return c, nil
}
func (c *Client) Status() Status { c.mu.Lock(); defer c.mu.Unlock(); return c.status }
func (c *Client) clearExchange() {
	c.request.Clear()
	c.request = nil
	c.keys.clear()
	clear(c.last)
	c.last = nil
}
func (c *Client) terminal(state State) {
	c.clearExchange()
	clear(c.config.UserName)
	clear(c.config.MachineName)
	c.config = Config{}
	clear(c.hwid[:])
	c.random = nil
	c.status.State = state
}
func (c *Client) Close() { c.mu.Lock(); defer c.mu.Unlock(); c.terminal(Closed) }
func (c *Client) active(ctx context.Context) error {
	if c.status.State == Closed {
		return ErrClosed
	}
	if c.status.State == Failed || c.status.State == Complete {
		return ErrState
	}
	if err := ctx.Err(); err != nil {
		c.terminal(Failed)
		return err
	}
	return nil
}
func (c *Client) fail(err error) (Result, error) { c.terminal(Failed); return Result{}, err }
func (c *Client) remember(b []byte)              { clear(c.last); c.last = bytes.Clone(b) }

// Start requires a key independently authenticated by the connection layer for
// this Request (including the specified MCS fallback if the certificate is absent).
// Supplying an arbitrary key does not authenticate the server. cached must have
// been selected in that connection's store namespace and match product/scope/HWID.
func (c *Client) Start(ctx context.Context, key *rsa.PublicKey, cached *License) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.startLocked(ctx, key, cached)
}

// StartVerified authenticates the certificate retained in this exchange before
// constructing any client request. Verification and the trust callback run
// outside the mutex, so Status/Close remain usable. A stale verification result
// cannot act on a reset, closed, or already-started exchange.
//
// On certificate rejection, Result.Reply is ERR_INVALID_SERVER_CERTIFICATE /
// ST_TOTAL_ABORT and an error is returned (local algorithm policy failure uses
// ERR_NO_LICENSE). The caller should send this reply
// before closing the transport. Cancellation or a concurrent state change does
// not produce an abort. Empty certificates fail: a TLS key is not an implicit
// replacement for the MCS certificate fallback specified by MS-RDPELE.
func (c *Client) StartVerified(ctx context.Context, now time.Time, verify CertificateVerifier, cached *License) (Result, error) {
	c.mu.Lock()
	if err := c.active(ctx); err != nil {
		c.mu.Unlock()
		return Result{}, err
	}
	if c.status.State != NeedKey {
		r, err := c.fail(ErrState)
		c.mu.Unlock()
		return r, err
	}
	request := c.request
	raw := bytes.Clone(request.Certificate)
	c.mu.Unlock()
	defer clear(raw)
	key, _, err := VerifyCertificate(ctx, raw, now, verify)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.State == Closed {
		return Result{}, ErrClosed
	}
	if c.status.State != NeedKey || c.request != request {
		return Result{}, ErrState
	}
	if activeErr := c.active(ctx); activeErr != nil {
		return Result{}, activeErr
	}
	if err != nil {
		c.terminal(Failed)
		code := uint32(1)
		if err == ErrCrypto {
			code = 2
		}
		return Result{Reply: abortPacket(code)}, err
	}
	return c.startLocked(ctx, key, cached)
}

func (c *Client) startLocked(ctx context.Context, key *rsa.PublicKey, cached *License) (Result, error) {
	if err := c.active(ctx); err != nil {
		return Result{}, err
	}
	if c.status.State != NeedKey {
		return c.fail(ErrState)
	}
	if cached != nil && !cached.Matches(c.request, c.hwid) {
		return c.fail(ErrCachedLicense)
	}
	if err := cryptoAvailable(); err != nil {
		return c.fail(err)
	}
	var cr [32]byte
	var secret [48]byte
	defer clear(cr[:])
	defer clear(secret[:])
	if _, err := io.ReadFull(c.random, cr[:]); err != nil {
		return c.fail(err)
	}
	if _, err := io.ReadFull(c.random, secret[:]); err != nil {
		return c.fail(err)
	}
	encrypted, err := encryptPremaster(key, secret)
	if err != nil {
		return c.fail(err)
	}
	defer clear(encrypted)
	k := derive(secret, cr, c.request.random)
	defer k.clear()
	b := binary.LittleEndian.AppendUint32(nil, 1)
	b = binary.LittleEndian.AppendUint32(b, c.config.PlatformID)
	b = append(b, cr[:]...)
	b = blob(b, 2, encrypted)
	kind := NewRequestMessage
	if cached == nil {
		b = blob(b, 15, append(bytes.Clone(c.config.UserName), 0))
		b = blob(b, 16, append(bytes.Clone(c.config.MachineName), 0))
	} else {
		kind = LicenseInfoMessage
		b = blob(b, 1, cached.Data)
		hw := k.crypt(c.hwid[:])
		b = blob(b, 9, hw)
		clear(hw)
		mac := k.checksum(c.hwid[:])
		b = append(b, mac[:]...)
	}
	defer clear(b)
	reply, err := packet(kind, b)
	if err != nil {
		return c.fail(err)
	}
	if err = ctx.Err(); err != nil {
		clear(reply)
		return c.fail(err)
	}
	c.keys = k
	c.status.Cached = cached != nil
	c.status.State = AwaitServer
	c.remember(reply)
	return Result{Reply: reply}, nil
}

// Abort refuses issuance locally (1=invalid server certificate, 2=no license).
// It never manufactures STATUS_VALID_CLIENT or converts a server failure to success.
func (c *Client) Abort(code uint32) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.status.State == Closed {
		return Result{}, ErrClosed
	}
	if c.status.State != NeedKey || (code != 1 && code != 2) {
		return c.fail(ErrState)
	}
	reply := abortPacket(code)
	c.terminal(Failed)
	return Result{Reply: reply}, nil
}

func (c *Client) Handle(ctx context.Context, b []byte) (Result, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.active(ctx); err != nil {
		return Result{}, err
	}
	c.status.Messages++
	if c.status.Messages > 32 {
		return c.fail(ErrLimit)
	}
	m, err := parse(b)
	if err != nil {
		return c.fail(err)
	}
	defer m.request.Clear()
	switch m.kind {
	case RequestMessage:
		if c.status.State != Await {
			return c.fail(ErrState)
		}
		c.request = m.request.clone()
		c.status.State = NeedKey
		return Result{Request: m.request.clone()}, nil
	case ErrorMessage:
		if c.status.State == NeedKey {
			return c.fail(ErrState)
		}
		if m.code == 7 {
			if m.transition != 2 {
				return c.fail(ErrInvalid)
			}
			c.terminal(Complete)
			return Result{Done: true}, nil
		}
		switch m.transition {
		case 3:
			if c.status.State == Await {
				return c.fail(ErrState)
			}
			c.status.Resets++
			if c.status.Resets > 2 {
				return c.fail(ErrLimit)
			}
			c.clearExchange()
			c.status.State = Await
			c.status.Cached = false
			return Result{Reset: true}, nil
		case 4:
			if len(c.last) == 0 {
				return c.fail(ErrState)
			}
			c.status.Resends++
			if c.status.Resends > 3 {
				return c.fail(ErrLimit)
			}
			return Result{Reply: bytes.Clone(c.last), Resent: true}, nil
		default:
			return c.fail(&ServerError{Code: m.code, Transition: m.transition})
		}
	case ChallengeMessage:
		if c.status.State != AwaitServer {
			return c.fail(ErrState)
		}
		plain, err := c.keys.open(m.encrypted, m.mac)
		if err != nil {
			return c.fail(err)
		}
		defer clear(plain)
		response := binary.LittleEndian.AppendUint16(nil, 0x100)
		response = binary.LittleEndian.AppendUint16(response, c.config.ClientType)
		response = binary.LittleEndian.AppendUint16(response, 3)
		response = binary.LittleEndian.AppendUint16(response, uint16(len(plain)))
		response = append(response, plain...)
		defer clear(response)
		mac := c.keys.checksum(response, c.hwid[:])
		challenge := c.keys.crypt(response)
		hwid := c.keys.crypt(c.hwid[:])
		defer clear(challenge)
		defer clear(hwid)
		body := blob(nil, 9, challenge)
		body = blob(body, 9, hwid)
		body = append(body, mac[:]...)
		defer clear(body)
		reply, err := packet(ResponseMessage, body)
		if err != nil {
			return c.fail(err)
		}
		c.remember(reply)
		c.status.State = AwaitLicense
		return Result{Reply: reply}, nil
	case NewLicenseMessage, UpgradeMessage:
		if c.status.State != AwaitLicense {
			return c.fail(ErrState)
		}
		if m.kind == UpgradeMessage && !c.status.Cached {
			return c.fail(ErrState)
		}
		plain, err := c.keys.open(m.encrypted, m.mac)
		if err != nil {
			return c.fail(err)
		}
		defer clear(plain)
		license, err := parseLicense(plain, c.hwid)
		if err != nil {
			return c.fail(err)
		}
		c.status.Issued = m.kind == NewLicenseMessage
		c.status.Upgraded = m.kind == UpgradeMessage
		c.terminal(Complete)
		return Result{Done: true, License: license}, nil
	default:
		return c.fail(ErrState)
	}
}
