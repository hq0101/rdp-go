// Package rdgateway provides an explicitly authenticated HTTPS RD Gateway
// target byte connection. It implements the RDGHTTP 1.0 persistent IN/OUT
// profile; it does not perform the target's RDP, TLS or NLA handshake.
// Gateway and target credentials and certificate trust are independent.
// This profile has local peer coverage, not real RD Gateway acceptance.
package rdgateway

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/hq0101/rdp-go/internal/ntlm"
	"github.com/hq0101/rdp-go/internal/rdghttp"
)

type Authentication uint8

const (
	NTLM Authentication = iota
	NegotiateNTLM
	NegotiateRawNTLM
	NegotiateKerberos
)

// Credentials belong to the gateway, not the RDP target. No SSO is attempted.
type Credentials struct {
	Username, Domain string
	Password         string `json:"-"`
}

func (Credentials) String() string   { return "rdgateway.Credentials{redacted}" }
func (Credentials) GoString() string { return "rdgateway.Credentials{redacted}" }

const (
	RedirEnableAll        = rdghttp.RedirEnableAll
	RedirDisableAll       = rdghttp.RedirDisableAll
	RedirDisableDrive     = rdghttp.RedirDisableDrive
	RedirDisablePrinter   = rdghttp.RedirDisablePrinter
	RedirDisablePort      = rdghttp.RedirDisablePort
	RedirDisableClipboard = rdghttp.RedirDisableClipboard
	RedirDisablePnP       = rdghttp.RedirDisablePnP
)

type Info struct {
	TunnelID, ChannelID, Capabilities uint32
	RedirectionFlags                  uint32
	RedirectionFlagsPresent           bool
}

type Options struct {
	Authentication Authentication
	Kerberos       *KerberosOptions // required exactly for NegotiateKerberos
	// TLSConfig is cloned. TLS >= 1.2 with verified roots or an explicit leaf
	// SHA-256 pin is required. Unconditional InsecureSkipVerify is rejected.
	TLSConfig               *tls.Config
	CertificateSHA256       string
	ClientName              string
	Resources, Alternatives []string
	Port                    uint16
	// HandshakeTimeout covers all authentication, decisions and channel setup;
	// zero means 30 seconds. Callbacks must observe the supplied context.
	HandshakeTimeout time.Duration
	// ControlTimeout bounds graceful close and control writes; zero means 5s.
	ControlTimeout time.Duration
	// ReceiveBuffer is a fixed byte ring: default 1 MiB, 65535..16 MiB.
	// A full ring applies backpressure to OUT, including later control packets.
	ReceiveBuffer int
	// Consent must explicitly accept a present prompt; nil denies it. The
	// callback is synchronous; treat the prompt as untrusted server text.
	Consent func(context.Context, string) error
	// ApplyPolicy is REQUIRED, even when no flags are present. Before returning
	// nil, apply these restrictions to the forthcoming RDP session and every
	// reconnect. Reject policies the application cannot enforce. No target
	// channel is created before this succeeds. This byte layer cannot enforce
	// clipboard/device policy inside the target's encrypted RDP traffic.
	ApplyPolicy func(context.Context, Info) error
}

var (
	ErrInvalid     = rdghttp.ErrInvalid
	ErrLimit       = rdghttp.ErrLimit
	ErrDenied      = rdghttp.ErrDenied
	ErrUnsupported = rdghttp.ErrUnsupported
)

// StatusError reports an RDG binary failure without including peer payloads.
type StatusError struct {
	PacketType uint16
	Code       uint32
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("rdgateway: packet %d status 0x%08x", e.PacketType, e.Code)
}

// INStatusError means the streaming IN request ended with an unexpected HTTP
// response. Even an early 200 terminates the connection. No request is replayed.
type INStatusError struct{ Code int }

func (e *INStatusError) Error() string {
	return fmt.Sprintf("rdgateway: unexpected IN HTTP status %d", e.Code)
}

func publicError(err error) error {
	if e, ok := err.(*rdghttp.StatusError); ok {
		return &StatusError{uint16(e.Type), e.Code}
	}
	return err
}

// DialContext establishes a target channel via gatewayAddress (host:port).
// ctx controls setup only; after success use deadlines, Shutdown or Close.
// It never dials Resources directly, follows redirects, discovers proxies,
// opens UDP, or retries a partially sent request. The supported HTTP body
// profile uses exactly ten initial seed bytes on each persistent connection.
func DialContext(ctx context.Context, gatewayAddress string, credentials Credentials, o Options) (conn *Conn, err error) {
	if ctx == nil || o.ApplyPolicy == nil || o.Authentication > NegotiateKerberos || o.HandshakeTimeout < 0 || o.ControlTimeout < 0 {
		return nil, ErrInvalid
	}
	if o.ReceiveBuffer == 0 {
		o.ReceiveBuffer = 1 << 20
	}
	if o.ReceiveBuffer < rdghttp.MaxDataSize || o.ReceiveBuffer > 16<<20 {
		return nil, ErrInvalid
	}
	if o.HandshakeTimeout == 0 {
		o.HandshakeTimeout = 30 * time.Second
	}
	if o.ControlTimeout == 0 {
		o.ControlTimeout = 5 * time.Second
	}
	engine, err := rdghttp.NewClient(rdghttp.Config{ClientName: o.ClientName, Resources: o.Resources, Alternatives: o.Alternatives, Port: o.Port})
	if err != nil {
		return nil, publicError(err)
	}
	target := address{"rdgateway", net.JoinHostPort(o.Resources[0], strconv.Itoa(int(o.Port)))}
	defer func() {
		if conn == nil {
			engine.Abort()
		}
	}()
	ctx, cancel := context.WithTimeout(ctx, o.HandshakeTimeout)
	defer cancel()
	var kerberosOptions *rdghttp.HTTPKerberosOptions
	if o.Kerberos != nil {
		k := rdghttp.HTTPKerberosOptions(*o.Kerberos.Clone())
		kerberosOptions = &k
	}
	pair, err := rdghttp.DialHTTPPair(ctx, gatewayAddress, ntlm.Credentials{Username: credentials.Username, Domain: credentials.Domain, Password: credentials.Password}, rdghttp.HTTPOptions{Kerberos: kerberosOptions, Authentication: rdghttp.HTTPAuthentication(o.Authentication), TLSConfig: o.TLSConfig, CertificateSHA256: o.CertificateSHA256, HandshakeTimeout: o.HandshakeTimeout})
	if err != nil {
		return nil, publicError(err)
	}
	s, err := pair.OpenStreams(ctx)
	if err != nil {
		pair.Close()
		return nil, err
	}
	c := newConn(s, engine, o.ReceiveBuffer, o.ControlTimeout)
	c.target = target
	c.wg.Add(1)
	go c.watchIN()
	callbackDone := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { c.stop(ctx.Err(), false); close(callbackDone) })
	defer func() {
		if !stop() {
			<-callbackDone
		}
		if ctx.Err() != nil {
			err = ctx.Err()
		} else if d, ok := ctx.Deadline(); ok && !time.Now().Before(d) {
			err = context.DeadlineExceeded
		}
		if ctx.Err() == nil {
			c.mu.Lock()
			if c.terminal != nil {
				err = c.terminal
			}
			c.mu.Unlock()
		}
		if err != nil {
			c.Close()
			conn = nil
		}
	}()
	if d, ok := ctx.Deadline(); ok {
		err = s.SetDeadline(d)
	}
	if err == nil {
		err = c.setup(ctx, o)
	}
	if err != nil {
		return nil, publicError(err)
	}
	if err = s.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	c.wg.Add(1)
	go c.readOUT()
	return c, nil
}

func (c *Conn) setup(ctx context.Context, o Options) error {
	c.engineMu.Lock()
	step, err := c.engine.Start()
	c.engineMu.Unlock()
	for err == nil {
		for _, f := range step.Outbound {
			err = c.stream.WriteFrame(f)
			clear(f.Body)
			if err != nil {
				return err
			}
		}
		if step.Event == rdghttp.Connected {
			c.info = Info(step.Info)
			return nil
		}
		var f rdghttp.Frame
		f, err = c.stream.ReadFrame()
		if err != nil {
			break
		}
		c.engineMu.Lock()
		step, err = c.engine.Receive(f)
		c.engineMu.Unlock()
		clear(f.Body)
		if err != nil {
			break
		}
		switch step.Event {
		case rdghttp.ConsentRequired:
			if o.Consent == nil {
				return ErrDenied
			}
			if err = o.Consent(ctx, step.Consent); err != nil {
				return err
			}
			if err = ctx.Err(); err != nil {
				return err
			}
			c.engineMu.Lock()
			step, err = c.engine.AcceptConsent(true)
			c.engineMu.Unlock()
		case rdghttp.PolicyRequired:
			if err = o.ApplyPolicy(ctx, Info(step.Info)); err != nil {
				return err
			}
			if err = ctx.Err(); err != nil {
				return err
			}
			c.engineMu.Lock()
			step, err = c.engine.AcceptPolicy(true)
			c.engineMu.Unlock()
		case rdghttp.ReceivedService:
			err = c.pushService(step.Data)
		}
	}
	return err
}
