package rdp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/internal/logon"
	"github.com/hq0101/rdp-go/internal/rdstls"
)

var (
	ErrReconnectUnavailable = errors.New("rdp: no usable reconnect credential after network failure")
	ErrReconnectRejected    = errors.New("rdp: server rejected auto-reconnection")
	ErrReconnectIdentity    = errors.New("rdp: reconnect identity differs from the original connection")
	ErrReconnectSession     = errors.New("rdp: reconnect did not restore the original session")
)

// A decoder can return EOF for a truncated payload without losing the socket.
// Only a transport-observed failure makes an event-handler error retryable.
type reconnectEventError struct {
	err     error
	network bool
}

func (e *reconnectEventError) Error() string { return "rdp reconnect event handler: " + e.err.Error() }
func (e *reconnectEventError) Unwrap() error { return e.err }

// ReconnectPolicy bounds one Reconnect invocation, including NLA, activation
// and confirmation. Zero values mean 3 attempts, 500 ms initial backoff, 5 s
// maximum backoff and 60 s total timeout. Only network failures are retried.
type ReconnectPolicy struct {
	// RetryReliableUDP preserves the original UDP offer after a bound-side
	// network failure. By default recovery renegotiates managed DVCs over TCP
	// and retains that choice for later recoveries. Main-TCP loss alone does
	// not change the original offer. This never replays old DVC messages.
	RetryReliableUDP                bool
	MaxAttempts                     int
	InitialDelay, MaxDelay, Timeout time.Duration
}

func (p ReconnectPolicy) normalized() (ReconnectPolicy, error) {
	if p.MaxAttempts == 0 {
		p.MaxAttempts = 3
	}
	if p.InitialDelay == 0 {
		p.InitialDelay = 500 * time.Millisecond
	}
	if p.MaxDelay == 0 {
		p.MaxDelay = 5 * time.Second
	}
	if p.Timeout == 0 {
		p.Timeout = time.Minute
	}
	if p.MaxAttempts < 1 || p.MaxAttempts > 10 || p.InitialDelay <= 0 || p.MaxDelay < p.InitialDelay || p.MaxDelay > 30*time.Second || p.Timeout <= 0 || p.Timeout > 10*time.Minute {
		return p, errors.New("rdp: invalid reconnect policy")
	}
	return p, nil
}

type reconnectState struct {
	mu                            sync.Mutex
	gate                          chan struct{}
	address, user, domain         string
	opts                          Options
	settings                      gcc.ClientSettings
	certificate                   [32]byte
	rdstls                        bool // immutable authentication mode; no password retained
	cookie                        *logon.Cookie
	expires                       time.Time
	terminal, inProgress, resumed bool
	attempts                      int
	tcpFallback                   bool
	updates                       uint64
	resumedID                     uint32
	cancel                        context.CancelFunc
}

// ReconnectInfo contains no secret or serialized cookie. CookieAvailable only
// describes a locally retained credential; the server can invalidate it sooner.
// For opt-in sessions, NetworkFailure reports transport loss independently of cookie
// availability, including an unconfirmed recovery candidate. It does not by
// itself authorize recovery. Ready additionally requires a usable cookie. Resumed is
// set only after a new logon notification and fresh cookie confirm the old ID.
type ReconnectInfo struct {
	NetworkFailure                                                   bool // diagnostic; Ready still gates a new Reconnect call
	TCPFallback                                                      bool // this connection was recovered with UDP disabled
	Enabled, Negotiated, CookieAvailable, Ready, InProgress, Resumed bool
	Attempts                                                         int
	CookieUpdates                                                    uint64
	SessionID                                                        uint32
}

func cloneReconnectOptions(o Options) Options {
	o.RemoteApp = cloneRemoteApp(o.RemoteApp)
	o.Gateway = cloneGateway(o.Gateway)
	o.gatewayPreflight = nil
	o.Licensing = o.Licensing.Clone()
	o.RoutingToken = append([]byte(nil), o.RoutingToken...)
	if o.ExpectedTSVURL != nil {
		o.ExpectedTSVURL = append([]byte{}, o.ExpectedTSVURL...)
	}
	if o.Kerberos != nil {
		o.Kerberos = o.Kerberos.Clone()
	}
	o.DynamicChannels = cloneDynamicOptions(o.DynamicChannels)
	if o.StaticChannelLimits != nil {
		limits := make(map[string]int, len(o.StaticChannelLimits))
		for k, v := range o.StaticChannelLimits {
			limits[k] = v
		}
		o.StaticChannelLimits = limits
	}
	if o.TLSConfig != nil {
		o.TLSConfig = o.TLSConfig.Clone()
		if o.TLSConfig.RootCAs != nil {
			o.TLSConfig.RootCAs = o.TLSConfig.RootCAs.Clone()
		}
		if o.TLSConfig.ClientCAs != nil {
			o.TLSConfig.ClientCAs = o.TLSConfig.ClientCAs.Clone()
		}
	}
	return o
}

func newReconnectState(address string, c Credentials, o Options, s gcc.ClientSettings) *reconnectState {
	if s.RedirectedSessionID != nil {
		id := *s.RedirectedSessionID
		s.RedirectedSessionID = &id
	}
	s.Channels = append([]gcc.Channel(nil), s.Channels...)
	s.Monitors = append(s.Monitors[:0:0], s.Monitors...)
	return &reconnectState{gate: make(chan struct{}, 1), address: address, user: c.Username, domain: c.Domain, opts: cloneReconnectOptions(o), settings: s}
}

func (r *reconnectState) discardLocked() {
	r.cookie.Clear()
	r.cookie = nil
	r.expires = time.Time{}
}
func (r *reconnectState) expireLocked() {
	if r.cookie != nil && !time.Now().Before(r.expires) {
		r.discardLocked()
	}
}
func (r *reconnectState) clearRoutingLocked() {
	r.opts.Gateway = nil
	r.opts.gatewayPreflight = nil
	clearLicensingOptions(r.opts.Licensing)
	r.opts.Licensing = nil
	clear(r.opts.RoutingToken)
	r.opts.RoutingToken = nil
	clear(r.opts.ExpectedTSVURL)
	r.opts.ExpectedTSVURL = nil
}
func (s *Session) discardReconnect() {
	if r := s.reconnect; r != nil {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.terminal = true
		r.clearRoutingLocked()
		r.discardLocked()
		if r.cancel != nil {
			r.cancel()
		}
	}
}

func (s *Session) ReconnectInfo() ReconnectInfo {
	r := s.reconnect
	if r == nil {
		return ReconnectInfo{}
	}
	info := ReconnectInfo{Enabled: true, Negotiated: s.Info().AutoReconnect, NetworkFailure: s.networkFailed()}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.expireLocked()
	info.TCPFallback = r.tcpFallback
	info.CookieAvailable = r.cookie != nil && !r.terminal
	info.Ready = info.CookieAvailable && !r.inProgress && info.NetworkFailure
	info.InProgress, info.Resumed, info.Attempts, info.CookieUpdates = r.inProgress, r.resumed, r.attempts, r.updates
	if r.cookie != nil {
		info.SessionID = r.cookie.SessionID()
	} else if r.resumed {
		info.SessionID = r.resumedID
	}
	return info
}

func reconnectableNetworkError(err error) bool {
	if err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, net.ErrClosed) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var op *net.OpError
	if errors.As(err, &op) {
		var system *os.SyscallError
		var dns *net.DNSError
		return errors.As(op.Err, &system) || (errors.As(op.Err, &dns) && (dns.IsTimeout || dns.IsTemporary)) || op.Timeout()
	}
	return false
}

// failSession distinguishes a lost transport from intentional termination or
// malformed/authentication/server-error PDUs. Cached protocol state is never
// reused across a new connection, even when the old cookie is retained.
func (s *Session) failSession(err error) {
	s.active.Store(false)
	if recoverableSessionError(err) && s.networkFailed() {
		if s.dynamic != nil {
			s.dynamic.stop(err)
		}
		s.connection.Transport.Close()
		return
	}
	s.closeNow()
}

// Reconnect performs bounded automatic reconnection after a network failure.
// It returns a NEW Session only after logon plus a fresh server cookie confirm
// the original session ID. Rebuild all graphics, virtual-channel, clipboard
// and held-input state for that connection; never replay unacknowledged input.
//
// Enable Options.AutoReconnect on the original DialSession and continue reading
// events to receive cookies. Do not call Close on the old Session until after
// Reconnect returns: explicit Close discards its credential and cancels retries.
// NLA sessions require fresh credentials with the same username/domain, retained
// only for this call. RDSTLS sessions use their server ARC cookie and may pass
// zero Credentials; supplied names must still match and Password is unused.
// Both modes require normal certificate checks and original leaf identity
// before authentication material can be sent. Authentication never downgrades.
//
// Calls are serialized and context-cancellable. A successful successor consumes
// the old credential. Certificate/authentication/protocol failures or an ARC
// rejection terminate retries and discard it; there is no password fallback.
func (s *Session) Reconnect(ctx context.Context, c Credentials, policy ReconnectPolicy) (*Session, error) {
	return s.reconnectWithEvents(ctx, c, policy, nil)
}

// ReconnectWithEvents additionally services protocol events while waiting for
// logon confirmation. Graphics/DVC servers may require capability responses or
// frame acknowledgements before they send that confirmation. The handler runs
// serially with an activated, still-unconfirmed candidate Session and the retry
// context. It must honor that context, must not call ReadEvent, and must not
// publish graphics or accept user input until this method succeeds.
//
// Events passed to the handler are consumed, not queued again. Retries may call
// it with a different candidate; rebuild all candidate state on that change and
// discard it on failure. A nil handler behaves exactly like Reconnect.
func (s *Session) ReconnectWithEvents(ctx context.Context, c Credentials, policy ReconnectPolicy, handle func(context.Context, *Session, Event) error) (*Session, error) {
	return s.reconnectWithEvents(ctx, c, policy, handle)
}

func (s *Session) reconnectWithEvents(ctx context.Context, c Credentials, policy ReconnectPolicy, handle func(context.Context, *Session, Event) error) (*Session, error) {
	policy, err := policy.normalized()
	if err != nil {
		return nil, err
	}
	r := s.reconnect
	if r == nil {
		return nil, ErrReconnectUnavailable
	}
	if r.rdstls {
		if c.Username == "" && c.Domain == "" {
			c.Username, c.Domain = r.user, r.domain
		}
		c.Password = ""
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Username != r.user || c.Domain != r.domain {
		return nil, ErrReconnectIdentity
	}
	ctx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()
	select {
	case r.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-r.gate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.expireLocked()
	if r.terminal || r.cookie == nil || !s.networkFailed() {
		r.mu.Unlock()
		return nil, ErrReconnectUnavailable
	}
	wantedID := r.cookie.SessionID()
	r.inProgress, r.cancel = true, cancel
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.inProgress = false; r.cancel = nil; r.mu.Unlock() }()
	// Tear down the failed carriers without explicit Session.Close, which
	// would discard the retained cookie. Join readers before creating a new
	// connection; no old DVC callbacks may overlap the successor.
	s.active.Store(false)
	if s.dynamic != nil {
		s.dynamic.stop(net.ErrClosed)
		select {
		case <-s.dynamic.workersDone:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	s.connection.Transport.Close()
	r.mu.Lock()
	baseOptions := cloneReconnectOptions(r.opts)
	r.mu.Unlock()
	defer clearLicensingOptions(baseOptions.Licensing)
	defer clear(baseOptions.RoutingToken)
	defer clear(baseOptions.ExpectedTSVURL)
	settings := r.settings
	if r.rdstls {
		settings.RedirectedSessionID = &wantedID
	}
	tcpFallback := r.tcpFallback
	useTCP := func() {
		if baseOptions.DynamicChannels != nil && baseOptions.DynamicChannels.ReliableUDP {
			baseOptions.DynamicChannels.ReliableUDP = false
			baseOptions.DynamicChannels.ReceiveWindow = 0
			settings.MultitransportFlags = 0
			tcpFallback = true
		}
	}
	if s.sideNetworkFailed() && !policy.RetryReliableUDP {
		useTCP()
	}
	opts := cloneReconnectOptions(baseOptions)
	defer clearLicensingOptions(opts.Licensing)
	defer clear(opts.RoutingToken)
	defer clear(opts.ExpectedTSVURL)
	if opts.TLSConfig == nil {
		opts.TLSConfig = &tls.Config{}
	}
	verify := opts.TLSConfig.VerifyConnection
	pin := r.certificate
	opts.TLSConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].Raw) != pin {
			return ErrReconnectIdentity
		}
		if verify != nil {
			return verify(state)
		}
		return nil
	}
	delay := policy.InitialDelay
	var last error
	for attempt := 0; attempt < policy.MaxAttempts; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
			delay = min(delay*2, policy.MaxDelay)
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		r.mu.Lock()
		r.expireLocked()
		if r.terminal || r.cookie == nil {
			r.mu.Unlock()
			return nil, ErrReconnectUnavailable
		}
		packet, err := r.cookie.ClientPacketTLS()
		login := sessionLogin{reconnectPacket: packet}
		if err == nil && r.rdstls {
			raw, e := r.cookie.RDSTLSPacket()
			err = e
			if err == nil {
				var auth []byte
				auth, err = rdstls.CookieRequest(raw)
				login.rdstls = &rdstlsAuthentication{packet: auth, certificate: r.certificate, reconnect: true}
			}
			clear(raw)
		}
		if err == nil {
			r.attempts++
		}
		r.mu.Unlock()
		if err != nil {
			clear(packet)
			login.clear()
			return nil, err
		}
		var expectedBinding *[sha256.Size]byte
		if s.hasExpectedTSVURL {
			expectedBinding = &s.expectedTSVURL
		}
		next, err := dialSessionLogin(ctx, r.address, c, opts, settings, login, expectedBinding)
		clear(packet)
		login.clear()
		if err == nil {
			err = next.confirmReconnect(ctx, wantedID, handle)
			if err != nil {
				if next.sideNetworkFailed() && !policy.RetryReliableUDP {
					useTCP()
					opts.DynamicChannels = cloneDynamicOptions(baseOptions.DynamicChannels)
				}
				next.Close()
			}
		}
		if err == nil {
			r.mu.Lock()
			if r.terminal || ctx.Err() != nil {
				r.mu.Unlock()
				next.Close()
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return nil, context.Canceled
			}
			r.terminal = true
			r.discardLocked()
			r.clearRoutingLocked()
			r.mu.Unlock()
			// Keep only the original verification configuration for the next
			// reconnect, rather than stacking closures on every recovery.
			next.reconnect.mu.Lock()
			next.reconnect.clearRoutingLocked()
			next.reconnect.opts = cloneReconnectOptions(baseOptions)
			next.reconnect.tcpFallback = tcpFallback
			next.reconnect.resumed = true
			next.reconnect.resumedID = wantedID
			next.reconnect.mu.Unlock()
			next.redirect = s.redirect
			return next, nil
		}
		last = err
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		// A per-attempt handshake timeout can be retried while the overall
		// caller budget remains. Other context cancellation is terminal.
		var sideErr *sideFailureError
		retryable := reconnectableNetworkError(err) || errors.Is(err, context.DeadlineExceeded)
		if errors.As(err, &sideErr) {
			retryable = sideErr.network
		}
		var eventErr *reconnectEventError
		if errors.As(err, &eventErr) {
			retryable = eventErr.network && recoverableSessionError(err)
		}
		if !retryable {
			s.discardReconnect()
			return nil, err
		}
	}
	return nil, fmt.Errorf("rdp: reconnect attempts exhausted: %w", last)
}

func (s *Session) confirmReconnect(ctx context.Context, wantedID uint32, handle func(context.Context, *Session, Event) error) error {
	if !s.Info().AutoReconnect || s.reconnect == nil {
		return ErrReconnectUnavailable
	}
	var queued []Event
	bytes := 0
	loggedOn := false
	limit := 256
	if handle != nil {
		limit = 4096
	}
	for events := 0; events < limit; events++ {
		e, err := s.ReadEvent(ctx)
		if err != nil {
			return err
		}
		if e.Kind == EventLogonInfo && e.Logon.Logon {
			if e.Logon.SessionIDKnown && e.Logon.SessionID != wantedID {
				return ErrReconnectSession
			}
			loggedOn = true
		}
		if handle != nil {
			if err := handle(ctx, s, e); err != nil {
				return &reconnectEventError{err: err, network: s.networkFailed()}
			}
		} else {
			bytes += len(e.Payload)
			if bytes > 8<<20 {
				return errors.New("rdp: too many events before reconnect confirmation")
			}
			queued = append(queued, e)
		}
		r := s.reconnect
		r.mu.Lock()
		fresh := r.cookie != nil
		matching := fresh && r.cookie.SessionID() == wantedID
		r.mu.Unlock()
		if fresh && !matching {
			return ErrReconnectSession
		}
		if loggedOn && matching && s.Info().Active {
			s.pending = append(queued, s.pending...)
			return nil
		}
	}
	return errors.New("rdp: reconnect confirmation event limit exceeded")
}
