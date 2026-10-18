package rdp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/pdu"
)

var (
	ErrRedirectionUnavailable = errors.New("rdp: redirection cannot be followed by this session")
	ErrRedirectionLimit       = errors.New("rdp: redirection hop limit reached")
	ErrRedirectionLoop        = errors.New("rdp: repeated redirection destination, session and route")
	ErrRedirectionCredentials = errors.New("rdp: redirected server credentials require explicit handling")
	ErrRedirectionRDSTLS      = errors.New("rdp: redirected credentials require explicit RDSTLS handling")
)

// RedirectionPolicy explicitly authorizes following server redirection. Resolve
// is mandatory and is invoked synchronously after the old connection closes,
// before any bytes are sent to the new target. It must honor ctx. The library
// retains this callback, so its captured credential storage is the caller's
// responsibility. MaxHops defaults to 5 (maximum 16), cumulatively across live
// redirections and ordinary ARC recovery. Timeout defaults to 60 seconds (at
// most 10 minutes) for each DialSessionWithRedirection or FollowRedirection call.
// Network failures are returned, not retried against other destinations.
type RedirectionPolicy struct {
	Resolve func(context.Context, RedirectionContext) (RedirectionTarget, error)
	MaxHops int
	Timeout time.Duration
}

// RedirectionContext identifies the authenticated source and the proposed hop.
// Info is an owned metadata snapshot. Request is borrowed only until Resolve
// returns; the library clears it on every outcome. Explicit Field copies are
// owned by the caller. Do not retain/use Request asynchronously or clear it in
// Resolve. Target names and certificates are assertions, not authorization.
type RedirectionContext struct {
	ViaGateway              bool
	FromAddress             string
	SourceCertificateSHA256 [sha256.Size]byte
	Hop                     int
	Info                    pdu.RedirectionInfo
	Request                 *pdu.Redirection
}

// RedirectionTarget supplies the full authentication/trust decision for a hop.
// Address is a concrete host:port chosen by the application, including any
// broker routing choice. It is never inferred from untrusted server names.
// Nil TLSConfig/empty pin uses system PKI for that address; no old server pin,
// ServerName, Kerberos configuration or credentials are inherited. A TLS
// ServerName may bind a selected IP/routing endpoint to the intended hostname.
// Kerberos and SPNEGO have the same meaning as in Options.
//
// PasswordMode explicitly selects how to handle a supplied server password or
// legacy cookie. The zero value rejects it. Forwarding requires Credentials to
// match any server-supplied username/domain; identities are never overwritten.
// PK-encrypted blobs require RedirectionPasswordRDSTLS. A required
// LB_DONTSTOREUSERNAME username must always match Credentials.Username.
type RedirectionTarget struct {
	// Gateway is chosen separately for this hop; no old gateway credentials or
	// trust are inherited. Leaving a gateway route requires AllowDirect.
	Gateway           *GatewayOptions `json:"-"`
	AllowDirect       bool
	Address           string
	Credentials       Credentials `json:"-"`
	TLSConfig         *tls.Config `json:"-"`
	CertificateSHA256 string
	Kerberos          *KerberosOptions `json:"-"`
	SPNEGO            bool
	// Licensing must be chosen explicitly for this target. Source identity,
	// license trust policy and store are never inherited across redirection.
	Licensing    *LicensingOptions `json:"-"`
	PasswordMode RedirectionPasswordMode
	// IgnoreServerPassword is the original spelling of RedirectionPasswordIgnore.
	// It cannot be combined with a nonzero PasswordMode.
	IgnoreServerPassword bool
}

func (RedirectionTarget) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "[redacted redirection target]")
}
func (RedirectionTarget) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted redirection target]"`), nil
}

type redirectState struct {
	policy          RedirectionPolicy
	opts            Options // graphics/channels/transport only; no authentication or route
	settings        gcc.ClientSettings
	address         string
	hops            int
	seen            map[[sha256.Size]byte]struct{}
	expectedBinding *[sha256.Size]byte
}

// RedirectionStatus is connection metadata, not confirmation of remote logon.
type RedirectionStatus struct {
	// Pending indicates a terminal wire request is being handed to the sole
	// reader. It lets concurrent writers defer shutdown to that reader. It is
	// not authorization to follow, and carries no request or credentials.
	Pending bool
	Enabled bool
	Hops    int
	Address string
}

func (s *Session) RedirectionInfo() RedirectionStatus {
	if s == nil || s.redirect == nil {
		return RedirectionStatus{}
	}
	return RedirectionStatus{Enabled: true, Pending: s.redirectPending.Load(), Hops: s.redirect.hops, Address: s.redirect.address}
}

func (p RedirectionPolicy) normalized() (RedirectionPolicy, error) {
	if p.MaxHops == 0 {
		p.MaxHops = 5
	}
	if p.Timeout == 0 {
		p.Timeout = time.Minute
	}
	if p.Resolve == nil || p.MaxHops < 1 || p.MaxHops > 16 || p.Timeout <= 0 || p.Timeout > 10*time.Minute {
		return p, errors.New("rdp: invalid redirection policy")
	}
	return p, nil
}

func cloneRedirectSettings(s gcc.ClientSettings) gcc.ClientSettings {
	s.Channels = append([]gcc.Channel(nil), s.Channels...)
	s.Monitors = append(s.Monitors[:0:0], s.Monitors...)
	if s.RedirectedSessionID != nil {
		id := *s.RedirectedSessionID
		s.RedirectedSessionID = &id
	}
	return s
}

// DialSessionWithRedirection offers redirection (version 5 by default, or 6 via
// settings.ServerRedirectionVersion) and follows redirects received during
// activation using policy.Resolve. It returns only the final
// activated Session, not proof of shell logon or of the requested session ID.
// Graphics, channels and platform resources belong to that fresh Session.
// A later RedirectionError from ReadEvent can be passed to s.FollowRedirection.
// Initial credentials and all resolved credentials are used only during dialing.
func DialSessionWithRedirection(ctx context.Context, address string, c Credentials, opts Options, settings gcc.ClientSettings, policy RedirectionPolicy) (*Session, error) {
	policy, err := policy.normalized()
	if err != nil {
		return nil, err
	}
	key, err := redirectionKey(address, settings.RedirectedSessionID, opts.RoutingToken)
	if err != nil {
		return nil, err
	}
	opts = cloneReconnectOptions(opts)
	defer clearLicensingOptions(opts.Licensing)
	defer clear(opts.RoutingToken)
	defer clear(opts.ExpectedTSVURL)
	settings = cloneRedirectSettings(settings)
	settings.ServerRedirection = true
	base := opts
	base.Gateway, base.gatewayPreflight = nil, nil
	base.TLSConfig, base.Kerberos = nil, nil
	base.CertificateSHA256, base.Cookie = "", ""
	base.SPNEGO = false
	base.Licensing = nil
	base.RoutingToken, base.ExpectedTSVURL = nil, nil
	state := &redirectState{policy: policy, opts: base, settings: settings, address: address, seen: map[[sha256.Size]byte]struct{}{key: {}}}
	if opts.ExpectedTSVURL != nil {
		digest := sha256.Sum256(opts.ExpectedTSVURL)
		state.expectedBinding = &digest
	}
	ctx, cancel := context.WithTimeout(ctx, policy.Timeout)
	defer cancel()
	s, err := dialSession(ctx, address, c, opts, settings, nil)
	if err == nil {
		if ctx.Err() != nil {
			s.Close()
			return nil, ctx.Err()
		}
		s.redirect = state
		return s, nil
	}
	redirected, ok := err.(*activationRedirection)
	if !ok {
		return nil, err
	}
	return followRedirections(ctx, redirected.request, state)
}

// FollowRedirection consumes a RedirectionError returned by this Session's
// ReadEvent. The session must originate from DialSessionWithRedirection (or its
// ordinary ARC successor). It follows activation-time redirects with the same
// cumulative hop history and returns a fresh Session. Rebuild graphics, DVC,
// clipboard/audio/device state before publishing it to the user. No protocol
// messages or resources from the old session are replayed.
//
// Only one follow attempt is allowed per source Session; failures need a new
// explicit dial. The request is cleared after consumption. Close cancels an
// in-progress follow and prevents starting one, even after ReadEvent terminated
// the old transport. A wrong-source request is rejected without consuming it.
func (s *Session) FollowRedirection(ctx context.Context, request *RedirectionError) (*Session, error) {
	if s == nil || request == nil || request.source != s || s.redirect == nil {
		return nil, ErrRedirectionUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, s.redirect.policy.Timeout)
	defer cancel()
	s.redirectMu.Lock()
	if s.redirectClosed || s.redirectUsed {
		s.redirectMu.Unlock()
		return nil, ErrRedirectionUnavailable
	}
	s.redirectUsed, s.redirectCancel = true, cancel
	s.redirectMu.Unlock()
	defer func() { s.redirectMu.Lock(); s.redirectCancel = nil; s.redirectMu.Unlock() }()
	next, err := followRedirections(ctx, request, s.redirect)
	s.redirectMu.Lock()
	closed := s.redirectClosed
	s.redirectMu.Unlock()
	if err == nil && (closed || ctx.Err() != nil) {
		next.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, context.Canceled
	}
	return next, err
}

// A policy's error text might contain credentials; preserve errors.Is/As while
// keeping the library's ordinary error message safe for diagnostics.
type redirectionPolicyError struct{ cause error }

func (e *redirectionPolicyError) Error() string              { return "rdp: redirection policy rejected the target" }
func (e *redirectionPolicyError) Unwrap() error              { return e.cause }
func (e *redirectionPolicyError) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, e.Error()) }

func followRedirections(ctx context.Context, request *RedirectionError, state *redirectState) (*Session, error) {
	for {
		next, updated, err := followOneRedirection(ctx, request, state)
		if err == nil {
			next.redirect = updated
			return next, nil
		}
		following, ok := err.(*activationRedirection)
		if !ok {
			return nil, err
		}
		// Only a redirection emitted by the newly dialed session is eligible.
		// A policy cannot manufacture one through its own wrapped error.
		if updated == nil {
			return nil, err
		}
		request, state = following.request, updated
	}
}

func followOneRedirection(ctx context.Context, request *RedirectionError, state *redirectState) (*Session, *redirectState, error) {
	if request == nil || request.Request == nil || request.source == nil || !request.claimed.CompareAndSwap(false, true) {
		return nil, nil, ErrRedirectionUnavailable
	}
	defer request.Request.Clear()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if state.hops >= state.policy.MaxHops {
		return nil, nil, ErrRedirectionLimit
	}
	old := request.source
	old.closeNow()
	if old.dynamic != nil {
		select {
		case <-old.dynamic.workersDone:
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
	info, err := request.Request.Info()
	if err != nil {
		return nil, nil, err
	}
	if info.Flags&pdu.RedirectInformationOnly != 0 {
		return nil, nil, ErrRedirectionUnavailable
	}
	certs := old.TLSState().PeerCertificates
	if len(certs) == 0 {
		return nil, nil, ErrRedirectionUnavailable
	}
	_, viaGateway := old.GatewayInfo()
	proposal := RedirectionContext{ViaGateway: viaGateway, FromAddress: state.address, SourceCertificateSHA256: sha256.Sum256(certs[0].Raw), Hop: state.hops + 1, Info: info, Request: request.Request}
	decision, err := state.policy.Resolve(ctx, proposal)
	if ctx.Err() != nil {
		return nil, nil, ctx.Err()
	}
	if err != nil {
		return nil, nil, &redirectionPolicyError{cause: err}
	}
	if viaGateway && decision.Gateway == nil && !decision.AllowDirect {
		return nil, nil, ErrGatewayRoute
	}
	if decision.Gateway != nil && decision.AllowDirect {
		return nil, nil, ErrGatewayRoute
	}
	credentials, login, err := prepareRedirectLogin(request.Request, info, decision)
	defer login.clear()
	if err != nil {
		return nil, nil, err
	}
	// A route without a direct network-address flag is passed verbatim, per
	// MS-RDPBCGR. Resolve approves its destination together with the TLS identity.
	var route []byte
	if info.Flags&pdu.RedirectTargetAddress == 0 && info.Flags&pdu.RedirectLoadBalanceInfo != 0 {
		route, err = request.Request.Field(pdu.RedirectLoadBalanceInfo)
		if err != nil {
			return nil, nil, err
		}
		defer clear(route)
		if len(route) == 0 {
			return nil, nil, errors.New("rdp: empty redirection routing token")
		}
	}
	id := info.SessionID
	key, err := redirectionKey(decision.Address, &id, route)
	if err != nil {
		return nil, nil, err
	}
	if _, exists := state.seen[key]; exists {
		return nil, nil, ErrRedirectionLoop
	}
	updated := *state
	updated.address, updated.hops = decision.Address, state.hops+1
	updated.seen = make(map[[sha256.Size]byte]struct{}, len(state.seen)+1)
	for k := range state.seen {
		updated.seen[k] = struct{}{}
	}
	updated.seen[key] = struct{}{}
	opts := state.opts
	opts.TLSConfig, opts.CertificateSHA256 = decision.TLSConfig, decision.CertificateSHA256
	opts.Kerberos, opts.SPNEGO = decision.Kerberos, decision.SPNEGO
	opts.Gateway = decision.Gateway
	opts.Licensing = decision.Licensing
	opts.RoutingToken = route
	opts = cloneReconnectOptions(opts)
	defer clearLicensingOptions(opts.Licensing)
	defer clear(opts.RoutingToken)
	settings := cloneRedirectSettings(state.settings)
	settings.RedirectedSessionID = &id
	next, err := dialSessionLogin(ctx, decision.Address, credentials, opts, settings, login, state.expectedBinding)
	if err == nil && ctx.Err() != nil {
		next.Close()
		return nil, nil, ctx.Err()
	}
	return next, &updated, err
}

// Exact endpoint/session/route repeats stop a chain. DNS aliases are not
// resolved just for cycle detection; the cumulative hop bound covers them.
func redirectionKey(address string, id *uint32, route []byte) ([sha256.Size]byte, error) {
	var zero [sha256.Size]byte
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || len(host) > 253 {
		return zero, errors.New("rdp: redirection address requires a host and numeric port")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return zero, errors.New("rdp: invalid redirection port")
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return zero, errors.New("rdp: invalid redirection port")
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		host = ip.Unmap().String()
	} else {
		for _, c := range host {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
				return zero, errors.New("rdp: invalid redirection hostname")
			}
		}
		host = strings.TrimSuffix(strings.ToLower(host), ".")
		if host == "" {
			return zero, errors.New("rdp: empty redirection hostname")
		}
	}
	b := []byte(net.JoinHostPort(host, strconv.Itoa(n)))
	b = append(b, 0)
	if id != nil {
		b = append(b, 1)
		b = binary.LittleEndian.AppendUint32(b, *id)
	} else {
		b = append(b, 0)
	}
	routeHash := sha256.Sum256(route)
	b = append(b, routeHash[:]...)
	return sha256.Sum256(b), nil
}
