package rdp

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/hq0101/rdp-go/bulk"
	"github.com/hq0101/rdp-go/credssp"
	"github.com/hq0101/rdp-go/internal/rdstls"
	"io"
	"net"
	"time"

	"github.com/hq0101/rdp-go/tpkt"
	"github.com/hq0101/rdp-go/x224"
)

var ErrUnexpectedProtocol = errors.New("rdp: server selected an unexpected security protocol")

// Options configures DialTLS, DialNLA, DialChannels and DialSession. Its zero value enables certificate verification,
// TLS 1.2 or newer, a ten-second total handshake timeout, and 65535-byte packets.
type Options struct {
	// Gateway selects an explicit independent HTTPS gateway. Nil dials the
	// target directly. The total HandshakeTimeout includes gateway setup.
	Gateway          *GatewayOptions
	gatewayPreflight gatewayPreflight // per-call checks; never retained for ARC

	HandshakeTimeout time.Duration
	// Licensing enables authenticated MS-RDPELE issuance/renewal with an explicit
	// stable client identity and application-owned store. Nil is status-only.
	Licensing *LicensingOptions
	// SPNEGO wraps NTLMv2 in SPNEGO and requires both mechanism-list signatures.
	// False preserves direct NTLMv2. This does not enable Kerberos, credential
	// discovery, or fallback between authentication mechanisms. Reconnect retains it.
	SPNEGO bool
	// Kerberos selects pure-Go SPNEGO/Kerberos instead of NTLM. It requires an
	// explicit realm/KDC, performs fresh ticket acquisition on each connection,
	// and never falls back to NTLM. SPNEGO is implied. Reconnect copies this
	// configuration; no password or Kerberos ticket is retained by Session.
	Kerberos *KerberosOptions
	// DynamicChannels opts into Session-owned DVC routing and EventDynamic.
	// Nil retains raw drdynvc events and the existing caller-managed API.
	DynamicChannels *DynamicChannelOptions
	// RemoteApp selects base RemoteApp negotiation in DialSession. It requires
	// DrawingOrders, an explicit rail channel and application-owned consumers;
	// it does not launch programs or create windows. Nil keeps desktop mode.
	RemoteApp *RemoteAppOptions
	// StaticChannelLimits overrides the default 1 MiB message limit by requested
	// channel name. Values must be 1..vchan.HardLimit; the map is copied during
	// DialSession. Configure the matching vchan.Decoder.Limit at the consumer.
	// No channel is enlarged unless explicitly configured, e.g. cliprdr images.
	StaticChannelLimits map[string]int
	// AutoReconnect offers cookie-based reconnection and retains its opaque
	// credential in memory. After a network failure call Session.Reconnect with
	// fresh NLA credentials (RDSTLS instead uses its server cookie). No password
	// or retry loop is retained; this option
	// alone starts no background reader. Close discards reconnect state.
	AutoReconnect bool
	// AudioPlayback permits server audio redirection. Requires an explicit rdpsnd
	// static channel and a caller that handles its messages using rdpsnd.Client,
	// consumes returned PCM frames, then sends playback confirmations. This does
	// not open a speaker or install an audio reader. The default disables audio.
	// Windows also requires an rdpdr channel; rdpdr.CoreClient can handle its core
	// handshake with an empty device list when device redirection is not wanted.
	AudioPlayback bool
	// AudioCapture advertises client audio input support. Requires an explicit
	// AUDIO_INPUT listener in DynamicChannels, or caller-managed drdynvc. The
	// caller handles audin.Client requests and supplies PCM after source approval.
	// This flag does not acquire a microphone or start recording. Default false.
	AudioCapture bool
	// NetworkAutoDetect responds to server RTT/bandwidth probes on the main
	// connection; GraphicsPipeline implies it. Heartbeat accepts server liveness
	// hints without automatically disconnecting. Both require extended GCC data.
	NetworkAutoDetect, Heartbeat bool
	// TLSConfig is cloned before use. Nil uses system trust roots. ServerName
	// defaults to the address host. Callers must not mutate it during DialTLS.
	TLSConfig *tls.Config
	// CertificateSHA256 explicitly trusts one leaf certificate by its 64-character
	// hexadecimal SHA-256 fingerprint, replacing CA and hostname verification.
	// Obtain the fingerprint through a trusted channel. Certificate validity dates
	// and caller verification callbacks are still checked. Empty uses normal PKI.
	CertificateSHA256 string
	// Cookie is an optional plaintext mstshash routing identifier.
	Cookie string
	// RoutingToken is an explicit opaque X.224 routing token, including CRLF.
	// It is mutually exclusive with Cookie and sent before TLS. No destination
	// is selected automatically. Reconnect retains an independent copy.
	RoutingToken []byte `json:"-"`
	// ExpectedTSVURL is the exact TSV URL previously placed by the caller in
	// RoutingToken. When non-nil, DialSession rejects a returned TSV URL that
	// differs, including an informational redirection. Nil disables this check;
	// opaque routing tokens are never inspected to infer it. Requires a routing
	// token and at most 65535 bytes. Reconnect retains an independent copy.
	ExpectedTSVURL []byte `json:"-"`
	// MaxPacketSize includes packet headers. Zero means 65535; minimum is 19.
	MaxPacketSize int
	// BulkCompression requests compressed server output on graphics and static
	// channels. ReadEvent returns decompressed payloads. Outgoing channel chunks
	// use MPPC 8K if the server permits it, else remain uncompressed. The zero
	// value retains the uncompressed profile.
	BulkCompression bool
	// BulkCompressionLevel limits accepted packages when BulkCompression is true.
	// Zero (bulk.Default) offers all implemented packages up to RDP 6.1.
	BulkCompressionLevel bulk.Level
	// DrawingOrders opts into basic GDI orders and volatile Revision 1 bitmap
	// caches in 24/32-bit sessions. Process updates sequentially using
	// graphics.Framebuffer.Apply, and call Framebuffer.Resize on EventActivated.
	// The default retains bitmap-only output for existing consumers.
	DrawingOrders bool
	// ExtendedOrders adds MultiDst/Pat/ScrBlt, MultiOpaqueRect, LineTo and Polyline.
	// Requires DrawingOrders. Set Framebuffer.AllowExtendedOrders from SessionInfo.
	ExtendedOrders bool
	// ShapeOrders enables solid/pattern PolygonSC/CB and EllipseSC/CB at 24/32 bpp.
	// Requires DrawingOrders; synchronize Framebuffer.AllowShapeOrders after activation.
	ShapeOrders bool
	// NewPointer requests arbitrary-depth pointer updates, including 32-bit alpha.
	// LargePointer additionally requests negotiated 96/384-pixel shapes. Consumers
	// must handle EventLargePointer and configure graphics.PointerDecoder.
	NewPointer, LargePointer bool
	// GlyphCache enables bounded glyph/fragment caches and all three text orders.
	// GlyphCacheV2 requests the compact Revision 2 cache encoding (else Revision 1).
	// Requires DrawingOrders; synchronize Framebuffer glyph flags after activation.
	GlyphCache, GlyphCacheV2 bool
	// BitmapCacheV2 requests compact Revision 2 caches when DrawingOrders is on
	// and the server supports them. Otherwise Revision 1 remains in use.
	BitmapCacheV2 bool
	// BitmapCacheV3 adds codec-aware Revision 3 caches when BitmapCacheV2 and
	// server support are present. Set Framebuffer.AllowBitmapCacheV3 from the
	// effective SessionInfo after activation and each reactivation.
	BitmapCacheV3 bool
	// BrushCache enables the 8x8 mono/color brush caches with DrawingOrders.
	// Set Framebuffer.AllowBrushCache from the effective session info.
	BrushCache bool
	// OffscreenCache enables 100 writable cached surfaces within 7680 KiB of
	// wire pixel storage. Set Framebuffer.AllowOffscreen and OffscreenDepth from
	// SessionInfo.OffscreenCache and BitsPerPixel after every activation.
	OffscreenCache bool
	// SurfaceCommands enables EventSurfaceCommands at 32 bpp. Consumers must
	// render those events with Framebuffer.ApplySurfaceCommands and acknowledge
	// completed frames via AcknowledgeFrame if SessionInfo.FrameAcknowledge is set.
	SurfaceCommands bool
	// GraphicsPipeline offers RDPGFX over drdynvc at 32 bpp. The caller must
	// register rdpgfx.ChannelName, process its dynamic-channel events with
	// rdpgfx.Client and send the returned replies. It requires a drdynvc channel.
	// Select the Version 8 ThinClient or Progressive profile on rdpgfx.Client.
	GraphicsPipeline bool
	// NSCodec requests NSCodec-compressed Surface and Revision 3 bitmaps. It requires
	// SurfaceCommands and server support. Set Framebuffer.AllowNSCodec to the
	// effective SessionInfo.NSCodec after activation and each reactivation.
	NSCodec bool
}

// ProbeOptions configures a negotiation-only diagnostic connection.
type ProbeOptions struct {
	// Gateway authenticates to the gateway only; Probe still sends no RDP
	// target credentials and does not authenticate the target's reply.
	Gateway *GatewayOptions

	Timeout time.Duration
	Cookie  string
	// RoutingToken has the same cleartext/destination constraints as Options.
	RoutingToken []byte `json:"-"`
	// RequestedProtocols defaults to TLS | HYBRID. Advertising HYBRID here
	// only tests negotiation; Probe does not implement or attempt CredSSP.
	RequestedProtocols x224.Protocol
}

// Probe exchanges only X.224 negotiation PDUs, then closes the connection.
// Its result is unauthenticated and MUST NOT be treated as proof of identity,
// successful login, or verified support for the advertised features.
// A legacy server's Standard Security selection is reported without using it.
func Probe(ctx context.Context, address string, opts ProbeOptions) (x224.Confirm, error) {
	var zero x224.Confirm
	p := opts.RequestedProtocols
	if p == 0 {
		p = x224.ProtocolTLS | x224.ProtocolHybrid
	}
	request, err := (x224.Request{Protocols: p, Cookie: opts.Cookie, RoutingToken: opts.RoutingToken}).MarshalBinary()
	if err != nil {
		return zero, err
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return zero, fmt.Errorf("rdp address (host:port required): %w", err)
	}
	ctx, cancel, err := handshakeContext(ctx, opts.Timeout)
	if err != nil {
		return zero, err
	}
	defer cancel()
	conn, err := dialTarget(ctx, address, Options{Gateway: opts.Gateway})
	if err != nil {
		return zero, fmt.Errorf("rdp dial: %w", err)
	}
	defer conn.Close()
	confirm, err := negotiate(ctx, conn, request)
	if err != nil {
		return zero, err
	}
	if confirm.SelectedProtocol != x224.ProtocolRDP && p&confirm.SelectedProtocol == 0 {
		return zero, fmt.Errorf("%w: %s", ErrUnexpectedProtocol, confirm.SelectedProtocol)
	}
	return confirm, nil
}

// DialTLS establishes a verified TLS transport, stopping before MCS/GCC.
// It advertises TLS only and rejects Standard Security and unsolicited NLA.
// Hosts requiring NLA reject this entry point; use DialNLA or DialChannels.
// The context applies to dialing and handshaking, not the transport lifetime.
func DialTLS(ctx context.Context, address string, opts Options) (*Transport, error) {
	return dialSecurity(ctx, address, opts, x224.ProtocolTLS, nil)
}

// Credentials contains explicit username/domain/password credentials. Username
// and Domain are separate fields; DOMAIN\\user is not split automatically.
type Credentials = credssp.Credentials

// KerberosOptions configures explicit cross-platform Kerberos authentication.
type KerberosOptions = credssp.KerberosOptions

// DialNLA establishes verified TLS and performs CredSSP 5/6 with NTLMv2, or
// SPNEGO/Kerberos when Options.Kerberos is configured.
// It never falls back to TLS-only or Standard Security. Success means credentials
// were delegated after server binding verification, not that a desktop is ready.
// For HYBRID_EX it also checks the early user authorization result.
func DialNLA(ctx context.Context, address string, c Credentials, opts Options) (*Transport, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return dialSecurity(ctx, address, opts, x224.ProtocolTLS|x224.ProtocolHybrid|x224.ProtocolHybridEx, &c)
}

func dialSecurity(ctx context.Context, address string, opts Options, protocols x224.Protocol, credentials *Credentials) (*Transport, error) {
	return dialSecurityAuth(ctx, address, opts, protocols, credentials, nil)
}

func dialSecurityAuth(ctx context.Context, address string, opts Options, protocols x224.Protocol, credentials *Credentials, redirected *rdstlsAuthentication) (*Transport, error) {
	if redirected != nil && (credentials != nil || protocols != x224.ProtocolRDSTLS || len(redirected.packet) == 0) {
		return nil, ErrRedirectionCredentials
	}
	if credentials == nil && opts.SPNEGO {
		return nil, errors.New("rdp: SPNEGO requires NLA credentials")
	}
	if credentials == nil && opts.Kerberos != nil {
		return nil, errors.New("rdp: Kerberos requires NLA credentials")
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("rdp address (host:port required): %w", err)
	}
	maxSize := opts.MaxPacketSize
	if maxSize == 0 {
		maxSize = tpkt.MaxPacketSize
	}
	if maxSize < 19 || maxSize > tpkt.MaxPacketSize {
		return nil, errors.New("rdp: MaxPacketSize must be 19..65535")
	}
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.TLSConfig != nil {
		config = opts.TLSConfig.Clone()
	}
	if config.MinVersion == 0 {
		config.MinVersion = tls.VersionTLS12
	}
	if config.MinVersion < tls.VersionTLS12 {
		return nil, errors.New("rdp: TLS versions below 1.2 are not supported")
	}
	if config.MaxVersion != 0 && config.MaxVersion < config.MinVersion {
		return nil, errors.New("rdp: invalid TLS version range")
	}
	if config.ServerName == "" {
		config.ServerName = host
	}
	if opts.Kerberos != nil {
		opts.Kerberos = opts.Kerberos.Clone()
		if err := opts.Kerberos.Validate("TERMSRV/"+config.ServerName, *credentials); err != nil {
			return nil, err
		}
	}
	if config.InsecureSkipVerify {
		return nil, errors.New("rdp: InsecureSkipVerify is not supported; configure RootCAs and ServerName or CertificateSHA256")
	}
	if err := configureCertificatePin(config, opts.CertificateSHA256); err != nil {
		return nil, err
	}
	if redirected != nil {
		bindRDSTLSCertificate(config, redirected.certificate)
	}
	if credentials != nil || redirected != nil {
		config.ClientSessionCache = nil
		config.SessionTicketsDisabled = true
	}
	request, err := (x224.Request{Protocols: protocols, Cookie: opts.Cookie, RoutingToken: opts.RoutingToken}).MarshalBinary()
	if err != nil {
		return nil, err
	}
	ctx, cancel, err := handshakeContext(ctx, opts.HandshakeTimeout)
	if err != nil {
		return nil, err
	}
	defer cancel()
	raw, err := dialTarget(ctx, address, opts)
	if err != nil {
		return nil, fmt.Errorf("rdp dial: %w", err)
	}
	success := false
	defer func() {
		if !success {
			raw.Close()
		}
	}()
	confirm, err := negotiate(ctx, raw, request)
	if err != nil {
		return nil, err
	}
	if redirected != nil && confirm.SelectedProtocol != x224.ProtocolRDSTLS || redirected == nil && ((credentials == nil && confirm.SelectedProtocol != x224.ProtocolTLS) || (credentials != nil && confirm.SelectedProtocol != x224.ProtocolHybrid && confirm.SelectedProtocol != x224.ProtocolHybridEx)) {
		return nil, fmt.Errorf("%w: received %s", ErrUnexpectedProtocol, confirm.SelectedProtocol)
	}
	conn := tls.Client(raw, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("rdp TLS handshake: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var nla NLAState
	if credentials != nil {
		err = runIO(ctx, conn.SetDeadline, func() error {
			state := conn.ConnectionState()
			if (len(state.VerifiedChains) == 0 && opts.CertificateSHA256 == "") || len(state.PeerCertificates) == 0 {
				return errors.New("rdp: NLA requires verified TLS")
			}
			authenticate := credssp.Authenticate
			if opts.SPNEGO {
				authenticate = credssp.AuthenticateSPNEGO
			}
			var authErr error
			if opts.Kerberos != nil {
				authErr = credssp.AuthenticateKerberos(ctx, conn, state.PeerCertificates[0], "TERMSRV/"+config.ServerName, *credentials, *opts.Kerberos)
			} else {
				authErr = authenticate(conn, state.PeerCertificates[0], "TERMSRV/"+config.ServerName, *credentials)
			}
			if authErr != nil {
				return authErr
			}
			nla.Kerberos = opts.Kerberos != nil
			nla.SPNEGO = opts.SPNEGO || nla.Kerberos
			nla.CredentialsDelegated = true
			if confirm.SelectedProtocol == x224.ProtocolHybridEx {
				var b [4]byte
				if _, err := io.ReadFull(conn, b[:]); err != nil {
					return err
				}
				code := binary.LittleEndian.Uint32(b[:])
				if code != 0 {
					return &AuthorizationError{Code: code}
				}
				nla.EarlyAuthorizationConfirmed = true
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("rdp NLA: %w", err)
		}
	}
	var rdstate RDSTLSState
	if redirected != nil {
		err = runIO(ctx, conn.SetDeadline, func() error { return rdstls.Authenticate(conn, redirected.packet) })
		if err != nil {
			return nil, fmt.Errorf("rdp RDSTLS: %w", err)
		}
		rdstate = RDSTLSState{Authenticated: true, AutoReconnect: redirected.reconnect, Version: 1}
	}
	success = true
	t := newTransport(raw, conn, confirm, maxSize)
	t.gatewayDynamic = cloneDynamicOptions(opts.DynamicChannels)
	t.requested = protocols
	t.nla = nla
	t.rdstls = rdstate
	t.certificatePinned = opts.CertificateSHA256 != ""
	return t, nil
}

type AuthorizationError struct{ Code uint32 }

func (e *AuthorizationError) Error() string {
	return fmt.Sprintf("rdp: early user authorization rejected (0x%08x)", e.Code)
}

func handshakeContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc, error) {
	if timeout < 0 {
		return nil, nil, errors.New("rdp: handshake timeout must not be negative")
	}
	if timeout == 0 {
		timeout = 10 * time.Second
	}
	c, cancel := context.WithTimeout(ctx, timeout)
	return c, cancel, nil
}

func negotiate(ctx context.Context, conn net.Conn, request []byte) (x224.Confirm, error) {
	var result x224.Confirm
	err := runIO(ctx, conn.SetDeadline, func() error {
		if err := tpkt.Write(conn, request); err != nil {
			return err
		}
		b, err := tpkt.Read(conn, 260)
		if err != nil {
			return err
		}
		result, err = x224.ParseConfirm(b)
		return err
	})
	if err != nil {
		return x224.Confirm{}, fmt.Errorf("rdp negotiation: %w", err)
	}
	return result, nil
}

// runIO binds cancellation to just the relevant I/O direction. Waiting for an
// already-running callback before clearing deadlines prevents stale deadlines
// from leaking into a subsequent operation. The caller serializes that direction.
func runIO(ctx context.Context, setDeadline func(time.Time) error, fn func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err := setDeadline(deadline); err != nil {
		return err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		setDeadline(time.Now())
		close(done)
	})
	err := fn()
	if !stop() {
		<-done
	}
	clearErr := setDeadline(time.Time{})
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// A socket deadline can fire just before context's timer callback runs.
	if err != nil && !deadline.IsZero() && !time.Now().Before(deadline) {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return context.DeadlineExceeded
		}
	}
	if err != nil {
		return err
	}
	return clearErr
}
