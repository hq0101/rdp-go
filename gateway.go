package rdp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/rdgateway"
)

// GatewayOptions selects an explicit HTTPS gateway route for one RDP target.
// Credentials is called afresh for every connection, including ARC. It must
// honor ctx. The library retains the callback, not its returned password;
// any credential storage captured by the callback belongs to the application.
type GatewayOptions struct {
	Address     string
	Credentials func(context.Context) (rdgateway.Credentials, error) `json:"-"`
	// AdjustResources lets DialChannels and DialSession remove prohibited static
	// channels and managed DVC listeners, and disable prohibited audio, before
	// creating the target connection. The default rejects conflicting settings.
	// It never enables resources. Raw drdynvc under a PnP/all restriction still
	// requires managed DynamicChannels. ApplyPolicy must configure application
	// devices and custom resources; rdpdr remains available for its empty core.
	// Inspect Resources on the returned connection/session before starting any
	// resource consumers. ARC reapplies each fresh policy to the original request.
	// Probe, DialTLS, DialNLA and a subsequent OpenChannels remain strict.
	AdjustResources bool
	// Resources, Alternatives and Port must be empty: the exact RDP address
	// supplies the resource and port. ApplyPolicy remains mandatory; it must
	// configure application devices/custom channels before returning nil.
	// Root session APIs additionally reject conflicting known channel settings
	// and prohibited RDPDR announcements. Low-level WriteMCS remains caller-
	// managed and must not be used to bypass policy. Gateway trust/authentication
	// are independent of Options.TLSConfig/CertificateSHA256 and RDP credentials.
	Options rdgateway.Options `json:"-"`
}

func (*GatewayOptions) String() string   { return "rdp.GatewayOptions{private configuration}" }
func (*GatewayOptions) GoString() string { return "rdp.GatewayOptions{private configuration}" }

type gatewayPreflight func(rdgateway.Info) error

var ErrGatewayRoute = errors.New("rdp: gateway route requires an explicit supported configuration")

func cloneGateway(g *GatewayOptions) *GatewayOptions {
	if g == nil {
		return nil
	}
	c := *g
	if g.Options.Kerberos != nil {
		c.Options.Kerberos = g.Options.Kerberos.Clone()
	}
	c.Options.Resources = append([]string(nil), g.Options.Resources...)
	c.Options.Alternatives = append([]string(nil), g.Options.Alternatives...)
	if g.Options.TLSConfig != nil {
		c.Options.TLSConfig = g.Options.TLSConfig.Clone()
		if g.Options.TLSConfig.RootCAs != nil {
			c.Options.TLSConfig.RootCAs = g.Options.TLSConfig.RootCAs.Clone()
		}
		if g.Options.TLSConfig.ClientCAs != nil {
			c.Options.TLSConfig.ClientCAs = g.Options.TLSConfig.ClientCAs.Clone()
		}
	}
	return &c
}

func dialTarget(ctx context.Context, address string, o Options) (net.Conn, error) {
	if o.Gateway == nil {
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	g := cloneGateway(o.Gateway)
	if g.Credentials == nil || g.Address == "" || g.Options.ApplyPolicy == nil || len(g.Options.Resources) != 0 || len(g.Options.Alternatives) != 0 || g.Options.Port != 0 {
		return nil, ErrGatewayRoute
	}
	if o.DynamicChannels != nil && o.DynamicChannels.ReliableUDP {
		return nil, ErrGatewayRoute
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return nil, ErrGatewayRoute
	}
	g.Options.Resources = []string{host}
	g.Options.Port = uint16(n)
	if g.Options.ClientName == "" {
		g.Options.ClientName = "openrdp"
	}
	apply := g.Options.ApplyPolicy
	g.Options.ApplyPolicy = func(ctx context.Context, i rdgateway.Info) error {
		if o.gatewayPreflight != nil {
			if err := o.gatewayPreflight(i); err != nil {
				return err
			}
		} else if err := checkGatewaySettings(i, o, gcc.ClientSettings{}); err != nil {
			return err
		}
		return apply(ctx, i)
	}
	credentials, err := g.Credentials(ctx)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return rdgateway.DialContext(ctx, g.Address, credentials, g.Options)
}

// GatewayInfo distinguishes the outer gateway from the authenticated RDP
// target. TLSState/NLAState always describe the target, never the gateway.
func (t *Transport) GatewayInfo() (rdgateway.Info, bool) {
	if t != nil {
		if c, ok := t.raw.(*rdgateway.Conn); ok {
			return c.Info(), true
		}
	}
	return rdgateway.Info{}, false
}
func (s *Session) GatewayInfo() (rdgateway.Info, bool) { return s.connection.Transport.GatewayInfo() }
func (t *Transport) GatewayAddr() net.Addr {
	if c, ok := t.raw.(*rdgateway.Conn); ok {
		return c.GatewayAddr()
	}
	return nil
}

// ReadGatewayService consumes an opaque service message without mixing it into
// RDP data. Applications using a gateway must consume its bounded service queue.
func (t *Transport) ReadGatewayService(ctx context.Context) ([]byte, error) {
	if c, ok := t.raw.(*rdgateway.Conn); ok {
		return c.ReadService(ctx)
	}
	return nil, ErrGatewayRoute
}
func (s *Session) ReadGatewayService(ctx context.Context) ([]byte, error) {
	return s.connection.Transport.ReadGatewayService(ctx)
}

func checkGatewaySettings(i rdgateway.Info, o Options, s gcc.ClientSettings) error {
	p, err := rdgateway.NewPolicy(i)
	if err != nil {
		return err
	}
	if s.MultitransportFlags != 0 || o.DynamicChannels != nil && o.DynamicChannels.ReliableUDP {
		return ErrGatewayRoute
	}
	if p.AllDisabled() && (o.AudioPlayback || o.AudioCapture) {
		return rdgateway.ErrPolicy
	}
	for _, ch := range s.Channels {
		switch strings.ToLower(ch.Name) {
		case "cliprdr":
			if !p.ClipboardAllowed() {
				return rdgateway.ErrPolicy
			}
		case "rdpsnd":
			if p.AllDisabled() {
				return rdgateway.ErrPolicy
			}
		case "drdynvc":
			if (!p.PnPAllowed() || p.AllDisabled()) && o.DynamicChannels == nil {
				return fmt.Errorf("%w: restricted gateway requires managed DVC", rdgateway.ErrPolicy)
			}
		case "rdpdr": // Device announcements are checked individually by Session.
		case "rail": // RemoteApp control is not device redirection.
		default:
			if p.AllDisabled() {
				return fmt.Errorf("%w: unclassified static channel", rdgateway.ErrPolicy)
			}
		}
	}
	if o.DynamicChannels != nil {
		for name := range o.DynamicChannels.Listeners {
			if !gatewayListenerAllowed(p, name) {
				return fmt.Errorf("%w: unclassified or redirected DVC", rdgateway.ErrPolicy)
			}
		}
	}
	return nil
}

// The gateway has a logical RemoteAddr but a real local TCP address snapshot.
// Client Info needs only that local IP, with no hostname resolution or UDP dial.
func clientIP(c net.Conn) (string, error) {
	if a, ok := c.LocalAddr().(*net.TCPAddr); ok && a.IP != nil {
		return a.IP.String(), nil
	}
	if _, ok := c.(*rdgateway.Conn); ok {
		host, _, err := net.SplitHostPort(c.LocalAddr().String())
		if err == nil {
			if j := strings.LastIndexByte(host, '%'); j >= 0 {
				host = host[:j]
			}
			if ip := net.ParseIP(host); ip != nil {
				return ip.String(), nil
			}
		}
	}
	return "", errors.New("rdp: missing client TCP address")
}
