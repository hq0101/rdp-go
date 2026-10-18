package rdghttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hq0101/rdp-go/internal/der"
	"github.com/hq0101/rdp-go/internal/kerberos"
	"github.com/hq0101/rdp-go/internal/krbcrypto"
	"github.com/hq0101/rdp-go/internal/ntlm"
	"github.com/hq0101/rdp-go/internal/spnego"
	"github.com/hq0101/rdp-go/kdcproxy"
)

// HTTPKerberosOptions is the independent gateway KDC/service configuration.
// Password-based, same-realm AES only; no discovery, SSO, cache or NTLM fallback.
type HTTPKerberosOptions struct {
	Realm, KDC        string
	Proxy             *kdcproxy.Options // explicit alternative to direct KDC/Network
	ServicePrincipal  string            // defaults to HTTP/<verified TLS ServerName>
	Network           string
	Timeout, Lifetime time.Duration
	Enctypes          []int32
	WorkLimit         uint32
}

func (o HTTPKerberosOptions) Validate(target string, c ntlm.Credentials) error {
	_, _, err := o.prepare(target, c)
	return err
}
func (o HTTPKerberosOptions) prepare(target string, c ntlm.Credentials) (*kerberos.Client, kerberos.Principal, error) {
	if err := c.Validate(); err != nil {
		return nil, kerberos.Principal{}, err
	}
	if strings.ContainsAny(c.Username, "@/\\") || len(c.Username) > 1024 || strings.IndexFunc(c.Username, unicode.IsControl) >= 0 {
		return nil, kerberos.Principal{}, errors.New("rdghttp: Kerberos requires separate gateway account and realm")
	}
	if o.ServicePrincipal != "" {
		target = o.ServicePrincipal
	}
	parts := strings.Split(target, "/")
	if len(parts) != 2 || parts[0] != "HTTP" || !httpHost(parts[1]) || len(target) > 1024 || !utf8.ValidString(target) || strings.IndexFunc(target, unicode.IsControl) >= 0 {
		return nil, kerberos.Principal{}, errors.New("rdghttp: gateway Kerberos service must be HTTP/host")
	}
	if len(o.Enctypes) > 4 {
		return nil, kerberos.Principal{}, ErrInvalid
	}
	types := make([]krbcrypto.Enctype, len(o.Enctypes))
	for i, e := range o.Enctypes {
		types[i] = krbcrypto.Enctype(e)
	}
	k, err := kerberos.New(kerberos.Config{Realm: o.Realm, KDC: o.KDC, Proxy: o.Proxy, Network: o.Network, Timeout: o.Timeout, Lifetime: o.Lifetime, Enctypes: types, WorkLimit: o.WorkLimit})
	return k, kerberos.Principal{NameType: 2, Components: parts}, err
}

// A pair-scoped ticket avoids duplicate password derivation while each HTTPS
// connection gets a fresh authenticator, subkey and sequence. Nothing survives
// DialHTTPPair. Ticket acquisition starts only after TLS trust and the initial
// empty Negotiate challenge, never on an unverified or wrong-scheme endpoint.
type httpKerberosFactory struct {
	client      *kerberos.Client
	service     kerberos.Principal
	credentials ntlm.Credentials
	ticket      *kerberos.Ticket
}

func (f *httpKerberosFactory) close() {
	if f == nil {
		return
	}
	f.ticket.Clear()
	f.ticket = nil
	f.credentials = ntlm.Credentials{}
}
func (f *httpKerberosFactory) begin(ctx context.Context, cert *x509.Certificate) (*kerberos.ServiceContext, []byte, error) {
	endpoint, err := httpTLSEndpoint(cert)
	if err != nil {
		return nil, nil, err
	}
	defer clear(endpoint)
	if f.ticket == nil {
		tgt, err := f.client.AcquireTGT(ctx, kerberos.Credentials{Client: kerberos.Principal{NameType: 1, Components: []string{f.credentials.Username}}, Password: f.credentials.Password})
		if err != nil {
			return nil, nil, fmt.Errorf("rdghttp: gateway Kerberos TGT: %w", err)
		}
		defer tgt.Clear()
		f.ticket, err = f.client.AcquireService(ctx, tgt, f.service)
		if err != nil {
			return nil, nil, fmt.Errorf("rdghttp: gateway Kerberos service: %w", err)
		}
	}
	return f.client.BeginService(ctx, f.ticket, &kerberos.ChannelBindings{ApplicationData: endpoint})
}

var httpKerberosOID = []byte{6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 1, 2, 2}

func httpKerberosList() []byte { return der.Wrap(0x30, httpKerberosOID) }

type httpKerberosContext interface {
	Finish([]byte) error
	GetMIC([]byte) ([]byte, error)
	VerifyMIC([]byte, []byte) error
}

// RFC4178 5(b): with an acceptor-final mechanism (Kerberos), a successful
// two-token exchange can omit MICs. An extra MIC exchange requires BOTH MICs,
// an incomplete/request-mic 401, and our accept-complete response. A 200 must
// never be exposed while a response token still needs sending.
func httpKerberosReply(s httpKerberosContext, status int, token []byte) ([]byte, error) {
	r, err := spnego.ParseResponse(token)
	if err != nil || !bytes.Equal(r.Mechanism, httpKerberosOID) || len(r.Token) == 0 {
		return nil, ErrHTTPAuth
	}
	if status == 200 {
		if r.State != 0 || r.MIC != nil {
			return nil, ErrHTTPAuth
		}
		return nil, s.Finish(r.Token)
	}
	if status != 401 || (r.State != 1 && r.State != 3) || len(r.MIC) == 0 {
		return nil, ErrHTTPAuth
	}
	if err = s.Finish(r.Token); err != nil {
		return nil, err
	}
	list := httpKerberosList()
	if err = s.VerifyMIC(list, r.MIC); err != nil {
		return nil, err
	}
	mic, err := s.GetMIC(list)
	if err != nil {
		return nil, err
	}
	defer clear(mic)
	return der.Wrap(0xa1, der.Wrap(0x30, der.Wrap(0xa0, der.Integer(0x0a, 0)), der.Wrap(0xa3, der.Wrap(4, mic)))), nil
}
func httpKerberosComplete(token []byte) error {
	// Both GSS directions were verified before our final MIC. HTTP may omit
	// its redundant completion token; a present token must only acknowledge.
	if len(token) == 0 {
		return nil
	}
	r, err := spnego.ParseResponse(token)
	if err != nil || r.State != 0 || r.Token != nil || r.MIC != nil {
		return ErrHTTPAuth
	}
	return nil // repeated supportedMech is ignored after selection (MS-SPNG).
}

func authenticateKerberosHTTP(ctx context.Context, w io.Writer, r *bufio.Reader, method, host, id string, f *httpKerberosFactory, cert *x509.Certificate) (*http.Response, error) {
	s, ap, err := f.begin(ctx, cert)
	if err != nil {
		return nil, err
	}
	defer s.Close()
	defer clear(ap)
	initial := spnego.Initial(ap, httpKerberosList())
	defer clear(initial)
	send := func(token []byte) error {
		if len(token) == 0 || len(token) > maxAuthToken {
			return ErrLimit
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		return writeHTTPRequest(w, method, host, id, "Negotiate "+base64.StdEncoding.EncodeToString(token))
	}
	if err = send(initial); err != nil {
		return nil, err
	}
	resp, err := readHTTPResponse(r, method)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 && resp.StatusCode != 401 {
		return nil, ErrHTTPAuth
	}
	token, found, err := authChallenge(resp.Header.Values("WWW-Authenticate"), "Negotiate")
	if err != nil || !found || len(token) == 0 {
		return nil, ErrHTTPAuth
	}
	next, err := httpKerberosReply(s, resp.StatusCode, token)
	clear(token)
	if err != nil {
		return nil, err
	}
	defer clear(next)
	if resp.StatusCode == 200 {
		return resp, nil
	}
	if err = drainAuthResponse(resp); err != nil {
		return nil, err
	}
	if err = send(next); err != nil {
		return nil, err
	}
	resp, err = readHTTPResponse(r, method)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, ErrHTTPAuth
	}
	token, _, err = authChallenge(resp.Header.Values("WWW-Authenticate"), "Negotiate")
	if err != nil {
		return nil, ErrHTTPAuth
	}
	err = httpKerberosComplete(token)
	clear(token)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
