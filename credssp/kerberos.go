package credssp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hq0101/rdp-go/internal/der"
	"github.com/hq0101/rdp-go/internal/kerberos"
	"github.com/hq0101/rdp-go/internal/krbcrypto"
	"github.com/hq0101/rdp-go/kdcproxy"
)

// KerberosOptions selects explicit password-based Kerberos, without OS APIs,
// credential discovery, referrals, ticket caching, or NTLM fallback. Realm and
// either KDC (host:port) or Proxy are required. Username is a single account name; Domain is
// passed unchanged in the delegated Windows credentials (e.g. the AD domain).
// The caller must not mutate options during authentication.
type KerberosOptions struct {
	Realm, KDC string
	Proxy      *kdcproxy.Options // explicit HTTPS alternative; excludes KDC and Network
	// ServicePrincipal defaults to the target passed to AuthenticateKerberos,
	// normally TERMSRV/<TLS ServerName>. An override must also use TERMSRV/host.
	ServicePrincipal  string
	Network           string        // tcp (default), or udp with one TCP retry on response-too-big
	Timeout, Lifetime time.Duration // defaults: 15 seconds per KDC operation, 8 hours
	// Enctypes is an ordered AES-only list, defaulting to 20, 19, 18, 17.
	Enctypes  []int32
	WorkLimit uint32 // password-derivation iteration cap; zero uses the default
}

// Clone returns an independent configuration; it never contains credentials,
// tickets or session keys.
func (o KerberosOptions) Clone() *KerberosOptions {
	o.Enctypes = append([]int32(nil), o.Enctypes...)
	if o.Proxy != nil {
		o.Proxy = o.Proxy.Clone()
	}
	return &o
}

// Validate checks local configuration and identities without network access.
func (o KerberosOptions) Validate(target string, c Credentials) error {
	_, _, err := o.prepare(target, c)
	return err
}

func (o KerberosOptions) prepare(target string, c Credentials) (*kerberos.Client, kerberos.Principal, error) {
	if err := c.Validate(); err != nil {
		return nil, kerberos.Principal{}, err
	}
	if strings.ContainsAny(c.Username, "@/\\") || len(c.Username) > 1024 || strings.IndexFunc(c.Username, unicode.IsControl) >= 0 {
		return nil, kerberos.Principal{}, errors.New("credssp: Kerberos requires a separate account name and realm")
	}
	if o.ServicePrincipal != "" {
		target = o.ServicePrincipal
	}
	if len(target) > 1024 || !utf8.ValidString(target) || strings.IndexFunc(target, unicode.IsControl) >= 0 {
		return nil, kerberos.Principal{}, errors.New("credssp: invalid Kerberos service name")
	}
	parts := strings.Split(target, "/")
	if len(parts) != 2 || parts[0] != "TERMSRV" || parts[1] == "" || strings.ContainsAny(parts[1], "@\\ ") {
		return nil, kerberos.Principal{}, errors.New("credssp: Kerberos service must be TERMSRV/host")
	}
	if len(o.Enctypes) > 4 {
		return nil, kerberos.Principal{}, errors.New("credssp: too many Kerberos enctypes")
	}
	types := make([]krbcrypto.Enctype, len(o.Enctypes))
	for i, e := range o.Enctypes {
		types[i] = krbcrypto.Enctype(e)
	}
	k, err := kerberos.New(kerberos.Config{Realm: o.Realm, KDC: o.KDC, Proxy: o.Proxy, Network: o.Network, Timeout: o.Timeout, Lifetime: o.Lifetime, Enctypes: types, WorkLimit: o.WorkLimit})
	return k, kerberos.Principal{NameType: 2, Components: parts}, err
}

// AuthenticateKerberos performs CredSSP 5/6 using only SPNEGO/Kerberos and AES.
// The caller MUST first verify TLS, apply I/O deadlines/cancellation to rw and
// close it on failure. ctx bounds KDC operations and pending authentication;
// it cannot interrupt an arbitrary io.ReadWriter. All tickets/keys are cleared
// before return. Success means binding verified and password delegated, not
// that Windows authorized a desktop. HYBRID_EX authorization is caller-owned.
func AuthenticateKerberos(ctx context.Context, rw io.ReadWriter, cert *x509.Certificate, target string, c Credentials, o KerberosOptions) error {
	k, service, err := o.prepare(target, c)
	if err != nil {
		return err
	}
	if cert == nil {
		return errors.New("credssp: certificate is required")
	}
	publicKey, err := subjectKey(cert)
	if err != nil {
		return err
	}
	endpoint, err := tlsServerEndPoint(cert)
	if err != nil {
		return err
	}
	tgt, err := k.AcquireTGT(ctx, kerberos.Credentials{Client: kerberos.Principal{NameType: 1, Components: []string{c.Username}}, Password: c.Password})
	if err != nil {
		return fmt.Errorf("credssp: Kerberos TGT: %w", err)
	}
	defer tgt.Clear()
	ticket, err := k.AcquireService(ctx, tgt, service)
	if err != nil {
		return fmt.Errorf("credssp: Kerberos service ticket: %w", err)
	}
	defer ticket.Clear()
	// SEC_CHANNEL_BINDINGS uses zero address types with absent addresses.
	s, initial, err := k.BeginService(ctx, ticket, &kerberos.ChannelBindings{ApplicationData: endpoint})
	if err != nil {
		return err
	}
	defer s.Close()
	return authenticateKerberosService(rw, publicKey, c, s, initial)
}

// Kept separate from ticket acquisition so the negotiation state machine can
// be exercised against malformed peers without making authentication retries.
type kerberosSecurity interface {
	Finish([]byte) error
	GetMIC([]byte) ([]byte, error)
	VerifyMIC([]byte, []byte) error
	Seal([]byte) ([]byte, error)
	Unseal([]byte) ([]byte, error)
}

var kerberosOID = []byte{6, 9, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 1, 2, 2}

func authenticateKerberosService(rw io.ReadWriter, publicKey []byte, c Credentials, s kerberosSecurity, initial []byte) error {
	list := der.Wrap(0x30, kerberosOID)
	token := spnegoInitMechanisms(initial, list)
	if len(token) > maxSPNEGOToken {
		return ErrProtocol
	}
	if err := der.Write(rw, (request{version: 6, token: token}).marshal()); err != nil {
		return err
	}
	reply, err := readRequest(rw)
	if err != nil {
		return err
	}
	version := min(reply.version, 6)
	if version < 5 || reply.auth != nil || reply.binding != nil || reply.nonce != nil {
		return ErrProtocol
	}
	r, err := parseSPNEGOResponse(reply.token)
	if err != nil || r.state < 0 || r.state == 2 || !bytes.Equal(r.mechanism, kerberosOID) || len(r.token) == 0 {
		return ErrProtocol
	}
	if err = s.Finish(r.token); err != nil {
		return err
	}
	var lastToken []byte
	if r.mic != nil {
		// RFC 4178 5(b): Kerberos mutual authentication ends at the acceptor.
		// An optional/required list MIC arrives with AP-REP, then we return ours.
		if r.state != 1 && r.state != 3 {
			return ErrProtocol
		}
		if err = s.VerifyMIC(list, r.mic); err != nil {
			return err
		}
		mic, err := s.GetMIC(list)
		if err != nil {
			return err
		}
		lastToken = der.Wrap(0xa1, der.Wrap(0x30, der.Wrap(0xa0, der.Integer(0x0a, 0)), der.Wrap(0xa3, der.Wrap(4, mic))))
	} else if r.state != 0 {
		return ErrProtocol // request-mic without the acceptor's MIC is invalid
	}
	var nonce [32]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	bound, err := s.Seal(bindingHash(true, nonce[:], publicKey))
	if err != nil {
		return err
	}
	if err = der.Write(rw, (request{version: version, token: lastToken, binding: bound, nonce: nonce[:]}).marshal()); err != nil {
		return err
	}
	reply, err = readRequest(rw)
	if err != nil {
		return err
	}
	if reply.token != nil {
		// A peer may acknowledge our final MIC with the binding or in one
		// preceding TSRequest. The AP-REP and server MIC cannot be repeated.
		if lastToken == nil || min(reply.version, 6) != version || reply.auth != nil || reply.nonce != nil {
			return ErrProtocol
		}
		completed, e := parseSPNEGOResponse(reply.token)
		if e != nil || completed.state != 0 || completed.token != nil || completed.mic != nil {
			return ErrProtocol
		}
		if len(reply.binding) == 0 {
			reply, err = readRequest(rw)
			if err != nil {
				return err
			}
		} else {
			reply.token = nil
		}
	}
	if min(reply.version, 6) != version || reply.auth != nil || reply.nonce != nil || reply.token != nil || len(reply.binding) == 0 {
		return ErrProtocol
	}
	actual, err := s.Unseal(reply.binding)
	if err != nil {
		return err
	}
	defer clear(actual)
	if !hmac.Equal(actual, bindingHash(false, nonce[:], publicKey)) {
		return ErrBinding
	}
	plain := passwordCredentials(c)
	defer clear(plain)
	sealed, err := s.Seal(plain)
	if err != nil {
		return err
	}
	return der.Write(rw, (request{version: version, auth: sealed}).marshal())
}
