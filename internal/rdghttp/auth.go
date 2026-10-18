package rdghttp

import (
	"bytes"
	"github.com/hq0101/rdp-go/internal/ntlm"
	"github.com/hq0101/rdp-go/internal/spnego"
)

// HTTPAuthentication selects a complete wire profile, not a preference list.
// No profile falls back or discovers OS credentials. Gateway
// and target RDP credentials remain independent. All profiles require TLS trust.
type HTTPAuthentication uint8

const (
	HTTPNTLM          HTTPAuthentication = iota // MS-NTHT, raw NTLM under the NTLM scheme
	HTTPNegotiateNTLM                           // RFC4178/4559, NTLM only, both mechanism-list MICs required
	// Explicit interoperability mode for peers using the Negotiate header with
	// raw NTLMSSP tokens. Observed with an independent Windows client; this is
	// not a SPNEGO envelope or an implicit response to a negotiation failure.
	HTTPNegotiateRawNTLM
	HTTPNegotiateKerberos // explicit SPNEGO/Kerberos with mutual authentication
)

func (a HTTPAuthentication) valid() bool { return a <= HTTPNegotiateKerberos }
func (a HTTPAuthentication) scheme() string {
	if a == HTTPNTLM {
		return "NTLM"
	}
	return "Negotiate"
}

// Serial, one-shot authentication state for one physical HTTPS connection.
// Call Close even on failure. No credentials or server challenge are retained.
type httpAuth struct {
	profile  HTTPAuthentication
	state    uint8
	neg      []byte
	security *ntlm.HTTPMICSecurity
}

func (a *httpAuth) Close() {
	clear(a.neg)
	a.neg = nil
	a.security.Close()
	a.security = nil
	a.state = 3
}
func (a *httpAuth) start() ([]byte, error) {
	if !a.profile.valid() || a.profile == HTTPNegotiateKerberos || a.state != 0 {
		return nil, ErrHTTPAuth
	}
	a.state = 1
	if a.profile == HTTPNegotiateNTLM {
		a.neg = ntlm.NegotiateHTTPMIC()
		return spnego.Initial(a.neg, spnego.NTLMList()), nil
	}
	a.neg = ntlm.NegotiateHTTP()
	return bytes.Clone(a.neg), nil
}
func (a *httpAuth) challenge(token []byte, c ntlm.Credentials, target string, cb []byte) (out []byte, err error) {
	if a.state != 1 {
		return nil, ErrHTTPAuth
	}
	a.state = 2 // A failure cannot be retried on the same transcript.
	defer func() {
		if err != nil {
			a.Close()
			out = nil
		}
	}()
	if a.profile != HTTPNegotiateNTLM {
		ch, e := ntlm.ParseHTTPChallenge(token)
		if e != nil {
			return nil, ErrHTTPAuth
		}
		return ntlm.AuthenticateHTTP(c, a.neg, ch, target, cb)
	}
	r, e := spnego.ParseResponse(token)
	if e != nil || (r.State != 1 && r.State != 3) || !bytes.Equal(r.Mechanism, []byte(spnego.NTLMOID)) || len(r.Token) == 0 || r.MIC != nil {
		return nil, ErrHTTPAuth
	}
	ch, e := ntlm.ParseHTTPMICChallenge(r.Token)
	if e != nil {
		return nil, ErrHTTPAuth
	}
	auth, security, e := ntlm.AuthenticateHTTPMIC(c, a.neg, ch, target, cb)
	if e != nil {
		return nil, e
	}
	a.security = security
	defer clear(auth)
	mic, e := security.MechListMIC(spnego.NTLMList())
	if e != nil {
		return nil, ErrHTTPAuth
	}
	defer clear(mic)
	return spnego.Authenticate(auth, mic), nil
}
func (a *httpAuth) finish(token []byte) error {
	if a.state != 2 {
		return ErrHTTPAuth
	}
	defer a.Close()
	if a.profile != HTTPNegotiateNTLM {
		if len(token) != 0 {
			return ErrHTTPAuth
		}
		return nil
	}
	r, e := spnego.ParseResponse(token)
	if e != nil || r.State != 0 || r.Token != nil || len(r.MIC) != 16 {
		return ErrHTTPAuth
	}
	// MS-SPNG3.3.5: a repeated supportedMech after selection is ignored. DER
	// validation still applies; it cannot change the selected key or MIC list.
	if a.security.VerifyMechListMIC(spnego.NTLMList(), r.MIC) != nil {
		return ErrHTTPAuth
	}
	return nil
}
