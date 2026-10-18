package rdp

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"

	"github.com/hq0101/rdp-go/internal/rdstls"
	"github.com/hq0101/rdp-go/pdu"
)

var ErrRDSTLSIdentity = errors.New("rdp: RDSTLS target certificate does not match the redirection")

// RDSTLSAuthenticationError carries a server result code. A successful RDSTLS
// exchange authenticates the connection, but does not prove desktop logon.
type RDSTLSAuthenticationError = rdstls.AuthenticationError

type RDSTLSState struct {
	Authenticated bool
	AutoReconnect bool
	Version       uint16
}

func (t *Transport) RDSTLSState() RDSTLSState { return t.rdstls }
func (s *Session) RDSTLSState() RDSTLSState   { return s.connection.Transport.RDSTLSState() }

// One attempt only. No serialized authentication packet is retained. When
// enabled, AutoReconnect separately owns the next server cookie for recovery.
// The certificate digest is non-secret binding.
type rdstlsAuthentication struct {
	packet      []byte
	certificate [sha256.Size]byte
	reconnect   bool
}

func (*rdstlsAuthentication) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "[redacted RDSTLS authentication]")
}
func (*rdstlsAuthentication) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted RDSTLS authentication]"`), nil
}

func (l sessionLogin) clear() {
	clear(l.redirectionCookie)
	if l.rdstls != nil {
		clear(l.rdstls.packet)
	}
}

func prepareRedirectLogin(request *pdu.Redirection, info pdu.RedirectionInfo, target RedirectionTarget) (Credentials, sessionLogin, error) {
	if target.PasswordMode != RedirectionPasswordRDSTLS {
		c, cookie, err := redirectedCredentials(request, info, target)
		return c, sessionLogin{redirectionCookie: cookie}, err
	}
	fail := func(err error) (Credentials, sessionLogin, error) { return Credentials{}, sessionLogin{}, err }
	const required = pdu.RedirectPassword | pdu.RedirectPasswordPKEncrypted | pdu.RedirectGUID | pdu.RedirectCertificate | pdu.RedirectUsername | pdu.RedirectDomain
	if info.Flags&required != required || info.Flags&pdu.RedirectSmartcard != 0 || target.IgnoreServerPassword || target.SPNEGO || target.Kerberos != nil || target.Credentials.Username != info.Username || target.Credentials.Domain != info.Domain {
		return fail(ErrRedirectionCredentials)
	}
	c := target.Credentials
	c.Password = "" // RDSTLS uses only the encrypted server blob, never a local password.
	if err := c.Validate(); err != nil {
		return fail(err)
	}
	cert, err := request.CertificateDER()
	if err != nil {
		return fail(err)
	}
	defer clear(cert)
	if _, err := x509.ParseCertificate(cert); err != nil {
		return fail(ErrRedirectionCredentials)
	}
	var fields [4][]byte
	defer func() {
		for _, b := range fields {
			clear(b)
		}
	}()
	for i, flag := range []pdu.RedirectionFlags{pdu.RedirectGUID, pdu.RedirectUsername, pdu.RedirectDomain, pdu.RedirectPassword} {
		fields[i], err = request.Field(flag)
		if err != nil {
			return fail(err)
		}
	}
	packet, err := rdstls.PasswordRequest(fields[0], fields[1], fields[2], fields[3])
	if err != nil {
		return fail(err)
	}
	return c, sessionLogin{rdstls: &rdstlsAuthentication{packet: packet, certificate: sha256.Sum256(cert)}}, nil
}

func bindRDSTLSCertificate(config *tls.Config, expected [sha256.Size]byte) {
	verify := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || sha256.Sum256(state.PeerCertificates[0].Raw) != expected {
			return ErrRDSTLSIdentity
		}
		if verify != nil {
			return verify(state)
		}
		return nil
	}
}
