package credssp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/hq0101/rdp-go/internal/der"
	"github.com/hq0101/rdp-go/internal/ntlm"
)

// Authenticate runs CredSSP over a TLS-protected stream. The caller MUST verify
// the certificate before calling, apply I/O deadlines, and close on any error.
// Success means server binding verified and credentials delegated; HYBRID has no
// final credential-acceptance reply. It does not imply an authorized RDP desktop.
// NTLM is selected directly. Use AuthenticateSPNEGO for wrapped NTLM negotiation.
// target is the expected service principal, e.g. TERMSRV/rdp.example.com.
func Authenticate(rw io.ReadWriter, cert *x509.Certificate, target string, c Credentials) error {
	return authenticate(rw, cert, target, c, false)
}

// AuthenticateSPNEGO runs CredSSP with RFC 4178/MS-SPNG negotiation, offering
// NTLMv2 only. Both mechanism-list MICs and the TLS key binding are required.
// It never silently retries raw NTLM or negotiates an unimplemented mechanism.
// The certificate verification, deadlines and close-on-error requirements of
// Authenticate also apply. Kerberos and server-initiated negotiation are absent.
func AuthenticateSPNEGO(rw io.ReadWriter, cert *x509.Certificate, target string, c Credentials) error {
	return authenticate(rw, cert, target, c, true)
}

func authenticate(rw io.ReadWriter, cert *x509.Certificate, target string, c Credentials, spnego bool) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if cert == nil || target == "" {
		return errors.New("credssp: certificate and target are required")
	}
	publicKey, err := subjectKey(cert)
	if err != nil {
		return err
	}
	cb, err := channelBinding(cert)
	if err != nil {
		return err
	}
	negotiate := ntlm.Negotiate()
	token := negotiate
	if spnego {
		token = spnegoInit(negotiate)
	}
	if err := der.Write(rw, (request{version: 6, token: token}).marshal()); err != nil {
		return fmt.Errorf("credssp: send negotiate: %w", err)
	}
	challenge, err := readRequest(rw)
	if err != nil {
		return fmt.Errorf("credssp: receive challenge: %w", err)
	}
	version := challenge.version
	if version > 6 {
		version = 6
	}
	if version < 5 || challenge.auth != nil || challenge.binding != nil || challenge.nonce != nil {
		return ErrProtocol
	}
	token = challenge.token
	if spnego {
		token, err = spnegoChallenge(token)
		if err != nil {
			return err
		}
	}
	ch, err := ntlm.ParseChallenge(token)
	if err != nil {
		return err
	}
	auth, security, err := ntlm.Authenticate(c, negotiate, ch, target, cb)
	if err != nil {
		return err
	}
	if spnego {
		mic, err := security.MechListMIC(mechanismList())
		if err != nil {
			return err
		}
		auth = spnegoAuthenticate(auth, mic)
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	clientHash := bindingHash(true, nonce[:], publicKey)
	encrypted, err := security.Seal(clientHash)
	if err != nil {
		return err
	}
	if err := der.Write(rw, (request{version: version, token: auth, binding: encrypted, nonce: nonce[:]}).marshal()); err != nil {
		return fmt.Errorf("credssp: send authenticate and binding: %w", err)
	}
	reply, err := readRequest(rw)
	if err != nil {
		return fmt.Errorf("credssp: receive server binding: %w", err)
	}
	if spnego {
		if err := spnegoFinish(reply, version, security); err != nil {
			return err
		}
		// Some acceptors return the completed negotiation and binding together;
		// others send a separate TSRequest for the key binding. Permit one such
		// split, never an unbounded exchange or delegation before verification.
		if len(reply.binding) == 0 {
			reply, err = readRequest(rw)
			if err != nil {
				return fmt.Errorf("credssp: receive server binding: %w", err)
			}
		} else {
			reply.token = nil // completion and MIC were validated above
		}
	}
	effective := reply.version
	if effective > 6 {
		effective = 6
	}
	if effective != version || reply.auth != nil || reply.nonce != nil || len(reply.binding) == 0 {
		return ErrProtocol
	}
	if len(reply.token) != 0 {
		return ErrProtocol
	}
	actual, err := security.Unseal(reply.binding)
	if err != nil {
		return err
	}
	if !hmac.Equal(actual, bindingHash(false, nonce[:], publicKey)) {
		return ErrBinding
	}
	plain := passwordCredentials(c)
	defer clear(plain)
	sealed, err := security.Seal(plain)
	if err != nil {
		return err
	}
	if err := der.Write(rw, (request{version: version, auth: sealed}).marshal()); err != nil {
		return fmt.Errorf("credssp: delegate credentials: %w", err)
	}
	return nil
}

func spnegoFinish(reply request, version uint32, security *ntlm.Security) error {
	if min(reply.version, 6) != version || reply.auth != nil || reply.nonce != nil {
		return ErrProtocol
	}
	finished, err := parseSPNEGOResponse(reply.token)
	if err != nil || finished.state != 0 || len(finished.token) != 0 || len(finished.mic) != 16 {
		return ErrProtocol
	}
	// A repeated supportedMech is ignored, per MS-SPNG 3.3.5. It cannot change
	// the already selected mechanism, transcript, keys or required MIC.
	return security.VerifyMechListMIC(mechanismList(), finished.mic)
}

func bindingHash(client bool, nonce, key []byte) []byte {
	prefix := "CredSSP Server-To-Client Binding Hash\x00"
	if client {
		prefix = "CredSSP Client-To-Server Binding Hash\x00"
	}
	h := sha256.New()
	h.Write([]byte(prefix))
	h.Write(nonce)
	h.Write(key)
	return h.Sum(nil)
}
func subjectKey(cert *x509.Certificate) ([]byte, error) {
	var spki struct {
		Algorithm asn1.RawValue
		Key       asn1.BitString
	}
	rest, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki)
	if err != nil || len(rest) != 0 || spki.Key.BitLength%8 != 0 || len(spki.Key.Bytes) == 0 {
		return nil, ErrProtocol
	}
	return spki.Key.Bytes, nil
}

// RFC 5929 tls-server-end-point, serialized as GSS channel bindings (RFC 2744),
// hashed with MD5 for MS-NLMP MsvAvChannelBindings.
func channelBinding(cert *x509.Certificate) ([]byte, error) {
	app, err := tlsServerEndPoint(cert)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b[16:], uint32(len(app)))
	b = append(b, app...)
	h := md5.Sum(b)
	return h[:], nil
}

func tlsServerEndPoint(cert *x509.Certificate) ([]byte, error) {
	var digest []byte
	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256:
		h := sha256.Sum256(cert.Raw)
		digest = h[:]
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		h := sha512.Sum384(cert.Raw)
		digest = h[:]
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		h := sha512.Sum512(cert.Raw)
		digest = h[:]
	default:
		return nil, errors.New("credssp: unsupported certificate signature algorithm for channel binding")
	}
	return append([]byte("tls-server-end-point:"), digest...), nil
}
