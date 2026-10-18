package rdpemt

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)

var ErrIdentity = errors.New("rdpemt: sideband identity does not match verified main connection")

// ServerIdentity is an immutable snapshot from an authenticated main connection.
// It contains no credentials or cookie. Its zero value cannot authorize a tunnel.
type ServerIdentity struct {
	fingerprint         [32]byte
	notBefore, notAfter time.Time
	valid               bool
}

func (s ServerIdentity) String() string   { return "rdpemt.ServerIdentity{private identity}" }
func (s ServerIdentity) GoString() string { return s.String() }

// IdentityFromTLS requires the state of the verified main RDP TLS connection.
// certificatePinned must be true only when that connection already verified an
// explicitly trusted leaf fingerprint (e.g. Transport.CertificatePinned()). It
// is not permission to trust an arbitrary certificate or an incomplete handshake.
func IdentityFromTLS(state tls.ConnectionState, certificatePinned bool) (ServerIdentity, error) {
	if !state.HandshakeComplete || state.Version < tls.VersionTLS12 || len(state.PeerCertificates) == 0 || state.PeerCertificates[0] == nil || !certificatePinned && len(state.VerifiedChains) == 0 {
		return ServerIdentity{}, ErrIdentity
	}
	c := state.PeerCertificates[0]
	now := time.Now()
	if len(c.Raw) == 0 || now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return ServerIdentity{}, ErrIdentity
	}
	return ServerIdentity{fingerprint: sha256.Sum256(c.Raw), notBefore: c.NotBefore, notAfter: c.NotAfter, valid: true}, nil
}

func (s ServerIdentity) verify(state tls.ConnectionState, now time.Time) error {
	if state.Version < tls.VersionTLS12 {
		return ErrIdentity
	}
	return s.verifyCertificates(state.PeerCertificates, now)
}

func (s ServerIdentity) verifyCertificates(certs []*x509.Certificate, now time.Time) error {
	if !s.valid || now.Before(s.notBefore) || now.After(s.notAfter) || len(certs) == 0 || certs[0] == nil {
		return ErrIdentity
	}
	c := certs[0]
	hash := sha256.Sum256(c.Raw)
	if len(c.Raw) == 0 || subtle.ConstantTimeCompare(hash[:], s.fingerprint[:]) != 1 || now.Before(c.NotBefore) || now.After(c.NotAfter) {
		return ErrIdentity
	}
	return nil
}

// TLSConfig pins the exact leaf already authenticated on the main connection.
// The custom mandatory check replaces public-CA/hostname verification; it does
// not trust a new self-signed certificate. BindReliable independently rechecks
// this identity before transmitting the cookie, even if the config is modified.
func (s ServerIdentity) TLSConfig() *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true, VerifyConnection: func(state tls.ConnectionState) error { return s.verify(state, time.Now()) }}
}
