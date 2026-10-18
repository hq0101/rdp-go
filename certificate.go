package rdp

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"time"
)

func configureCertificatePin(config *tls.Config, fingerprint string) error {
	if fingerprint == "" {
		return nil
	}
	pin, err := hex.DecodeString(fingerprint)
	if err != nil || len(pin) != sha256.Size {
		return errors.New("rdp: CertificateSHA256 must be exactly 64 hexadecimal characters")
	}
	verify := config.VerifyConnection
	// Replace PKI with exact leaf identity verification, never unconditional trust.
	config.InsecureSkipVerify = true
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return errors.New("rdp: server did not provide a certificate")
		}
		cert := state.PeerCertificates[0]
		digest := sha256.Sum256(cert.Raw)
		if subtle.ConstantTimeCompare(digest[:], pin) != 1 {
			return errors.New("rdp: server certificate SHA-256 fingerprint mismatch")
		}
		now := time.Now()
		if config.Time != nil {
			now = config.Time()
		}
		if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
			return errors.New("rdp: pinned server certificate is outside its validity period")
		}
		if verify != nil {
			return verify(state)
		}
		return nil
	}
	return nil
}
