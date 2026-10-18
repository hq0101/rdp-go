package rdp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/hq0101/rdp-go/internal/licensing"
	"github.com/hq0101/rdp-go/mcs"
	"github.com/hq0101/rdp-go/pdu"
)

type licenseActivation struct {
	options               *LicensingOptions
	address, user, domain string
	namespace, peer       [32]byte
}

// MS-RDPBCGR 2.2 limits the entire SendDataRequest/Indication to 16383 bytes.
// At the upper bound the MCS header occupies eight bytes. The standalone core
// can parse larger license blobs; that does not authorize sending larger PDUs.
const maxLicenseMCSPayload = mcs.MaxDataPayload

func (s *Session) licenseActivation(address string, c Credentials, o *LicensingOptions) (*licenseActivation, error) {
	if o == nil {
		return nil, nil
	}
	state := s.TLSState()
	if !state.HandshakeComplete || len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 && !s.CertificatePinned() {
		return nil, ErrLicenseCertificate
	}
	peer := sha256.Sum256(state.PeerCertificates[0].Raw)
	return &licenseActivation{options: o, address: address, user: c.Username, domain: c.Domain, peer: peer, namespace: licenseNamespace(address, c.Username, c.Domain, peer)}, nil
}
func (a *licenseActivation) verifier(ctx context.Context, info licensing.CertificateInfo) error {
	o := a.options
	if o.CertificateSHA256 != "" {
		pin, _ := hex.DecodeString(o.CertificateSHA256)
		if e := licensing.PinnedCertificate([32]byte(pin))(ctx, info); e != nil {
			return e
		}
	}
	if o.VerifyCertificate != nil {
		return o.VerifyCertificate(ctx, LicensingCertificate{Address: a.address, Username: a.user, Domain: a.domain, TLSCertificateSHA256: a.peer, Version: info.Version, Temporary: info.Temporary, ChainLength: info.ChainLength, KeyBits: info.KeyBits, WireSHA256: info.WireSHA256, LeafSHA256: info.LeafSHA256, NotBefore: info.NotBefore, NotAfter: info.NotAfter})
	}
	return ctx.Err() // Trust distribution over the already authenticated TLS peer.
}
func (s *Session) sendLicense(ctx context.Context, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	if len(b) > maxLicenseMCSPayload {
		return ErrLicenseMessageSize
	}
	frame, e := mcs.SendDataRequest(s.info.UserChannel, s.info.IOChannel, b)
	if e != nil {
		return e
	}
	defer clear(frame)
	return s.connection.Transport.WriteMCS(ctx, frame)
}
func (s *Session) abortLicense(ctx context.Context, c *licensing.Client, code uint32, cause error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	r, e := c.Abort(code)
	defer r.Clear()
	if e != nil {
		return errors.Join(cause, e)
	}
	if e = s.sendLicense(ctx, r.Reply); e != nil {
		return errors.Join(cause, e)
	}
	return cause
}
func (s *Session) startLicense(ctx context.Context, c *licensing.Client, a *licenseActivation, request *licensing.Request) (licensing.Result, error) {
	// This private exchange has one reader and no other goroutine can mutate c.
	// Verify, load and Start therefore refer to the same retained request. Do not
	// query application storage or generate random/key material before trust.
	key, _, e := licensing.VerifyCertificate(ctx, request.Certificate, time.Now(), a.verifier)
	if e != nil {
		code := uint32(1)
		if errors.Is(e, licensing.ErrCrypto) {
			code = 2
		}
		return licensing.Result{}, s.abortLicense(ctx, c, code, fmt.Errorf("%w: %w", ErrLicenseCertificate, e))
	}
	s.licensingInfo.CertificateVerified = true
	i := a.options.Identity
	var hw [20]byte
	binary.LittleEndian.PutUint32(hw[:4], i.PlatformID)
	copy(hw[4:], i.HardwareID[:])
	q := LicenseQuery{Namespace: a.namespace, HardwareID: hw, Product: LicenseProduct(request.Product), Scopes: cloneLicenseScopes(request.Scopes)}
	defer q.Clear()
	borrowed := q.Clone()
	record, e := a.options.Store.Load(ctx, borrowed)
	borrowed.Clear()
	defer record.Clear()
	if ctx.Err() != nil {
		return licensing.Result{}, ctx.Err()
	}
	if e != nil || record != nil && !licenseRecordMatches(record, q) {
		return licensing.Result{}, s.abortLicense(ctx, c, 2, ErrLicenseStore)
	}
	var cached *licensing.License
	if record != nil {
		cached = &licensing.License{Product: licensing.Product(record.Product), Scope: record.Scope, Data: record.Data, HardwareID: record.HardwareID}
	}
	return c.Start(ctx, key, cached)
}
func (s *Session) receiveLicense(ctx context.Context, a *licenseActivation) error {
	var c *licensing.Client
	if a != nil {
		var e error
		c, e = licensing.New(a.options.config())
		if e != nil {
			return e
		}
		defer c.Close()
		s.licensingInfo.Enabled = true
	}
	notices := 0
	for n := 0; n < 49; n++ {
		d, event, e := s.packet(ctx)
		if e != nil {
			return fmt.Errorf("receive license: %w", e)
		}
		if event != nil || d.Channel != s.info.IOChannel {
			clear(d.Payload)
			return errors.New("rdp: expected licensing on I/O channel")
		}
		redirected, e := s.redirectionBeforeLicense(d.Payload)
		if e != nil {
			clear(d.Payload)
			return e
		}
		if redirected {
			clear(d.Payload)
			notices++
			if notices > 16 {
				return errors.New("rdp: too many redirection notices before license")
			}
			continue
		}
		if len(d.Payload) > maxLicenseMCSPayload {
			clear(d.Payload)
			return ErrLicenseMessageSize
		}
		if c == nil {
			e = pdu.ParseLicense(d.Payload)
			clear(d.Payload)
			if e != nil {
				return e
			}
			s.licensingInfo.Accepted = true
			s.licensingInfo.Messages = 1
			return nil
		}
		r, e := c.Handle(ctx, d.Payload)
		clear(d.Payload)
		if e != nil {
			r.Clear()
			var failure *licensing.ServerError
			if errors.As(e, &failure) {
				return &pdu.LicenseError{Code: failure.Code, Transition: failure.Transition}
			}
			return e
		}
		if r.Request != nil {
			started, startErr := s.startLicense(ctx, c, a, r.Request)
			r.Clear()
			r = started
			e = startErr
		}
		if e == nil {
			e = s.sendLicense(ctx, r.Reply)
		}
		if e != nil {
			r.Clear()
			return e
		}
		if r.Reset {
			s.licensingInfo.CertificateVerified = false
		}
		if r.License != nil {
			l := r.License
			record := LicenseRecord{Namespace: a.namespace, HardwareID: l.HardwareID, Product: LicenseProduct(l.Product), Scope: append([]byte(nil), l.Scope...), Data: append([]byte(nil), l.Data...)}
			e = a.options.Store.Save(ctx, record)
			record.Clear()
			if ctx.Err() != nil {
				r.Clear()
				return ctx.Err()
			}
			if e != nil {
				r.Clear()
				return ErrLicenseStore
			}
			s.licensingInfo.Stored = true
		}
		status := c.Status()
		s.licensingInfo.Messages = status.Messages
		s.licensingInfo.Resets = status.Resets
		s.licensingInfo.Resends = status.Resends
		s.licensingInfo.Cached = status.Cached
		s.licensingInfo.Issued = status.Issued
		s.licensingInfo.Upgraded = status.Upgraded
		done := r.Done
		r.Clear()
		if done {
			s.licensingInfo.Accepted = true
			return nil
		}
	}
	return errors.New("rdp: licensing message budget exceeded")
}
