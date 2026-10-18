package rdp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hq0101/rdp-go/internal/licensing"
)

var (
	ErrLicenseConfiguration = errors.New("rdp: invalid licensing configuration")
	ErrLicenseCertificate   = errors.New("rdp: license certificate rejected")
	ErrLicenseStore         = errors.New("rdp: license store operation failed")
	ErrLicenseStoreClosed   = errors.New("rdp: license store closed")
	ErrLicenseStoreLimit    = errors.New("rdp: license store capacity exceeded")
	ErrLicenseMessageSize   = errors.New("rdp: licensing message exceeds MCS protocol size limit")
)

// LicenseIdentity is supplied and persisted by the application. HardwareID is a
// stable nonzero 16-byte installation identity, not an automatically collected
// hardware fingerprint. Reuse it when reusing stored CALs. Names are already
// encoded in the server's ANSI code page, without a NUL; no UTF-8 conversion or
// OS/machine/user discovery is performed. UserName represents the login account.
// PlatformID and ClientType are MS-RDPELE values; zero ClientType means OTHER.
type LicenseIdentity struct {
	licenseRedacted
	PlatformID            uint32
	ClientType            uint16
	HardwareID            [16]byte
	UserName, MachineName []byte
}

// LicensingOptions opts DialSession into MS-RDPELE issuance and renewal. A stable
// identity and Store are required. Nil Options.Licensing preserves status-only
// licensing. The library never reads the system's client-license registry.
//
// By default, a correctly signed licensing certificate is trusted as delivered
// by this independently verified TLS peer. CertificateSHA256 additionally pins
// the complete SERVER_CERTIFICATE blob (64 hex digits), NOT the TLS certificate.
// VerifyCertificate, if supplied, is an additional policy; it cannot bypass TLS,
// wire signatures, dates or a configured pin. Callbacks are synchronous and must
// honor ctx. Stores and captured callback state remain application-owned.
type LicensingOptions struct {
	licenseRedacted
	Identity          LicenseIdentity
	Store             LicenseStore
	CertificateSHA256 string
	VerifyCertificate func(context.Context, LicensingCertificate) error
}

// LicensingCertificate describes the authenticated connection and its separate
// licensing certificate. No password, CAL or certificate mutable buffers escape.
// Signature integrity is not PKIX verification: the licensing layer has no
// CA/DNS/EKU/revocation policy. Identity trust comes from TLS and optional policy.
type LicensingCertificate struct {
	licenseRedacted
	Address, Username, Domain string
	TLSCertificateSHA256      [32]byte
	Version                   uint32
	Temporary                 bool
	ChainLength, KeyBits      int
	WireSHA256, LeafSHA256    [32]byte
	NotBefore, NotAfter       time.Time
}

type LicenseProduct struct {
	Version     uint32
	Company, ID string
}

// LicenseQuery is borrowed by Load for the duration of the call. Namespace is
// derived from the exact dial address, login account/domain and authenticated
// TLS leaf certificate. A different target/account/certificate never implicitly
// shares a stored license. Explicit application migration can use a custom store.
type LicenseQuery struct {
	licenseRedacted
	Namespace  [32]byte
	HardwareID [20]byte
	Product    LicenseProduct
	Scopes     [][]byte
}

// LicenseRecord contains only an opaque server-issued CAL and its exact lookup
// identity. Data is not synthesized or interpreted as a transferable license.
type LicenseRecord struct {
	licenseRedacted
	Namespace   [32]byte
	HardwareID  [20]byte
	Product     LicenseProduct
	Scope, Data []byte
}

// LicenseStore permits a persistent implementation without platform dependencies.
// Load returns an owned record (or nil,nil for a miss), which the library clears.
// Save borrows its input until return; retain only a Clone or a completed durable
// write. Implementations must support concurrent sessions and respect ctx. Errors
// fail the handshake; the library never silently discards a newly issued CAL.
type LicenseStore interface {
	Load(context.Context, LicenseQuery) (*LicenseRecord, error)
	Save(context.Context, LicenseRecord) error
}

func (r LicenseRecord) Clone() LicenseRecord {
	r.Scope = bytes.Clone(r.Scope)
	r.Data = bytes.Clone(r.Data)
	return r
}
func (r *LicenseRecord) Clear() {
	if r != nil {
		clear(r.Scope)
		clear(r.Data)
		*r = LicenseRecord{}
	}
}
func (q LicenseQuery) Clone() LicenseQuery { q.Scopes = cloneLicenseScopes(q.Scopes); return q }
func (q *LicenseQuery) Clear() {
	if q != nil {
		for _, b := range q.Scopes {
			clear(b)
		}
		*q = LicenseQuery{}
	}
}

type licenseRedacted struct{}

func (licenseRedacted) Format(s fmt.State, _ rune) { io.WriteString(s, "[redacted licensing data]") }
func (licenseRedacted) MarshalJSON() ([]byte, error) {
	return []byte(`"[redacted licensing data]"`), nil
}

func cloneLicenseScopes(scopes [][]byte) [][]byte {
	out := make([][]byte, len(scopes))
	for i, b := range scopes {
		out[i] = bytes.Clone(b)
	}
	return out
}
func (o *LicensingOptions) Clone() *LicensingOptions {
	if o == nil {
		return nil
	}
	n := *o
	n.Identity.UserName = bytes.Clone(o.Identity.UserName)
	n.Identity.MachineName = bytes.Clone(o.Identity.MachineName)
	return &n
}

// clearLicensingOptions clears only an owned options copy. It never closes the
// shared Store. Go cannot guarantee erasure of strings or runtime copies.
func clearLicensingOptions(o *LicensingOptions) {
	if o != nil {
		clear(o.Identity.UserName)
		clear(o.Identity.MachineName)
		*o = LicensingOptions{}
	}
}
func (o *LicensingOptions) config() licensing.Config {
	i := o.Identity
	return licensing.Config{UserName: i.UserName, MachineName: i.MachineName, PlatformID: i.PlatformID, ClientType: i.ClientType, HardwareID: i.HardwareID}
}
func prepareLicensing(o *LicensingOptions) (*LicensingOptions, error) {
	if o == nil {
		return nil, nil
	}
	if o.Store == nil {
		return nil, ErrLicenseConfiguration
	}
	if o.CertificateSHA256 != "" {
		b, e := hex.DecodeString(o.CertificateSHA256)
		if e != nil || len(b) != 32 || bytes.Equal(b, make([]byte, 32)) {
			return nil, ErrLicenseConfiguration
		}
	}
	c, e := licensing.New(o.config())
	if e != nil {
		return nil, ErrLicenseConfiguration
	}
	c.Close()
	return o.Clone(), nil
}

func licenseHashPart(h hash.Hash, b []byte) {
	h.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(b))))
	h.Write(b)
}
func licenseNamespace(address, user, domain string, cert [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte("openrdp/license/namespace/v1\x00"))
	for _, s := range []string{address, user, domain} {
		licenseHashPart(h, []byte(s))
	}
	h.Write(cert[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}
func validLicenseText(s string) bool {
	if len(s) > licensing.MaxText*2 || !utf8.ValidString(s) || strings.IndexByte(s, 0) >= 0 {
		return false
	}
	n := 1
	for _, r := range s {
		n++
		if r > 0xffff {
			n++
		}
		if n*2 > licensing.MaxText {
			return false
		}
	}
	return true
}
func validLicenseScope(b []byte) bool { return len(b) < licensing.MaxText && bytes.IndexByte(b, 0) < 0 }
func validLicenseBase(namespace [32]byte, hw [20]byte, p LicenseProduct) bool {
	return namespace != ([32]byte{}) && !bytes.Equal(hw[4:], make([]byte, 16)) && validLicenseText(p.Company) && validLicenseText(p.ID)
}
func validLicenseQuery(q LicenseQuery) bool {
	if !validLicenseBase(q.Namespace, q.HardwareID, q.Product) || len(q.Scopes) > licensing.MaxScopes {
		return false
	}
	for _, s := range q.Scopes {
		if !validLicenseScope(s) {
			return false
		}
	}
	return true
}
func validLicenseRecord(r LicenseRecord) bool {
	return validLicenseBase(r.Namespace, r.HardwareID, r.Product) && validLicenseScope(r.Scope) && len(r.Data) > 0 && len(r.Data) <= licensing.MaxLicense
}
func licenseRecordMatches(r *LicenseRecord, q LicenseQuery) bool {
	if r == nil || !validLicenseRecord(*r) || r.Namespace != q.Namespace || r.HardwareID != q.HardwareID || r.Product != q.Product {
		return false
	}
	for _, scope := range q.Scopes {
		if bytes.Equal(scope, r.Scope) {
			return true
		}
	}
	return false
}

// LicensingState reports protocol and storage completion, not Windows shell logon.
// It contains no CAL, client identifier or callback-owned values.
type LicensingState struct {
	Enabled, Accepted, CertificateVerified bool
	Cached, Issued, Upgraded, Stored       bool
	Messages, Resets, Resends              int
}

func (s *Session) LicensingState() LicensingState {
	s.infoMu.RLock()
	defer s.infoMu.RUnlock()
	return s.licensingInfo
}
