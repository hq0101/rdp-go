package licensing

import (
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"
	"slices"
	"time"
)

var (
	ErrCertificate          = errors.New("licensing: malformed or unsupported server certificate")
	ErrCertificateSignature = errors.New("licensing: server certificate signature mismatch")
	ErrCertificateTime      = errors.New("licensing: server certificate outside validity period")
	ErrCertificateTrust     = errors.New("licensing: server certificate not trusted")
)

// CertificateInfo contains metadata only. Signature integrity does not establish
// server identity: the proprietary signing private key is public, and an X.509
// licensing chain may start at a self-signed license server. These are not Web
// PKI chains and this package does not apply CA, DNS, EKU or revocation policy.
type CertificateInfo struct {
	Version                uint32
	Temporary              bool
	ChainLength, KeyBits   int
	WireSHA256, LeafSHA256 [32]byte
	// Intersection of all X.509 certificate validity periods; zero for version 1.
	NotBefore, NotAfter time.Time
}

// CertificateVerifier must bind the certificate to an independently authenticated
// connection or a previously trusted exact fingerprint. It receives no mutable
// parser/key state. Nil denies trust. It must respect ctx; no goroutine is started.
// A successful signature check alone is not sufficient to implement this policy.
type CertificateVerifier func(context.Context, CertificateInfo) error

// PinnedCertificate trusts the SHA-256 of the complete SERVER_CERTIFICATE wire
// value, not its TLS certificate, leaf alone, or RSA key. Zero never trusts.
func PinnedCertificate(expected [32]byte) CertificateVerifier {
	return func(ctx context.Context, info CertificateInfo) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if expected == ([32]byte{}) || subtle.ConstantTimeCompare(expected[:], info.WireSHA256[:]) != 1 {
			return ErrCertificateTrust
		}
		return nil
	}
}

type parsedCertificate struct {
	info              CertificateInfo
	key               *rsa.PublicKey
	chain             []licenseX509
	signed, signature []byte // proprietary certificate
}

// InspectCertificate parses bounded wire structures, without authenticating
// signatures, validity or trust. It never returns a usable encryption key.
func InspectCertificate(b []byte) (CertificateInfo, error) {
	p, err := parseCertificate(b)
	if err != nil {
		return CertificateInfo{}, err
	}
	return p.info, nil
}

// VerifyCertificate checks protocol signatures and dates, then invokes the
// mandatory independent trust decision. It returns an owned RSA key only after
// all checks succeed. now must be explicit and nonzero. No TLS trust is inferred.
func VerifyCertificate(ctx context.Context, b []byte, now time.Time, verify CertificateVerifier) (*rsa.PublicKey, CertificateInfo, error) {
	failed := func(err error) (*rsa.PublicKey, CertificateInfo, error) { return nil, CertificateInfo{}, err }
	if err := ctx.Err(); err != nil {
		return failed(err)
	}
	if verify == nil {
		return failed(ErrCertificateTrust)
	}
	if now.IsZero() {
		return failed(ErrCertificateTime)
	}
	if len(b) < 4 || len(b) > 65535 {
		return failed(ErrCertificate)
	}
	// Own all bytes across the caller's trust callback.
	p, err := parseCertificate(bytes.Clone(b))
	if err != nil {
		return failed(err)
	}
	if err := cryptoAvailable(); err != nil {
		return failed(err)
	}
	if p.info.Version == 1 {
		if err := verifyProprietary(p.signed, p.signature); err != nil {
			return failed(err)
		}
	} else {
		for i := range p.chain {
			if err := ctx.Err(); err != nil {
				return failed(err)
			}
			c := &p.chain[i]
			if now.Before(c.before) || now.After(c.after) {
				return failed(ErrCertificateTime)
			}
			parent := c
			if i > 0 {
				parent = &p.chain[i-1]
			}
			if !bytes.Equal(c.issuer, parent.subject) {
				return failed(ErrCertificateSignature)
			}
			if !verifyLicenseSignature(parent.key, c.algorithm, c.signed, c.signature) {
				return failed(ErrCertificateSignature)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return failed(err)
	}
	if err := verify(ctx, p.info); err != nil {
		if ctx.Err() != nil {
			return failed(ctx.Err())
		}
		return failed(ErrCertificateTrust) // callback text may contain identity/secrets
	}
	if err := ctx.Err(); err != nil {
		return failed(err)
	}
	return &rsa.PublicKey{N: new(big.Int).Set(p.key.N), E: p.key.E}, p.info, nil
}

func parseCertificate(b []byte) (parsedCertificate, error) {
	var p parsedCertificate
	if len(b) < 4 || len(b) > 65535 {
		return p, ErrCertificate
	}
	r := reader{b: b}
	v := r.u32()
	p.info.Version, p.info.Temporary = v&0x7fffffff, v&0x80000000 != 0
	p.info.WireSHA256 = sha256.Sum256(b)
	switch p.info.Version {
	case 1:
		if r.u32() != 1 || r.u32() != 1 || r.u16() != 6 {
			return parsedCertificate{}, ErrCertificate
		}
		pub := r.take(int(r.u16()))
		key, err := parseProprietaryKey(pub)
		if r.bad || err != nil {
			return parsedCertificate{}, ErrCertificate
		}
		p.key = key
		p.signed = b[:len(b)-len(r.b)]
		if r.u16() != 8 || r.u16() != 72 {
			return parsedCertificate{}, ErrCertificate
		}
		p.signature = r.take(64)
		padding := r.take(8)
		if r.bad || len(r.b) != 0 || !allZero(padding) {
			return parsedCertificate{}, ErrCertificate
		}
		p.info.ChainLength = 1
		p.info.LeafSHA256 = p.info.WireSHA256
	case 2:
		count := r.u32()
		if count < 2 || count > 200 {
			return parsedCertificate{}, ErrCertificate
		}
		p.chain = make([]licenseX509, 0, count)
		seen := make(map[[32]byte]bool)
		for i := uint32(0); i < count; i++ {
			der := r.sized(65535)
			c, err := parseLicenseX509(der)
			if r.bad || err != nil {
				return parsedCertificate{}, ErrCertificate
			}
			hash := sha256.Sum256(der)
			if seen[hash] {
				return parsedCertificate{}, ErrCertificate
			}
			seen[hash] = true
			p.chain = append(p.chain, c)
			p.key, p.info.LeafSHA256 = c.key, hash
			if p.info.NotBefore.IsZero() || c.before.After(p.info.NotBefore) {
				p.info.NotBefore = c.before
			}
			if p.info.NotAfter.IsZero() || c.after.Before(p.info.NotAfter) {
				p.info.NotAfter = c.after
			}
		}
		// The spec defines the padding length, not its contents.
		r.take(8 + 4*int(count))
		if r.bad || len(r.b) != 0 {
			return parsedCertificate{}, ErrCertificate
		}
		p.info.ChainLength = int(count)
	default:
		return parsedCertificate{}, ErrCertificate
	}
	p.info.KeyBits = p.key.N.BitLen()
	return p, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
func littleInteger(b []byte) *big.Int {
	out := bytes.Clone(b)
	slices.Reverse(out)
	return new(big.Int).SetBytes(out)
}
func validRSA(key *rsa.PublicKey) bool {
	return key != nil && key.N != nil && key.N.Sign() > 0 && key.N.BitLen() >= 512 && key.N.BitLen() <= 8192 && key.N.Bit(0) == 1 && key.E >= 3 && key.E <= 0x7fffffff && key.E%2 == 1
}
func parseProprietaryKey(b []byte) (*rsa.PublicKey, error) {
	if len(b) < 20 {
		return nil, ErrCertificate
	}
	r := reader{b: b}
	if r.u32() != 0x31415352 {
		return nil, ErrCertificate
	}
	length, bits, data, exponent := r.u32(), r.u32(), r.u32(), r.u32()
	if bits < 512 || bits > 8192 || bits%8 != 0 || length != bits/8+8 || data != bits/8-1 || len(r.b) != int(length) {
		return nil, ErrCertificate
	}
	key := &rsa.PublicKey{N: littleInteger(r.take(int(bits / 8))), E: int(exponent)}
	if !allZero(r.take(8)) || !validRSA(key) || key.N.BitLen() != int(bits) {
		return nil, ErrCertificate
	}
	return key, nil
}

// Public, well-known Terminal Services signing key, MS-RDPBCGR 5.3.3.1.1.
// Verifying this signature is a format/integrity check, never a trust anchor.
func verifyProprietary(signed, signature []byte) error {
	if err := cryptoAvailable(); err != nil {
		return err
	}
	modulus, _ := hex.DecodeString("3d3a5ebd72433ec94dbbc11e4aba5fcb3e882087eff5c1e2d7b76b9af2524595ce63656b583afeef7ce7bffe3df65c7d6c5e06091af561bb2093095f056dea87")
	n, s := littleInteger(modulus), littleInteger(signature)
	if len(signature) != 64 || s.Cmp(n) >= 0 {
		return ErrCertificateSignature
	}
	m := new(big.Int).Exp(s, big.NewInt(0xc0887b5b), n)
	got := m.FillBytes(make([]byte, 64))
	slices.Reverse(got)
	want := bytes.Repeat([]byte{0xff}, 64)
	digest := md5.Sum(signed)
	copy(want, digest[:])
	want[16], want[62], want[63] = 0, 1, 0
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrCertificateSignature
	}
	return nil
}

type licenseX509 struct {
	key                                *rsa.PublicKey
	algorithm                          x509.SignatureAlgorithm
	signed, signature, issuer, subject []byte
	before, after                      time.Time
}

// This protocol-specific reader preserves signed DER bytes. In particular,
// MS-RDPELE certificates use OIW rsaSignature (1.3.14.3.2.15) as a key OID,
// SHA-1/OIW signature OIDs, and opaque critical licensing extensions. Rewriting
// a DER certificate to make crypto/x509 accept it would invalidate its signature.
func parseLicenseX509(b []byte) (licenseX509, error) {
	bad := func() (licenseX509, error) { return licenseX509{}, ErrCertificate }
	outer, ok := derSequence(b)
	if !ok || len(outer) != 3 {
		return bad()
	}
	tbs, ok := derSequence(outer[0].FullBytes)
	if !ok {
		return bad()
	}
	version := 0
	if len(tbs) > 0 && tbs[0].Class == 2 && tbs[0].Tag == 0 && tbs[0].IsCompound {
		if !derDecode(tbs[0].Bytes, &version) || version < 0 || version > 2 {
			return bad()
		}
		tbs = tbs[1:]
	}
	if len(tbs) < 6 {
		return bad()
	}
	var serial *big.Int
	if !derDecode(tbs[0].FullBytes, &serial) || serial == nil || serial.Sign() <= 0 {
		return bad()
	}
	inner, ok := rsaSignatureAlgorithm(tbs[1])
	algorithm, outerOK := rsaSignatureAlgorithm(outer[1])
	if !ok || !outerOK || inner != algorithm {
		return bad()
	}
	if !validNameDER(tbs[2]) || !validNameDER(tbs[4]) {
		return bad()
	}
	validity, ok := derSequence(tbs[3].FullBytes)
	if !ok || len(validity) != 2 {
		return bad()
	}
	c := licenseX509{algorithm: algorithm, signed: outer[0].FullBytes, issuer: tbs[2].FullBytes, subject: tbs[4].FullBytes}
	if !derDecode(validity[0].FullBytes, &c.before) || !derDecode(validity[1].FullBytes, &c.after) || c.after.Before(c.before) {
		return bad()
	}
	spki, ok := derSequence(tbs[5].FullBytes)
	if !ok || len(spki) != 2 {
		return bad()
	}
	oid, ok := rsaAlgorithmOID(spki[0])
	if !ok || (oid != "1.2.840.113549.1.1.1" && oid != "1.3.14.3.2.15") {
		return bad()
	}
	var pub, sig asn1.BitString
	if !derDecode(spki[1].FullBytes, &pub) || pub.BitLength != len(pub.Bytes)*8 || !derDecode(outer[2].FullBytes, &sig) || sig.BitLength != len(sig.Bytes)*8 {
		return bad()
	}
	parts, ok := derSequence(pub.Bytes)
	key := &rsa.PublicKey{}
	if !ok || len(parts) != 2 || !derDecode(parts[0].FullBytes, &key.N) || !derDecode(parts[1].FullBytes, &key.E) || !validRSA(key) || len(sig.Bytes) < 64 || len(sig.Bytes) > 1024 {
		return bad()
	}
	c.key, c.signature = key, sig.Bytes
	lastTag := 0
	for _, optional := range tbs[6:] {
		if optional.Class != 2 || optional.Tag <= lastTag || optional.Tag > 3 {
			return bad()
		}
		lastTag = optional.Tag
		if optional.Tag == 3 {
			if version != 2 || !optional.IsCompound || !validExtensions(optional.Bytes) {
				return bad()
			}
		} else {
			if version == 0 || optional.IsCompound || len(optional.Bytes) < 1 {
				return bad()
			}
			// IMPLICIT BIT STRING: validate unused-bit count and zero padding.
			bits := optional.Bytes[0]
			if bits > 7 || len(optional.Bytes) == 1 && bits != 0 || bits > 0 && optional.Bytes[len(optional.Bytes)-1]&byte((1<<bits)-1) != 0 {
				return bad()
			}
		}
	}
	return c, nil
}

func derDecode(b []byte, out any) bool {
	rest, err := asn1.Unmarshal(b, out)
	return err == nil && len(rest) == 0
}
func derSequence(b []byte) ([]asn1.RawValue, bool) {
	var seq asn1.RawValue
	if !derDecode(b, &seq) || seq.Class != 0 || seq.Tag != 16 || !seq.IsCompound {
		return nil, false
	}
	var values []asn1.RawValue
	for len(seq.Bytes) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(seq.Bytes, &v)
		if err != nil || len(values) >= 256 {
			return nil, false
		}
		values = append(values, v)
		seq.Bytes = rest
	}
	return values, true
}
func rsaAlgorithmOID(v asn1.RawValue) (string, bool) {
	fields, ok := derSequence(v.FullBytes)
	if !ok || len(fields) < 1 || len(fields) > 2 {
		return "", false
	}
	var oid asn1.ObjectIdentifier
	if !derDecode(fields[0].FullBytes, &oid) || len(fields) == 2 && !bytes.Equal(fields[1].FullBytes, []byte{5, 0}) {
		return "", false
	}
	return oid.String(), true
}
func rsaSignatureAlgorithm(v asn1.RawValue) (x509.SignatureAlgorithm, bool) {
	oid, ok := rsaAlgorithmOID(v)
	if !ok {
		return 0, false
	}
	switch oid {
	case "1.2.840.113549.1.1.5", "1.3.14.3.2.29":
		return x509.SHA1WithRSA, true
	case "1.2.840.113549.1.1.11":
		return x509.SHA256WithRSA, true
	case "1.2.840.113549.1.1.12":
		return x509.SHA384WithRSA, true
	case "1.2.840.113549.1.1.13":
		return x509.SHA512WithRSA, true
	}
	return 0, false
}
func validNameDER(v asn1.RawValue) bool {
	sets, ok := derSequence(v.FullBytes)
	if !ok {
		return false
	}
	for _, set := range sets {
		if set.Class != 0 || set.Tag != 17 || !set.IsCompound || len(set.Bytes) == 0 {
			return false
		}
		b := set.Bytes
		for len(b) > 0 {
			var attribute asn1.RawValue
			rest, err := asn1.Unmarshal(b, &attribute)
			if err != nil {
				return false
			}
			fields, ok := derSequence(attribute.FullBytes)
			var oid asn1.ObjectIdentifier
			if !ok || len(fields) != 2 || !derDecode(fields[0].FullBytes, &oid) {
				return false
			}
			b = rest
		}
	}
	return true
}
func validExtensions(b []byte) bool {
	values, ok := derSequence(b)
	if !ok || len(values) == 0 || len(values) > 64 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range values {
		fields, ok := derSequence(value.FullBytes)
		if !ok || len(fields) < 2 || len(fields) > 3 {
			return false
		}
		var oid asn1.ObjectIdentifier
		if !derDecode(fields[0].FullBytes, &oid) || seen[oid.String()] {
			return false
		}
		seen[oid.String()] = true
		if len(fields) == 3 {
			var critical bool
			if !derDecode(fields[1].FullBytes, &critical) {
				return false
			}
		}
		var data []byte
		if !derDecode(fields[len(fields)-1].FullBytes, &data) {
			return false
		}
	}
	return true
}

// Public RSA verification for the licensing format, including its historical
// 512-bit keys and SHA-1 signatures. This is not exposed as a general signature
// API. Compare the complete fixed-width EMSA-PKCS1-v1_5 block, never a suffix.
// VerifyCertificate checks process crypto policy before invoking this helper.
func verifyLicenseSignature(key *rsa.PublicKey, algorithm x509.SignatureAlgorithm, signed, signature []byte) bool {
	if !validRSA(key) || len(signature) != (key.N.BitLen()+7)/8 {
		return false
	}
	var digest, prefix []byte
	switch algorithm {
	case x509.SHA1WithRSA:
		h := sha1.Sum(signed)
		digest = h[:]
		prefix, _ = hex.DecodeString("3021300906052b0e03021a05000414")
	case x509.SHA256WithRSA:
		h := sha256.Sum256(signed)
		digest = h[:]
		prefix, _ = hex.DecodeString("3031300d060960864801650304020105000420")
	case x509.SHA384WithRSA:
		h := sha512.Sum384(signed)
		digest = h[:]
		prefix, _ = hex.DecodeString("3041300d060960864801650304020205000430")
	case x509.SHA512WithRSA:
		h := sha512.Sum512(signed)
		digest = h[:]
		prefix, _ = hex.DecodeString("3051300d060960864801650304020305000440")
	default:
		return false
	}
	padding := len(signature) - len(prefix) - len(digest) - 3
	if padding < 8 {
		return false
	}
	s := new(big.Int).SetBytes(signature)
	if s.Cmp(key.N) >= 0 {
		return false
	}
	got := new(big.Int).Exp(s, big.NewInt(int64(key.E)), key.N).FillBytes(make([]byte, len(signature)))
	want := append([]byte{0, 1}, bytes.Repeat([]byte{0xff}, padding)...)
	want = append(want, 0)
	want = append(want, prefix...)
	want = append(want, digest...)
	return subtle.ConstantTimeCompare(got, want) == 1
}
