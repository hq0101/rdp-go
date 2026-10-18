package dtls

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"net"
)

const (
	clientHello        = 1
	serverHello        = 2
	helloVerify        = 3
	certificateMessage = 11
	serverKeyExchange  = 12
	serverHelloDone    = 14
	clientKeyExchange  = 16
	finishedMessage    = 20
	ecdheRSA128        = 0xc02f
	ecdheECDSA128      = 0xc02b
)

var ErrUnsupported = errors.New("dtls: unsupported handshake feature")
var ErrHandshake = errors.New("dtls: invalid handshake state or message")

func append16(b []byte, n int) []byte { return binary.BigEndian.AppendUint16(b, uint16(n)) }
func extension(b []byte, typ uint16, data []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, typ)
	b = append16(b, len(data))
	return append(b, data...)
}

func helloBody(random [32]byte, cookie []byte, name string) ([]byte, error) {
	if len(cookie) > 255 || len(name) > 253 || bytes.IndexByte([]byte(name), 0) >= 0 {
		return nil, ErrInvalid
	}
	b := append([]byte{0xfe, 0xfd}, random[:]...)
	b = append(b, 0, byte(len(cookie))) // empty session ID, no resumption
	b = append(b, cookie...)
	b = append(b, 0, 4, 0xc0, 0x2f, 0xc0, 0x2b, 1, 0) // ciphers, null compression
	var ex []byte
	if name != "" && net.ParseIP(name) == nil {
		host := append16([]byte{0}, len(name))
		host = append(host, name...)
		ex = extension(ex, 0, append(append16(nil, len(host)), host...))
	}
	ex = extension(ex, 10, []byte{0, 6, 0, 23, 0, 24, 0, 29})    // P-256, P-384, X25519
	ex = extension(ex, 11, []byte{1, 0})                         // uncompressed EC points
	ex = extension(ex, 13, []byte{0, 8, 4, 1, 5, 1, 4, 3, 5, 3}) // SHA256/384 RSA/ECDSA
	ex = extension(ex, 23, nil)                                  // extended master secret
	ex = extension(ex, 0xff01, []byte{0})                        // initial secure renegotiation indication
	b = append16(b, len(ex))
	return append(b, ex...), nil
}

type serverParameters struct {
	random [32]byte
	cipher uint16
	ems    bool
}

func parseServerHello(b []byte, offeredSNI, allowLegacy bool) (p serverParameters, err error) {
	if len(b) < 38 || binary.BigEndian.Uint16(b) != Version12 {
		return p, ErrHandshake
	}
	copy(p.random[:], b[2:34])
	n := int(b[34])
	if n > 32 || len(b) < 38+n {
		return p, ErrInvalid
	}
	p.cipher = binary.BigEndian.Uint16(b[35+n:])
	if p.cipher != ecdheRSA128 && p.cipher != ecdheECDSA128 {
		return p, ErrUnsupported
	}
	if b[37+n] != 0 {
		return p, ErrUnsupported
	}
	b = b[38+n:]
	if len(b) > 0 {
		if len(b) < 2 || int(binary.BigEndian.Uint16(b)) != len(b)-2 {
			return p, ErrInvalid
		}
		b = b[2:]
	}
	seen := map[uint16]bool{}
	for len(b) > 0 {
		if len(b) < 4 {
			return p, ErrInvalid
		}
		typ, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint16(b[2:]))
		if seen[typ] || n > len(b)-4 {
			return p, ErrInvalid
		}
		seen[typ] = true
		v := b[4 : 4+n]
		b = b[4+n:]
		switch typ {
		case 0:
			if !offeredSNI || n != 0 {
				return p, ErrHandshake
			}
		case 23:
			if n != 0 {
				return p, ErrInvalid
			}
			p.ems = true
		case 0xff01:
			if !bytes.Equal(v, []byte{0}) {
				return p, ErrHandshake
			}
		case 11:
			if n < 2 || int(v[0]) != n-1 || !bytes.Contains(v[1:], []byte{0}) {
				return p, ErrHandshake
			}
		default:
			return p, ErrUnsupported // unsolicited extensions are not ignored
		}
	}
	if !p.ems && !allowLegacy {
		return p, ErrUnsupported
	}
	return p, nil
}

func parseCertificates(b []byte) ([]*x509.Certificate, error) {
	if len(b) < 3 || uint24(b[:3]) != len(b)-3 || len(b) > 256<<10 {
		return nil, ErrInvalid
	}
	b = b[3:]
	var chain []*x509.Certificate
	for len(b) > 0 {
		if len(chain) == 16 || len(b) < 3 {
			return nil, ErrLimit
		}
		n := uint24(b[:3])
		b = b[3:]
		if n == 0 || n > len(b) {
			return nil, ErrInvalid
		}
		c, err := x509.ParseCertificate(bytes.Clone(b[:n]))
		if err != nil {
			return nil, err
		}
		chain = append(chain, c)
		b = b[n:]
	}
	if len(chain) == 0 {
		return nil, ErrHandshake
	}
	return chain, nil
}

func verifyKeyExchange(b []byte, leaf *x509.Certificate, suite uint16, client, server [32]byte) (*ecdh.PublicKey, error) {
	if len(b) < 8 || b[0] != 3 {
		return nil, ErrInvalid
	}
	var curve ecdh.Curve
	switch binary.BigEndian.Uint16(b[1:3]) {
	case 23:
		curve = ecdh.P256()
	case 24:
		curve = ecdh.P384()
	case 29:
		curve = ecdh.X25519()
	default:
		return nil, ErrUnsupported
	}
	n := int(b[3])
	end := 4 + n
	if n == 0 || len(b) < end+4 || int(binary.BigEndian.Uint16(b[end+2:])) != len(b)-end-4 {
		return nil, ErrInvalid
	}
	pub, err := curve.NewPublicKey(b[4:end])
	if err != nil {
		return nil, err
	}
	var digest []byte
	var hash crypto.Hash
	data := append(append(append([]byte(nil), client[:]...), server[:]...), b[:end]...)
	switch b[end] {
	case 4:
		v := sha256.Sum256(data)
		digest = v[:]
		hash = crypto.SHA256
	case 5:
		v := sha512.Sum384(data)
		digest = v[:]
		hash = crypto.SHA384
	default:
		return nil, ErrUnsupported
	}
	sig := b[end+4:]
	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if suite != ecdheRSA128 || b[end+1] != 1 || key.N.BitLen() < 2048 || key.N.BitLen() > 8192 {
			return nil, ErrUnsupported
		}
		if err := rsa.VerifyPKCS1v15(key, hash, digest, sig); err != nil {
			return nil, ErrAuthentication
		}
	case *ecdsa.PublicKey:
		if suite != ecdheECDSA128 || b[end+1] != 3 || key.Curve.Params().BitSize < 256 || key.Curve.Params().BitSize > 521 {
			return nil, ErrUnsupported
		}
		if !ecdsa.VerifyASN1(key, digest, sig) {
			return nil, ErrAuthentication
		}
	default:
		return nil, ErrUnsupported
	}
	return pub, nil
}

// tlsPRF implements TLS 1.2 P_SHA256 for the two offered AES-128-GCM suites.
func tlsPRF(secret []byte, label string, seed []byte, size int) []byte {
	input := append([]byte(label), seed...)
	a := bytes.Clone(input)
	out := make([]byte, 0, size+32)
	mac := hmac.New(sha256.New, secret)
	for len(out) < size {
		mac.Reset()
		mac.Write(a)
		clear(a)
		a = mac.Sum(nil)
		mac.Reset()
		mac.Write(a)
		mac.Write(input)
		out = mac.Sum(out)
	}
	clear(a)
	clear(input)
	clear(out[size:])
	return out[:size]
}
