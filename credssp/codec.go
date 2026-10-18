// Package credssp implements CredSSP 5/6 with NTLMv2 or Kerberos over verified TLS.
// It delegates a password only after verifying the TLS key binding.
package credssp

import (
	"errors"
	"fmt"
	"github.com/hq0101/rdp-go/internal/der"
	"github.com/hq0101/rdp-go/internal/ntlm"
	"io"
)

type Credentials = ntlm.Credentials

var ErrProtocol = errors.New("credssp: invalid or unsupported protocol message")
var ErrBinding = errors.New("credssp: server public-key binding verification failed")

type StatusError struct{ Code uint32 }

func (e *StatusError) Error() string { return fmt.Sprintf("credssp: server NTSTATUS 0x%08x", e.Code) }

type request struct {
	version                     uint32
	token, auth, binding, nonce []byte
	status                      *uint32
}

func (r request) marshal() []byte {
	b := der.Wrap(0xa0, der.Integer(2, r.version))
	if r.token != nil {
		b = append(b, der.Wrap(0xa1, der.Wrap(0x30, der.Wrap(0x30, der.Wrap(0xa0, der.Wrap(4, r.token)))))...)
	}
	for _, f := range []struct {
		tag  byte
		data []byte
	}{{0xa2, r.auth}, {0xa3, r.binding}} {
		if f.data != nil {
			b = append(b, der.Wrap(f.tag, der.Wrap(4, f.data))...)
		}
	}
	if r.status != nil {
		b = append(b, der.Wrap(0xa4, der.Integer(2, *r.status))...)
	}
	if r.nonce != nil {
		b = append(b, der.Wrap(0xa5, der.Wrap(4, r.nonce))...)
	}
	return der.Wrap(0x30, b)
}

func unwrap(b []byte, tag byte) ([]byte, error) {
	p, err := der.Take(&b, tag)
	if err != nil || len(b) != 0 {
		return nil, ErrProtocol
	}
	return p, nil
}
func parseRequest(b []byte) (request, error) {
	var r request
	b, err := unwrap(b, 0x30)
	if err != nil {
		return r, err
	}
	last := byte(0x9f)
	for len(b) > 0 {
		tag := b[0]
		if tag < 0xa0 || tag > 0xa5 || tag <= last {
			return r, ErrProtocol
		}
		last = tag
		p, err := der.Take(&b, tag)
		if err != nil {
			return r, err
		}
		switch tag {
		case 0xa0, 0xa4:
			p, err = unwrap(p, 2)
			if err != nil {
				return r, err
			}
			v, err := der.Uint(p)
			if err != nil {
				return r, err
			}
			if tag == 0xa0 {
				r.version = v
			} else {
				r.status = &v
			}
		case 0xa1:
			for _, t := range []byte{0x30, 0x30, 0xa0, 4} {
				p, err = unwrap(p, t)
				if err != nil {
					return r, err
				}
			}
			r.token = p
		default:
			p, err = unwrap(p, 4)
			if err != nil {
				return r, err
			}
			switch tag {
			case 0xa2:
				r.auth = p
			case 0xa3:
				r.binding = p
			case 0xa5:
				r.nonce = p
			}
		}
	}
	if r.version < 2 {
		return r, ErrProtocol
	}
	return r, nil
}
func readRequest(r io.Reader) (request, error) {
	b, err := der.ReadSequence(r)
	if err != nil {
		return request{}, err
	}
	v, err := parseRequest(b)
	if err != nil {
		return v, err
	}
	if v.status != nil {
		return v, &StatusError{Code: *v.status}
	}
	return v, nil
}
func passwordCredentials(c Credentials) []byte {
	inner := der.Wrap(0x30, der.Wrap(0xa0, der.Wrap(4, ntlm.UTF16(c.Domain))), der.Wrap(0xa1, der.Wrap(4, ntlm.UTF16(c.Username))), der.Wrap(0xa2, der.Wrap(4, ntlm.UTF16(c.Password))))
	return der.Wrap(0x30, der.Wrap(0xa0, der.Integer(2, 1)), der.Wrap(0xa1, der.Wrap(4, inner)))
}
