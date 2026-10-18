// Package spnego provides the bounded DER envelope shared by CredSSP and
// HTTP Negotiate. Callers enforce mechanism choice, message order and MICs.
package spnego

import (
	"bytes"
	"encoding/asn1"
	"errors"
	"github.com/hq0101/rdp-go/internal/der"
)

var ErrInvalid = errors.New("spnego: invalid negotiation token")

const MaxToken = 128 << 10
const NTLMOID = "\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"

var oid = []byte{6, 6, 0x2b, 6, 1, 5, 5, 2}

func NTLMList() []byte { return der.Wrap(0x30, []byte(NTLMOID)) }
func Initial(token, list []byte) []byte {
	return der.Wrap(0x60, oid, der.Wrap(0xa0, der.Wrap(0x30, der.Wrap(0xa0, list), der.Wrap(0xa2, der.Wrap(4, token)))))
}

// Authenticate encodes an initiator NegTokenResp. A nil MIC omits the field;
// an explicitly empty MIC is represented, so validation can distinguish it.
func Authenticate(token, mic []byte) []byte {
	var fields []byte
	if token != nil {
		fields = append(fields, der.Wrap(0xa2, der.Wrap(4, token))...)
	}
	if mic != nil {
		fields = append(fields, der.Wrap(0xa3, der.Wrap(4, mic))...)
	}
	return der.Wrap(0xa1, der.Wrap(0x30, fields))
}

type Response struct {
	State                 int // -1 means absent, distinct from accept-completed (0)
	Mechanism, Token, MIC []byte
}

// Unlike the outer TSRequest's bounded BER reader, negotiation tokens use DER.
// Check shortest lengths as well as tag, order, duplicates and complete input.
func take(b *[]byte, tag byte) ([]byte, error) {
	before := *b
	p, err := der.Take(b, tag)
	if err != nil || !bytes.Equal(before[:len(before)-len(*b)], der.Wrap(tag, p)) {
		return nil, ErrInvalid
	}
	return p, nil
}

func unwrap(b []byte, tag byte) ([]byte, error) {
	p, err := take(&b, tag)
	if err != nil || len(b) != 0 {
		return nil, ErrInvalid
	}
	return p, nil
}

func ParseResponse(b []byte) (Response, error) {
	r := Response{State: -1}
	if len(b) > MaxToken {
		return r, ErrInvalid
	}
	b, err := unwrap(b, 0xa1)
	if err != nil {
		return r, err
	}
	b, err = unwrap(b, 0x30)
	if err != nil {
		return r, err
	}
	last := byte(0x9f)
	for len(b) > 0 {
		tag := b[0]
		if tag <= last || tag > 0xa3 {
			return r, ErrInvalid
		}
		last = tag
		field, err := take(&b, tag)
		if err != nil {
			return r, err
		}
		switch tag {
		case 0xa0:
			value, err := unwrap(field, 0x0a)
			if err != nil || len(value) != 1 || value[0] > 3 {
				return r, ErrInvalid
			}
			r.State = int(value[0])
		case 0xa1:
			// Validate even a repeated supportedMech that will be ignored after
			// selection (MS-SPNG 3.3.5). Unknown OIDs are never offered/selected.
			var oid asn1.ObjectIdentifier
			rest, err := asn1.Unmarshal(field, &oid)
			if err != nil || len(rest) != 0 {
				return r, ErrInvalid
			}
			canonical, err := asn1.Marshal(oid)
			if err != nil || !bytes.Equal(field, canonical) {
				return r, ErrInvalid
			}
			r.Mechanism = field
		default:
			value, err := unwrap(field, 4)
			if err != nil {
				return r, err
			}
			if tag == 0xa2 {
				r.Token = value
			} else {
				r.MIC = value
			}
		}
	}
	return r, nil
}
