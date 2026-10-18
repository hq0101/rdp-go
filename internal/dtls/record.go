// Package dtls implements an internal DTLS 1.2 client with certificate-authenticated
// ECDHE, AES-128-GCM, bounded handshake retransmission and datagram application I/O.
// RDP lossy-tunnel identity binding and Session integration remain separate work.
package dtls

import (
	"encoding/binary"
	"errors"
)

const (
	Version10        uint16 = 0xfeff // only for initial handshake framing, not GCM
	Version12        uint16 = 0xfefd
	ChangeCipherSpec uint8  = 20
	Alert            uint8  = 21
	Handshake        uint8  = 22
	ApplicationData  uint8  = 23
	RecordHeader            = 13
	MaxPlaintext            = 1 << 14
	MaxCiphertext           = MaxPlaintext + 2048
	MaxDatagram             = 65535
	MaxRecords              = 64
	MaxSequence      uint64 = 1<<48 - 1
)

var (
	ErrInvalid        = errors.New("dtls: invalid encoding or configuration")
	ErrLimit          = errors.New("dtls: resource limit exceeded")
	ErrVersion        = errors.New("dtls: unsupported record version")
	ErrEpoch          = errors.New("dtls: unexpected epoch")
	ErrReplay         = errors.New("dtls: duplicate or stale record")
	ErrAuthentication = errors.New("dtls: record authentication failed")
	ErrSequence       = errors.New("dtls: sequence exhausted")
	ErrConflict       = errors.New("dtls: conflicting handshake fragments")
	ErrClosed         = errors.New("dtls: closed state")
)

type Record struct {
	Type           uint8
	Version, Epoch uint16
	Sequence       uint64
	Payload        []byte
}

func (r Record) String() string   { return "dtls.Record{private payload}" }
func (r Record) GoString() string { return r.String() }

func validType(t uint8) bool { return t >= ChangeCipherSpec && t <= ApplicationData }

func (r Record) validate() error {
	if !validType(r.Type) || r.Sequence > MaxSequence {
		return ErrInvalid
	}
	if r.Version != Version10 && r.Version != Version12 {
		return ErrVersion
	}
	if len(r.Payload) > MaxCiphertext || r.Epoch == 0 && len(r.Payload) > MaxPlaintext {
		return ErrLimit
	}
	return nil
}

func putHeader(b []byte, r Record, length int) {
	b[0] = r.Type
	binary.BigEndian.PutUint16(b[1:3], r.Version)
	binary.BigEndian.PutUint64(b[3:11], uint64(r.Epoch)<<48|r.Sequence)
	binary.BigEndian.PutUint16(b[11:13], uint16(length))
}

func (r Record) Marshal() ([]byte, error) {
	if err := r.validate(); err != nil {
		return nil, err
	}
	b := make([]byte, RecordHeader+len(r.Payload))
	putHeader(b, r, len(r.Payload))
	copy(b[RecordHeader:], r.Payload)
	return b, nil
}

// ParseDatagram accepts complete records only; no record spans datagrams.
// A malformed trailing record rejects the entire input. Successful records
// own their payloads. This validates framing, not plaintext or authentication.
func ParseDatagram(b []byte) ([]Record, error) {
	if len(b) == 0 {
		return nil, ErrInvalid
	}
	if len(b) > MaxDatagram {
		return nil, ErrLimit
	}
	var records []Record
	for len(b) != 0 {
		if len(records) == MaxRecords {
			return nil, ErrLimit
		}
		if len(b) < RecordHeader {
			return nil, ErrInvalid
		}
		n := int(binary.BigEndian.Uint16(b[11:13]))
		if n > MaxCiphertext {
			return nil, ErrLimit
		}
		if n > len(b)-RecordHeader {
			return nil, ErrInvalid
		}
		r := Record{Type: b[0], Version: binary.BigEndian.Uint16(b[1:3]), Epoch: binary.BigEndian.Uint16(b[3:5]), Sequence: binary.BigEndian.Uint64(b[3:11]) & MaxSequence, Payload: b[13 : 13+n]}
		if err := r.validate(); err != nil {
			return nil, err
		}
		r.Payload = append([]byte(nil), r.Payload...)
		records = append(records, r)
		b = b[13+n:]
	}
	return records, nil
}
