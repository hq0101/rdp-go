// Package kerberos implements bounded Kerberos ticket acquisition for the RDP
// client. Application authentication and CredSSP integration are separate steps.
package kerberos

import (
	"errors"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/hq0101/rdp-go/internal/der"
	"github.com/hq0101/rdp-go/internal/krbcrypto"
)

var (
	ErrInvalid     = errors.New("kerberos: invalid message or configuration")
	ErrUnsupported = errors.New("kerberos: unsupported mechanism or extension")
	ErrIdentity    = errors.New("kerberos: reply identity does not match request")
	ErrReply       = errors.New("kerberos: invalid authenticated reply")
)

type Principal struct {
	NameType   int32
	Components []string
}

func (p Principal) valid() bool {
	if p.NameType < 0 || len(p.Components) == 0 || len(p.Components) > 16 {
		return false
	}
	for _, s := range p.Components {
		if !validName(s, 1024) {
			return false
		}
	}
	return true
}
func (p Principal) clone() Principal {
	return Principal{p.NameType, append([]string(nil), p.Components...)}
}
func (p Principal) equal(q Principal) bool {
	// RFC4120 names are the component sequence; name-type is only a hint.
	if len(p.Components) != len(q.Components) {
		return false
	}
	for i := range p.Components {
		if p.Components[i] != q.Components[i] {
			return false
		}
	}
	return true
}
func (p Principal) marshal() []byte {
	var names []byte
	for _, s := range p.Components {
		names = append(names, generalString(s)...)
	}
	return sequence(contextField(0, integer(uint32(p.NameType))), contextField(1, sequence(names)))
}
func parsePrincipal(b []byte) (Principal, error) {
	f := readFields(b, 0, 3, 3)
	p := Principal{NameType: f.int32(0)}
	items := f.get(1, 0x30)
	for f.err == nil && len(items) > 0 {
		if len(p.Components) >= 16 {
			return p, ErrInvalid
		}
		name, _, err := take(&items, 0x1b)
		f.reject(err)
		p.Components = append(p.Components, string(name))
	}
	if !p.valid() {
		f.reject(ErrInvalid)
	}
	return p, f.err
}
func (f *fields) principal(i int) Principal {
	p, err := parsePrincipal(f.raw[i])
	f.reject(err)
	return p
}

type encryptedData struct {
	Type    int32
	KVNO    uint32
	HasKVNO bool
	Cipher  []byte
}

func (e encryptedData) marshal() []byte {
	parts := [][]byte{contextField(0, integer(uint32(e.Type)))}
	if e.HasKVNO {
		parts = append(parts, contextField(1, integer(e.KVNO)))
	}
	return sequence(append(parts, contextField(2, octets(e.Cipher)))...)
}
func parseEncrypted(b []byte) (encryptedData, error) {
	f := readFields(b, 0, 7, 5)
	e := encryptedData{Type: f.int32(0), HasKVNO: f.has(1)}
	if e.HasKVNO {
		e.KVNO = f.uint32(1)
	}
	e.Cipher = f.get(2, 4)
	if len(e.Cipher) == 0 {
		f.reject(ErrInvalid)
	}
	return e, f.err
}

type paData struct {
	Type  int32
	Value []byte
}

func marshalPA(items []paData) []byte {
	var b []byte
	for _, p := range items {
		b = append(b, sequence(contextField(1, integer(uint32(p.Type))), contextField(2, octets(p.Value)))...)
	}
	return sequence(b)
}
func parsePA(b []byte) ([]paData, error) {
	items, err := unwrap(b, 0x30)
	if err != nil {
		return nil, err
	}
	var result []paData
	for len(items) > 0 {
		if len(result) >= maxItems {
			return nil, ErrInvalid
		}
		_, item, err := take(&items, 0x30)
		if err != nil {
			return nil, err
		}
		f := readFields(item, 0, 6, 6)
		p := paData{Type: f.int32(1), Value: f.get(2, 4)}
		if f.err != nil || len(p.Value) > 64<<10 {
			return nil, ErrInvalid
		}
		result = append(result, p)
	}
	return result, nil
}
func uniquePA(items []paData, kind int32) ([]byte, bool, error) {
	var found []byte
	present := false
	for _, p := range items {
		if p.Type == kind {
			if present {
				return nil, false, ErrInvalid
			}
			found = p.Value
			present = true
		}
	}
	return found, present, nil
}

type wireTicket struct {
	Realm     string
	Server    Principal
	Encrypted encryptedData
	Raw       []byte
}

func parseTicket(b []byte) (wireTicket, error) {
	f := readFields(b, 0x61, 15, 15)
	t := wireTicket{Realm: f.text(1, 1024), Server: f.principal(2), Raw: b}
	if f.int32(0) != 5 {
		f.reject(ErrInvalid)
	}
	var err error
	t.Encrypted, err = parseEncrypted(f.raw[3])
	f.reject(err)
	return t, f.err
}

type kdcReply struct {
	Type        int32
	PA          []paData
	ClientRealm string
	Client      Principal
	Ticket      wireTicket
	Encrypted   encryptedData
}

func parseReply(b []byte, kind int32) (kdcReply, error) {
	r := kdcReply{}
	if kind != 11 && kind != 13 {
		return r, ErrInvalid
	}
	f := readFields(b, byte(0x60+kind), 0x7f, 0x7b)
	r.Type = f.int32(1)
	if f.int32(0) != 5 || r.Type != kind {
		f.reject(ErrInvalid)
	}
	var err error
	if f.has(2) {
		r.PA, err = parsePA(f.raw[2])
		f.reject(err)
		if len(r.PA) == 0 {
			f.reject(ErrInvalid)
		}
	}
	r.ClientRealm = f.text(3, 1024)
	r.Client = f.principal(4)
	r.Ticket, err = parseTicket(f.raw[5])
	f.reject(err)
	r.Encrypted, err = parseEncrypted(f.raw[6])
	f.reject(err)
	return r, f.err
}

// KDCError contains an unauthenticated server error. Text is deliberately not
// exposed as a diagnostic, and its clock/realm cannot redirect or retime us.
type KDCError struct {
	Code        int32
	serverRealm string
	server      Principal
	data        []byte
}

func (e *KDCError) Error() string    { return fmt.Sprintf("kerberos KDC: error %d", e.Code) }
func (e *KDCError) GoString() string { return e.Error() }
func parseError(b []byte) (*KDCError, error) {
	f := readFields(b, 0x7e, 0x1fff, 0x673)
	if f.int32(0) != 5 || f.int32(1) != 30 {
		f.reject(ErrInvalid)
	}
	if f.has(2) {
		f.timestamp(2)
	}
	if f.has(3) {
		f.microseconds(3)
	}
	f.timestamp(4)
	f.microseconds(5)
	e := &KDCError{Code: f.int32(6), serverRealm: f.text(9, 1024), server: f.principal(10)}
	if e.Code < 0 {
		f.reject(ErrInvalid)
	}
	if f.has(7) {
		f.text(7, 1024)
	}
	if f.has(8) {
		f.principal(8)
	}
	if f.has(11) {
		text := f.get(11, 0x1b)
		if len(text) > 64<<10 || !utf8.Valid(text) {
			f.reject(ErrInvalid)
		}
	}
	if f.has(12) {
		e.data = f.get(12, 4)
	}
	return e, f.err
}

type etypeHint struct {
	Type         krbcrypto.Enctype
	Salt, Params []byte
	HasSalt      bool
}

func parseEtypeInfo(b []byte) ([]etypeHint, error) {
	items, err := unwrap(b, 0x30)
	if err != nil {
		return nil, err
	}
	var result []etypeHint
	seen := make(map[krbcrypto.Enctype]bool)
	for len(items) > 0 {
		if len(result) >= maxItems {
			return nil, ErrInvalid
		}
		_, item, err := take(&items, 0x30)
		if err != nil {
			return nil, err
		}
		f := readFields(item, 0, 7, 1)
		h := etypeHint{Type: krbcrypto.Enctype(f.int32(0)), HasSalt: f.has(1)}
		if h.HasSalt {
			h.Salt = f.get(1, 0x1b)
			if len(h.Salt) > krbcrypto.MaxSaltBytes || !utf8.Valid(h.Salt) {
				f.reject(ErrInvalid)
			}
		}
		if f.has(2) {
			h.Params = f.get(2, 4)
			// Parameters belong to the enctype. Unsupported hint types can carry
			// other layouts; StringToKey checks the selected AES profile's four
			// bytes and cost before any password work.
			if len(h.Params) > 64<<10 {
				f.reject(ErrInvalid)
			}
		}
		if f.err != nil || seen[h.Type] {
			return nil, ErrInvalid
		}
		seen[h.Type] = true
		result = append(result, h)
	}
	if len(result) == 0 {
		return nil, ErrInvalid
	}
	return result, nil
}

type replyPart struct {
	KeyType                                 krbcrypto.Enctype
	Key                                     []byte
	Nonce, Flags                            uint32
	AuthTime, StartTime, EndTime, RenewTill time.Time
	Realm                                   string
	Server                                  Principal
	Addresses                               bool
	PA                                      []paData
}

func parseReplyPart(b []byte, kind int32) (replyPart, error) {
	r := replyPart{}
	if kind != 25 && kind != 26 {
		return r, ErrInvalid
	}
	f := readFields(b, byte(0x60+kind), 0x1fff, 0x6b7)
	key := readFields(f.raw[0], 0, 3, 3)
	r.KeyType = krbcrypto.Enctype(key.int32(0))
	r.Key = key.get(1, 4)
	f.reject(key.err)
	last := f.get(1, 0x30)
	for count := 0; len(last) > 0 && f.err == nil; count++ {
		if count >= maxItems {
			f.reject(ErrInvalid)
			break
		}
		_, item, err := take(&last, 0x30)
		f.reject(err)
		entry := readFields(item, 0, 3, 3)
		entry.int32(0)
		entry.timestamp(1)
		f.reject(entry.err)
	}
	r.Nonce = f.uint32(2)
	if f.has(3) {
		f.timestamp(3)
	}
	r.Flags = f.flags(4)
	r.AuthTime = f.timestamp(5)
	r.StartTime = r.AuthTime
	if f.has(6) {
		r.StartTime = f.timestamp(6)
	}
	r.EndTime = f.timestamp(7)
	if f.has(8) {
		r.RenewTill = f.timestamp(8)
	}
	r.Realm = f.text(9, 1024)
	r.Server = f.principal(10)
	if f.has(11) {
		r.Addresses = true
		items := f.get(11, 0x30)
		if len(items) == 0 {
			f.reject(ErrInvalid)
		}
		for count := 0; len(items) > 0 && f.err == nil; count++ {
			if count >= maxItems {
				f.reject(ErrInvalid)
				break
			}
			_, item, err := take(&items, 0x30)
			f.reject(err)
			a := readFields(item, 0, 3, 3)
			a.int32(0)
			if len(a.get(1, 4)) > 1024 {
				a.reject(ErrInvalid)
			}
			f.reject(a.err)
		}
	}
	if f.has(12) {
		var err error
		r.PA, err = parsePA(f.raw[12])
		f.reject(err)
		if len(r.PA) == 0 {
			f.reject(ErrInvalid)
		}
	}
	return r, f.err
}

func marshalBody(client *Principal, realm string, server Principal, till time.Time, nonce uint32, types []krbcrypto.Enctype) []byte {
	parts := [][]byte{contextField(0, bitFlags(0))}
	if client != nil {
		parts = append(parts, contextField(1, client.marshal()))
	}
	parts = append(parts, contextField(2, generalString(realm)), contextField(3, server.marshal()), contextField(5, kerberosTime(till)), contextField(7, integer(nonce)))
	var list []byte
	for _, e := range types {
		list = append(list, integer(uint32(e))...)
	}
	return sequence(append(parts, contextField(8, sequence(list)))...)
}
func marshalRequest(kind byte, body []byte, pa []paData) []byte {
	return application(kind, contextField(1, integer(5)), contextField(2, integer(uint32(kind))), contextField(3, marshalPA(pa)), contextField(4, body))
}
func marshalTimestamp(t time.Time) []byte {
	return sequence(contextField(0, kerberosTime(t)), contextField(1, integer(uint32(t.Nanosecond()/1000))))
}
func marshalChecksum(kind int32, value []byte) []byte {
	return sequence(contextField(0, integer(uint32(kind))), contextField(1, octets(value)))
}
func parseChecksum(b []byte) (int32, []byte, error) {
	f := readFields(b, 0, 3, 3)
	kind := f.int32(0)
	sum := f.get(1, 4)
	return kind, sum, f.err
}
func pacRequest() paData { return paData{128, sequence(contextField(0, der.Wrap(1, []byte{0xff})))} }
