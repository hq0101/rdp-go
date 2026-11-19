package cliprdr

import (
	"encoding/binary"
	"errors"
	"github.com/hq0101/rdp-go/vchan"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const MaxMessage = vchan.HardLimit
const MaxDataBytes = MaxMessage - 8
const MaxOfferBytes = 64 << 20
const MaxFormats = 256
const DIB = 8
const DIBV5 = 17
const HTMLName = "HTML Format"
const PNGName = "PNG"

var ErrFormat = errors.New("cliprdr: invalid format or offer limit exceeded")
var ErrNoFormat = errors.New("cliprdr: requested remote format is unavailable")

// Format IDs belong to the advertising endpoint. Registered formats are resolved
// by Name on requests; never reuse a local registered ID on the remote endpoint.
// A standard format (<0xc000) is resolved by ID, irrespective of its display name.
type Format struct {
	ID   uint32
	Name string
}
type Data struct {
	Format Format
	Bytes  []byte
}

func (c *Client) RemoteFormatList() []Format { return append([]Format(nil), c.remoteFormats...) }

// ValidateFormatList checks a complete reassembled Format List PDU using the
// negotiated name encoding without changing ownership, versions or pending
// operations. Native adapters may use it before bounded, ordered deferral.
// It does not acknowledge the offer; Handle must still process it later.
func (c *Client) ValidateFormatList(p []byte) error {
	p, err := clipboardPacket(p)
	if err != nil || !c.ready || binary.LittleEndian.Uint16(p) != 2 {
		return ErrProtocol
	}
	_, err = c.formatList(binary.LittleEndian.Uint16(p[2:]), p[8:])
	return err
}

func (c *Client) formatList(flags uint16, body []byte) ([]Format, error) {
	if flags != 0 && flags != 4 {
		return nil, ErrProtocol
	}
	return parseFormats(body, c.longNames, flags == 4)
}
func (c *Client) clearLocal() {
	c.fileOwnershipChanged()
	for _, d := range c.local {
		clear(d.Bytes)
	}
	c.local = nil
	c.delayed = nil
	c.dataOwner = nil
}

// Reset releases held clipboard bytes and forgets negotiation and pending
// operations. Only use when destroying a connection, never to cancel an
// untagged request on a live channel.
func (c *Client) Reset() {
	c.clearLocal()
	clear(c.serving)
	if c.files != nil {
		// Opaque handles may outlive this Client; release everything reachable
		// through their old owner as well as the Client's own references.
		*c.files = fileState{}
	}
	*c = Client{}
}

// Publish snapshots all representations of one clipboard item. Input order is
// preserved (preferred formats first). Empty offers clear the clipboard. Bytes
// are generic wire data; use the typed encoders for Unicode, HTML, PNG and DIB.
// Wait for OfferResult; a successful offer is not proof of an application paste.
func (c *Client) Publish(data []Data) ([]byte, error) {
	if !c.ready {
		return nil, ErrNotReady
	}
	if c.offerPending || c.readPending || len(c.serving) != 0 {
		return nil, ErrBusy
	}
	if len(data) > MaxFormats {
		return nil, ErrFormat
	}
	list := make([]Format, len(data))
	sum := 0
	for i, d := range data {
		if len(d.Bytes) > MaxDataBytes || len(d.Bytes) > MaxOfferBytes-sum {
			return nil, ErrFormat
		}
		sum += len(d.Bytes)
		list[i] = d.Format
	}
	body, err := encodeFormats(list, c.longNames)
	if err != nil {
		return nil, err
	}
	owned := make([]Data, len(data))
	for i, d := range data {
		owned[i] = Data{d.Format, append([]byte{}, d.Bytes...)}
	}
	return c.beginOffer(body, owned, nil), nil
}

// Request starts one untagged read of an advertised format. Name takes priority
// for registered formats; an ID-only request must be in the current remote list.
// Handle returns owned bytes in DataResult. Decode them separately; no HTML is
// executed and no image profile, link, or file reference is dereferenced here.
func (c *Client) Request(want Format) ([]byte, error) {
	if !c.ready {
		return nil, ErrNotReady
	}
	if c.readPending || c.offerPending {
		return nil, ErrBusy
	}
	var found *Format
	for i := range c.remoteFormats {
		f := &c.remoteFormats[i]
		if (want.Name != "" && (want.ID == 0 || want.ID >= 0xc000) && f.ID >= 0xc000 && strings.EqualFold(want.Name, f.Name)) || (want.Name == "" && want.ID == f.ID) || (want.ID > 0 && want.ID < 0xc000 && want.ID == f.ID) {
			found = f
			break
		}
	}
	if found == nil {
		return nil, ErrNoFormat
	}
	c.readFormat = *found
	c.readPending = true
	c.readText = false
	c.readVersion = c.remoteVersion
	return packet(4, 0, binary.LittleEndian.AppendUint32(nil, found.ID)), nil
}

func validateFormats(list []Format) error {
	if len(list) > MaxFormats {
		return ErrFormat
	}
	ids := map[uint32]bool{}
	var names []string
	for _, f := range list {
		if f.ID == 0 || ids[f.ID] || len(f.Name) > 4096 || !utf8.ValidString(f.Name) || strings.ContainsRune(f.Name, 0) || len(utf16.Encode([]rune(f.Name))) > 1024 {
			return ErrFormat
		}
		ids[f.ID] = true
		if f.ID >= 0xc000 && f.Name != "" {
			// Use the same equivalence as Request; lowercasing alone misses
			// Unicode simple-fold equivalents such as Greek final sigma.
			for _, name := range names {
				if strings.EqualFold(name, f.Name) {
					return ErrFormat
				}
			}
			names = append(names, f.Name)
		}
	}
	return nil
}
func encodeFormats(list []Format, long bool) ([]byte, error) {
	if err := validateFormats(list); err != nil {
		return nil, err
	}
	var b []byte
	for _, f := range list {
		units := utf16.Encode([]rune(f.Name))
		// Do not silently truncate locally published names into another identity.
		if !long && len(units) > 15 {
			return nil, ErrFormat
		}
		b = binary.LittleEndian.AppendUint32(b, f.ID)
		if long {
			for _, u := range units {
				b = binary.LittleEndian.AppendUint16(b, u)
			}
			b = append(b, 0, 0)
		} else {
			start := len(b)
			b = append(b, make([]byte, 32)...)
			for i, u := range units {
				binary.LittleEndian.PutUint16(b[start+i*2:], u)
			}
		}
	}
	return b, nil
}

func parseFormats(b []byte, long, ascii bool) ([]Format, error) {
	if long && ascii {
		return nil, ErrProtocol
	}
	var list []Format
	for len(b) > 0 {
		if len(b) < 4 || len(list) >= MaxFormats {
			return nil, ErrProtocol
		}
		f := Format{ID: binary.LittleEndian.Uint32(b)}
		b = b[4:]
		if !long {
			if len(b) < 32 {
				return nil, ErrProtocol
			}
			name := b[:32]
			b = b[32:]
			if ascii {
				var s strings.Builder
				for _, v := range name {
					if v == 0 {
						break
					}
					s.WriteRune(rune(v))
				}
				f.Name = s.String()
			} else {
				var err error
				f.Name, err = decodeName(name, true)
				if err != nil {
					return nil, err
				}
			}
		} else {
			end := -1
			for i := 0; i+1 < len(b) && i <= 2048; i += 2 {
				if b[i] == 0 && b[i+1] == 0 {
					end = i + 2
					break
				}
			}
			if end < 0 {
				return nil, ErrProtocol
			}
			var err error
			f.Name, err = decodeName(b[:end], false)
			if err != nil {
				return nil, err
			}
			b = b[end:]
		}
		list = append(list, f)
	}
	if validateFormats(list) != nil {
		return nil, ErrProtocol
	}
	return list, nil
}

// Short wire fields can fill the complete fixed field when truncated. A dangling
// high surrogate at that boundary is discarded; long names require a terminator.
func decodeName(b []byte, truncated bool) (string, error) {
	var runes []rune
	for i := 0; i+1 < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 {
			return string(runes), nil
		}
		if u >= 0xd800 && u <= 0xdbff {
			if i+4 > len(b) {
				if truncated {
					return string(runes), nil
				}
				return "", ErrProtocol
			}
			v := binary.LittleEndian.Uint16(b[i+2:])
			if v < 0xdc00 || v > 0xdfff {
				return "", ErrProtocol
			}
			runes = append(runes, utf16.DecodeRune(rune(u), rune(v)))
			i += 2
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", ErrProtocol
		} else {
			runes = append(runes, rune(u))
		}
	}
	if truncated {
		return string(runes), nil
	}
	return "", ErrProtocol
}
