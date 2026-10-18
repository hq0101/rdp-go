// Package cliprdr implements bounded MS-RDPECLIP delayed-rendering transfers.
// It never reads or changes the operating system clipboard. Callers explicitly
// publish/request formats and transport returned PDUs over the cliprdr channel.
package cliprdr

import (
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/hq0101/rdp-go/vchan"
)

const MaxTextBytes = 256 << 10
const UnicodeText = 13

var (
	ErrProtocol = errors.New("cliprdr: invalid or unexpected clipboard PDU")
	ErrText     = errors.New("cliprdr: invalid or oversized Unicode text")
	ErrNotReady = errors.New("cliprdr: channel is not ready")
	ErrBusy     = errors.New("cliprdr: a clipboard operation is still pending")
	ErrNoText   = errors.New("cliprdr: remote clipboard has no Unicode text")
	ErrRejected = errors.New("cliprdr: remote clipboard operation was rejected")
	ErrChanged  = errors.New("cliprdr: clipboard changed while data was being requested")
)

type EventKind uint8

const (
	NoEvent EventKind = iota
	Ready
	RemoteFormats
	OfferResult
	TextResult
	TextServed
	DataResult
	DataServed
	FileListResult
	FileContentsNeeded
	FileContentsResult
	FileRetentionChanged
)

type Event struct {
	Files       *FileList
	FileRequest *FileRequest
	FileResult  *FileResult
	Kind        EventKind
	Text        string
	Format      Format
	Data        []byte // owned generic-format bytes; nil for the RequestText wrapper
	Err         error
}
type Status struct {
	Ready         bool   `json:"ready"`
	Busy          bool   `json:"busy"`
	RemoteText    bool   `json:"remote_text"`
	LocalOwned    bool   `json:"local_owned"`
	LocalAccepted bool   `json:"local_accepted"`
	RemoteVersion uint64 `json:"remote_version"`
}

// Client's zero value is ready to receive server capabilities and Monitor Ready.
// All methods require caller synchronization. Keep one client per connection.
// Initial synchronization advertises an empty clipboard. Nothing is requested
// automatically or forwarded to a local clipboard. File streaming is opt-in.
type Client struct {
	files                                 *fileState
	ready, capsSeen, longNames            bool
	offerPending, readPending             bool
	offerLocal                            bool
	localOwned, localAccepted, remoteText bool
	local                                 []Data
	remoteFormats                         []Format
	readFormat                            Format
	readText                              bool
	remoteVersion, readVersion            uint64
}

func (c *Client) Status() Status {
	return Status{c.ready, c.offerPending || c.readPending, c.remoteText, c.localOwned, c.localAccepted, c.remoteVersion}
}

func packet(typ, flags uint16, body []byte) []byte {
	b := binary.LittleEndian.AppendUint16(nil, typ)
	b = binary.LittleEndian.AppendUint16(b, flags)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(body)))
	return append(b, body...)
}

// EncodeText creates null-terminated CF_UNICODETEXT with Windows CRLF newlines.
// Input is UTF-8, bounded to MaxTextBytes, and cannot contain embedded NULs.
func EncodeText(text string) ([]byte, error) {
	if len(text) > MaxTextBytes || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
		return nil, ErrText
	}
	text = strings.ReplaceAll(strings.ReplaceAll(text, "\r\n", "\n"), "\r", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n")
	u := utf16.Encode([]rune(text))
	b := make([]byte, (len(u)+1)*2)
	if len(b) > vchan.MaxMessage-8 {
		return nil, ErrText
	}
	for i, v := range u {
		binary.LittleEndian.PutUint16(b[i*2:], v)
	}
	return b, nil
}

// DecodeText validates UTF-16 through the first NUL and normalizes CRLF to LF.
// Bytes after the terminator are allocation padding and are not exposed.
func DecodeText(b []byte) (string, error) {
	if len(b) < 2 || len(b)%2 != 0 || len(b) > vchan.MaxMessage-8 {
		return "", ErrText
	}
	var out strings.Builder
	for i := 0; i < len(b); i += 2 {
		u := binary.LittleEndian.Uint16(b[i:])
		if u == 0 {
			text := strings.ReplaceAll(out.String(), "\r\n", "\n")
			if len(text) > MaxTextBytes {
				return "", ErrText
			}
			return text, nil
		}
		r := rune(u)
		if u >= 0xd800 && u <= 0xdbff {
			if i+4 > len(b) {
				return "", ErrText
			}
			v := binary.LittleEndian.Uint16(b[i+2:])
			if v < 0xdc00 || v > 0xdfff {
				return "", ErrText
			}
			r = utf16.DecodeRune(r, rune(v))
			i += 2
		} else if u >= 0xdc00 && u <= 0xdfff {
			return "", ErrText
		}
		out.WriteRune(r)
		if out.Len() > MaxTextBytes*2 {
			return "", ErrText
		}
	}
	return "", ErrText
}

// PublishText offers text using delayed rendering. Handle must continue running
// to receive the acknowledgement and serve later server data requests. Wait for
// OfferResult before describing the offer as accepted. A wire send failure must
// terminate this client/connection; do not reuse the advanced protocol state.
func (c *Client) PublishText(text string) ([]byte, error) {
	data, err := EncodeText(text)
	if err != nil {
		return nil, err
	}
	return c.Publish([]Data{{Format: Format{ID: UnicodeText}, Bytes: data}})
}

// RequestText is the typed Unicode wrapper. Pending requests must be drained
// after a caller timeout; a response has no request ID on the wire.
func (c *Client) RequestText() ([]byte, error) {
	b, err := c.Request(Format{ID: UnicodeText})
	if err == ErrNoFormat {
		return nil, ErrNoText
	}
	if err == nil {
		c.readText = true
	}
	return b, err
}

// Handle consumes exactly one reassembled clipboard PDU. Send returned replies
// in order before calling another operation. Protocol errors are terminal.
func (c *Client) Handle(b []byte) (replies [][]byte, event Event, err error) {
	b, err = clipboardPacket(b)
	if err != nil {
		return nil, event, ErrProtocol
	}
	typ, flags := binary.LittleEndian.Uint16(b), binary.LittleEndian.Uint16(b[2:])
	body := b[8:]
	if !c.ready && typ != 1 && typ != 7 {
		return nil, event, ErrProtocol
	}
	switch typ {
	case 7:
		if c.ready || c.capsSeen || flags != 0 {
			return nil, event, ErrProtocol
		}
		general, err := capabilities(body)
		if err != nil {
			return nil, event, err
		}
		c.capsSeen, c.longNames = true, general&capLong != 0
		if c.files != nil && general&(capLong|capFiles) == capLong|capFiles {
			c.files.negotiated = general&(capFiles|capLock|capHuge) | capNoPaths
		}
	case 1:
		if c.ready || flags != 0 || len(body) != 0 {
			return nil, event, ErrProtocol
		}
		if c.capsSeen {
			general := uint32(2)
			if c.files != nil {
				general |= c.files.negotiated
			}
			caps := []byte{1, 0, 0, 0, 1, 0, 12, 0, 2, 0, 0, 0}
			replies = append(replies, packet(7, 0, binary.LittleEndian.AppendUint32(caps, general)))
		}
		replies = append(replies, packet(2, 0, nil))
		c.ready, c.offerPending = true, true
		event.Kind = Ready
	case 2:
		if flags != 0 && flags != 4 {
			return nil, event, ErrProtocol
		}
		list, err := parseFormats(body, c.longNames, flags == 4)
		if err != nil {
			return nil, event, err
		}
		c.remoteVersion++
		c.remoteFormats = list
		c.remoteText = false
		for _, f := range list {
			if f.ID == UnicodeText {
				c.remoteText = true
			}
		}
		c.localOwned, c.localAccepted = false, false
		c.clearLocal()
		replies = [][]byte{packet(3, 1, nil)}
		event.Kind = RemoteFormats
	case 3:
		if !c.offerPending || len(body) != 0 || (flags != 1 && flags != 2) {
			return nil, event, ErrProtocol
		}
		if c.files != nil && c.files.offer != nil {
			if flags == 2 {
				c.files.offer.rejected = true
			}
			c.files.offer = nil
		}
		c.offerPending = false
		c.localAccepted = flags == 1 && c.localOwned
		event.Kind = OfferResult
		if c.offerLocal && !c.localOwned && flags == 1 {
			event.Err = ErrChanged
		}
		c.offerLocal = false
		if flags == 2 {
			c.localOwned = false
			c.clearLocal()
			event.Err = ErrRejected
		}
	case 4:
		if flags != 0 || len(body) != 4 {
			return nil, event, ErrProtocol
		}
		id := binary.LittleEndian.Uint32(body)
		replies = [][]byte{packet(5, 2, nil)}
		if c.localOwned {
			for _, d := range c.local {
				if d.Format.ID == id {
					replies = [][]byte{packet(5, 1, d.Bytes)}
					event.Kind = DataServed
					event.Format = d.Format
					if id == UnicodeText {
						event.Kind = TextServed
					}
					break
				}
			}
		}

	case 5:
		if !c.readPending || (flags != 1 && flags != 2) || (flags == 2 && len(body) != 0) {
			return nil, event, ErrProtocol
		}
		event.Kind = DataResult
		event.Format = c.readFormat
		if c.readText {
			event.Kind = TextResult
		}
		if flags == 2 {
			event.Err = ErrRejected
		} else if c.readVersion != c.remoteVersion {
			event.Err = ErrChanged
		} else if c.readText {
			event.Text, event.Err = DecodeText(body)
		} else {
			event.Data = append([]byte{}, body...)
		}
		// Payload decoding failure ends this operation, not the channel. The
		// response is consumed, so a subsequent explicit request is unambiguous.
		if c.readVersion != c.remoteVersion {
			event.Text = ""
			event.Data = nil
			event.Err = ErrChanged
		}
		if c.files != nil && c.files.read != nil {
			replies = c.finishFileList(&event)
		}
		c.readPending = false
		c.readText = false
		c.readFormat = Format{}

	case 8, 9, 10, 11:
		return c.handleFilePDU(typ, flags, body)
	default:
		return nil, event, ErrProtocol // unsupported / direct-filesystem mode
	}
	return replies, event, nil
}

// MS-RDPECLIP Appendix A <1>: Windows can append four bytes outside dataLen.
// Ignore exactly that trailer, never treat it as format data or a clipDataId.
// All other length mismatches and the aggregate message limit remain errors.
func clipboardPacket(b []byte) ([]byte, error) {
	if len(b) < 8 || len(b) > MaxMessage {
		return nil, ErrProtocol
	}
	n := uint64(binary.LittleEndian.Uint32(b[4:])) + 8
	if n != uint64(len(b)) && n+4 != uint64(len(b)) {
		return nil, ErrProtocol
	}
	return b[:int(n)], nil
}

func capabilities(b []byte) (uint32, error) {
	if len(b) < 4 {
		return 0, ErrProtocol
	}
	n := int(binary.LittleEndian.Uint16(b))
	b = b[4:]
	if n > 64 {
		return 0, ErrProtocol
	}
	var general uint32
	seen := false
	for i := 0; i < n; i++ {
		if len(b) < 4 {
			return 0, ErrProtocol
		}
		typ, l := binary.LittleEndian.Uint16(b), int(binary.LittleEndian.Uint16(b[2:]))
		if l < 4 || l > len(b) {
			return 0, ErrProtocol
		}
		if typ == 1 {
			if seen || l < 12 {
				return 0, ErrProtocol
			}
			seen = true
			general = binary.LittleEndian.Uint32(b[8:])
		}
		b = b[l:]
	}
	if len(b) != 0 {
		return 0, ErrProtocol
	}
	return general, nil
}
