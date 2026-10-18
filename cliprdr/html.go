package cliprdr

import (
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

const MaxHTMLBytes = 4 << 20

var ErrHTML = errors.New("cliprdr: invalid or oversized HTML clipboard data")

// HTML contains untrusted UTF-8 markup, never a rendered or sanitized document.
// Consumers must not insert it into a privileged DOM or follow its URLs.
type HTML struct {
	Context, Fragment, SourceURL, Selection string
	HasSelection                            bool
}

// EncodeHTML wraps a fragment with context and computes byte (not rune) offsets.
// It preserves markup verbatim; it does not parse, sanitize or execute HTML.
func EncodeHTML(fragment string) ([]byte, error) {
	if len(fragment) > MaxHTMLBytes-512 || !utf8.ValidString(fragment) || strings.ContainsRune(fragment, 0) {
		return nil, ErrHTML
	}
	const template = "Version:1.0\r\nStartHTML:%010d\r\nEndHTML:%010d\r\nStartFragment:%010d\r\nEndFragment:%010d\r\n"
	const before = "<html><body><!--StartFragment-->"
	const after = "<!--EndFragment--></body></html>"
	start := len(fmt.Sprintf(template, 0, 0, 0, 0))
	first := start + len(before)
	last := first + len(fragment)
	head := fmt.Sprintf(template, start, last+len(after), first, last)
	return []byte(head + before + fragment + after + "\x00"), nil
}

// DecodeHTML validates CF_HTML offsets, optional context/selection, UTF-8 byte
// boundaries and allocation bounds. Trailing allocator padding is not exposed.
// Contextless (-1/-1), CR/LF/CRLF and older 0.9 headers are supported.
func DecodeHTML(b []byte) (HTML, error) {
	var out HTML
	if len(b) == 0 || len(b) > MaxHTMLBytes {
		return out, ErrHTML
	}
	values := map[string]int{}
	seen := map[string]bool{}
	pos := 0
	for pos < len(b) && pos < 16384 {
		if start, ok := values["StartHTML"]; ok && start >= 0 && pos >= start {
			break
		}
		if start, ok := values["StartFragment"]; ok && pos >= start {
			break
		}
		end := pos
		for end < len(b) && end < 16384 && b[end] != '\r' && b[end] != '\n' {
			end++
		}
		if end == len(b) || end == 16384 {
			break
		}
		line := string(b[pos:end])
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			break
		}
		key, value := line[:colon], strings.TrimSpace(line[colon+1:])
		for _, ch := range key {
			if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z') {
				return HTML{}, ErrHTML
			}
		}
		if seen[key] || len(seen) >= 64 {
			return HTML{}, ErrHTML
		}
		seen[key] = true
		switch key {
		case "Version":
			if value != "0.9" && value != "1.0" {
				return HTML{}, ErrHTML
			}
		case "StartHTML", "EndHTML", "StartFragment", "EndFragment", "StartSelection", "EndSelection":
			if value != "-1" {
				if value == "" || len(value) > 20 {
					return HTML{}, ErrHTML
				}
				for _, v := range value {
					if v < '0' || v > '9' {
						return HTML{}, ErrHTML
					}
				}
			}
			n, e := strconv.ParseInt(value, 10, 32)
			if e != nil {
				return HTML{}, ErrHTML
			}
			values[key] = int(n)
		case "SourceURL":
			if !utf8.ValidString(value) || strings.ContainsRune(value, 0) {
				return HTML{}, ErrHTML
			}
			out.SourceURL = value
		}
		pos = end + 1
		if b[end] == '\r' && pos < len(b) && b[pos] == '\n' {
			pos++
		}
	}
	for _, k := range []string{"Version", "StartHTML", "EndHTML", "StartFragment", "EndFragment"} {
		if !seen[k] {
			return HTML{}, ErrHTML
		}
	}
	hs, he, fs, fe := values["StartHTML"], values["EndHTML"], values["StartFragment"], values["EndFragment"]
	valid := func(a, z int) bool {
		return a >= pos && z >= a && z <= len(b) && (a == len(b) || utf8.RuneStart(b[a])) && (z == len(b) || utf8.RuneStart(b[z])) && utf8.Valid(b[a:z]) && !bytes.ContainsRune(b[a:z], 0)
	}
	if !valid(fs, fe) {
		return HTML{}, ErrHTML
	}
	if hs == -1 && he == -1 {
	} else if !valid(hs, he) || fs < hs || fe > he {
		return HTML{}, ErrHTML
	} else {
		out.Context = string(b[hs:he])
	}
	if seen["StartSelection"] != seen["EndSelection"] {
		return HTML{}, ErrHTML
	}
	if seen["StartSelection"] {
		s, e := values["StartSelection"], values["EndSelection"]
		if !valid(s, e) || s < fs || e > fe {
			return HTML{}, ErrHTML
		}
		out.Selection = string(b[s:e])
		out.HasSelection = true
	}
	out.Fragment = string(b[fs:fe])
	return out, nil
}

// PublishHTML also supplies a caller-provided plain text representation. HTML's
// registration ID is local to this client and resolved by name at the peer.
func (c *Client) PublishHTML(fragment, plain string) ([]byte, error) {
	h, e := EncodeHTML(fragment)
	if e != nil {
		return nil, e
	}
	t, e := EncodeText(plain)
	if e != nil {
		return nil, e
	}
	return c.Publish([]Data{{Format{ID: 0xc001, Name: HTMLName}, h}, {Format{ID: UnicodeText}, t}})
}
