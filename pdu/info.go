// Package pdu implements TLS-protected RDP client information, licensing status,
// capability exchange and slow-path share PDUs. It does not render graphics.
package pdu

import (
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var ErrInvalid = errors.New("rdp pdu: invalid or unsupported message")

// SetAudioCapture adjusts only INFO_AUDIOCAPTURE in a ClientInfo buffer produced
// by this package. The caller must implement AUDIO_INPUT before advertising it.
func SetAudioCapture(info []byte, enabled bool) error {
	if len(info) < 22 || binary.LittleEndian.Uint32(info) != 0x40 {
		return ErrInvalid
	}
	flags := binary.LittleEndian.Uint32(info[8:]) &^ uint32(0x200000)
	if enabled {
		flags |= 0x200000
	}
	binary.LittleEndian.PutUint32(info[8:], flags)
	return nil
}

// SetAudioPlayback adjusts INFO_NOAUDIOPLAYBACK in a buffer produced by one of
// this package's ClientInfo encoders, including ClientInfoWithReconnect. No
// credentials or other flags change. This is not a general Client Info parser.
// The caller must have registered rdpsnd and an audio consumer before enabling.
func SetAudioPlayback(info []byte, enabled bool) error {
	if len(info) < 22 || binary.LittleEndian.Uint32(info) != 0x40 {
		return ErrInvalid
	}
	flags := binary.LittleEndian.Uint32(info[8:]) | 0x80000
	if enabled {
		flags &^= 0x80000
	}
	binary.LittleEndian.PutUint32(info[8:], flags)
	return nil
}

func utf16Bytes(s string) []byte {
	var b []byte
	for _, c := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}
	return b
}

// ClientInfo includes the Basic Security Header required for SEC_INFO_PKT even
// under TLS. INFO_AUTOLOGON requires the supplied password here even when NLA
// has already completed. The returned buffer is sensitive; never log it.
// Client address and directory use terminating UTF-16 NULs. The default time zone
// is UTC; no auto-reconnect cookie, bulk compression or audio redirection is sent.
func ClientInfo(user, domain, password, address string, keyboardLayout uint32) ([]byte, error) {
	return ClientInfoWithCompression(user, domain, password, address, keyboardLayout, false)
}

// ClientInfoWithCompression additionally offers MPPC 8K and 64K when enabled.
// The returned buffer contains credentials and must be cleared after sending.
func ClientInfoWithCompression(user, domain, password, address string, keyboardLayout uint32, enabled bool) ([]byte, error) {
	return ClientInfoWithCompressionType(user, domain, password, address, keyboardLayout, enabled, 1)
}

// ClientInfoWithCompressionType offers an inclusive maximum package: 0=MPPC8K,
// 1=MPPC64K, 2=RDP6, 3=RDP6.1. No package is offered when enabled is false.
// The returned buffer contains credentials and must be cleared after sending.
func ClientInfoWithCompressionType(user, domain, password, address string, keyboardLayout uint32, enabled bool, maximum byte) ([]byte, error) {
	return clientInfo(user, domain, password, address, keyboardLayout, enabled, maximum, nil)
}

// ClientInfoWithRedirectionCookie forwards an explicitly selected legacy opaque
// LB_PASSWORD cookie after NLA. The cookie is copied verbatim into Password;
// cbPassword counts all of its bytes and a separate two-byte NUL follows it.
// It is not decoded as Unicode, trimmed, or used for CredSSP authentication.
// The bounded profile accepts 1..510 bytes, leaving room for the terminator in
// the 512-byte password field. It does not implement RDSTLS authentication.
// The caller must classify the cookie and validate its target separately.
// The input is borrowed during this call; clear the returned buffer after use.
func ClientInfoWithRedirectionCookie(user, domain, address string, keyboardLayout uint32, enabled bool, maximum byte, cookie []byte) ([]byte, error) {
	if len(cookie) == 0 || len(cookie) > 510 {
		return nil, ErrInvalid
	}
	return clientInfo(user, domain, "", address, keyboardLayout, enabled, maximum, cookie)
}

func clientInfo(user, domain, password, address string, keyboardLayout uint32, enabled bool, maximum byte, cookie []byte) ([]byte, error) {
	if maximum > 3 {
		return nil, ErrInvalid
	}
	fields := []string{domain, user, password, "", ""}
	encoded := make([][]byte, len(fields))
	defer func() {
		for _, b := range encoded {
			clear(b)
		}
	}()
	for i, s := range fields {
		if i == 2 && cookie != nil {
			encoded[i] = append([]byte(nil), cookie...)
			continue
		}
		if !utf8.ValidString(s) || strings.ContainsRune(s, 0) || len(s) > 1024 {
			return nil, ErrInvalid
		}
		encoded[i] = utf16Bytes(s)
		if len(encoded[i]) > 510 {
			return nil, ErrInvalid
		}
	}
	ip := net.ParseIP(address)
	if ip == nil {
		return nil, ErrInvalid
	}
	family := uint16(2)
	if ip.To4() == nil {
		family = 23
	}
	addr := append(utf16Bytes(ip.String()), 0, 0)
	if len(addr) > 80 {
		return nil, ErrInvalid
	}
	if keyboardLayout == 0 {
		keyboardLayout = 0x409
	}
	b := binary.LittleEndian.AppendUint32(nil, 0x40) // SEC_INFO_PKT
	b = binary.LittleEndian.AppendUint32(b, keyboardLayout&0xffff)
	// Unicode, mouse/wheel, Windows keys, auto-logon, logon/error notifications,
	// and no audio playback. Windows-key input requires INFO_ENABLEWINDOWSKEY.
	flags := uint32(0x000b0159)
	if enabled {
		flags |= 0x80 | uint32(maximum)<<9
	} // INFO_COMPRESSION and CompressionTypeMask
	b = binary.LittleEndian.AppendUint32(b, flags)
	for _, s := range encoded {
		b = binary.LittleEndian.AppendUint16(b, uint16(len(s)))
	}
	for _, s := range encoded {
		b = append(b, s...)
		b = append(b, 0, 0)
	}
	b = binary.LittleEndian.AppendUint16(b, family)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(addr)))
	b = append(b, addr...)
	dir := append(utf16Bytes("openrdp"), 0, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(dir)))
	b = append(b, dir...)
	b = append(b, make([]byte, 172)...)
	b = binary.LittleEndian.AppendUint32(b, 0) // clientSessionId
	// Preserve desktop wallpaper. Disable only full-window drag and menu
	// animations; PERF_DISABLE_WALLPAPER (0x1) must remain clear.
	b = binary.LittleEndian.AppendUint32(b, 6)
	b = append(b, 0, 0, 0, 0, 0, 0) // no reconnect cookie, reserved fields
	return b, nil
}

// ClientInfoAfterRDSTLS carries the selected identity after successful RDSTLS
// authentication. This profile sends the encrypted password only in the RDSTLS
// request; this packet has an empty password and INFO_AUTOLOGON cleared. Real
// RDS interoperability for this profile remains unverified. The caller must
// wait for successful RDSTLS authentication before sending it.
func ClientInfoAfterRDSTLS(user, domain, address string, keyboardLayout uint32, enabled bool, maximum byte) ([]byte, error) {
	b, err := ClientInfoWithCompressionType(user, domain, "", address, keyboardLayout, enabled, maximum)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(b[8:], binary.LittleEndian.Uint32(b[8:])&^8)
	return b, nil
}

// ClientInfoWithReconnect sends a derived ARC_CS_PRIVATE_PACKET. It omits the
// auto-logon password and clears INFO_AUTOLOGON so a rejected cookie cannot
// silently fall back to that password. NLA authentication is still required.
// Both cookie and the returned buffer are sensitive; clear them after use.
func ClientInfoWithReconnect(user, domain, address string, keyboardLayout uint32, enabled bool, maximum byte, cookie []byte) ([]byte, error) {
	if len(cookie) != 28 || binary.LittleEndian.Uint32(cookie) != 28 || binary.LittleEndian.Uint32(cookie[4:]) != 1 {
		return nil, ErrInvalid
	}
	b, err := ClientInfoWithCompressionType(user, domain, "", address, keyboardLayout, enabled, maximum)
	if err != nil {
		return nil, err
	}
	binary.LittleEndian.PutUint32(b[8:], binary.LittleEndian.Uint32(b[8:])&^8)
	// Existing encoder ends with cbAutoReconnectCookie and two reserved words.
	i := len(b) - 6
	out := make([]byte, 0, len(b)+28)
	out = append(out, b[:i]...)
	out = binary.LittleEndian.AppendUint16(out, 28)
	out = append(out, cookie...)
	out = append(out, 0, 0, 0, 0)
	clear(b)
	return out, nil
}
