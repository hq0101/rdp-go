package rdp

import (
	"encoding/binary"
	"unicode/utf16"

	"github.com/hq0101/rdp-go/pdu"
)

// RedirectionPasswordMode classifies server-supplied LB_PASSWORD material.
// Classification is explicit: opaque cookies can resemble valid Unicode.
type RedirectionPasswordMode uint8

const (
	// RedirectionPasswordReject is the default when LB_PASSWORD is present.
	RedirectionPasswordReject RedirectionPasswordMode = iota
	// RedirectionPasswordIgnore performs a fresh NLA/Client Info login with the
	// returned Credentials. Deployments requiring the supplied cookie may fail.
	RedirectionPasswordIgnore
	// RedirectionPasswordUTF16 accepts a terminated, well-formed clear password
	// (at most 512 bytes including NUL). It replaces Credentials.Password for
	// NLA and Client Info. Credentials.Username/Domain must match server fields
	// when present. An empty password is valid; the terminator is never hashed.
	RedirectionPasswordUTF16
	// RedirectionPasswordCookie forwards 1..510 opaque bytes in Client Info.
	// NLA uses the separately supplied Credentials, whose username/domain must
	// match server fields when present. No TLS-only fallback is attempted.
	// This legacy compatibility path needs real RDS interoperability validation.
	RedirectionPasswordCookie
	// RedirectionPasswordRDSTLS sends PK-encrypted credentials using RDSTLS v1,
	// with both the explicit target trust policy and broker certificate binding.
	// Requires username/domain, GUID, certificate and encrypted password fields.
	// Credentials supplies matching names only; its Password is unused. SPNEGO,
	// Kerberos and IgnoreServerPassword cannot be combined with this mode.
	// Real RDS interoperability remains unverified.
	RedirectionPasswordRDSTLS
)

// The returned cookie is an owned mutable copy, cleared by the dial caller.
// No secret is attached to an error. Password strings follow Credentials'
// lifetime: Go cannot guarantee erasure of strings or cryptographic copies.
func redirectedCredentials(request *pdu.Redirection, info pdu.RedirectionInfo, target RedirectionTarget) (Credentials, []byte, error) {
	fail := func(err error) (Credentials, []byte, error) { return Credentials{}, nil, err }
	if info.Flags&pdu.RedirectPasswordPKEncrypted != 0 {
		return fail(ErrRedirectionRDSTLS)
	}
	mode := target.PasswordMode
	if target.IgnoreServerPassword {
		if mode != RedirectionPasswordReject {
			return fail(ErrRedirectionCredentials)
		}
		mode = RedirectionPasswordIgnore
	}
	if mode > RedirectionPasswordCookie {
		return fail(ErrRedirectionCredentials)
	}
	c := target.Credentials
	if info.Flags&pdu.RedirectDontStoreUsername != 0 && c.Username != info.Username {
		return fail(ErrRedirectionCredentials)
	}
	if mode == RedirectionPasswordUTF16 || mode == RedirectionPasswordCookie {
		if info.Flags&pdu.RedirectPassword == 0 || info.Flags&pdu.RedirectSmartcard != 0 ||
			info.Flags&pdu.RedirectUsername != 0 && c.Username != info.Username ||
			info.Flags&pdu.RedirectDomain != 0 && c.Domain != info.Domain {
			return fail(ErrRedirectionCredentials)
		}
		raw, err := request.Field(pdu.RedirectPassword)
		if err != nil {
			return fail(err)
		}
		if mode == RedirectionPasswordCookie {
			if len(raw) == 0 || len(raw) > 510 {
				clear(raw)
				return fail(ErrRedirectionCredentials)
			}
			if err := c.Validate(); err != nil {
				clear(raw)
				return fail(err)
			}
			return c, raw, nil
		}
		c.Password, err = redirectionPassword(raw)
		clear(raw)
		if err != nil {
			return fail(err)
		}
	} else if mode == RedirectionPasswordReject && info.Flags&pdu.RedirectPassword != 0 {
		return fail(ErrRedirectionCredentials)
	}
	if err := c.Validate(); err != nil {
		return fail(err)
	}
	return c, nil, nil
}

func redirectionPassword(raw []byte) (string, error) {
	if len(raw) < 2 || len(raw) > 512 || len(raw)%2 != 0 || binary.LittleEndian.Uint16(raw[len(raw)-2:]) != 0 {
		return "", ErrRedirectionCredentials
	}
	units := make([]uint16, len(raw)/2-1)
	defer clear(units)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(raw[2*i:])
	}
	for i := 0; i < len(units); i++ {
		u := units[i]
		if u == 0 || u >= 0xdc00 && u <= 0xdfff {
			return "", ErrRedirectionCredentials
		}
		if u >= 0xd800 && u <= 0xdbff {
			i++
			if i == len(units) || units[i] < 0xdc00 || units[i] > 0xdfff {
				return "", ErrRedirectionCredentials
			}
		}
	}
	runes := utf16.Decode(units)
	defer clear(runes)
	return string(runes), nil
}
