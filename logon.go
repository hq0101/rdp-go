package rdp

import (
	"github.com/hq0101/rdp-go/internal/logon"
	"time"
)

type LogonInfoType uint32

const (
	LogonShort LogonInfoType = iota
	LogonLong
	LogonPlain
	LogonExtended
)

// LogonInfo is one server notification, not the current transport or shell
// state. Logon is true only for an explicit short/long/plain logon notification.
// An extended cookie or warning alone does not imply successful logon.
// Names are the server's report and may differ from the requested credentials.
// ReconnectCookieReceived reports presence only, not stored/reusable credentials
// or server acceptance; consult ReconnectInfo for local readiness. No secret is exposed.
type LogonInfo struct {
	Type                          LogonInfoType
	Logon                         bool
	IdentityKnown, SessionIDKnown bool
	Domain, Username              string
	SessionID                     uint32
	ReconnectCookieReceived       bool
	ErrorNotification             bool
	ErrorType, ErrorData          uint32
}

// LastLogonInfo returns the latest successfully decoded Save Session Info
// notification. The bool is false until one arrives. It is a historical
// snapshot, retained across reactivation and Close; Info().Active is separate.
func (s *Session) LastLogonInfo() (LogonInfo, bool) {
	s.infoMu.RLock()
	defer s.infoMu.RUnlock()
	return s.logonInfo, s.hasLogonInfo
}

func (s *Session) decodeLogon(data []byte) (LogonInfo, error) {
	// No raw cookie is delivered to application event handlers. Best-effort
	// clearing of this payload is not a guarantee about Go/TLS runtime copies.
	defer clear(data)
	m, err := logon.Parse(data)
	if err != nil {
		return LogonInfo{}, err
	}
	defer func() { m.Cookie.Clear() }()
	info := LogonInfo{Type: LogonInfoType(m.Type), Logon: m.Logon, IdentityKnown: m.IdentityKnown, SessionIDKnown: m.SessionIDKnown, Domain: m.Domain, Username: m.Username, SessionID: m.SessionID, ReconnectCookieReceived: m.Cookie != nil, ErrorNotification: m.ErrorNotification, ErrorType: m.ErrorType, ErrorData: m.ErrorData}
	// Transfer ownership only after both endpoints negotiated the extension.
	if r := s.reconnect; r != nil && m.Cookie != nil && s.Info().AutoReconnect {
		r.mu.Lock()
		select {
		case <-s.connection.Transport.closed:
		default:
			if !r.terminal && !r.inProgress {
				r.discardLocked()
				r.cookie = m.Cookie
				m.Cookie = nil
				r.expires = time.Now().Add(time.Hour)
				r.updates++
			}
		}
		r.mu.Unlock()
	}
	s.infoMu.Lock()
	s.logonInfo, s.hasLogonInfo = info, true
	s.infoMu.Unlock()
	return info, nil
}
