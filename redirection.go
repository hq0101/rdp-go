package rdp

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/hq0101/rdp-go/pdu"
)

// RedirectionError is a terminal server request, distinct from network failure
// and cookie-based automatic reconnect. The old connection is closed before
// DialSession or ReadEvent returns it. Request owns confidential server data;
// call Request.Clear when finished. Error text intentionally contains no target,
// username, password, certificate or routing token.
//
// Plain DialSession/ReadEvent open no new connection. Callers may explicitly use
// DialSessionWithRedirection/FollowRedirection to apply their destination,
// TLS identity and credential policy before dialing a new session.
// Server-supplied certificates never change the library's trust policy.
type RedirectionError struct {
	Request *pdu.Redirection
	source  *Session
	claimed atomic.Bool
}

func (*RedirectionError) Error() string                { return "rdp: server requested session redirection" }
func (r *RedirectionError) Format(f fmt.State, _ rune) { _, _ = io.WriteString(f, r.Error()) }

// Only dialSession may create this tag, after verifying that its own protocol
// reader emitted the request. errors.As alone cannot distinguish a real wire
// redirect from an application TLS callback returning another session's error.
type activationRedirection struct {
	request *RedirectionError
	cause   error
}

func (e *activationRedirection) Error() string { return "rdp activation: " + e.cause.Error() }
func (e *activationRedirection) Unwrap() error { return e.cause }

func (s *Session) handleRedirection(v pdu.Share) (*Event, error) {
	defer clear(v.Body)
	request, err := pdu.ParseRedirection(v)
	if err != nil {
		return nil, err
	}
	info, err := request.Info()
	if err != nil {
		request.Clear()
		return nil, err
	}
	if s.hasExpectedTSVURL && info.Flags&pdu.RedirectTSVURL != 0 {
		url, err := request.Field(pdu.RedirectTSVURL)
		digest := sha256.Sum256(url)
		clear(url)
		if err != nil || digest != s.expectedTSVURL {
			request.Clear()
			return nil, errors.New("rdp: redirected TSV URL differs from the requested value")
		}
	}
	if info.Flags&pdu.RedirectInformationOnly != 0 {
		request.Clear()
		return &Event{Kind: EventRedirectionInfo, Channel: s.info.IOChannel, Redirection: info}, nil
	}
	s.redirectPending.Store(true)
	return nil, &RedirectionError{Request: request, source: s}
}

// Licensing has a different header from ordinary shares. A broker may redirect
// before licensing, so inspect only the precise redirection type at this point.
// The outer framing remains strict and no standard-security variant is accepted.
func (s *Session) redirectionBeforeLicense(payload []byte) (bool, error) {
	if len(payload) < 4 || binary.LittleEndian.Uint16(payload[2:])&15 != pdu.RedirectionPDU {
		return false, nil
	}
	shares, err := pdu.ParseShares(payload)
	if err != nil {
		return true, err
	}
	for _, v := range shares {
		if v.Type != pdu.RedirectionPDU || v.Source != 1002 {
			return true, pdu.ErrInvalid
		}
		event, err := s.handleRedirection(v)
		if err != nil {
			return true, err
		}
		if len(s.pending) >= 16 {
			return true, errors.New("rdp: too many redirection notices before activation")
		}
		s.pending = append(s.pending, *event)
	}
	return true, nil
}
