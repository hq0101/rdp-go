package rdp

import (
	"context"
	"encoding/binary"
	"errors"
	"time"

	"github.com/hq0101/rdp-go/autodetect"
	"github.com/hq0101/rdp-go/mcs"
)

// NetworkInfo is a snapshot for this connection, not a health guarantee.
// RTT/bandwidth metrics are server reports; no sample means unknown, not zero.
// LastDataReceived is updated by the protocol reader, so application stalls can
// delay it. Heartbeat hints do not trigger reconnects or change timeouts.
type NetworkInfo struct {
	Enabled, HeartbeatEnabled       bool
	MessageChannel                  uint16
	Stats                           autodetect.Stats
	LastDataReceived, LastHeartbeat time.Time
	Heartbeats                      uint64
	Heartbeat                       autodetect.Heartbeat
}

func (s *Session) NetworkInfo() NetworkInfo {
	s.networkMu.Lock()
	defer s.networkMu.Unlock()
	v := s.networkInfo
	v.Stats = s.networkDetector.Stats()
	return v
}

func (s *Session) observeNetworkData(n int) error {
	if !s.info.NetworkAutoDetect && !s.info.Heartbeat {
		return nil
	}
	s.networkMu.Lock()
	defer s.networkMu.Unlock()
	if err := s.networkDetector.ObserveData(n); err != nil {
		return err
	}
	s.networkInfo.LastDataReceived = time.Now()
	return nil
}

func (s *Session) handleNetworkMessage(ctx context.Context, b []byte) error {
	if len(b) < 4 {
		return autodetect.ErrInvalid
	}
	// TLS uses the four-byte Basic Security Header. flagsHi is unused, even
	// when FLAGSHI_VALID is set. Reject encryption, wrong directions, and mixed
	// message classes instead of misrouting data into Share/virtual channels.
	flags := binary.LittleEndian.Uint16(b) &^ uint16(0x8000)
	if flags == 2 {
		if s.dynamic == nil {
			return errors.New("rdp: unsolicited multitransport request")
		}
		return s.dynamic.bootstrap(ctx, b)
	}
	now := time.Now()
	s.networkMu.Lock()
	next := s.networkDetector
	var reply []byte
	var err error
	switch flags {
	case 0x1000:
		if !s.info.NetworkAutoDetect {
			err = errors.New("rdp: unsolicited network probe")
			break
		}
		reply, err = next.Handle(b[4:], now, s.networkEstablished)
	case 0x4000:
		if !s.info.Heartbeat {
			err = errors.New("rdp: unsolicited heartbeat")
			break
		}
		var h autodetect.Heartbeat
		h, err = autodetect.ParseHeartbeat(b[4:])
		if err == nil {
			err = next.ObserveData(len(b) - 4)
		}
		if err == nil {
			s.networkInfo.Heartbeat, s.networkInfo.LastHeartbeat = h, now
			s.networkInfo.Heartbeats++
		}
	default:
		err = errors.New("rdp: unsupported message-channel security flags")
	}
	if err == nil {
		s.networkDetector = next
		s.networkInfo.LastDataReceived = now
	}
	s.networkMu.Unlock()
	if err != nil {
		return err
	}
	if reply == nil {
		return nil
	}
	payload := append([]byte{0, 0x20, 0, 0}, reply...)
	p, err := mcs.SendDataRequest(s.info.UserChannel, s.info.MessageChannel, payload)
	if err != nil {
		return err
	}
	return s.connection.Transport.WriteMCS(ctx, p)
}
