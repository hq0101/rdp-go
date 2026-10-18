package rdp

import (
	"errors"
	"net"

	"github.com/hq0101/rdp-go/rdpudp"
	"github.com/hq0101/rdp-go/rdpudp2"
)

// Only this adapter's observed failure can authorize sideband recovery. An
// EOF manufactured by a decoder or TLS failure must never be sufficient.
type dynamicUDP interface {
	Err() error
	Stats() rdpudp.ConnStats
}

type sideFailureError struct {
	cause   error
	network bool
}

func (e *sideFailureError) Error() string { return "rdp reliable tunnel: " + e.cause.Error() }
func (e *sideFailureError) Unwrap() error { return e.cause }

func sideNetworkError(err error) bool {
	return reconnectableNetworkError(err) || errors.Is(err, rdpudp.ErrDataTimeout) ||
		errors.Is(err, rdpudp.ErrRetransmits) || errors.Is(err, rdpudp2.ErrTimeout)
}

func (m *dynamicState) sideError(err error) error {
	if m.mainFailed.Load() || m.life.Err() != nil {
		return err
	}
	m.mu.Lock()
	u, bound := m.udp, m.info.Bound
	m.mu.Unlock()
	network := bound && u != nil && sideNetworkError(err) && sideNetworkError(u.Err())
	return &sideFailureError{cause: err, network: network}
}

func (m *dynamicState) stopSide(err error) {
	if m.mainFailed.Load() || m.life.Err() != nil {
		return
	}
	m.stop(m.sideError(err))
}

func (s *Session) sideNetworkFailed() bool {
	if s.dynamic == nil {
		return false
	}
	s.dynamic.mu.Lock()
	defer s.dynamic.mu.Unlock()
	return s.dynamic.info.SideNetworkFailure
}

func (s *Session) networkFailed() bool {
	return s.connection.Transport.failedNetwork() || s.sideNetworkFailed()
}

func recoverableSessionError(err error) bool {
	var side *sideFailureError
	if errors.As(err, &side) {
		return side.network
	}
	return reconnectableNetworkError(err) || errors.Is(err, net.ErrClosed)
}
