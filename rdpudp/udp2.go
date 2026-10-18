package rdpudp

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/hq0101/rdp-go/rdpudp2"
)

// HashCookie converts the main RDP connection's 16-byte securityCookie to the
// eight SHA-256 words of a Version3 SYN. It is not authentication by itself.
// Windows interprets each four digest bytes as a little-endian word, then
// transmits that word in network order. Sending the raw digest instead causes
// Windows 10 22H2 to reject the hash and negotiate Version2.
func HashCookie(cookie [16]byte) [8]uint32 {
	digest := sha256.Sum256(cookie[:])
	var words [8]uint32
	for i := range words {
		words[i] = binary.LittleEndian.Uint32(digest[i*4:])
	}
	return words
}

func windowLog(window uint16) byte {
	var log byte = 1
	for log < 9 && uint32(1)<<(log+1) <= uint32(window) {
		log++
	}
	return log
}

func newDataEngine(p Parameters, c EndpointConfig, rtt time.Duration, now time.Time) (dataEngine, error) {
	if p.Version != Version3 {
		return NewEndpoint(p, c, now)
	}
	if p.Lossy || p.LocalWindow == 0 || p.RemoteWindow == 0 || !mtuOK(p.SendMTU) || !mtuOK(p.ReceiveMTU) || c.ReorderTimeout != 0 {
		return nil, ErrInvalid
	}
	// Windows 10 22H2 starts UDP2 coded sequences at 100 and channel sequences
	// at 1, independently of the old-format SYN ISNs. This handoff profile has
	// been verified with sideband TLS against that server; other servers still
	// need interoperability testing. A full-cycle bias permits earlier ACKs.
	return rdpudp2.NewEndpoint(rdpudp2.Config{LocalFirstCoded: (1 << 16) + 100, RemoteFirstCoded: (1 << 16) + 100, LocalFirstChannel: 1, RemoteFirstChannel: 1,
		LogWindow: windowLog(p.LocalWindow), RemoteLogWindow: windowLog(p.RemoteWindow), MTU: int(p.SendMTU), ReceiveMTU: int(p.ReceiveMTU),
		QueuePackets: c.QueuePackets, Retransmits: c.Retransmits, InitialRTT: rtt}, now)
}
