// Package gcc implements the RDP GCC Conference Create and core/security/network
// data blocks for Enhanced RDP Security. Standard RDP Security is not supported.
package gcc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/hq0101/rdp-go/display"
	"github.com/hq0101/rdp-go/x224"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

var ErrInvalid = errors.New("gcc: invalid or unsupported settings")
var ErrNegotiationMismatch = errors.New("gcc: server negotiation replay does not match client request")
var ErrExtendedData = errors.New("gcc: server did not advertise extended client data support")

// ChannelShowProtocol requests visible static-channel headers when sending,
// including unfragmented messages. cliprdr requires this; drdynvc does not.
// The server ignores this GCC option; Session applies the corresponding flag.
const ChannelShowProtocol uint32 = 0x00200000

// ChannelCompressRDP requests compression when session bulk compression is on.
// ChannelCompress requests compression independently; DialSession requires its
// BulkCompression option for either flag. Direct DialChannels remains low-level.
const (
	ChannelCompressRDP uint32 = 0x00800000
	ChannelCompress    uint32 = 0x00400000
)

type Channel struct {
	Name    string
	Options uint32
}
type ClientSettings struct {
	Width, Height uint16
	// ServerRedirection offers enhanced-security redirection (version 5 by default).
	// DialSession reports a terminal *rdp.RedirectionError; it does not
	// follow a new destination or reuse credentials automatically.
	ServerRedirection bool
	// ServerRedirectionVersion is 5 (default) or 6. Version 6 additionally
	// advertises RDSTLS credential redirection; its consumer must handle it.
	// A nonzero value requires ServerRedirection.
	ServerRedirectionVersion uint8
	// RedirectedSessionID requests the broker-specified target session. Zero
	// is valid when the pointer is non-nil. Requires ServerRedirection.
	RedirectedSessionID *uint32
	// Monitors optionally requests an explicit topology with DPI/orientation.
	// Zero Width/Height derive from its bounding rectangle; nonzero dimensions
	// must match. Requires server ExtendedClientDataSupported. Nil retains the
	// legacy single-monitor dimensions/defaults; values are not modified.
	Monitors []display.Monitor
	// ColorDepth is 15, 16, 24 or 32; zero retains the 24-bit default.
	// A 32-bit request uses the protocol's early flag and 24-bit fallback.
	ColorDepth uint16
	// GraphicsPipeline advertises the dynamic graphics extension. Its consumer
	// must implement the negotiated profile; requires 32 bpp and drdynvc.
	GraphicsPipeline bool
	// NetworkAutoDetect and Heartbeat require ExtendedClientDataSupported and
	// a server-assigned message channel. GraphicsPipeline implies NetworkAutoDetect.
	NetworkAutoDetect, Heartbeat bool
	// MultitransportFlags is a low-level offer for DialChannels consumers which
	// implement sideband bootstrap/tunnels. DialSession currently rejects it.
	// Valid bits are UDP reliable (1), lossy (4), preferred (0x100), SoftSync (0x200).
	MultitransportFlags uint32
	ClientName          string
	KeyboardLayout      uint32
	Channels            []Channel
}

func perLength(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	return []byte{0x80 | byte(n>>8), byte(n)}
}
func takeLength(b *[]byte) (int, error) {
	if len(*b) < 1 {
		return 0, ErrInvalid
	}
	n := int((*b)[0])
	*b = (*b)[1:]
	if n&0x80 != 0 {
		if len(*b) < 1 {
			return 0, ErrInvalid
		}
		n = (n&0x7f)<<8 | int((*b)[0])
		*b = (*b)[1:]
	}
	return n, nil
}
func block(t uint16, b []byte) []byte {
	h := binary.LittleEndian.AppendUint16(nil, t)
	h = binary.LittleEndian.AppendUint16(h, uint16(len(b)+4))
	return append(h, b...)
}

func CreateRequest(s ClientSettings, selected x224.Protocol) ([]byte, error) {
	return CreateRequestWithFlags(s, selected, 0)
}

// CreateRequestWithFlags uses the flags from the server's X.224 confirmation.
// Explicit monitor blocks are never sent without ExtendedClientDataSupported.
// CreateRequest preserves the legacy API and assumes no extended support.
func CreateRequestWithFlags(s ClientSettings, selected x224.Protocol, serverFlags byte) ([]byte, error) {
	if s.ServerRedirectionVersion != 0 && (s.ServerRedirectionVersion != 5 && s.ServerRedirectionVersion != 6 || !s.ServerRedirection) {
		return nil, ErrInvalid
	}
	if s.RedirectedSessionID != nil && !s.ServerRedirection {
		return nil, ErrInvalid
	}
	s.NetworkAutoDetect = s.NetworkAutoDetect || s.GraphicsPipeline
	if s.MultitransportFlags & ^uint32(0x305) != 0 || s.MultitransportFlags != 0 && s.MultitransportFlags&5 == 0 {
		return nil, ErrInvalid
	}
	if s.MultitransportFlags != 0 {
		found := false
		for _, channel := range s.Channels {
			found = found || channel.Name == "drdynvc"
		}
		if !found {
			return nil, errors.New("gcc: multitransport requires drdynvc")
		}
	}
	if (s.NetworkAutoDetect || s.Heartbeat || s.MultitransportFlags != 0) && serverFlags&x224.ExtendedClientDataSupported == 0 {
		return nil, ErrExtendedData
	}
	if selected != x224.ProtocolTLS && selected != x224.ProtocolHybrid && selected != x224.ProtocolHybridEx && selected != x224.ProtocolRDSTLS {
		return nil, ErrInvalid
	}
	if len(s.Monitors) != 0 {
		monitors, bounds, err := display.Normalize(s.Monitors)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalid, err)
		}
		if serverFlags&x224.ExtendedClientDataSupported == 0 {
			return nil, ErrExtendedData
		}
		if s.Width != 0 && int(s.Width) != bounds.Dx() || s.Height != 0 && int(s.Height) != bounds.Dy() {
			return nil, ErrInvalid
		}
		s.Monitors, s.Width, s.Height = monitors, uint16(bounds.Dx()), uint16(bounds.Dy())
	}
	if s.Width == 0 {
		s.Width = 1280
	}
	if s.Height == 0 {
		s.Height = 720
	}
	if s.ColorDepth == 0 {
		s.ColorDepth = 24
	}
	if s.ColorDepth != 15 && s.ColorDepth != 16 && s.ColorDepth != 24 && s.ColorDepth != 32 {
		return nil, ErrInvalid
	}
	if s.Width < 200 || s.Height < 200 || s.Width > 8192 || s.Height > 8192 || len(s.Channels) > 31 {
		return nil, ErrInvalid
	}
	if s.ClientName == "" {
		s.ClientName = "RDPGO"
	}
	name := utf16.Encode([]rune(s.ClientName))
	if !utf8.ValidString(s.ClientName) || strings.ContainsRune(s.ClientName, 0) || len(name) > 15 {
		return nil, ErrInvalid
	}
	if s.KeyboardLayout == 0 {
		s.KeyboardLayout = 0x409
	}
	core := make([]byte, 234)
	binary.LittleEndian.PutUint16(core, 0xc001)
	binary.LittleEndian.PutUint16(core[2:], 234)
	binary.LittleEndian.PutUint32(core[4:], 0x80004)
	binary.LittleEndian.PutUint16(core[8:], s.Width)
	binary.LittleEndian.PutUint16(core[10:], s.Height)
	binary.LittleEndian.PutUint16(core[12:], 0xca01)
	binary.LittleEndian.PutUint16(core[14:], 0xaa03)
	binary.LittleEndian.PutUint32(core[16:], s.KeyboardLayout)
	binary.LittleEndian.PutUint32(core[20:], 2600)
	for i, v := range name {
		binary.LittleEndian.PutUint16(core[24+2*i:], v)
	}
	binary.LittleEndian.PutUint32(core[56:], 4)
	binary.LittleEndian.PutUint32(core[64:], 12)
	binary.LittleEndian.PutUint16(core[132:], 0xca01)
	depth, early := s.ColorDepth, uint16(0x41) // Error info and server Monitor Layout.
	if s.NetworkAutoDetect {
		early |= 0x80
	}
	if s.Heartbeat {
		early |= 0x400
	}
	if s.GraphicsPipeline {
		found := false
		for _, channel := range s.Channels {
			found = found || channel.Name == "drdynvc"
		}
		if s.ColorDepth != 32 || !found {
			return nil, errors.New("gcc: graphics pipeline requires 32 bpp and drdynvc")
		}
		early |= 0x100
	}
	if depth == 32 {
		depth, early = 24, early|2
	}
	binary.LittleEndian.PutUint16(core[140:], depth)
	binary.LittleEndian.PutUint16(core[142:], 15) // 15/16/24/32-bit bitmap support
	binary.LittleEndian.PutUint16(core[144:], early)
	binary.LittleEndian.PutUint32(core[212:], uint32(selected))
	// RDP 8.1 display fields: unspecified physical size, landscape, 100% scale.
	binary.LittleEndian.PutUint32(core[226:], 100)
	binary.LittleEndian.PutUint32(core[230:], 100)
	for _, m := range s.Monitors {
		if !m.Primary {
			continue
		}
		binary.LittleEndian.PutUint32(core[216:], m.PhysicalWidth)
		binary.LittleEndian.PutUint32(core[220:], m.PhysicalHeight)
		binary.LittleEndian.PutUint16(core[224:], uint16(m.Orientation))
		binary.LittleEndian.PutUint32(core[226:], m.DesktopScaleFactor)
		binary.LittleEndian.PutUint32(core[230:], m.DeviceScaleFactor)
	}
	data := append(core, block(0xc002, make([]byte, 8))...)
	if s.ServerRedirection {
		flags, id := uint32(1|4<<2), uint32(0) // version 5 by default
		if s.ServerRedirectionVersion == 6 {
			flags = 1 | 5<<2
		}
		if s.RedirectedSessionID != nil {
			flags |= 2
			id = *s.RedirectedSessionID
		}
		cluster := binary.LittleEndian.AppendUint32(nil, flags)
		cluster = binary.LittleEndian.AppendUint32(cluster, id)
		data = append(data, block(0xc004, cluster)...)
	}
	network := binary.LittleEndian.AppendUint32(nil, uint32(len(s.Channels)))
	names := map[string]bool{}
	for _, ch := range s.Channels {
		if len(ch.Name) == 0 || len(ch.Name) > 7 || names[ch.Name] {
			return nil, ErrInvalid
		}
		names[ch.Name] = true
		for _, v := range []byte(ch.Name) {
			if v < 0x21 || v > 0x7e {
				return nil, ErrInvalid
			}
		}
		field := make([]byte, 12)
		copy(field, ch.Name)
		binary.LittleEndian.PutUint32(field[8:], ch.Options)
		network = append(network, field...)
	}
	data = append(data, block(0xc003, network)...)
	if s.NetworkAutoDetect || s.Heartbeat || s.MultitransportFlags != 0 {
		data = append(data, block(0xc006, make([]byte, 4))...)
	}
	if s.MultitransportFlags != 0 {
		data = append(data, block(0xc00a, binary.LittleEndian.AppendUint32(nil, s.MultitransportFlags))...)
	}
	if len(s.Monitors) != 0 {
		monitor := binary.LittleEndian.AppendUint32(make([]byte, 4), uint32(len(s.Monitors)))
		attributes := binary.LittleEndian.AppendUint32(make([]byte, 4), 20)
		attributes = binary.LittleEndian.AppendUint32(attributes, uint32(len(s.Monitors)))
		for _, m := range s.Monitors {
			flags := uint32(0)
			if m.Primary {
				flags = 1
			}
			for _, value := range []uint32{uint32(m.Left), uint32(m.Top), uint32(int64(m.Left) + int64(m.Width) - 1), uint32(int64(m.Top) + int64(m.Height) - 1), flags} {
				monitor = binary.LittleEndian.AppendUint32(monitor, value)
			}
			for _, value := range []uint32{m.PhysicalWidth, m.PhysicalHeight, m.Orientation, m.DesktopScaleFactor, m.DeviceScaleFactor} {
				attributes = binary.LittleEndian.AppendUint32(attributes, value)
			}
		}
		data = append(data, block(0xc005, monitor)...)
		data = append(data, block(0xc008, attributes)...)
	}
	limit := 1024
	if serverFlags&x224.ExtendedClientDataSupported != 0 {
		limit = 4096
	}
	if len(data) >= limit {
		return nil, ErrInvalid
	}
	inner := []byte{0, 8, 0, 0x10, 0, 1, 0xc0, 0, 'D', 'u', 'c', 'a'}
	inner = append(inner, perLength(len(data))...)
	inner = append(inner, data...)
	b := []byte{0, 5, 0, 0x14, 0x7c, 0, 1}
	b = append(b, perLength(len(inner))...)
	b = append(b, inner...)
	// MS-RDPBCGR 2.2.1.3 limits the complete GCC request, including wrappers.
	if len(b) >= limit {
		return nil, ErrInvalid
	}
	return b, nil
}

type ServerSettings struct {
	Version             uint32
	RequestedProtocols  x224.Protocol
	EarlyCapabilities   uint32
	IOChannel           uint16
	MessageChannel      uint16 // zero means not provided/usable; never a static channel
	HasMessageChannel   bool
	MultitransportFlags uint32
	HasMultitransport   bool
	ChannelIDs          []uint16
}

func ParseResponse(b []byte, requested x224.Protocol, channelCount int) (ServerSettings, error) {
	var s ServerSettings
	if channelCount < 0 || channelCount > 31 || len(b) < 7 || !bytes.Equal(b[:7], []byte{0, 5, 0, 0x14, 0x7c, 0, 1}) {
		return s, ErrInvalid
	}
	b = b[7:]
	// MS-RDPBCGR requires ignoring the GCC connectPDU length in responses.
	if _, err := takeLength(&b); err != nil {
		return s, err
	}
	if len(b) < 4 || b[0] != 0x14 {
		return s, ErrInvalid
	}
	b = b[3:] // choice and nodeID
	tagLen, err := takeLength(&b)
	if err != nil || tagLen < 1 || tagLen > 4 || len(b) < tagLen+8 {
		return s, ErrInvalid
	}
	b = b[tagLen:]
	if !bytes.Equal(b[:8], []byte{0, 1, 0xc0, 0, 'M', 'c', 'D', 'n'}) {
		return s, ErrInvalid
	}
	b = b[8:]
	n, err := takeLength(&b)
	if err != nil || n != len(b) {
		return s, ErrInvalid
	}
	seen := map[uint16]bool{}
	for len(b) > 0 {
		if len(b) < 4 {
			return s, ErrInvalid
		}
		typ, size := binary.LittleEndian.Uint16(b), int(binary.LittleEndian.Uint16(b[2:]))
		if size < 4 || size > len(b) || seen[typ] {
			return s, ErrInvalid
		}
		seen[typ] = true
		p := b[4:size]
		b = b[size:]
		switch typ {
		case 0x0c08:
			if len(p) != 4 {
				return s, ErrInvalid
			}
			s.HasMultitransport = true
			s.MultitransportFlags = binary.LittleEndian.Uint32(p)
			// Unknown server capability bits are not enabled by the client.
		case 0x0c04:
			if len(p) != 2 {
				return s, ErrInvalid
			}
			s.HasMessageChannel = true
			s.MessageChannel = binary.LittleEndian.Uint16(p)
			if s.MessageChannel != 0 && s.MessageChannel < 1001 {
				return s, ErrInvalid
			}
		case 0x0c01:
			if len(p) != 8 && len(p) != 12 {
				return s, ErrInvalid
			}
			s.Version = binary.LittleEndian.Uint32(p)
			s.RequestedProtocols = x224.Protocol(binary.LittleEndian.Uint32(p[4:]))
			if s.Version < 0x80004 || s.Version>>16 != 8 {
				return s, ErrInvalid
			}
			if s.RequestedProtocols != requested {
				return s, ErrNegotiationMismatch
			}
			if len(p) == 12 {
				s.EarlyCapabilities = binary.LittleEndian.Uint32(p[8:])
			}
		case 0x0c02:
			if len(p) != 8 || binary.LittleEndian.Uint32(p) != 0 || binary.LittleEndian.Uint32(p[4:]) != 0 {
				return s, ErrInvalid
			}
		case 0x0c03:
			if len(p) < 4 {
				return s, ErrInvalid
			}
			s.IOChannel = binary.LittleEndian.Uint16(p)
			count := int(binary.LittleEndian.Uint16(p[2:]))
			if s.IOChannel < 1001 || count != channelCount || len(p) != 4+count*2+(count%2)*2 {
				return s, ErrInvalid
			}
			ids := map[uint16]bool{s.IOChannel: true}
			for i := 0; i < count; i++ {
				id := binary.LittleEndian.Uint16(p[4+i*2:])
				if id < 1001 || ids[id] {
					return s, ErrInvalid
				}
				ids[id] = true
				s.ChannelIDs = append(s.ChannelIDs, id)
			}
		}
	}
	if !seen[0x0c01] || !seen[0x0c02] || !seen[0x0c03] {
		return s, ErrInvalid
	}
	if s.MessageChannel != 0 {
		if s.MessageChannel == s.IOChannel {
			return s, ErrInvalid
		}
		for _, id := range s.ChannelIDs {
			if id == s.MessageChannel {
				return s, ErrInvalid
			}
		}
	}
	return s, nil
}
