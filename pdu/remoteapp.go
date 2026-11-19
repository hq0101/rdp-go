package pdu

import (
	"encoding/binary"
	"errors"
)

const (
	RailLevelSupported        uint32 = 1
	RailLevelLanguageBar      uint32 = 0x2
	RailLevelShellIntegration uint32 = 0x4
	RailLevelLanguageIME      uint32 = 0x8
	RailLevelServerIME        uint32 = 0x10
	RailLevelHandshakeEx      uint32 = 0x80
	RailLevelCloaking         uint32 = 0x40
	WindowLevelSupported      uint32 = 1
	WindowLevelExtended       uint32 = 2
)

// ErrRemoteAppUnsupported means the server did not offer both required RAIL
// capabilities. A requested RemoteApp connection must end, without silently
// falling back to a desktop session.
var ErrRemoteAppUnsupported = errors.New("rdp pdu: RemoteApp capabilities not supported")

// RemoteAppCapabilities holds RAIL and Window List capability fields. In Demand
// it describes the server's offer; after Negotiate it contains exactly the
// supported client response, including the reduced per-connection icon bounds.
// Unknown server RAIL bits are retained in Demand but never echoed.
type RemoteAppCapabilities struct {
	RailSupportLevel, WindowSupportLevel uint32
	IconCaches                           uint8
	IconEntries                          uint16
}

func (c RemoteAppCapabilities) Enabled() bool {
	return c.RailSupportLevel&RailLevelSupported != 0 && (c.WindowSupportLevel == WindowLevelSupported || c.WindowSupportLevel == WindowLevelExtended)
}
func (c RemoteAppCapabilities) HandshakeEx() bool {
	return c.Enabled() && c.RailSupportLevel&RailLevelHandshakeEx != 0
}
func (c RemoteAppCapabilities) Cloaking() bool {
	return c.Enabled() && c.RailSupportLevel&RailLevelCloaking != 0
}
func (c RemoteAppCapabilities) LanguageBar() bool {
	return c.Enabled() && c.RailSupportLevel&RailLevelLanguageBar != 0
}
func (c RemoteAppCapabilities) ShellIntegration() bool {
	return c.Enabled() && c.RailSupportLevel&RailLevelShellIntegration != 0
}
func (c RemoteAppCapabilities) LanguageIME() bool {
	return c.Enabled() && c.RailSupportLevel&RailLevelLanguageIME != 0
}
func (c RemoteAppCapabilities) ServerIME() bool {
	return c.LanguageIME() && c.RailSupportLevel&RailLevelServerIME != 0
}
func (c RemoteAppCapabilities) ExtendedWindows() bool {
	return c.Enabled() && c.WindowSupportLevel == WindowLevelExtended
}

// RemoteAppOptions requests the implemented RemoteApp capability profile.
// Enhanced requests GFX window delivery, subject to the server handshake.
// Language/IME and shell integration require explicit host integration; neither
// is advertised by default. The application must
// consume RAIL and window drawing messages; negotiation creates no local UI.
// Zero counts disable icon caching. Nonzero counts must be paired and total at
// most 32768 slots, matching WindowState's hard slot bound. There are no implicit
// defaults; applications must supply storage and enforce their byte budgets.
type RemoteAppOptions struct {
	// Language features default off. These require a host adapter that supplies
	// profiles/compartments and consumes server notices without feedback loops.
	// ServerIME requires LanguageIME. Negotiation alone creates no native UI.
	LanguageBar, LanguageIME, ServerIME bool
	Cloaking                            bool // Application handles retained invisible windows and input release.
	// ShellIntegration advertises extended shell integration (tabbed windows,
	// overlay icons). The application must present tabs and consume rail
	// Taskbar Tab Info notices; negotiation alone creates no local UI.
	ShellIntegration             bool
	Enhanced                     bool // Request only; HandshakeEx determines the actual mode.
	HandshakeEx, ExtendedWindows bool
	IconCaches                   uint8
	IconEntries                  uint16
}

func (o RemoteAppOptions) Validate() error {
	if o.ServerIME && !o.LanguageIME {
		return ErrInvalid
	}
	if (o.IconCaches == 0) != (o.IconEntries == 0) || int(o.IconCaches)*int(o.IconEntries) > 32768 {
		return ErrInvalid
	}
	return nil
}

func (o RemoteAppOptions) Negotiate(d Demand) (RemoteAppCapabilities, error) {
	if err := o.Validate(); err != nil {
		return RemoteAppCapabilities{}, err
	}
	s := d.RemoteApp
	if !s.Enabled() {
		return RemoteAppCapabilities{}, ErrRemoteAppUnsupported
	}
	c := RemoteAppCapabilities{RailSupportLevel: RailLevelSupported, WindowSupportLevel: WindowLevelSupported}
	if o.HandshakeEx && s.HandshakeEx() {
		c.RailSupportLevel |= RailLevelHandshakeEx
	}
	if o.Cloaking && s.Cloaking() {
		c.RailSupportLevel |= RailLevelCloaking
	}
	if o.ShellIntegration && s.ShellIntegration() {
		c.RailSupportLevel |= RailLevelShellIntegration
	}
	if o.LanguageBar && s.LanguageBar() {
		c.RailSupportLevel |= RailLevelLanguageBar
	}
	if o.LanguageIME && s.LanguageIME() {
		c.RailSupportLevel |= RailLevelLanguageIME
	}
	if o.ServerIME && c.LanguageIME() && s.ServerIME() {
		c.RailSupportLevel |= RailLevelServerIME
	}
	if o.ExtendedWindows && s.ExtendedWindows() {
		c.WindowSupportLevel = WindowLevelExtended
	}
	c.IconCaches = min(o.IconCaches, s.IconCaches)
	c.IconEntries = min(o.IconEntries, s.IconEntries)
	if c.IconCaches == 0 || c.IconEntries == 0 {
		c.IconCaches, c.IconEntries = 0, 0
	}
	return c, nil
}

// ConfirmRemoteApp adds both required capabilities to Confirm Active. This
// profile requires drawing orders at 24/32 bpp so it can deliver Windowing
// Alternate Secondary Drawing Orders. It never emits unsupported server flags.
func ConfirmRemoteApp(source uint16, d Demand, layout uint32, g GraphicsOptions, o RemoteAppOptions) ([]byte, error) {
	c, err := o.Negotiate(d)
	if err != nil {
		return nil, err
	}
	if !g.Effective(d).DrawingOrders {
		return nil, ErrInvalid
	}
	return confirmGraphics(source, d, layout, g, &c)
}

// SetRemoteApp selects base RemoteApp (or desktop), clearing any Enhanced flag.
func SetRemoteApp(info []byte, enabled bool) error {
	return SetRemoteAppMode(info, enabled, false)
}

// SetRemoteAppMode selects INFO_RAIL and optionally INFO_HIDEF_RAIL_SUPPORTED.
// Enhanced requires enabled and a GFX window consumer. The server may decline
// Enhanced while accepting base RemoteApp. Only use buffers from this package's
// ClientInfo encoders; this is not an untrusted Client Info parser. Credentials,
// ARC/redirection bytes and unrelated flags are unchanged, including on error.
func SetRemoteAppMode(info []byte, enabled, enhanced bool) error {
	if enhanced && !enabled || len(info) < 22 || binary.LittleEndian.Uint32(info) != 0x40 {
		return ErrInvalid
	}
	flags := binary.LittleEndian.Uint32(info[8:]) &^ uint32(0x8000|0x02000000)
	if enabled {
		flags |= 0x8000
	}
	if enhanced {
		flags |= 0x02000000
	}
	binary.LittleEndian.PutUint32(info[8:], flags)
	return nil
}
