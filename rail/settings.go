package rail

import "slices"

// FilterKeys describes TS_FILTERKEYS. Times are milliseconds, without the
// cbSize member of the native Windows FILTERKEYS structure.
type FilterKeys struct{ Flags, WaitTime, DelayTime, RepeatTime, BounceTime uint32 }

// AccentColor describes TS_ACCENTCOLOR, without accessing the registry.
// Flags select fields as in MS-RDPERP 2.2.2.4.6 (mask 0x0bff). That table has
// no flag for StartColorMenu; this encoder does not invent the reserved 0x400
// bit. Palette is an opaque byte sequence with an explicit byte length, bounded
// by the RAIL PDU limit. Bit 0x800 must be set when Palette is nonempty.
type AccentColor struct {
	FieldsValidFlags                                         uint32
	AccentColor, ColorizationColor, ColorizationColorBalance uint32
	ColorizationAfterglow, ColorizationAfterglowBalance      uint32
	ColorizationBlurBalance, ColorizationGlassAttribute      uint32
	ColorPrevalence, EnableWindowColorization                uint32
	AccentColorMenu, StartColorMenu                          uint32
	Palette                                                  []byte
}

// Settings contains explicitly supplied optional RAIL accessibility and UI
// preferences. Nil means do not send; non-nil zero/false means send that value.
// The library does not infer values from the host, browser scale, or DPI.
// All fields are validated even if the server does not support them. Byte
// caption fields use the Windows.Media.ClosedCaptioning enum values (not RGB,
// percentages or font names); their valid ranges are documented below.
type Settings struct {
	// HandshakeExtendedSPI: CaretWidth >=1; StickyKeys mask 0xffff01ff,
	// ToggleKeys mask 0x1f, FilterKeys.Flags mask 0x7f.
	CaretWidth, StickyKeys, ToggleKeys *uint32
	FilterKeys                         *FilterKeys
	// HandshakeExtendedSPI2. Duration is seconds.
	Animations, AdvancedEffects, AutoHideScrollbars *bool
	MessageDuration                                 *uint32
	CaptionFontColor                                *byte // 0..8: default, white, black, red, green, blue, yellow, magenta, cyan.
	CaptionFontOpacity                              *byte // 0..4: default, 100%, 75%, 25%, 0%.
	CaptionFontSize                                 *byte // 0..4: default, 50%, 100%, 150%, 200%.
	CaptionFontStyle                                *byte // 0..7: default, mono serif, proportional serif, mono sans, proportional sans, casual, cursive, small caps.
	CaptionFontEdge                                 *byte // 0..5: default, none, raised, depressed, uniform, shadow.
	CaptionBackgroundColor, CaptionRegionColor      *byte // 0..8.
	CaptionBackgroundOpacity, CaptionRegionOpacity  *byte // 0..4.
	// HandshakeExtendedSPI3. Theme booleans are encoded as four bytes.
	Accent                           *AccentColor
	SystemLightTheme, AppsLightTheme *bool
	// Independent HandshakeTextScale / HandshakeCaretBlink capabilities.
	TextScale  *uint32 // 100..225 percent, not monitor DPI or framebuffer scaling.
	CaretBlink *uint32 // milliseconds; 0xffffffff means no blinking.
}

type settingPacket struct {
	name       string
	capability uint32
	data       []byte
}

// SettingsStatus reports the latest settings call or initial snapshot. Prepared
// means encoded into returned packets, not written or applied. Queued precedes
// the server handshake; Unsupported identifies fields omitted by its gates.
// Slices returned by Client.SettingsStatus are independently owned.
type SettingsStatus struct {
	Queued      bool     `json:"queued"`
	Prepared    []string `json:"prepared"`
	Unsupported []string `json:"unsupported"`
}
type SettingsUpdate struct {
	Packets [][]byte
	Status  SettingsStatus
}

func (s Settings) compile() ([]settingPacket, error) {
	var out []settingPacket
	add := func(name string, capability, id uint32, b []byte) {
		out = append(out, settingPacket{name, capability, systemParameter(id, b)})
	}
	u32 := func(name string, id, gate uint32, p *uint32) {
		if p != nil {
			add(name, gate, id, le.AppendUint32(nil, *p))
		}
	}
	flag := func(name string, id, gate uint32, p *bool, wide bool) {
		if p != nil {
			b := []byte{boolean(*p)}
			if wide {
				b = le.AppendUint32(nil, uint32(boolean(*p)))
			}
			add(name, gate, id, b)
		}
	}
	if s.CaretWidth != nil && *s.CaretWidth == 0 || s.StickyKeys != nil && *s.StickyKeys & ^uint32(0xffff01ff) != 0 || s.ToggleKeys != nil && *s.ToggleKeys & ^uint32(0x1f) != 0 {
		return nil, ErrInvalid
	}
	u32("caret_width", 0x2007, HandshakeExtendedSPI, s.CaretWidth)
	u32("sticky_keys", 0x3b, HandshakeExtendedSPI, s.StickyKeys)
	u32("toggle_keys", 0x35, HandshakeExtendedSPI, s.ToggleKeys)
	if f := s.FilterKeys; f != nil {
		if f.Flags & ^uint32(0x7f) != 0 {
			return nil, ErrInvalid
		}
		var b []byte
		for _, n := range []uint32{f.Flags, f.WaitTime, f.DelayTime, f.RepeatTime, f.BounceTime} {
			b = le.AppendUint32(b, n)
		}
		add("filter_keys", HandshakeExtendedSPI, 0x33, b)
	}
	flag("animations", 0xf002, HandshakeExtendedSPI2, s.Animations, false)
	flag("advanced_effects", 0xf003, HandshakeExtendedSPI2, s.AdvancedEffects, false)
	flag("auto_hide_scrollbars", 0xf004, HandshakeExtendedSPI2, s.AutoHideScrollbars, false)
	u32("message_duration", 0xf005, HandshakeExtendedSPI2, s.MessageDuration)
	for _, e := range []struct {
		name string
		id   uint32
		p    *byte
		max  byte
	}{
		{"caption_font_color", 0xf006, s.CaptionFontColor, 8}, {"caption_font_opacity", 0xf007, s.CaptionFontOpacity, 4},
		{"caption_font_size", 0xf008, s.CaptionFontSize, 4}, {"caption_font_style", 0xf009, s.CaptionFontStyle, 7},
		{"caption_font_edge", 0xf00a, s.CaptionFontEdge, 5}, {"caption_background_color", 0xf00b, s.CaptionBackgroundColor, 8},
		{"caption_background_opacity", 0xf00c, s.CaptionBackgroundOpacity, 4}, {"caption_region_color", 0xf00d, s.CaptionRegionColor, 8},
		{"caption_region_opacity", 0xf00e, s.CaptionRegionOpacity, 4},
	} {
		if e.p != nil {
			if *e.p > e.max {
				return nil, ErrInvalid
			}
			add(e.name, HandshakeExtendedSPI2, e.id, []byte{*e.p})
		}
	}
	if a := s.Accent; a != nil {
		// 4-byte PDU header + 4-byte SPI + 13 uint32 members = 60 bytes.
		if a.FieldsValidFlags & ^uint32(0xbff) != 0 || len(a.Palette) > MaxPDU-60 || len(a.Palette) > 0 && a.FieldsValidFlags&0x800 == 0 {
			return nil, ErrInvalid
		}
		b := make([]byte, 0, 52+len(a.Palette))
		for _, n := range []uint32{a.FieldsValidFlags, a.AccentColor, a.ColorizationColor, a.ColorizationColorBalance, a.ColorizationAfterglow, a.ColorizationAfterglowBalance, a.ColorizationBlurBalance, a.ColorizationGlassAttribute, a.ColorPrevalence, a.EnableWindowColorization, a.AccentColorMenu, a.StartColorMenu, uint32(len(a.Palette))} {
			b = le.AppendUint32(b, n)
		}
		b = append(b, a.Palette...)
		add("accent", HandshakeExtendedSPI3, 0xf00f, b)
	}
	flag("system_light_theme", 0xf010, HandshakeExtendedSPI3, s.SystemLightTheme, true)
	flag("apps_light_theme", 0xf011, HandshakeExtendedSPI3, s.AppsLightTheme, true)
	if s.TextScale != nil {
		if *s.TextScale < 100 || *s.TextScale > 225 {
			return nil, ErrInvalid
		}
		out = append(out, settingPacket{"text_scale", HandshakeTextScale, packet(OrderTextScale, le.AppendUint32(nil, *s.TextScale))})
	}
	if s.CaretBlink != nil {
		out = append(out, settingPacket{"caret_blink", HandshakeCaretBlink, packet(OrderCaretBlink, le.AppendUint32(nil, *s.CaretBlink))})
	}
	return out, nil
}

// Validate checks every explicitly supplied value without retaining it.
func (s Settings) Validate() error { _, err := s.compile(); return err }

func selectSettings(p []settingPacket, server Handshake) SettingsUpdate {
	var r SettingsUpdate
	for _, e := range p {
		if !server.Extended || server.Flags&e.capability == 0 {
			r.Status.Unsupported = append(r.Status.Unsupported, e.name)
			continue
		}
		r.Packets = append(r.Packets, e.data)
		r.Status.Prepared = append(r.Status.Prepared, e.name)
	}
	return r
}
func (c *Client) SettingsStatus() SettingsStatus {
	s := c.settingsStatus
	s.Prepared = slices.Clone(s.Prepared)
	s.Unsupported = slices.Clone(s.Unsupported)
	return s
}

// UpdateSettings atomically validates and prepares only the supplied fields.
// Before the handshake it replaces the queued optional snapshot and returns no
// packets. Afterwards it returns gated packets and names of unsupported fields;
// a newer SPI capability does not imply any older capability. Empty settings
// send nothing and never restore defaults. Callers synchronize all Client calls,
// send returned packets in order, and close on uncertain writes. Ready-time
// calls are patches, not a retained reconnect snapshot; reconnect with an
// explicit current Settings value in Options or another pre-handshake call.
func (c *Client) UpdateSettings(s Settings) (SettingsUpdate, error) {
	if c.closed || c.pending == nil {
		return SettingsUpdate{}, ErrClosed
	}
	p, err := s.compile()
	if err != nil {
		return SettingsUpdate{}, err
	}
	if !c.ready {
		c.initialSettings = p
		c.settingsStatus = SettingsStatus{Queued: len(p) > 0}
		return SettingsUpdate{Status: c.SettingsStatus()}, nil
	}
	r := selectSettings(p, c.server)
	c.settingsStatus = r.Status
	r.Status = c.SettingsStatus()
	return r, nil
}
