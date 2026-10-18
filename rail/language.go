package rail

// LanguageCapabilities is the subset confirmed by the enclosing RDP activation.
// ServerIME requires LanguageIME. Applications must implement local TSF/IME or
// equivalent platform integration before opting in; this package changes no OS
// settings and does not implement composition, candidates or native language UI.
type LanguageCapabilities struct {
	LanguageBar bool
	LanguageIME bool
	ServerIME   bool
}

func (s LanguageCapabilities) validate() error {
	if s.ServerIME && !s.LanguageIME {
		return ErrInvalid
	}
	return nil
}

type LanguageBarStatus uint32

const (
	LanguageBarFloating         LanguageBarStatus = 0x1
	LanguageBarDocked           LanguageBarStatus = 0x2
	LanguageBarMinimized        LanguageBarStatus = 0x4
	LanguageBarHidden           LanguageBarStatus = 0x8
	LanguageBarOpaque           LanguageBarStatus = 0x10
	LanguageBarLowTransparency  LanguageBarStatus = 0x20
	LanguageBarHighTransparency LanguageBarStatus = 0x40
	LanguageBarLabels           LanguageBarStatus = 0x80
	LanguageBarNoLabels         LanguageBarStatus = 0x100
	LanguageBarExtraIcons       LanguageBarStatus = 0x200
	LanguageBarNoExtraIcons     LanguageBarStatus = 0x400
	LanguageBarDeskband         LanguageBarStatus = 0x800
)

func (s LanguageBarStatus) validate() error {
	// Only the five display modes are explicitly mutually exclusive in RDPERP.
	modes := s & 0x80f
	if modes != 0 && modes&(modes-1) != 0 {
		return ErrInvalid
	}
	return nil
}

// EncodeLanguageBar encodes a client Language Bar Information PDU. It validates
// defined flags and mutually exclusive display modes; it performs no negotiation.
func EncodeLanguageBar(s LanguageBarStatus) ([]byte, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if s & ^LanguageBarStatus(0xfff) != 0 {
		return nil, ErrUnsupported
	}
	return packet(OrderLanguageBar, le.AppendUint32(nil, uint32(s))), nil
}

// GUID uses the conventional numerical GUID fields. Data1/2/3 are encoded in
// little endian; Data4 is copied verbatim. A zero GUID represents GUID_NULL.
type GUID struct {
	Data1        uint32
	Data2, Data3 uint16
	Data4        [8]byte
}

func (g GUID) appendTo(b []byte) []byte {
	b = le.AppendUint32(b, g.Data1)
	b = le.AppendUint16(b, g.Data2)
	b = le.AppendUint16(b, g.Data3)
	return append(b, g.Data4[:]...)
}

type ProfileType uint32

const (
	ProfileInputProcessor ProfileType = 1
	ProfileKeyboardLayout ProfileType = 2
)

// LanguageProfile identifies the client's active text service or keyboard
// layout. CLSID and ProfileID MUST be zero for ProfileKeyboardLayout. Custom
// text services are allowed; GUIDs are not restricted to Microsoft's IMEs.
// KeyboardLayout is the protocol's 32-bit HKL, not a native pointer-sized handle.
type LanguageProfile struct {
	Type             ProfileType
	LanguageID       uint16
	CLSID, ProfileID GUID
	KeyboardLayout   uint32
}

// EncodeLanguageProfile returns a 46-byte client-only PDU with no alignment
// padding between LanguageID and the GUIDs (MS-RDPERP 2.2.2.10.1).
func EncodeLanguageProfile(s LanguageProfile) ([]byte, error) {
	if s.Type != ProfileInputProcessor && s.Type != ProfileKeyboardLayout {
		return nil, ErrUnsupported
	}
	if s.Type == ProfileKeyboardLayout && (s.CLSID != (GUID{}) || s.ProfileID != (GUID{})) {
		return nil, ErrInvalid
	}
	b := le.AppendUint32(nil, uint32(s.Type))
	b = le.AppendUint16(b, s.LanguageID)
	b = s.CLSID.appendTo(b)
	b = s.ProfileID.appendTo(b)
	b = le.AppendUint32(b, s.KeyboardLayout)
	return packet(OrderLanguageProfile, b), nil
}

type IMEConversionMode uint32

const (
	IMEConversionNative       IMEConversionMode = 0x1
	IMEConversionKatakana     IMEConversionMode = 0x2
	IMEConversionFullShape    IMEConversionMode = 0x8
	IMEConversionRoman        IMEConversionMode = 0x10
	IMEConversionCharCode     IMEConversionMode = 0x20
	IMEConversionHanja        IMEConversionMode = 0x40
	IMEConversionSoftKeyboard IMEConversionMode = 0x80
	IMEConversionNone         IMEConversionMode = 0x100
	IMEConversionEUDC         IMEConversionMode = 0x200
	IMEConversionSymbol       IMEConversionMode = 0x400
	IMEConversionFixed        IMEConversionMode = 0x800
)

type IMESentenceMode uint32

const (
	IMESentenceNone          IMESentenceMode = 0
	IMESentencePluralClause  IMESentenceMode = 0x1
	IMESentenceSingleConvert IMESentenceMode = 0x2
	IMESentenceAutomatic     IMESentenceMode = 0x4
	IMESentencePhrasePredict IMESentenceMode = 0x8
	IMESentenceConversation  IMESentenceMode = 0x10
)

// IMECompartment is a snapshot, not keystrokes or composed text. Unknown received
// conversion/sentence flags are preserved for inspection, never auto-applied.
// Kana must be false for non-Japanese text processors.
type IMECompartment struct {
	Open           bool
	ConversionMode IMEConversionMode
	SentenceMode   IMESentenceMode
	Kana           bool
}

// EncodeIMECompartment validates defined flags and encodes the 20-byte PDU.
// Prefer Client.UpdateIMECompartment, which also checks the active profile.
func EncodeIMECompartment(s IMECompartment) ([]byte, error) {
	if s.ConversionMode & ^IMEConversionMode(0xffb) != 0 || s.SentenceMode & ^IMESentenceMode(0x1f) != 0 {
		return nil, ErrUnsupported
	}
	b := make([]byte, 16)
	if s.Open {
		le.PutUint32(b, 1)
	}
	le.PutUint32(b[4:], uint32(s.ConversionMode))
	le.PutUint32(b[8:], uint32(s.SentenceMode))
	if s.Kana {
		le.PutUint32(b[12:], 1)
	}
	return packet(OrderIMECompartment, b), nil
}

// LanguageStatus reports locally encoded requests, NOT server acknowledgement
// or the current native IME. ProfileSerial identifies a local profile selection
// within this Client; capture it with native callbacks and discard callbacks
// belonging to old connections. Received server notices have no profile ID or
// serial on the wire, so they cannot acknowledge or identify this selection.
type LanguageStatus struct {
	Capabilities  LanguageCapabilities
	ProfileKnown  bool
	Profile       LanguageProfile
	ProfileSerial uint64
}

func (c *Client) LanguageStatus() LanguageStatus { return c.language }

// ReconfigureLanguage applies the new activation's confirmed capability subset.
// It invalidates the local profile even if the capabilities are unchanged. Send
// a fresh explicit profile before compartments; no handshake/settings are replayed.
// This also prevents queued callbacks from a previous activation being reused.
func (c *Client) ReconfigureLanguage(s LanguageCapabilities) error {
	if c.closed || c.pending == nil {
		return ErrClosed
	}
	if err := s.validate(); err != nil {
		return err
	}
	c.language = LanguageStatus{Capabilities: s, ProfileSerial: c.language.ProfileSerial}
	return nil
}

func (c *Client) UpdateLanguageBar(s LanguageBarStatus) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if !c.language.Capabilities.LanguageBar {
		return nil, ErrUnsupported
	}
	return EncodeLanguageBar(s)
}

// UpdateLanguageProfile creates a new local selection, including for repeated
// identical profiles. Read LanguageStatus.ProfileSerial after success for use in
// UpdateIMECompartment. Send this PDU before later updates. Failed writes require
// closing the Client/transport; the serial is not a delivery acknowledgement.
func (c *Client) UpdateLanguageProfile(s LanguageProfile) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if !c.language.Capabilities.LanguageIME {
		return nil, ErrUnsupported
	}
	p, err := EncodeLanguageProfile(s)
	if err != nil {
		return nil, err
	}
	if c.language.ProfileSerial == ^uint64(0) {
		return nil, ErrBusy
	}
	c.language.ProfileKnown = true
	c.language.Profile = s
	c.language.ProfileSerial++
	return p, nil
}

// UpdateIMECompartment rejects stale local profile callbacks and requires a
// selected input processor. This cannot detect cross-direction network races;
// server compartment notices lack a profile identity and must be interpreted by
// the host's IME adapter without assuming correspondence to the current profile.
func (c *Client) UpdateIMECompartment(profileSerial uint64, s IMECompartment) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if !c.language.Capabilities.LanguageIME {
		return nil, ErrUnsupported
	}
	if !c.language.ProfileKnown || profileSerial == 0 || profileSerial != c.language.ProfileSerial || c.language.Profile.Type != ProfileInputProcessor {
		return nil, ErrState
	}
	if s.Kana && c.language.Profile.LanguageID&0x3ff != 0x11 {
		return nil, ErrInvalid
	}
	return EncodeIMECompartment(s)
}
