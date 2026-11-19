// Package rail implements the MS-RDPERP static virtual channel's initialization,
// program launch and baseline window control messages using only Go's standard
// library. It does not create local windows, execute local programs, change local
// system settings or perform I/O. rdp.Session can negotiate base RemoteApp;
// applications route its channel data to Client and drawing orders to WindowState.
// Enhanced RemoteApp graphics and client window presentation remain separate.
package rail

import (
	"encoding/binary"
	"errors"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	MaxPDU     = 65535
	MaxMessage = 1 << 20
	MaxOrders  = 256
	MaxPending = 32
)

var (
	ErrInvalid     = errors.New("rail: invalid message or option")
	ErrUnsupported = errors.New("rail: unsupported message or feature")
	ErrState       = errors.New("rail: unexpected message sequence")
	ErrNotReady    = errors.New("rail: handshake not complete")
	ErrClosed      = errors.New("rail: client closed or failed")
	ErrBusy        = errors.New("rail: pending request limit or ambiguous request")
)

type Order uint16

const (
	OrderExecute         Order = 0x0001
	OrderActivate        Order = 0x0002
	OrderSystemParameter Order = 0x0003
	OrderSystemCommand   Order = 0x0004
	OrderHandshake       Order = 0x0005
	OrderNotifyEvent     Order = 0x0006
	OrderWindowMove      Order = 0x0008
	OrderLocalMoveSize   Order = 0x0009
	OrderMinMaxInfo      Order = 0x000a
	OrderClientStatus    Order = 0x000b
	OrderSystemMenu      Order = 0x000c
	OrderLanguageBar     Order = 0x000d
	OrderLanguageProfile Order = 0x0011
	OrderIMECompartment  Order = 0x0012
	OrderGetAppID        Order = 0x000e
	OrderAppID           Order = 0x000f
	OrderTaskbarInfo     Order = 0x0010
	OrderHandshakeEx     Order = 0x0013
	OrderZOrderSync      Order = 0x0014
	OrderCloak           Order = 0x0015
	OrderPowerDisplay    Order = 0x0016
	OrderWindowSnap      Order = 0x0017
	OrderAppIDEx         Order = 0x0018
	OrderTextScale       Order = 0x0019
	OrderCaretBlink      Order = 0x001a
	OrderExecuteResult   Order = 0x0080
)

const (
	HandshakeEnhanced     uint32 = 1
	HandshakeExtendedSPI  uint32 = 2
	HandshakeSnap         uint32 = 4
	HandshakeTextScale    uint32 = 8
	HandshakeCaretBlink   uint32 = 16
	HandshakeExtendedSPI2 uint32 = 32
	HandshakeExtendedSPI3 uint32 = 64
)

type ExecuteFlags uint16

const (
	ExpandWorkingDirectory ExecuteFlags = 1
	TranslateFiles         ExecuteFlags = 2
	ExecuteFile            ExecuteFlags = 4
	ExpandArguments        ExecuteFlags = 8
	ExecuteAppUserModelID  ExecuteFlags = 16
)

type ResultCode uint16

const (
	ExecuteOK            ResultCode = 0
	ExecuteHookNotLoaded ResultCode = 1
	ExecuteDecodeFailed  ResultCode = 2
	ExecuteNotAllowed    ResultCode = 3
	ExecuteFileNotFound  ResultCode = 5
	ExecuteFailed        ResultCode = 6
	ExecuteSessionLocked ResultCode = 7
)

// ExecuteRequest describes a remote launch. Strings are UTF-8 and contain no
// NUL. ExeOrFile and WorkingDirectory are limited to 520 UTF-16 bytes each;
// Arguments to 16000. Arguments are passed verbatim; no shell escaping, variable
// expansion or file translation is performed locally. Flags explicitly request
// corresponding server behavior. An executable alias can be written "||name".
type ExecuteRequest struct {
	Flags                                  ExecuteFlags
	ExeOrFile, WorkingDirectory, Arguments string
}

type ExecuteResult struct {
	Flags     ExecuteFlags
	Code      ResultCode
	RawResult uint32
	ExeOrFile string
}

type Handshake struct {
	BuildNumber uint32
	Extended    bool
	Flags       uint32 // Unknown bits are preserved; they do not enable client features.
}

type ServerSystemParameter struct {
	Parameter uint32
	Enabled   bool
}

const (
	ScreenSaverActive uint32 = 0x11
	ScreenSaverSecure uint32 = 0x77
)

type MinMaxInfo struct {
	WindowID                                                     uint32
	MaxWidth, MaxHeight, MaxX, MaxY                              int16
	MinTrackWidth, MinTrackHeight, MaxTrackWidth, MaxTrackHeight int16
}

// Move/size operation values from MS-RDPERP 2.2.2.7.2.
const (
	MoveSizeLeft uint16 = iota + 1
	MoveSizeRight
	MoveSizeTop
	MoveSizeTopLeft
	MoveSizeTopRight
	MoveSizeBottom
	MoveSizeBottomLeft
	MoveSizeBottomRight
	MoveSizeMouse
	MoveSizeKeyMove
	MoveSizeKeySize
)

// MoveSize coordinates are signed. During a mouse move (Type 9) they are
// offsets; for resize/keyboard operations they identify the last mouse-down.
// For an ending operation they are the final window's top-left coordinates.
type MoveSize struct {
	WindowID uint32
	Start    bool
	Type     uint16 // 1..8 edges/corners, 9 mouse move, 10 key move, 11 key size.
	X, Y     int16
}

type ApplicationID struct {
	WindowID         uint32
	ID               string
	Extended         bool
	ProcessID        uint32
	ProcessImageName string
}

type CloakState struct {
	WindowID uint32
	Cloaked  bool
}

// TaskbarMessage values from MS-RDPERP 2.2.2.14.1.
type TaskbarMessage uint32

const (
	TaskbarTabRegister   TaskbarMessage = 1
	TaskbarTabUnregister TaskbarMessage = 2
	TaskbarTabOrder      TaskbarMessage = 3
	TaskbarTabActive     TaskbarMessage = 4
	TaskbarTabProperties TaskbarMessage = 5
)

// TaskbarTab is one server tab-group change. Body depends on Message: register
// and active carry the tab's window ID, order carries the window ID to precede
// (zero appends at the group end), properties carry STPFLAG bits, and unregister
// ignores Body (the wire SHOULD send zero). Window IDs identify remote session
// windows, never local OS windows; presenting tabs is the application's job.
type TaskbarTab struct {
	Message  TaskbarMessage
	WindowID uint32
	Body     uint32
}

// PowerDisplayState reports the server's display-required power request. Active
// means the remote session asks that the display stay powered on. The library
// only reports it; changing local power or display settings is never performed.
type PowerDisplayState struct {
	Active bool
}

// Event contains the one field corresponding to Order. All strings own their
// storage. Server notices must not be treated as authorization to alter local
// settings or execute commands. A successful ExecuteResult reports a remote
// launch, not proof that a window has been received or displayed.
type Event struct {
	LanguageBar     LanguageBarStatus // OrderLanguageBar; unknown bits preserved.
	IMECompartment  IMECompartment    // OrderIMECompartment; no profile identity on wire.
	Cloak           CloakState        // OrderCloak; only 0/1 are accepted on the wire.
	Taskbar         TaskbarTab        // OrderTaskbarInfo; requires negotiated shell integration.
	PowerDisplay    PowerDisplayState // OrderPowerDisplay; only 0/1 are accepted on the wire.
	Order           Order
	Handshake       Handshake
	Execute         ExecuteResult
	SystemParameter ServerSystemParameter
	MinMax          MinMaxInfo
	MoveSize        MoveSize
	ApplicationID   ApplicationID
	MarkerWindowID  uint32 // OrderZOrderSync; not a drawable or local OS window.
}

var le = binary.LittleEndian

func packet(typ Order, b []byte) []byte {
	p := make([]byte, 4, len(b)+4)
	le.PutUint16(p, uint16(typ))
	le.PutUint16(p[2:], uint16(len(b)+4))
	return append(p, b...)
}

func validExecuteFlags(f ExecuteFlags) bool {
	return f & ^ExecuteFlags(31) == 0 && (f&TranslateFiles == 0 || f&ExecuteFile != 0)
}

func encodeString(s string, limit int) ([]byte, error) {
	// No valid UTF-8 string fitting the UTF-16 limit needs more than 2*limit
	// bytes. Check before allocating rune/UTF-16 storage.
	if len(s) > limit*2 || !utf8.ValidString(s) || strings.ContainsRune(s, 0) {
		return nil, ErrInvalid
	}
	u := utf16.Encode([]rune(s))
	if len(u)*2 > limit {
		return nil, ErrInvalid
	}
	b := make([]byte, 0, len(u)*2)
	for _, v := range u {
		b = le.AppendUint16(b, v)
	}
	return b, nil
}

func decodeString(b []byte) (string, error) {
	if len(b)%2 != 0 {
		return "", ErrInvalid
	}
	u := make([]uint16, 0, len(b)/2)
	for i := 0; i < len(b); i += 2 {
		v := le.Uint16(b[i:])
		if v == 0 || v >= 0xdc00 && v <= 0xdfff {
			return "", ErrInvalid
		}
		u = append(u, v)
		if v >= 0xd800 && v <= 0xdbff {
			if i+4 > len(b) {
				return "", ErrInvalid
			}
			i += 2
			v = le.Uint16(b[i:])
			if v < 0xdc00 || v > 0xdfff {
				return "", ErrInvalid
			}
			u = append(u, v)
		}
	}
	return string(utf16.Decode(u)), nil
}

func fixedString(b []byte) (string, error) {
	for i := 0; i+1 < len(b); i += 2 {
		if le.Uint16(b[i:]) == 0 {
			return decodeString(b[:i])
		}
	}
	return "", ErrInvalid
}

// EncodeExecute creates exactly one PDU. Client.Execute additionally requires
// initialization and tracks the result. No terminating NUL is added.
func EncodeExecute(r ExecuteRequest) ([]byte, error) {
	if !validExecuteFlags(r.Flags) || r.ExeOrFile == "" {
		return nil, ErrInvalid
	}
	x, err := encodeString(r.ExeOrFile, 520)
	if err != nil {
		return nil, err
	}
	w, err := encodeString(r.WorkingDirectory, 520)
	if err != nil {
		return nil, err
	}
	a, err := encodeString(r.Arguments, 16000)
	if err != nil {
		return nil, err
	}
	b := le.AppendUint16(nil, uint16(r.Flags))
	for _, s := range [][]byte{x, w, a} {
		b = le.AppendUint16(b, uint16(len(s)))
	}
	for _, s := range [][]byte{x, w, a} {
		b = append(b, s...)
	}
	return packet(OrderExecute, b), nil
}

// ParseServerPDU parses exactly one complete RAIL PDU, without a static-channel
// header. It checks wire syntax but not negotiation or sequence. Unknown orders
// return ErrUnsupported. Reserved ExecuteResult padding and bytes following a
// fixed string's terminator are ignored as specified, never exposed.
func ParseServerPDU(p []byte) (Event, error) {
	var e Event
	if len(p) < 4 || len(p) > MaxPDU || int(le.Uint16(p[2:])) != len(p) {
		return e, ErrInvalid
	}
	e.Order = Order(le.Uint16(p))
	b := p[4:]
	switch e.Order {
	case OrderHandshake, OrderHandshakeEx:
		n := 4
		if e.Order == OrderHandshakeEx {
			n = 8
		}
		if len(b) != n {
			return Event{}, ErrInvalid
		}
		e.Handshake = Handshake{BuildNumber: le.Uint32(b), Extended: n == 8}
		if n == 8 {
			e.Handshake.Flags = le.Uint32(b[4:])
		}
	case OrderExecuteResult:
		if len(b) < 12 {
			return Event{}, ErrInvalid
		}
		r := ExecuteResult{Flags: ExecuteFlags(le.Uint16(b)), Code: ResultCode(le.Uint16(b[2:])), RawResult: le.Uint32(b[4:])}
		n := int(le.Uint16(b[10:]))
		if !validExecuteFlags(r.Flags) || n == 0 || n > 520 || len(b) != 12+n {
			return Event{}, ErrInvalid
		}
		switch r.Code {
		case ExecuteOK, ExecuteHookNotLoaded, ExecuteDecodeFailed, ExecuteNotAllowed, ExecuteFileNotFound, ExecuteFailed, ExecuteSessionLocked:
		default:
			return Event{}, ErrUnsupported
		}
		var err error
		r.ExeOrFile, err = decodeString(b[12:])
		if err != nil {
			return Event{}, err
		}
		e.Execute = r
	case OrderSystemParameter:
		if len(b) != 5 {
			return Event{}, ErrInvalid
		}
		v := le.Uint32(b)
		if v != ScreenSaverActive && v != ScreenSaverSecure {
			return Event{}, ErrUnsupported
		}
		e.SystemParameter = ServerSystemParameter{v, b[4] != 0}
	case OrderMinMaxInfo:
		if len(b) != 20 {
			return Event{}, ErrInvalid
		}
		e.MinMax = MinMaxInfo{WindowID: le.Uint32(b)}
		out := []*int16{&e.MinMax.MaxWidth, &e.MinMax.MaxHeight, &e.MinMax.MaxX, &e.MinMax.MaxY, &e.MinMax.MinTrackWidth, &e.MinMax.MinTrackHeight, &e.MinMax.MaxTrackWidth, &e.MinMax.MaxTrackHeight}
		for i, v := range out {
			*v = int16(le.Uint16(b[4+i*2:]))
		}
	case OrderLocalMoveSize:
		if len(b) != 12 {
			return Event{}, ErrInvalid
		}
		e.MoveSize = MoveSize{le.Uint32(b), le.Uint16(b[4:]) != 0, le.Uint16(b[6:]), int16(le.Uint16(b[8:])), int16(le.Uint16(b[10:]))}
		if e.MoveSize.Type < 1 || e.MoveSize.Type > 11 {
			return Event{}, ErrInvalid
		}
	case OrderLanguageBar:
		if len(b) != 4 {
			return Event{}, ErrInvalid
		}
		e.LanguageBar = LanguageBarStatus(le.Uint32(b))
		if err := e.LanguageBar.validate(); err != nil {
			return Event{}, err
		}
	case OrderIMECompartment:
		if len(b) != 16 || le.Uint32(b) > 1 || le.Uint32(b[12:]) > 1 {
			return Event{}, ErrInvalid
		}
		e.IMECompartment = IMECompartment{Open: le.Uint32(b) == 1, ConversionMode: IMEConversionMode(le.Uint32(b[4:])), SentenceMode: IMESentenceMode(le.Uint32(b[8:])), Kana: le.Uint32(b[12:]) == 1}
	case OrderCloak:
		if len(b) != 5 || b[4] > 1 {
			return Event{}, ErrInvalid
		}
		e.Cloak = CloakState{WindowID: le.Uint32(b), Cloaked: b[4] == 1}
	case OrderTaskbarInfo:
		if len(b) != 12 {
			return Event{}, ErrInvalid
		}
		e.Taskbar = TaskbarTab{Message: TaskbarMessage(le.Uint32(b)), WindowID: le.Uint32(b[4:]), Body: le.Uint32(b[8:])}
		if e.Taskbar.Message < TaskbarTabRegister || e.Taskbar.Message > TaskbarTabProperties {
			return Event{}, ErrUnsupported
		}
	case OrderPowerDisplay:
		if len(b) != 4 || le.Uint32(b) > 1 {
			return Event{}, ErrInvalid
		}
		e.PowerDisplay = PowerDisplayState{Active: le.Uint32(b) == 1}
	case OrderZOrderSync:
		if len(b) != 4 {
			return Event{}, ErrInvalid
		}
		e.MarkerWindowID = le.Uint32(b)
	case OrderAppID, OrderAppIDEx:
		n := 524
		if e.Order == OrderAppIDEx {
			n = 1048
		}
		if len(b) != n {
			return Event{}, ErrInvalid
		}
		e.ApplicationID.WindowID = le.Uint32(b)
		var err error
		e.ApplicationID.ID, err = fixedString(b[4:524])
		if err != nil {
			return Event{}, err
		}
		if n == 1048 {
			e.ApplicationID.Extended = true
			e.ApplicationID.ProcessID = le.Uint32(b[524:])
			e.ApplicationID.ProcessImageName, err = fixedString(b[528:])
			if err != nil {
				return Event{}, err
			}
		}
	default:
		return Event{}, ErrUnsupported
	}
	return e, nil
}
