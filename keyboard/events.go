// Package keyboard encodes RDP scancode input and tracks ownership of physical
// keys shared by a local IME and a remote desktop. It does not read OS input.
package keyboard

import (
	"encoding/binary"
	"errors"
)

var (
	ErrInvalid = errors.New("keyboard: invalid input")
	ErrBusy    = errors.New("keyboard: operation in progress")
	ErrStale   = errors.New("keyboard: stale focus")
	ErrClosed  = errors.New("keyboard: router closed")
	ErrFailed  = errors.New("keyboard: uncertain delivery; retire input target")
)

// MaxEvents is this library's per-PDU input bound, not a protocol maximum.
const MaxEvents = 64

// Event is one TS_KEYBOARD_EVENT. WasDown is KBDFLAGS_DOWN (the previous
// state), not the inverse of RELEASE. Extended denotes E0; Extended1 denotes
// the E1 CTRL component of Pause. The two prefixes cannot be combined.
type Event struct {
	ScanCode                           uint8
	Down, Extended, Extended1, WasDown bool
}

// MarshalEvents constructs a slow-path Input PDU payload (without ShareData).
// All events are validated before a payload is returned. No OS calls occur.
func MarshalEvents(events []Event) ([]byte, error) {
	if len(events) == 0 || len(events) > MaxEvents {
		return nil, ErrInvalid
	}
	for _, e := range events {
		if e.ScanCode == 0 || e.ScanCode > 0x7f || e.Extended && e.Extended1 || e.Extended1 && e.ScanCode != 0x1d {
			return nil, ErrInvalid
		}
	}
	b := make([]byte, 4+12*len(events))
	binary.LittleEndian.PutUint16(b, uint16(len(events)))
	for j, e := range events {
		var flags uint16
		if !e.Down {
			flags |= 0x8000
		}
		if e.Extended {
			flags |= 0x0100
		}
		if e.Extended1 {
			flags |= 0x0200
		}
		if e.WasDown {
			flags |= 0x4000
		}
		p := b[4+j*12:]
		binary.LittleEndian.PutUint16(p[4:], 4)
		binary.LittleEndian.PutUint16(p[6:], flags)
		binary.LittleEndian.PutUint16(p[8:], uint16(e.ScanCode))
	}
	return b, nil
}

// PauseEvents returns a complete MS-RDPBCGR Pause press/release. The E1 CTRL
// events do not represent the user's ordinary CTRL key. Send all four together.
func PauseEvents() [4]Event {
	return [4]Event{
		{ScanCode: 0x1d, Down: true, Extended1: true},
		{ScanCode: 0x45, Down: true},
		{ScanCode: 0x1d, Extended1: true, WasDown: true},
		{ScanCode: 0x45, WasDown: true},
	}
}

// Key identifies a physical set-1 key, independently of the active layout.
// Pause is a complete pulse rather than a held key; its other fields are zero.
type Key struct {
	ScanCode uint8
	Extended bool
	Pause    bool
}

// Input is one host key message after local IME/shortcut filtering. Count is
// the number of down events represented by this message, in [1,65535]; an up
// requires Count=1. WasDown identifies an auto-repeat/orphaned held key.
type Input struct {
	Key           Key
	Down, WasDown bool
	Count         uint16
}

func (in Input) valid() bool {
	k := in.Key
	keyOK := k.Pause && k.ScanCode == 0 && !k.Extended || !k.Pause && k.ScanCode > 0 && k.ScanCode <= 0x7f
	return keyOK && in.Count != 0 && (in.Down || in.Count == 1)
}

// Validate checks a host input without changing routing state or doing I/O.
func (in Input) Validate() error {
	if !in.valid() {
		return ErrInvalid
	}
	return nil
}

func (k Key) event(down, wasDown bool) Event {
	return Event{ScanCode: k.ScanCode, Extended: k.Extended, Down: down, WasDown: wasDown}
}
