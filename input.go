package rdp

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"time"
	"unicode/utf16"
	"unicode/utf8"
)

var ErrUnsupportedOperation = errors.New("rdp: server does not support this operation")

// writeActive may run concurrently with ReadEvent. Transport serializes writers.
// A cancelled queued write leaves the session open; an I/O failure closes it.
func (s *Session) writeActive(ctx context.Context, typ byte, payload []byte) error {
	if err := s.connection.Transport.acquire(ctx, s.inputGate); err != nil {
		return err
	}
	defer func() { <-s.inputGate }()
	return s.writeActiveLocked(ctx, typ, payload)
}

// Caller holds inputGate across the whole logical input operation.
func (s *Session) writeActiveLocked(ctx context.Context, typ byte, payload []byte) error {
	if !s.active.Load() {
		return ErrDeactivated
	}
	// Validate coordinates and form desktop rectangles after taking the gate:
	// capability re-exchange can change dimensions while a caller is queued.
	info := s.Info()
	switch typ {
	case 56:
		if !info.FrameAcknowledge {
			return ErrUnsupportedOperation
		}
	case 28:
		if binary.LittleEndian.Uint16(payload[8:]) == 5 && !info.UnicodeInput {
			return ErrUnsupportedOperation
		}
		if binary.LittleEndian.Uint16(payload[8:]) == 0x8001 && binary.LittleEndian.Uint16(payload[10:])&0x200 == 0 {
			if err := s.checkPosition(binary.LittleEndian.Uint16(payload[12:]), binary.LittleEndian.Uint16(payload[14:])); err != nil {
				return err
			}
		}
	case 33:
		if !info.RefreshRect {
			return ErrUnsupportedOperation
		}
		payload = desktopArea(info)
	case 35:
		if !info.SuppressOutput {
			return ErrUnsupportedOperation
		}
		if payload[0] != 0 {
			payload = desktopArea(info)
		}
	}
	err := s.sendData(ctx, typ, payload)
	if err != nil {
		select {
		case <-s.connection.Transport.closed:
			s.failSession(err)
		default:
		}
	}
	return err
}

// AcknowledgeFrame reports a fully rendered surface frame. Call only after
// ApplySurfaceCommands returns its ID in CompletedFrames, in receive order.
// Acknowledging receipt before rendering can overrun the client's frame queue.
func (s *Session) AcknowledgeFrame(ctx context.Context, id uint32) error {
	return s.writeActive(ctx, 56, binary.LittleEndian.AppendUint32(nil, id))
}

// MaxTextUnits bounds a SendText call, which may use several input PDUs.
const MaxTextUnits = 512

// Large Unicode bursts produced substituted characters in Windows edit controls
// during interoperability tests. Keep each burst small and give the application
// time to consume it. This is a pacing policy, not a wire-format limit or an
// application acknowledgment. Surrogate pairs remain in the same batch.
const textBatchUnits = 8
const textBatchInterval = 20 * time.Millisecond

// ValidateTextInput checks the UTF-8 and size bounds without sending input.
// NUL and control characters other than tab/newline are rejected.
func ValidateTextInput(text string) error {
	if !utf8.ValidString(text) || len(text) == 0 || len(text) > MaxTextUnits*3 {
		return errors.New("rdp: invalid or oversized input text")
	}
	n := 0
	for _, r := range text {
		if r == 0 || (r < 32 && r != '\n' && r != '\r' && r != '\t') || r == 127 {
			return errors.New("rdp: unsupported control character in text")
		}
		n++
		if r > 0xffff {
			n++
		}
		if n > MaxTextUnits {
			return errors.New("rdp: input text exceeds 512 UTF-16 units")
		}
	}
	return nil
}

// SendText sends UTF-8 text as paired Unicode key-down/up events, including
// UTF-16 surrogate pairs. CRLF and LF become CR, as expected by Windows edit
// controls. Rendering depends on the target application's Unicode support.
// The entire call is serialized against other input and reactivation.
// Unicode events are sent in paced batches. Cancellation after a batch leaves
// that prefix delivered; it does not undo or retry input already sent.
func (s *Session) SendText(ctx context.Context, text string) error {
	if err := ValidateTextInput(text); err != nil {
		return err
	}
	var units []uint16
	previousCR := false
	for _, r := range text {
		if r == '\n' && previousCR {
			previousCR = false
			continue
		}
		previousCR = r == '\r'
		if r == '\n' {
			r = '\r'
		}
		if r > 0xffff {
			a, b := utf16.EncodeRune(r)
			units = append(units, uint16(a), uint16(b))
		} else {
			units = append(units, uint16(r))
		}
	}
	if err := s.connection.Transport.acquire(ctx, s.inputGate); err != nil {
		return err
	}
	defer func() { <-s.inputGate }()
	for len(units) > 0 {
		if delay := time.Until(s.textNext); delay > 0 {
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-s.connection.Transport.closed:
				timer.Stop()
				return net.ErrClosed
			case <-timer.C:
			}
		}
		n := min(len(units), textBatchUnits)
		if n < len(units) && units[n-1] >= 0xd800 && units[n-1] <= 0xdbff {
			n--
		}
		b := make([]byte, 4+24*n)
		binary.LittleEndian.PutUint16(b, uint16(n*2))
		for i, u := range units[:n] {
			for j := 0; j < 2; j++ {
				off := 4 + (i*2+j)*12
				binary.LittleEndian.PutUint16(b[off+4:], 5)
				binary.LittleEndian.PutUint16(b[off+6:], uint16(j)*0x8000)
				binary.LittleEndian.PutUint16(b[off+8:], u)
			}
		}
		if err := s.writeActiveLocked(ctx, 28, b); err != nil {
			return err
		}
		s.textNext = time.Now().Add(textBatchInterval)
		units = units[n:]
	}
	return nil
}
func (s *Session) inputEvent(ctx context.Context, kind, flags, a, b uint16) error {
	data := make([]byte, 16)
	binary.LittleEndian.PutUint16(data, 1) // one event; padding and eventTime zero
	binary.LittleEndian.PutUint16(data[8:], kind)
	binary.LittleEndian.PutUint16(data[10:], flags)
	binary.LittleEndian.PutUint16(data[12:], a)
	binary.LittleEndian.PutUint16(data[14:], b)
	return s.writeActive(ctx, 28, data)
}

// SendKey sends an IBM set-1 scancode. extended denotes an E0-prefixed key.
// Every successful key-down should be paired with a key-up by the caller.
// This does not interpret characters, Unicode, or local keyboard layouts.
func (s *Session) SendKey(ctx context.Context, scancode uint8, down, extended bool) error {
	if scancode == 0 || scancode > 0x7f {
		return errors.New("rdp: invalid set-1 scancode")
	}
	var flags uint16
	if !down {
		flags = 0x8000
	}
	if extended {
		flags |= 0x100
	}
	return s.inputEvent(ctx, 4, flags, uint16(scancode), 0)
}

type MouseButton uint8

const (
	MouseLeft MouseButton = iota + 1
	MouseRight
	MouseMiddle
)

func (s *Session) checkPosition(x, y uint16) error {
	info := s.Info()
	if x >= info.Width || y >= info.Height {
		return errors.New("rdp: pointer outside desktop")
	}
	return nil
}
func (s *Session) MovePointer(ctx context.Context, x, y uint16) error {
	if err := s.checkPosition(x, y); err != nil {
		return err
	}
	return s.inputEvent(ctx, 0x8001, 0x800, x, y)
}
func (s *Session) SendMouseButton(ctx context.Context, button MouseButton, down bool, x, y uint16) error {
	if err := s.checkPosition(x, y); err != nil {
		return err
	}
	if button < MouseLeft || button > MouseMiddle {
		return errors.New("rdp: invalid mouse button")
	}
	flags := uint16(0x1000) << uint(button-1)
	if down {
		flags |= 0x8000
	}
	return s.inputEvent(ctx, 0x8001, flags, x, y)
}

// Scroll sends vertical wheel units, usually 120 per detent. Negative is down.
func (s *Session) Scroll(ctx context.Context, units int16) error {
	if units == 0 || units < -256 || units > 255 {
		return errors.New("rdp: wheel units must be nonzero and in [-256,255]")
	}
	return s.inputEvent(ctx, 0x8001, 0x200|(uint16(units)&0x1ff), 0, 0)
}

// SynchronizeKeys resets held keys and sets toggle states. Bits 0..3 correspond
// to Scroll Lock, Num Lock, Caps Lock and Kana Lock. No key presses are generated.
func (s *Session) SynchronizeKeys(ctx context.Context, toggleFlags uint32) error {
	if toggleFlags & ^uint32(15) != 0 {
		return errors.New("rdp: invalid keyboard toggle flags")
	}
	return s.inputEvent(ctx, 0, 0, uint16(toggleFlags), 0)
}

func desktopArea(info SessionInfo) []byte {
	b := make([]byte, 12)
	b[0] = 1
	binary.LittleEndian.PutUint16(b[8:], info.Width-1)
	binary.LittleEndian.PutUint16(b[10:], info.Height-1)
	return b
}

// Refresh asks a supporting server to redraw the entire desktop.
func (s *Session) Refresh(ctx context.Context) error {
	return s.writeActive(ctx, 33, nil)
}

// SetDisplayUpdates controls output when a viewer is minimized or restored.
// Enabling output requests updates for the full current desktop rectangle.
func (s *Session) SetDisplayUpdates(ctx context.Context, enabled bool) error {
	b := []byte{0, 0, 0, 0}
	if enabled {
		b[0] = 1
	}
	return s.writeActive(ctx, 35, b)
}
