package remoteapp

import (
	"errors"
	"github.com/hq0101/rdp-go/rail"
)

var ErrBalloonActive = errors.New("remoteapp: previous balloon must finish first")
var ErrBalloonLimit = errors.New("remoteapp: balloon tracking limit exceeded")

// BalloonHandle identifies one local display, not just one InfoTip value.
// Even reopening the same tip allocates a new Display. Treat it as opaque and
// bind callbacks to the connection on which Begin returned it.
type BalloonHandle struct {
	Identity            rail.NotificationIdentity
	InfoSerial, Display uint64
}

// NotificationEvent is a single RAIL notification message ready for NotifyEvent.
type NotificationEvent struct{ WindowID, IconID, Message uint32 }

// BalloonTracker is an I/O-free, bounded record of actually shown balloons.
// Its zero value is ready to use. Serialize Begin, End, Reconcile and Reset
// with protocol state changes and writes. Begin/End consume state before I/O;
// on a write failure retire the connection, never replay the returned message.
type BalloonTracker struct {
	next, epoch uint64
	epochKnown  bool
	active      map[rail.NotificationIdentity]BalloonHandle
}

// Count includes deleted icons awaiting their actual local HIDE callback.
func (b *BalloonTracker) Count() int { return len(b.active) }
func (b *BalloonTracker) Current(id rail.NotificationIdentity) (BalloonHandle, bool) {
	h, ok := b.active[id]
	return h, ok
}

// Reset discards callbacks without sending anything, for connection retirement
// or a desktop reset. Display serials never rewind on an existing tracker.
func (b *BalloonTracker) Reset() { clear(b.active) }

// Reconcile follows committed WindowState updates. It retains a deleted icon
// only for a later HIDE, but drops records when an observed ID is reused. Desktop
// reset/resync discards all callbacks. Call before accepting new UI events.
func (b *BalloonTracker) Reconcile(s *rail.WindowState) {
	if s == nil {
		b.Reset()
		b.epochKnown = false
		return
	}
	epoch, _ := s.ActivationVersion()
	monitored, syncing := s.Monitoring()
	if !monitored || syncing || b.epochKnown && b.epoch != epoch {
		b.Reset()
	}
	b.epoch, b.epochKnown = epoch, true
	for id := range b.active {
		if current, ok := s.NotificationIdentity(id.WindowID, id.ID); ok && current != id {
			delete(b.active, id)
		}
	}
}

// Begin records a shown balloon. fresh means the caller must send SHOW exactly
// once; a duplicate report returns the existing handle with fresh=false. A tip
// replacement must finish the old display before starting a new one. At most 64
// active/pending displays are retained. n must be a current connection snapshot.
func (b *BalloonTracker) Begin(n rail.Notification) (h BalloonHandle, fresh bool, err error) {
	if _, err = NotificationMessages(n, NotifyBalloonShow); err != nil {
		return h, false, err
	}
	if old, ok := b.active[n.Identity()]; ok {
		if old.InfoSerial != n.InfoSerial {
			return h, false, ErrBalloonActive
		}
		return old, false, nil
	}
	if len(b.active) >= 64 || b.next == ^uint64(0) {
		return h, false, ErrBalloonLimit
	}
	b.next++
	h = BalloonHandle{Identity: n.Identity(), InfoSerial: n.InfoSerial, Display: b.next}
	if b.active == nil {
		b.active = make(map[rail.NotificationIdentity]BalloonHandle)
	}
	b.active[h.Identity] = h
	return h, true, nil
}

// End consumes exactly one recorded display. current is the latest icon, or nil
// after deletion. A late callback never closes a reopened display or an observed
// replacement icon. If the old tip disappeared, dismissal becomes HIDE, even
// for a late click: never activate a changed/hidden/deleted icon.
// Invalid handles/reasons do not consume a valid current display.
func (b *BalloonTracker) End(h BalloonHandle, reason NotificationAction, current *rail.Notification) (event NotificationEvent, err error) {
	old, ok := b.active[h.Identity]
	if !ok || h != old {
		return event, ErrStale
	}
	if reason != NotifyBalloonHide && reason != NotifyBalloonTimeout && reason != NotifyBalloonClick {
		return event, rail.ErrInvalid
	}
	if current != nil && current.Identity() != h.Identity {
		delete(b.active, h.Identity)
		return event, ErrStale
	}
	sameTip := current != nil && current.InfoSerial == h.InfoSerial && current.State == 0 && (current.Version == 3 || current.Version == 4) && current.InfoTip.Text != ""
	if !sameTip {
		reason = NotifyBalloonHide
	}
	message := uint32(0x403)
	if reason == NotifyBalloonTimeout {
		message = 0x404
	}
	if reason == NotifyBalloonClick {
		message = 0x405
	}
	delete(b.active, h.Identity)
	return NotificationEvent{WindowID: h.Identity.WindowID, IconID: h.Identity.ID, Message: message}, nil
}
