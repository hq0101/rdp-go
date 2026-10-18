package remoteapp

import "github.com/hq0101/rdp-go/rail"

type NotificationAction string

const (
	NotifyLeftDown       NotificationAction = "left_down"
	NotifyLeftUp         NotificationAction = "left_up"
	NotifyLeftDouble     NotificationAction = "left_double"
	NotifyRightDown      NotificationAction = "right_down"
	NotifyRightUp        NotificationAction = "right_up"
	NotifyRightDouble    NotificationAction = "right_double"
	NotifySelect         NotificationAction = "select"
	NotifyKeySelect      NotificationAction = "key_select"
	NotifyKeyContext     NotificationAction = "key_context"
	NotifyBalloonShow    NotificationAction = "balloon_show"
	NotifyBalloonHide    NotificationAction = "balloon_hide"
	NotifyBalloonTimeout NotificationAction = "balloon_timeout"
	NotifyBalloonClick   NotificationAction = "balloon_click"
)

// NotificationMessages maps an actual local UI event to ordered NotifyEvent
// message values. It performs no I/O and never activates the owning window.
// Use a current Notification from the same connection; validate its identity
// and revision at send time. A failed write must not replay the remaining plan.
// Mouse double-click replaces the second down; its up is a separate event.
// Version 0 uses button pairs for keyboard activation/menu. Versions 3/4 use
// NIN/WM_CONTEXTMENU. An absent Version defaults to legacy version 0.
// Balloon callers track actual visibility and issue only one dismissal reason.
func NotificationMessages(n rail.Notification, a NotificationAction) ([]uint32, error) {
	if n.Generation == 0 {
		return nil, ErrStale
	}
	if n.Version != 0 && n.Version != 3 && n.Version != 4 {
		return nil, rail.ErrUnsupported
	}
	if n.State & ^uint32(1) != 0 {
		return nil, rail.ErrInvalid
	}
	if n.State&1 != 0 && a != NotifyBalloonHide {
		return nil, ErrHidden
	}
	switch a {
	case NotifyLeftDown:
		return []uint32{0x201}, nil
	case NotifyLeftUp:
		return []uint32{0x202}, nil
	case NotifyLeftDouble:
		return []uint32{0x203}, nil
	case NotifyRightDown:
		return []uint32{0x204}, nil
	case NotifyRightUp:
		return []uint32{0x205}, nil
	case NotifyRightDouble:
		return []uint32{0x206}, nil
	case NotifySelect, NotifyKeySelect:
		if n.Version == 0 {
			return []uint32{0x201, 0x202}, nil
		}
		if a == NotifySelect {
			return []uint32{0x400}, nil
		}
		return []uint32{0x401}, nil
	case NotifyKeyContext:
		if n.Version == 0 {
			return []uint32{0x204, 0x205}, nil
		}
		return []uint32{0x7b}, nil
	case NotifyBalloonShow, NotifyBalloonHide, NotifyBalloonTimeout, NotifyBalloonClick:
		if n.Version == 0 || n.InfoTip.Text == "" || n.InfoSerial == 0 {
			return nil, rail.ErrUnsupported
		}
		values := map[NotificationAction]uint32{NotifyBalloonShow: 0x402, NotifyBalloonHide: 0x403, NotifyBalloonTimeout: 0x404, NotifyBalloonClick: 0x405}
		return []uint32{values[a]}, nil
	default:
		return nil, rail.ErrInvalid
	}
}
