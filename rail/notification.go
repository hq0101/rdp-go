package rail

// NotificationIdentity is a local creation identity, independent of whether the
// icon's owning window is remoted. Reset never rewinds the generation counter.
type NotificationIdentity struct {
	WindowID, ID uint32
	Generation   uint64
}

func (n Notification) Identity() NotificationIdentity {
	return NotificationIdentity{WindowID: n.WindowID, ID: n.ID, Generation: n.Generation}
}

// NotificationIdentity reads scalar identity without copying icon pixels.
// Serialize this read with state updates, just like Notification.
func (s *WindowState) NotificationIdentity(window, icon uint32) (NotificationIdentity, bool) {
	n, ok := s.notifications[notifyKey{window, icon}]
	return n.Identity(), ok
}

// Notification returns one owned snapshot, including its independently owned icon.
func (s *WindowState) Notification(window, icon uint32) (Notification, bool) {
	n, ok := s.notifications[notifyKey{window, icon}]
	if !ok {
		return Notification{}, false
	}
	n.Icon = cloneIcon(n.Icon, make(map[*Icon]*Icon))
	return n, true
}

// NotificationRevision changes only on icon updates/deletion and desktop reset,
// allowing consumers to refresh independently of frequent window/graphics updates.
func (s *WindowState) NotificationRevision() uint64 { return s.notificationRevision }
