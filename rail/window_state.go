package rail

import (
	"errors"
	"maps"
	"slices"
)

var ErrWindowLimit = errors.New("rail: window state resource limit exceeded")

// WindowOptions must reflect the enclosing connection's negotiated Window List
// and RAIL capabilities/client status. This package does not advertise them.
// Zero limits default to 1024 windows, 2048 notifications, 4096 cached icons and
// 16 MiB of accounted state. Hard limits are 4096/8192/32768/64 MiB respectively.
// IconCaches and IconEntries describe actual negotiated bounds (zero means no
// cache). The specification gives an impossible 0xffff sentinel for its one-byte
// CacheId; this implementation interprets wire ID 0xff as uncached. This profile
// choice still needs confirmation with a real Windows RemoteApp server.
type WindowOptions struct {
	Extended, ResizeMargins, AppBar, ShellIntegration, HighDPIIcons bool
	IconCaches                                                      uint8
	IconEntries                                                     uint16
	MaxWindows, MaxNotifications, MaxCachedIcons, MaxBytes          int
}

type Window struct {
	// Cloaked is separate from ShowState; geometry, icons and lifetime survive.
	Cloaked         bool
	CloakSerial     uint64 // Changes on transitions, preventing hide/show ABA input reuse.
	ID, KnownFields uint32
	Generation      uint64 // Local creation serial; never a wire ID, preserved on updates.
	WindowProperties
	SmallIcon, LargeIcon, SmallOverlayIcon, LargeOverlayIcon *Icon
}

type Notification struct {
	Generation, Revision, InfoSerial uint64 // Local lifetime, update and balloon identifiers.
	WindowID, ID, KnownFields        uint32
	NotifyProperties
	Icon *Icon
}

type DesktopSnapshot struct {
	// Epoch changes when desktop contents are discarded. ActivationSerial also
	// changes for every explicit ActiveWindowId, including repeated IDs.
	Epoch, ActivationSerial                      uint64
	Revision                                     uint64
	Monitored, Syncing, ActiveKnown, ZOrderKnown bool
	ActiveWindowID                               uint32
	ZOrder                                       []uint32
	Windows                                      []Window
	Notifications                                []Notification
	CachedIcons, AccountedBytes                  int
}

type notifyKey struct{ window, id uint32 }

// WindowState maintains immutable internal entries and commits complete batches
// atomically. Methods require caller synchronization. Exported snapshots own
// their mutable storage; icons shared within one snapshot remain shared there,
// but never alias this state. There are no OS calls, callbacks or goroutines.
// Use one state per RDP connection; ordinary same-connection desktop switches
// discard windows/notifications but preserve the session-wide icon cache.
type WindowState struct {
	nextGeneration                         uint64
	nextNotification, notificationRevision uint64
	cloakRevision                          uint64
	options                                WindowOptions
	windows                                map[uint32]Window
	notifications                          map[notifyKey]Notification
	icons                                  map[IconReference]*Icon
	desktop                                DesktopSnapshot // No Window/Notification/bitmap data here.
}

func NewWindowState(o WindowOptions) (*WindowState, error) {
	if o.MaxWindows == 0 {
		o.MaxWindows = 1024
	}
	if o.MaxNotifications == 0 {
		o.MaxNotifications = 2048
	}
	if o.MaxCachedIcons == 0 {
		o.MaxCachedIcons = 4096
	}
	if o.MaxBytes == 0 {
		o.MaxBytes = 16 << 20
	}
	if o.MaxWindows < 1 || o.MaxWindows > 4096 || o.MaxNotifications < 1 || o.MaxNotifications > 8192 || o.MaxCachedIcons < 1 || o.MaxCachedIcons > 32768 || o.MaxBytes < 1024 || o.MaxBytes > 64<<20 || (o.IconCaches == 0) != (o.IconEntries == 0) {
		return nil, ErrInvalid
	}
	s := &WindowState{options: o}
	s.Reset()
	s.desktop.Revision = 0
	return s, nil
}

// ActivationVersion is a scalar snapshot without cloning icon/image data.
func (s *WindowState) ActivationVersion() (epoch, serial uint64) {
	return s.desktop.Epoch, s.desktop.ActivationSerial
}

func (s *WindowState) Options() WindowOptions { return s.options }
func (s *WindowState) Revision() uint64       { return s.desktop.Revision }

// Monitoring and ActiveWindow read scalar desktop metadata without cloning
// windows, regions or icon bitmaps. Serialize these reads with state updates.
func (s *WindowState) Monitoring() (monitored, syncing bool) {
	return s.desktop.Monitored, s.desktop.Syncing
}

func (s *WindowState) ActiveWindow() (id uint32, known bool) {
	return s.desktop.ActiveWindowID, s.desktop.ActiveKnown
}

// Window returns one owned window snapshot. It avoids copying other windows or
// notification icons when validating a presentation/input target. The caller
// must serialize this read with Apply/Reconfigure/Reset.
func (s *WindowState) Window(id uint32) (Window, bool) {
	w, ok := s.windows[id]
	if !ok {
		return Window{}, false
	}
	return cloneWindow(w, make(map[*Icon]*Icon)), true
}

// Reconfigure applies newly negotiated capabilities/limits on the same RDP
// connection before subsequent drawing orders. Windows, notifications and
// their current icon objects survive, including fields received under previous
// capabilities. Cache slots outside the new bounds are removed; displayed icons
// still referring to those objects remain valid and accounted. New orders use
// the new capability gates. Existing resource use must fit the new budgets.
// Any error leaves options, metadata, caches and revision unchanged. A new
// connection instead needs NewWindowState or an explicit Reset.
func (s *WindowState) Reconfigure(o WindowOptions) error {
	if s == nil || s.windows == nil || s.options.MaxBytes == 0 {
		return ErrInvalid
	}
	configured, err := NewWindowState(o)
	if err != nil {
		return err
	}
	next := *s
	next.options = configured.options
	next.icons = maps.Clone(s.icons)
	for k := range next.icons {
		if k.ID >= next.options.IconCaches || k.Entry >= next.options.IconEntries {
			delete(next.icons, k)
		}
	}
	if len(next.windows) > next.options.MaxWindows || len(next.notifications) > next.options.MaxNotifications || len(next.icons) > next.options.MaxCachedIcons {
		return ErrWindowLimit
	}
	used := next.account()
	if used > next.options.MaxBytes {
		return ErrWindowLimit
	}
	next.desktop.AccountedBytes = used
	next.desktop.Revision++
	*s = next
	return nil
}

// Reset discards all connection state, including icon caches. A new connection
// must use a new state (or an explicit Reset after all old consumers stop).
func (s *WindowState) Reset() {
	s.notificationRevision++
	s.cloakRevision++
	rev := s.desktop.Revision
	s.windows = make(map[uint32]Window)
	s.notifications = make(map[notifyKey]Notification)
	s.icons = make(map[IconReference]*Icon)
	s.desktop = DesktopSnapshot{Revision: rev + 1, Epoch: s.desktop.Epoch + 1, ActivationSerial: s.desktop.ActivationSerial + 1}
}

func cloneIcon(i *Icon, seen map[*Icon]*Icon) *Icon {
	if i == nil {
		return nil
	}
	if p := seen[i]; p != nil {
		return p
	}
	p := *i
	p.Mask = slices.Clone(i.Mask)
	p.Palette = slices.Clone(i.Palette)
	p.Color = slices.Clone(i.Color)
	seen[i] = &p
	return &p
}
func cloneWindow(w Window, seen map[*Icon]*Icon) Window {
	w.WindowRects = slices.Clone(w.WindowRects)
	w.VisibilityRects = slices.Clone(w.VisibilityRects)
	w.SmallIcon = cloneIcon(w.SmallIcon, seen)
	w.LargeIcon = cloneIcon(w.LargeIcon, seen)
	w.SmallOverlayIcon = cloneIcon(w.SmallOverlayIcon, seen)
	w.LargeOverlayIcon = cloneIcon(w.LargeOverlayIcon, seen)
	return w
}
func (s *WindowState) Snapshot() DesktopSnapshot {
	d := s.desktop
	d.ZOrder = slices.Clone(d.ZOrder)
	seen := make(map[*Icon]*Icon)
	for _, w := range s.windows {
		d.Windows = append(d.Windows, cloneWindow(w, seen))
	}
	slices.SortFunc(d.Windows, func(a, b Window) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	for _, n := range s.notifications {
		n.Icon = cloneIcon(n.Icon, seen)
		d.Notifications = append(d.Notifications, n)
	}
	slices.SortFunc(d.Notifications, func(a, b Notification) int {
		if a.WindowID < b.WindowID {
			return -1
		}
		if a.WindowID > b.WindowID {
			return 1
		}
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	d.CachedIcons = len(s.icons)
	return d
}

// Apply accepts graphics orders including their headers, in stream order. A
// batch is limited to 4096 orders/1 MiB. Parse, capability, cache or resource
// errors leave every previous entry, cache slot and revision unchanged. Unknown
// existing-window/notification updates are ignored (inline icons still populate
// the cache); new IDs must not already exist. Deleted orders may carry stale
// known field bits but no body. Window deletion also discards its notifications.
func (s *WindowState) Apply(orders ...[]byte) error {
	if s == nil || s.windows == nil || s.options.MaxBytes == 0 {
		return ErrInvalid
	}
	if len(orders) > 4096 {
		return ErrWindowLimit
	}
	size := 0
	for _, p := range orders {
		if len(p) > MaxMessage-size {
			return ErrWindowLimit
		}
		size += len(p)
	}
	if len(orders) == 0 {
		return nil
	}
	next := *s
	next.windows = maps.Clone(s.windows)
	next.notifications = maps.Clone(s.notifications)
	next.icons = maps.Clone(s.icons)
	for _, p := range orders {
		o, err := ParseWindowOrder(p)
		if err != nil {
			return err
		}
		if err = next.apply(o); err != nil {
			return err
		}
		if len(next.windows) > s.options.MaxWindows || len(next.notifications) > s.options.MaxNotifications || len(next.icons) > s.options.MaxCachedIcons {
			return ErrWindowLimit
		}
	}
	used := next.account()
	if used > s.options.MaxBytes {
		return ErrWindowLimit
	}
	next.desktop.AccountedBytes = used
	next.desktop.Revision++
	*s = next
	return nil
}

func (s *WindowState) cache(o WindowOrder) (*Icon, error) {
	if o.Icon != nil {
		i := o.Icon
		dim := uint16(32)
		if s.options.HighDPIIcons {
			dim = 96
		}
		if i.Width > dim || i.Height > dim {
			return nil, ErrUnsupported
		}
		if i.Cache.ID != 0xff {
			if i.Cache.ID >= s.options.IconCaches || i.Cache.Entry >= s.options.IconEntries {
				return nil, ErrInvalid
			}
			s.icons[i.Cache] = i
		}
		return i, nil
	}
	if o.CachedIcon != nil {
		k := *o.CachedIcon
		if k.ID >= s.options.IconCaches || k.Entry >= s.options.IconEntries {
			return nil, ErrInvalid
		}
		i := s.icons[k]
		if i == nil {
			return nil, ErrState
		}
		return i, nil
	}
	return nil, nil
}

func (s *WindowState) clearDesktop() {
	s.notificationRevision++
	s.desktop.Epoch++
	s.desktop.ActivationSerial++
	s.windows = make(map[uint32]Window)
	s.notifications = make(map[notifyKey]Notification)
	s.desktop.ActiveWindowID = 0
	s.desktop.ActiveKnown = false
	s.desktop.ZOrder = nil
	s.desktop.ZOrderKnown = false
}

func (s *WindowState) apply(o WindowOrder) error {
	f := o.Flags
	if f&DesktopType != 0 {
		if f&DesktopNone != 0 {
			s.clearDesktop()
			s.desktop.Monitored = false
			s.desktop.Syncing = false
			return nil
		}
		if f&DesktopSyncBegan != 0 {
			s.clearDesktop()
			s.desktop.Syncing = true
		}
		if f&DesktopHooked != 0 {
			s.desktop.Monitored = true
		}
		if f&DesktopSyncCompleted != 0 {
			s.desktop.Syncing = false
		}
		if f&DesktopActive != 0 {
			s.desktop.ActivationSerial++
			s.desktop.ActiveWindowID = o.ActiveWindowID
			s.desktop.ActiveKnown = true
		}
		if f&DesktopZOrder != 0 {
			s.desktop.ZOrder = o.ZOrder
			s.desktop.ZOrderKnown = true
		}
		return nil
	}
	if f&WindowDeleted != 0 {
		if f&NotifyType != 0 {
			if _, exists := s.notifications[notifyKey{o.WindowID, o.NotifyID}]; exists {
				s.notificationRevision++
			}
			delete(s.notifications, notifyKey{o.WindowID, o.NotifyID})
			return nil
		}
		delete(s.windows, o.WindowID)
		for k := range s.notifications {
			if k.window == o.WindowID {
				delete(s.notifications, k)
				s.notificationRevision++
			}
		}
		if s.desktop.ActiveKnown && s.desktop.ActiveWindowID == o.WindowID {
			s.desktop.ActiveKnown = false
			s.desktop.ActivationSerial++
			s.desktop.ActiveWindowID = 0
		}
		z := slices.Clone(s.desktop.ZOrder)
		s.desktop.ZOrder = slices.DeleteFunc(z, func(v uint32) bool { return v == o.WindowID })
		return nil
	}
	if f&WindowType != 0 {
		if !s.options.Extended && f&(FieldClientSize|FieldRPContent|FieldRootParent) != 0 || !s.options.ResizeMargins && f&(FieldResizeMarginX|FieldResizeMarginY) != 0 || !s.options.AppBar && f&(FieldAppBarEdge|FieldAppBarState) != 0 || !s.options.ShellIntegration && f&(FieldIconOverlay|FieldOverlayNull|FieldOverlayDescription|FieldTaskbarButton) != 0 {
			return ErrUnsupported
		}
		i, err := s.cache(o)
		if err != nil {
			return err
		}
		w, exists := s.windows[o.WindowID]
		if f&(WindowIcon|WindowCachedIcon) != 0 {
			if !exists {
				return nil
			}
			if f&FieldIconOverlay != 0 {
				if f&FieldIconBig != 0 {
					w.LargeOverlayIcon = i
				} else {
					w.SmallOverlayIcon = i
				}
			} else if f&FieldIconBig != 0 {
				w.LargeIcon = i
			} else {
				w.SmallIcon = i
			}
			s.windows[o.WindowID] = w
			return nil
		}
		if f&WindowNew != 0 {
			if exists {
				return ErrState
			}
			if s.nextGeneration == ^uint64(0) {
				return ErrWindowLimit
			}
			s.nextGeneration++
			w = Window{ID: o.WindowID, Generation: s.nextGeneration}
		} else if !exists {
			return nil
		}
		mergeWindow(&w.WindowProperties, o.Window, f)
		w.KnownFields |= f & windowFields
		if f&FieldOverlayNull != 0 {
			w.SmallOverlayIcon = nil
			w.LargeOverlayIcon = nil
		}
		s.windows[o.WindowID] = w
		return nil
	}
	i, err := s.cache(o)
	if err != nil {
		return err
	}
	k := notifyKey{o.WindowID, o.NotifyID}
	n, exists := s.notifications[k]
	if f&WindowNew != 0 {
		if exists {
			return ErrState
		}
		if s.nextNotification == ^uint64(0) {
			return ErrWindowLimit
		}
		s.nextNotification++
		n = Notification{WindowID: o.WindowID, ID: o.NotifyID, Generation: s.nextNotification}
	} else if !exists {
		return nil
	}
	if f&NotifyVersion != 0 {
		n.Version = o.Notify.Version
	}
	if f&NotifyTip != 0 {
		n.ToolTip = o.Notify.ToolTip
	}
	if f&NotifyInfoTip != 0 {
		n.InfoTip = o.Notify.InfoTip
		n.InfoSerial++
	}
	if f&NotifyState != 0 {
		n.State = o.Notify.State
	}
	if i != nil {
		n.Icon = i
	}
	n.KnownFields |= f & 15
	n.Revision++
	s.notificationRevision++
	s.notifications[k] = n
	return nil
}

func mergeWindow(w *WindowProperties, v WindowProperties, f uint32) {
	if f&FieldOwner != 0 {
		w.OwnerID = v.OwnerID
	}
	if f&FieldStyle != 0 {
		w.Style = v.Style
		w.ExtendedStyle = v.ExtendedStyle
	}
	if f&FieldShow != 0 {
		w.ShowState = v.ShowState
	}
	if f&FieldTitle != 0 {
		w.Title = v.Title
	}
	if f&FieldClientOffset != 0 {
		w.ClientX = v.ClientX
		w.ClientY = v.ClientY
	}
	if f&FieldClientSize != 0 {
		w.ClientWidth = v.ClientWidth
		w.ClientHeight = v.ClientHeight
	}
	if f&FieldResizeMarginX != 0 {
		w.MarginLeft = v.MarginLeft
		w.MarginRight = v.MarginRight
	}
	if f&FieldResizeMarginY != 0 {
		w.MarginTop = v.MarginTop
		w.MarginBottom = v.MarginBottom
	}
	if f&FieldRPContent != 0 {
		w.RPContent = v.RPContent
	}
	if f&FieldRootParent != 0 {
		w.RootParentID = v.RootParentID
	}
	if f&FieldWindowOffset != 0 {
		w.X = v.X
		w.Y = v.Y
	}
	if f&FieldClientDelta != 0 {
		w.ClientDeltaX = v.ClientDeltaX
		w.ClientDeltaY = v.ClientDeltaY
	}
	if f&FieldWindowSize != 0 {
		w.Width = v.Width
		w.Height = v.Height
	}
	if f&FieldWindowRects != 0 {
		w.WindowRects = v.WindowRects
	}
	if f&FieldVisibleOffset != 0 {
		w.VisibleX = v.VisibleX
		w.VisibleY = v.VisibleY
	}
	if f&FieldVisibility != 0 {
		w.VisibilityRects = v.VisibilityRects
	}
	if f&FieldOverlayDescription != 0 {
		w.OverlayDescription = v.OverlayDescription
	}
	if f&FieldTaskbarButton != 0 {
		w.TaskbarButton = v.TaskbarButton
	}
	if f&FieldEnforceZOrder != 0 {
		w.EnforceZOrder = v.EnforceZOrder
	}
	if f&FieldAppBarState != 0 {
		w.AppBarState = v.AppBarState
	}
	if f&FieldAppBarEdge != 0 {
		w.AppBarEdge = v.AppBarEdge
	}
}

// Account conservative fixed overhead plus variable storage, and unique icon
// objects across caches and active owners. Replacing a slot must not erase an
// older icon still referenced by a window or notification.
func (s *WindowState) account() int {
	used := len(s.desktop.ZOrder)*4 + len(s.icons)*64
	seen := make(map[*Icon]bool)
	icon := func(i *Icon) {
		if i != nil && !seen[i] {
			seen[i] = true
			used += 128 + len(i.Mask) + len(i.Palette) + len(i.Color)
		}
	}
	for _, i := range s.icons {
		icon(i)
	}
	for _, w := range s.windows {
		used += 512 + len(w.Title) + len(w.OverlayDescription) + (len(w.WindowRects)+len(w.VisibilityRects))*8
		icon(w.SmallIcon)
		icon(w.LargeIcon)
		icon(w.SmallOverlayIcon)
		icon(w.LargeOverlayIcon)
	}
	for _, n := range s.notifications {
		used += 256 + len(n.ToolTip) + len(n.InfoTip.Text) + len(n.InfoTip.Title)
		icon(n.Icon)
	}
	return used
}

// WindowIdentity identifies one local lifetime of a remote window. Generation
// changes on creation, including deletion/recreation within a single Apply.
type WindowIdentity struct {
	ID         uint32
	Generation uint64
}

// Identities returns sorted scalar identities without copying icons or titles.
// Reset and desktop resynchronization do not rewind creation serials.
func (s *WindowState) Identities() []WindowIdentity {
	var out []WindowIdentity
	for _, w := range s.windows {
		out = append(out, WindowIdentity{ID: w.ID, Generation: w.Generation})
	}
	slices.SortFunc(out, func(a, b WindowIdentity) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return out
}
