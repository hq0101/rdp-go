package rail

// Windowing orders travel in the RDP graphics stream, not on the rail channel.
// Values are MS-RDPERP FieldsPresentFlags; several low bits have different
// meanings for windows, notification icons and desktop orders.
const (
	WindowType              uint32 = 0x01000000
	NotifyType              uint32 = 0x02000000
	DesktopType             uint32 = 0x04000000
	WindowNew               uint32 = 0x10000000
	WindowDeleted           uint32 = 0x20000000
	WindowIcon              uint32 = 0x40000000
	WindowCachedIcon        uint32 = 0x80000000
	FieldOwner              uint32 = 0x2
	FieldTitle              uint32 = 0x4
	FieldStyle              uint32 = 0x8
	FieldShow               uint32 = 0x10
	FieldAppBarState        uint32 = 0x40
	FieldResizeMarginX      uint32 = 0x80
	FieldWindowRects        uint32 = 0x100
	FieldVisibility         uint32 = 0x200
	FieldWindowSize         uint32 = 0x400
	FieldWindowOffset       uint32 = 0x800
	FieldVisibleOffset      uint32 = 0x1000
	FieldIconBig            uint32 = 0x2000
	FieldClientOffset       uint32 = 0x4000
	FieldClientDelta        uint32 = 0x8000
	FieldClientSize         uint32 = 0x10000
	FieldRPContent          uint32 = 0x20000
	FieldRootParent         uint32 = 0x40000
	FieldEnforceZOrder      uint32 = 0x80000
	FieldIconOverlay        uint32 = 0x100000
	FieldOverlayNull        uint32 = 0x200000
	FieldOverlayDescription uint32 = 0x400000
	FieldTaskbarButton      uint32 = 0x800000
	FieldResizeMarginY      uint32 = 0x08000000
	FieldAppBarEdge         uint32 = 0x1
	NotifyTip               uint32 = 1
	NotifyInfoTip           uint32 = 2
	NotifyState             uint32 = 4
	NotifyVersion           uint32 = 8
	DesktopNone             uint32 = 1
	DesktopHooked           uint32 = 2
	DesktopSyncCompleted    uint32 = 4
	DesktopSyncBegan        uint32 = 8
	DesktopZOrder           uint32 = 0x10
	DesktopActive           uint32 = 0x20
)

const windowFields = FieldOwner | FieldTitle | FieldStyle | FieldShow | FieldAppBarState | FieldResizeMarginX | FieldWindowRects | FieldVisibility | FieldWindowSize | FieldWindowOffset | FieldVisibleOffset | FieldClientOffset | FieldClientDelta | FieldClientSize | FieldRPContent | FieldRootParent | FieldEnforceZOrder | FieldOverlayNull | FieldOverlayDescription | FieldTaskbarButton | FieldResizeMarginY | FieldAppBarEdge

// IconReference identifies a slot in the negotiated, session-wide icon cache.
type IconReference struct {
	Entry uint16
	ID    uint8
}

// Icon holds bounded, owned TS_ICON_INFO data in wire bitmap format. Mask and
// color planes can be absent. Decode validates a DIB layout and produces an
// immutable IconImage for transparent export or background-dependent drawing.
// Parsing/caching only validates wire fields; unsupported plane layouts can be
// retained as metadata, and Decode reports them without changing window state.
// Cache ID 0xff is treated as uncached by WindowState (see WindowOptions).
type Icon struct {
	Cache                IconReference
	BPP                  uint8
	Width, Height        uint16
	Mask, Palette, Color []byte
}

type WindowProperties struct {
	OwnerID, Style, ExtendedStyle                         uint32
	ShowState                                             byte
	Title                                                 string
	ClientX, ClientY                                      int32
	ClientWidth, ClientHeight                             uint32
	MarginLeft, MarginRight, MarginTop, MarginBottom      uint32
	RPContent                                             byte
	RootParentID                                          uint32
	X, Y, ClientDeltaX, ClientDeltaY                      int32
	Width, Height                                         uint32
	WindowRects                                           []Rectangle
	VisibleX, VisibleY                                    int32
	VisibilityRects                                       []Rectangle
	OverlayDescription                                    string
	TaskbarButton, EnforceZOrder, AppBarState, AppBarEdge byte
}

type Balloon struct {
	Timeout, Flags uint32
	Text, Title    string
}
type NotifyProperties struct {
	Version uint32
	ToolTip string
	InfoTip Balloon
	State   uint32
}

// WindowOrder is an owned, syntax-checked graphics order. Flags identify which
// fields are present, including explicit zero/empty updates. Parsing does not
// create windows, apply OS settings or validate capability/cache negotiation.
type WindowOrder struct {
	Flags              uint32
	WindowID, NotifyID uint32
	Window             WindowProperties
	Notify             NotifyProperties
	Icon               *Icon
	CachedIcon         *IconReference
	ActiveWindowID     uint32
	ZOrder             []uint32
}

type windowReader struct {
	b   []byte
	err error
}

func (r *windowReader) take(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.b) {
		r.err = ErrInvalid
		return nil
	}
	p := r.b[:n]
	r.b = r.b[n:]
	return p
}
func (r *windowReader) u8() byte {
	b := r.take(1)
	if b == nil {
		return 0
	}
	return b[0]
}
func (r *windowReader) u16() uint16 {
	b := r.take(2)
	if b == nil {
		return 0
	}
	return le.Uint16(b)
}
func (r *windowReader) u32() uint32 {
	b := r.take(4)
	if b == nil {
		return 0
	}
	return le.Uint32(b)
}
func (r *windowReader) text(limit int) string {
	n := int(r.u16())
	if n > limit || n%2 != 0 {
		r.err = ErrInvalid
		return ""
	}
	b := r.take(n)
	if r.err != nil {
		return ""
	}
	// Display strings may include a final NUL (e.g. window titles); embedded
	// NUL and unpaired UTF-16 surrogates are rejected, never silently replaced.
	if len(b) >= 2 && le.Uint16(b[len(b)-2:]) == 0 {
		b = b[:len(b)-2]
	}
	s, err := decodeString(b)
	if err != nil {
		r.err = err
	}
	return s
}
func (r *windowReader) rects() []Rectangle {
	n := int(r.u16())
	if n > len(r.b)/8 {
		r.err = ErrInvalid
		return nil
	}
	out := make([]Rectangle, n)
	for i := range out {
		out[i] = Rectangle{r.u16(), r.u16(), r.u16(), r.u16()}
		if out[i].Left > out[i].Right || out[i].Top > out[i].Bottom {
			r.err = ErrInvalid
		}
	}
	return out
}
func (r *windowReader) icon() *Icon {
	i := &Icon{Cache: IconReference{r.u16(), r.u8()}, BPP: r.u8(), Width: r.u16(), Height: r.u16()}
	if i.Width > MaxIconDimension || i.Height > MaxIconDimension || (i.Width == 0) != (i.Height == 0) {
		r.err = ErrInvalid
		return nil
	}
	colors := 0
	switch i.BPP {
	case 1, 4, 8:
		colors = int(r.u16())
	case 16, 24, 32:
	default:
		r.err = ErrUnsupported
		return nil
	}
	mask, pixels := int(r.u16()), int(r.u16())
	i.Mask = append([]byte(nil), r.take(mask)...)
	i.Palette = append([]byte(nil), r.take(colors)...)
	i.Color = append([]byte(nil), r.take(pixels)...)
	return i
}

// ParseWindowOrder consumes exactly one TS_ALTSEC_WINDOW order, including its
// 0x2e header and total OrderSize. Bounds derive from its uint16 wire length;
// batches are additionally bounded by WindowState.Apply. Unknown field bits
// are rejected because their lengths cannot be safely inferred.
func ParseWindowOrder(p []byte) (WindowOrder, error) {
	var o WindowOrder
	if len(p) < 7 || len(p) > MaxPDU || p[0] != 0x2e || int(le.Uint16(p[1:])) != len(p) {
		return o, ErrInvalid
	}
	r := windowReader{b: p[3:]}
	o.Flags = r.u32()
	f := o.Flags
	switch f & (WindowType | NotifyType | DesktopType) {
	case WindowType:
		if f & ^uint32(WindowType|WindowNew|WindowDeleted|WindowIcon|WindowCachedIcon|FieldIconBig|FieldIconOverlay|windowFields) != 0 {
			return WindowOrder{}, ErrUnsupported
		}
		o.WindowID = r.u32()
		if f&WindowDeleted != 0 {
			if f&WindowNew != 0 {
				return WindowOrder{}, ErrInvalid
			}
			// Deleted orders have no body even when known field bits are left
			// set, as in Microsoft's deleted notification example.
		} else if f&(WindowIcon|WindowCachedIcon) != 0 {
			if f&(WindowIcon|WindowCachedIcon) == WindowIcon|WindowCachedIcon || f&windowFields != 0 {
				return WindowOrder{}, ErrInvalid
			}
			if f&WindowIcon != 0 {
				o.Icon = r.icon()
			} else {
				o.CachedIcon = &IconReference{r.u16(), r.u8()}
			}
		} else {
			if f&(FieldIconBig|FieldIconOverlay) != 0 {
				return WindowOrder{}, ErrInvalid
			}
			w := &o.Window
			if f&FieldOwner != 0 {
				w.OwnerID = r.u32()
			}
			if f&FieldStyle != 0 {
				w.Style = r.u32()
				w.ExtendedStyle = r.u32()
			}
			if f&FieldShow != 0 {
				w.ShowState = r.u8()
				switch w.ShowState {
				case 0, 2, 3, 5:
				default:
					r.err = ErrInvalid
				}
			}
			if f&FieldTitle != 0 {
				w.Title = r.text(520)
			}
			if f&FieldClientOffset != 0 {
				w.ClientX = int32(r.u32())
				w.ClientY = int32(r.u32())
			}
			if f&FieldClientSize != 0 {
				w.ClientWidth = r.u32()
				w.ClientHeight = r.u32()
			}
			if f&FieldResizeMarginX != 0 {
				w.MarginLeft = r.u32()
				w.MarginRight = r.u32()
			}
			if f&FieldResizeMarginY != 0 {
				w.MarginTop = r.u32()
				w.MarginBottom = r.u32()
			}
			if f&FieldRPContent != 0 {
				w.RPContent = r.u8()
				if w.RPContent > 1 {
					r.err = ErrInvalid
				}
			}
			if f&FieldRootParent != 0 {
				w.RootParentID = r.u32()
			}
			if f&FieldWindowOffset != 0 {
				w.X = int32(r.u32())
				w.Y = int32(r.u32())
			}
			if f&FieldClientDelta != 0 {
				w.ClientDeltaX = int32(r.u32())
				w.ClientDeltaY = int32(r.u32())
			}
			if f&FieldWindowSize != 0 {
				w.Width = r.u32()
				w.Height = r.u32()
			}
			if f&FieldWindowRects != 0 {
				w.WindowRects = r.rects()
			}
			if f&FieldVisibleOffset != 0 {
				w.VisibleX = int32(r.u32())
				w.VisibleY = int32(r.u32())
			}
			if f&FieldVisibility != 0 {
				w.VisibilityRects = r.rects()
			}
			if f&FieldOverlayDescription != 0 {
				w.OverlayDescription = r.text(65534)
			}
			if f&FieldTaskbarButton != 0 {
				w.TaskbarButton = r.u8()
				if w.TaskbarButton > 1 {
					r.err = ErrInvalid
				}
			}
			if f&FieldEnforceZOrder != 0 {
				w.EnforceZOrder = r.u8()
				if w.EnforceZOrder > 1 {
					r.err = ErrInvalid
				}
			}
			if f&FieldAppBarState != 0 {
				w.AppBarState = r.u8()
				if w.AppBarState > 1 {
					r.err = ErrInvalid
				}
			}
			if f&FieldAppBarEdge != 0 {
				w.AppBarEdge = r.u8()
				if w.AppBarEdge > 3 {
					r.err = ErrInvalid
				}
			}
		}
	case NotifyType:
		if f & ^uint32(NotifyType|WindowNew|WindowDeleted|WindowIcon|WindowCachedIcon|15) != 0 {
			return WindowOrder{}, ErrUnsupported
		}
		o.WindowID = r.u32()
		o.NotifyID = r.u32()
		if f&WindowDeleted != 0 {
			if f&WindowNew != 0 {
				return WindowOrder{}, ErrInvalid
			}
		} else {
			icons := f & (WindowIcon | WindowCachedIcon)
			if icons == WindowIcon|WindowCachedIcon || f&WindowNew != 0 && icons == 0 {
				return WindowOrder{}, ErrInvalid
			}
			n := &o.Notify
			if f&NotifyVersion != 0 {
				n.Version = r.u32()
				if n.Version != 0 && n.Version != 3 && n.Version != 4 {
					r.err = ErrInvalid
				}
			}
			if f&NotifyTip != 0 {
				n.ToolTip = r.text(65534)
			}
			if f&NotifyInfoTip != 0 {
				n.InfoTip = Balloon{r.u32(), r.u32(), r.text(510), r.text(126)}
				if n.InfoTip.Flags & ^uint32(0x33) != 0 {
					r.err = ErrInvalid
				}
			}
			if f&NotifyState != 0 {
				n.State = r.u32()
				if n.State & ^uint32(1) != 0 {
					r.err = ErrInvalid
				}
			}
			if f&WindowIcon != 0 {
				o.Icon = r.icon()
			}
			if f&WindowCachedIcon != 0 {
				o.CachedIcon = &IconReference{r.u16(), r.u8()}
			}
		}
	case DesktopType:
		if f & ^uint32(DesktopType|0x3f) != 0 {
			return WindowOrder{}, ErrUnsupported
		}
		if f&DesktopNone != 0 {
			if f != DesktopType|DesktopNone {
				return WindowOrder{}, ErrInvalid
			}
		} else if f&DesktopSyncCompleted != 0 {
			if f != DesktopType|DesktopSyncCompleted {
				return WindowOrder{}, ErrInvalid
			}
		} else {
			if f&DesktopSyncBegan != 0 && f&DesktopHooked == 0 {
				return WindowOrder{}, ErrInvalid
			}
			if f&DesktopActive != 0 {
				o.ActiveWindowID = r.u32()
			}
			if f&DesktopZOrder != 0 {
				n := int(r.u8())
				if n > len(r.b)/4 {
					return WindowOrder{}, ErrInvalid
				}
				o.ZOrder = make([]uint32, n)
				seen := make(map[uint32]bool, n)
				for i := range o.ZOrder {
					o.ZOrder[i] = r.u32()
					if seen[o.ZOrder[i]] {
						r.err = ErrInvalid
					}
					seen[o.ZOrder[i]] = true
				}
			}
		}
	default:
		return WindowOrder{}, ErrInvalid
	}
	if r.err != nil {
		return WindowOrder{}, r.err
	}
	if len(r.b) != 0 {
		return WindowOrder{}, ErrInvalid
	}
	return o, nil
}
