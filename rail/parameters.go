package rail

// Rectangle is the unsigned TS_RECTANGLE_16 used for system parameters. Window
// move/menu messages instead use signed coordinates (WindowRectangle).
type Rectangle struct{ Left, Top, Right, Bottom uint16 }

// SystemParameters is an explicit snapshot supplied by the application. The
// library does not read host settings. WorkArea and Display must be nonempty
// rectangles, WorkArea must fit inside Display, and Taskbar may be all zero when
// absent. HighContrastScheme is limited to 4094 UTF-16 bytes plus its NUL.
// For signed virtual-screen coordinates and complete multi-monitor snapshots,
// use Client.UpdateDesktop. WorkArea keeps this legacy unsigned rectangle API.
type SystemParameters struct {
	DragFullWindows, KeyboardCues, KeyboardPreferred, MouseButtonSwap bool
	WorkArea, Display, Taskbar                                        Rectangle
	HighContrastFlags                                                 uint32
	HighContrastScheme                                                string
}

func (r Rectangle) nonempty() bool { return r.Left < r.Right && r.Top < r.Bottom }
func (r Rectangle) contains(s Rectangle) bool {
	return r.Left <= s.Left && r.Top <= s.Top && r.Right >= s.Right && r.Bottom >= s.Bottom
}
func (r Rectangle) bytes() []byte {
	b := make([]byte, 0, 8)
	for _, v := range []uint16{r.Left, r.Top, r.Right, r.Bottom} {
		b = le.AppendUint16(b, v)
	}
	return b
}

func boolean(v bool) byte {
	if v {
		return 1
	}
	return 0
}
func systemParameter(id uint32, b []byte) []byte {
	return packet(OrderSystemParameter, append(le.AppendUint32(nil, id), b...))
}

func (s SystemParameters) packets() ([][]byte, error) {
	if !s.WorkArea.nonempty() || !s.Display.nonempty() || !s.Display.contains(s.WorkArea) || s.Taskbar != (Rectangle{}) && (!s.Taskbar.nonempty() || !s.Display.contains(s.Taskbar)) {
		return nil, ErrInvalid
	}
	b, err := encodeString(s.HighContrastScheme, 4094)
	if err != nil {
		return nil, err
	}
	b = append(b, 0, 0)
	h := le.AppendUint32(nil, s.HighContrastFlags)
	h = le.AppendUint32(h, uint32(len(b)))
	h = append(h, b...)
	return [][]byte{
		systemParameter(0x43, h),
		systemParameter(0x25, []byte{boolean(s.DragFullWindows)}),
		systemParameter(0x100b, []byte{boolean(s.KeyboardCues)}),
		systemParameter(0x45, []byte{boolean(s.KeyboardPreferred)}),
		systemParameter(0x21, []byte{boolean(s.MouseButtonSwap)}),
		systemParameter(0xf001, s.Display.bytes()),
		systemParameter(0xf000, s.Taskbar.bytes()),
		systemParameter(0x2f, s.WorkArea.bytes()),
	}, nil
}
