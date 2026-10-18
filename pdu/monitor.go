package pdu

import "encoding/binary"

// Monitor is a server TS_MONITOR_DEF. Right and Bottom are inclusive. Layout
// notifications describe topology; Demand Active remains the desktop size
// authority. This parser does not allocate a framebuffer or enable multi-monitor
// rendering. At most 16 definitions are accepted, each at most 8192 per side.
type Monitor struct {
	Left, Top, Right, Bottom int32
	Primary                  bool
}

func ParseMonitorLayout(b []byte) ([]Monitor, error) {
	if len(b) < 4 {
		return nil, ErrInvalid
	}
	n := int(binary.LittleEndian.Uint32(b))
	if n < 1 || n > 16 || len(b) != 4+20*n {
		return nil, ErrInvalid
	}
	monitors := make([]Monitor, 0, n)
	primary := 0
	for i := 0; i < n; i++ {
		p := b[4+i*20:]
		m := Monitor{Left: int32(binary.LittleEndian.Uint32(p)), Top: int32(binary.LittleEndian.Uint32(p[4:])), Right: int32(binary.LittleEndian.Uint32(p[8:])), Bottom: int32(binary.LittleEndian.Uint32(p[12:])), Primary: binary.LittleEndian.Uint32(p[16:])&1 != 0}
		w, h := int64(m.Right)-int64(m.Left)+1, int64(m.Bottom)-int64(m.Top)+1
		if w < 200 || w > 8192 || h < 200 || h > 8192 || binary.LittleEndian.Uint32(p[16:])&^uint32(1) != 0 {
			return nil, ErrInvalid
		}
		if m.Primary {
			primary++
			if m.Left != 0 || m.Top != 0 {
				return nil, ErrInvalid
			}
		}
		monitors = append(monitors, m)
	}
	if primary != 1 {
		return nil, ErrInvalid
	}
	return monitors, nil
}
