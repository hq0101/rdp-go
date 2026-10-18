package rdpdr

import "encoding/binary"

// Windows FILETIME is a signed count of 100 ns intervals since 1601 here.
// Zero omits a field; -1/-2 request per-open timestamp suppression/restoration,
// which Unix timestamp setters cannot implement. Validate the complete request
// before a native call so an unsupported field cannot cause partial changes.
const (
	directoryTimeCreate = 1 << iota
	directoryTimeAccess
	directoryTimeWrite
	directoryTimeChange
)

type directoryUnixTime struct {
	seconds, nanos int64
	set            bool
}

func directoryPlanTimes(b BasicInformation, supported uint32) ([4]directoryUnixTime, uint32) {
	var plan [4]directoryUnixTime
	values := [4]int64{b.CreationTime, b.LastAccessTime, b.LastWriteTime, b.ChangeTime}
	for _, value := range values {
		if value < -2 {
			return plan, StatusInvalidParameter
		}
	}
	if b.Attributes != 0 {
		return plan, StatusNotSupported
	}
	for i, value := range values {
		if value != 0 && (value < 0 || supported&(1<<i) == 0) {
			return plan, StatusNotSupported
		}
	}
	for i, value := range values {
		if value != 0 {
			plan[i] = directoryUnixTime{value/10000000 - 11644473600, value % 10000000 * 100, true}
		}
	}
	return plan, 0
}

// Darwin's attrlist is 24 bytes; its buffer contains only selected fields in
// attribute-bit order (creation, modification, access), with no length prefix.
// ATTR_CMN_CHGTIME is deliberately excluded: XNU silently ignores that setter.
// This fixed-width layout is shared with platform-independent wire tests.
func directoryDarwinTimeAttributes(plan [4]directoryUnixTime) (attrs [24]byte, times []byte) {
	binary.LittleEndian.PutUint16(attrs[:], 5) // ATTR_BIT_MAP_COUNT
	var common uint32
	for _, field := range []struct {
		index int
		flag  uint32
	}{{0, 0x200}, {2, 0x400}, {1, 0x1000}} {
		t := plan[field.index]
		if t.set {
			common |= field.flag
			times = binary.LittleEndian.AppendUint64(times, uint64(t.seconds))
			times = binary.LittleEndian.AppendUint64(times, uint64(t.nanos))
		}
	}
	binary.LittleEndian.PutUint32(attrs[4:], common)
	return attrs, times
}
