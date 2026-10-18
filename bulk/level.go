package bulk

import "fmt"

// Level selects the highest server bulk-compression package a client accepts.
// These option values are distinct from the zero-based protocol Type constants.
type Level byte

const (
	Default Level = iota // highest implemented package, currently RDP 6.1
	MPPC8K
	MPPC64K
	RDP6
	RDP61
)

// WireType returns the inclusive maximum compression type for Client Info.
func (l Level) WireType() (byte, error) {
	if l == Default {
		return TypeRDP61, nil
	}
	if l > RDP61 {
		return 0, fmt.Errorf("bulk: invalid compression level %d", l)
	}
	return byte(l - 1), nil
}

func ParseLevel(s string) (Level, error) {
	switch s {
	case "auto":
		return Default, nil
	case "8k":
		return MPPC8K, nil
	case "64k":
		return MPPC64K, nil
	case "rdp6":
		return RDP6, nil
	case "rdp61":
		return RDP61, nil
	default:
		return 0, fmt.Errorf("bulk: level must be auto, 8k, 64k, rdp6 or rdp61")
	}
}
