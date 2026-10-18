package ime

import (
	"github.com/hq0101/rdp-go/rail"
	"slices"
	"sort"
)

type DisplayColorKind uint8

const (
	DisplayColorDefault DisplayColorKind = iota
	DisplayColorSystem
	DisplayColorRGB
)

// DisplayColor keeps system palette indices symbolic so the renderer can
// honor theme changes. RGB values use 0xRRGGBB; Default has Value zero.
type DisplayColor struct {
	Kind  DisplayColorKind
	Value uint32
}
type DisplayLine uint8

const (
	DisplayLineNone DisplayLine = iota
	DisplayLineSolid
	DisplayLineDot
	DisplayLineDash
	DisplayLineSquiggle
)

type DisplayConversion int32

const (
	DisplayInput DisplayConversion = iota
	DisplayTargetConverted
	DisplayConverted
	DisplayTargetNotConverted
	DisplayInputError
	DisplayFixedConverted
	DisplayOther DisplayConversion = -1
)

type DisplayStyle struct {
	Foreground, Background, Underline DisplayColor
	Line                              DisplayLine
	BoldLine                          bool
	Conversion                        DisplayConversion
}
type DisplayRun struct {
	Range TextRange
	ID    rail.GUID
	Style DisplayStyle
}

// TextPresentation is an owned, uncached rendering snapshot. Runs are sorted,
// nonoverlapping UTF-16 ranges; uncovered text uses application defaults.
// Runs describe display attributes, not guaranteed linguistic clause bounds.
// Snapshot.Revision identifies text/selection/composition/layout state, NOT
// attribute-only or system-theme changes. Resample for each rendering update;
// do not cache Runs solely by that revision. This is not a commit event.
type TextPresentation struct {
	Snapshot TextSnapshot
	Runs     []DisplayRun
}

// Fixed-width native TF_DISPLAYATTRIBUTE layout, also used by portable tests.
type displayColorData struct{ kind, value uint32 }
type displayData struct {
	foreground, background displayColorData
	line                   uint32
	bold                   int32
	underline              displayColorData
	conversion             int32
}

func decodeDisplayColor(v displayColorData) (DisplayColor, error) {
	switch v.kind {
	case 0:
		return DisplayColor{}, nil
	case 1:
		if v.value > 30 {
			return DisplayColor{}, rail.ErrUnsupported
		}
		return DisplayColor{DisplayColorSystem, v.value}, nil
	case 2:
		if v.value > 0xffffff {
			return DisplayColor{}, rail.ErrUnsupported
		}
		rgb := (v.value&255)<<16 | v.value&0xff00 | v.value>>16
		return DisplayColor{DisplayColorRGB, rgb}, nil
	default:
		return DisplayColor{}, rail.ErrUnsupported
	}
}
func decodeDisplay(v displayData) (DisplayStyle, error) {
	if v.line > 4 || v.conversion < -1 || v.conversion > 5 {
		return DisplayStyle{}, rail.ErrUnsupported
	}
	fg, err := decodeDisplayColor(v.foreground)
	if err != nil {
		return DisplayStyle{}, err
	}
	bg, err := decodeDisplayColor(v.background)
	if err != nil {
		return DisplayStyle{}, err
	}
	line, err := decodeDisplayColor(v.underline)
	if err != nil {
		return DisplayStyle{}, err
	}
	return DisplayStyle{fg, bg, line, DisplayLine(v.line), v.bold != 0, DisplayConversion(v.conversion)}, nil
}
func normalizeDisplayRuns(runs []DisplayRun, n int) ([]DisplayRun, error) {
	if n < 0 || n > 32768 || len(runs) > n {
		return nil, rail.ErrInvalid
	}
	out := slices.Clone(runs)
	sort.Slice(out, func(i, j int) bool { return out[i].Range.Start < out[j].Range.Start })
	var end int32
	for _, r := range out {
		if r.Range.Start < end || r.Range.End <= r.Range.Start || int64(r.Range.End) > int64(n) {
			return nil, ErrChanged
		}
		end = r.Range.End
	}
	return out, nil
}
