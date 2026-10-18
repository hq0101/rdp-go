package ime

import (
	"errors"
	"github.com/hq0101/rdp-go/rail"
	"unsafe"
)

var (
	propDisplay = rail.GUID{Data1: 0x34b45670, Data2: 0x7526, Data3: 0x11d2, Data4: [8]byte{0xa1, 0x47, 0, 0x10, 0x5a, 0x27, 0x99, 0xb5}}
	clsCategory = rail.GUID{Data1: 0xa4b544a1, Data2: 0x438d, Data3: 0x4b41, Data4: [8]byte{0x93, 0x25, 0x86, 0x95, 0x23, 0xe2, 0xd6, 0xc7}}
	iidCategory = rail.GUID{Data1: 0xc3acefb5, Data2: 0xf69d, Data3: 0x4905, Data4: [8]byte{0x93, 0x8f, 0xfc, 0xad, 0xcf, 0x4b, 0xe8, 0x30}}
	clsDisplay  = rail.GUID{Data1: 0x3ce74de4, Data2: 0x53d3, Data3: 0x4d74, Data4: [8]byte{0x8b, 0x83, 0x43, 0x1b, 0x38, 0x28, 0xba, 0x53}}
	iidDisplay  = rail.GUID{Data1: 0x8ded7393, Data2: 0x5db1, Data3: 0x475c, Data4: [8]byte{0x9e, 0x71, 0xa3, 0x91, 0x11, 0xb0, 0xff, 0x67}}
)

// Presentation samples text and native display properties without changing
// keyboard focus, IME modes or system display preferences. Drain Pump first.
// TakeChanges reports native edits, including property-only updates. Resample
// for application theme updates too; these do not necessarily change the text
// revision. Errors return no partial result.
func (d *WindowsDocument) Presentation() (TextPresentation, error) {
	if err := d.enter(false); err != nil {
		return TextPresentation{}, err
	}
	defer d.leave()
	return d.presentation()
}
func (i *WindowsInput) Presentation(t TextFocus) (TextPresentation, error) {
	if err := i.enter(); err != nil {
		return TextPresentation{}, err
	}
	defer i.leave()
	if err := i.check(t); err != nil {
		return TextPresentation{}, err
	}
	v, err := i.document.presentation()
	if err != nil {
		return TextPresentation{}, err
	}
	if err = i.check(t); err != nil {
		return TextPresentation{}, err
	}
	return v, nil
}
func (d *WindowsDocument) presentation() (TextPresentation, error) {
	version, err := d.store.changes.version()
	if err != nil {
		return TextPresentation{}, err
	}
	s, err := d.snapshot()
	if err != nil {
		return TextPresentation{}, err
	}
	if err = d.commitRevision(s.Revision); err != nil {
		return TextPresentation{}, err
	}
	runs, err := d.sampleDisplay(len(s.Text))
	if err != nil {
		return TextPresentation{}, err
	}
	if err = d.commitRevision(s.Revision); err != nil {
		return TextPresentation{}, err
	}
	if err = d.store.changes.check(version); err != nil {
		return TextPresentation{}, err
	}
	return TextPresentation{Snapshot: s, Runs: runs}, nil
}

// All COM releases finish before the caller's final revision/focus check.
func (d *WindowsDocument) sampleDisplay(n int) ([]DisplayRun, error) {
	category, err := createCOM(&clsCategory, &iidCategory)
	if err != nil {
		return nil, err
	}
	defer comCall(category, 2)
	manager, err := createCOM(&clsDisplay, &iidDisplay)
	if err != nil {
		return nil, err
	}
	defer comCall(manager, 2)
	var runs []DisplayRun
	lookup := displayLookup{category: category, manager: manager}
	err = d.readSession(func(ec uint32) error {
		var e error
		runs, e = readDisplayRuns(d.context, ec, n, lookup.resolve)
		return e
	})
	return runs, err
}

type displayEntry struct {
	style DisplayStyle
	err   error
}
type displayLookup struct {
	category, manager *comObject
	fallback          map[rail.GUID]displayEntry
}

func (l *displayLookup) resolve(atom uint32) (rail.GUID, DisplayStyle, error) {
	var id rail.GUID
	if hr := comCall(l.category, 15, uintptr(atom), uintptr(unsafe.Pointer(&id))); hr != 0 {
		return rail.GUID{}, DisplayStyle{}, hresult("CategoryMgr.GetGUID", hr)
	}
	var info *comObject
	hr := comCall(l.manager, 5, uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&info)), 0)
	if info != nil {
		defer comCall(info, 2)
	}
	if hr != 0 || info == nil {
		// Some installed providers expose attributes through enumeration but
		// fail direct lookup for the very same GUID. Enumerate once per sample,
		// with a strict budget, and retain value copies rather than COM objects.
		if l.fallback == nil {
			var err error
			l.fallback, err = enumerateDisplay(l.manager)
			if err != nil {
				return rail.GUID{}, DisplayStyle{}, err
			}
		}
		v, ok := l.fallback[id]
		if !ok {
			return rail.GUID{}, DisplayStyle{}, ErrUnavailable
		}
		return id, v.style, v.err
	}
	var raw displayData
	if hr = comCall(info, 5, uintptr(unsafe.Pointer(&raw))); hr != 0 {
		return rail.GUID{}, DisplayStyle{}, hresult("DisplayAttributeInfo.GetAttributeInfo", hr)
	}
	style, err := decodeDisplay(raw)
	return id, style, err
}

const maxDisplayDefinitions = 256

func enumerateDisplay(manager *comObject) (map[rail.GUID]displayEntry, error) {
	var e *comObject
	hr := comCall(manager, 4, uintptr(unsafe.Pointer(&e)))
	if e != nil {
		defer comCall(e, 2)
	}
	if hr != 0 {
		return nil, hresult("DisplayAttributeMgr.EnumInfo", hr)
	}
	if e == nil {
		return nil, ErrUnavailable
	}
	out := make(map[rail.GUID]displayEntry)
	for count := 0; ; count++ {
		var info *comObject
		var fetched uint32
		hr = comCall(e, 4, 1, uintptr(unsafe.Pointer(&info)), uintptr(unsafe.Pointer(&fetched)))
		if hr != 0 || fetched != 1 || info == nil {
			if info != nil {
				comCall(info, 2)
			}
			if hr == 1 && fetched == 0 && info == nil {
				return out, nil
			}
			if int32(hr) < 0 {
				return nil, hresult("DisplayInfo.Next", hr)
			}
			return nil, ErrChanged
		}
		if count >= maxDisplayDefinitions {
			comCall(info, 2)
			return nil, rail.ErrBusy
		}
		id, entry, err := func() (rail.GUID, displayEntry, error) {
			defer comCall(info, 2)
			var id rail.GUID
			var raw displayData
			if hr := comCall(info, 3, uintptr(unsafe.Pointer(&id))); hr != 0 {
				return id, displayEntry{}, hresult("DisplayInfo.GetGUID", hr)
			}
			if hr := comCall(info, 5, uintptr(unsafe.Pointer(&raw))); hr != 0 {
				return id, displayEntry{err: hresult("DisplayInfo.GetAttributeInfo", hr)}, nil
			}
			style, err := decodeDisplay(raw)
			return id, displayEntry{style, err}, nil
		}()
		if err != nil {
			return nil, err
		}
		if _, duplicate := out[id]; duplicate {
			return nil, ErrChanged
		}
		out[id] = entry
	}
}

func displayAtom(property, r *comObject, ec uint32) (atom uint32, present bool, err error) {
	var v nativeVariant
	hr := comCall(property, 5, uintptr(ec), uintptr(unsafe.Pointer(r)), uintptr(unsafe.Pointer(&v)))
	defer func() {
		hr, _, _ := variantClear.Call(uintptr(unsafe.Pointer(&v)))
		if int32(hr) < 0 {
			err = errors.Join(err, hresult("VariantClear(display)", hr))
		}
	}()
	if int32(hr) < 0 || hr > 1 {
		return 0, false, hresult("Property.GetValue", hr)
	}
	if v.kind == 0 {
		return 0, false, nil
	}
	if hr != 0 {
		return 0, false, ErrChanged
	}
	if v.kind != 3 {
		return 0, false, rail.ErrUnsupported
	}
	return uint32(v.data[0]), true, nil
}
func displayExtent(r *comObject) (TextRange, error) {
	acp, err := queryCOM(r, &iidRangeACP)
	if err != nil {
		return TextRange{}, err
	}
	defer comCall(acp, 2)
	var start, n int32
	if hr := comCall(acp, 25, uintptr(unsafe.Pointer(&start)), uintptr(unsafe.Pointer(&n))); hr != 0 {
		return TextRange{}, hresult("DisplayRange.GetExtent", hr)
	}
	if start < 0 || n < 0 || int64(start)+int64(n) > 0x7fffffff {
		return TextRange{}, ErrChanged
	}
	return TextRange{start, start + n}, nil
}

type displayResolver func(uint32) (rail.GUID, DisplayStyle, error)

func readDisplayRuns(context *comObject, ec uint32, n int, resolve displayResolver) ([]DisplayRun, error) {
	if n < 0 || n > 32768 {
		return nil, rail.ErrInvalid
	}
	var property *comObject
	hr := comCall(context, 12, uintptr(unsafe.Pointer(&propDisplay)), uintptr(unsafe.Pointer(&property)))
	if property != nil {
		defer comCall(property, 2)
	}
	if hr != 0 {
		return nil, hresult("Context.GetProperty(display)", hr)
	}
	if property == nil {
		return nil, ErrUnavailable
	}
	var enumerator *comObject
	hr = comCall(property, 4, uintptr(ec), uintptr(unsafe.Pointer(&enumerator)), 0)
	if enumerator != nil {
		defer comCall(enumerator, 2)
	}
	if hr != 0 {
		return nil, hresult("Property.EnumRanges", hr)
	}
	if enumerator == nil {
		return nil, ErrUnavailable
	}
	var runs []DisplayRun
	cache := make(map[uint32]DisplayRun)
	for count := 0; ; count++ {
		var r *comObject
		var fetched uint32
		hr = comCall(enumerator, 4, 1, uintptr(unsafe.Pointer(&r)), uintptr(unsafe.Pointer(&fetched)))
		if hr != 0 || fetched != 1 || r == nil {
			if r != nil {
				comCall(r, 2)
			}
			if hr == 1 && fetched == 0 && r == nil {
				break
			}
			if int32(hr) < 0 {
				return nil, hresult("DisplayRanges.Next", hr)
			}
			return nil, ErrChanged
		}
		// At most one nonempty run per code unit, plus one empty endpoint.
		if count > n {
			comCall(r, 2)
			return nil, rail.ErrBusy
		}
		entry, present, err := func() (DisplayRun, bool, error) {
			defer comCall(r, 2)
			extent, err := displayExtent(r)
			if err != nil {
				return DisplayRun{}, false, err
			}
			if extent.End > int32(n) {
				return DisplayRun{}, false, ErrChanged
			}
			if extent.Start == extent.End {
				return DisplayRun{}, false, nil
			}
			atom, has, err := displayAtom(property, r, ec)
			if err != nil || !has {
				return DisplayRun{}, false, err
			}
			entry, ok := cache[atom]
			if !ok {
				entry.ID, entry.Style, err = resolve(atom)
				if err != nil {
					return DisplayRun{}, false, err
				}
				cache[atom] = entry
			}
			entry.Range = extent
			return entry, true, nil
		}()
		if err != nil {
			return nil, err
		}
		if present {
			runs = append(runs, entry)
		}
	}
	return normalizeDisplayRuns(runs, n)
}
