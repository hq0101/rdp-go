package ime

import (
	"errors"
	"github.com/hq0101/rdp-go/rail"
	"syscall"
	"unsafe"
)

var (
	iidCandidates     = rail.GUID{Data1: 0xea1ea138, Data2: 0x19df, Data3: 0x11d7, Data4: [8]byte{0xa6, 0xd2, 0, 6, 0x5b, 0x84, 0x43, 0x5c}}
	candidateBSTRLen  = syscall.NewLazyDLL("oleaut32.dll").NewProc("SysStringByteLen")
	candidateBSTRFree = syscall.NewLazyDLL("oleaut32.dll").NewProc("SysFreeString")
)

// Candidates refreshes the current candidate UI elements belonging to this native
// document. It does not hide, select, page, or finalize the service's UI. Drain
// Pump first. A service using its own visible UI need not emit update hints;
// resample while that UI is active. Unsupported UI kinds are omitted, not
// treated as candidate lists. This does not activate UI-less mode or promise
// access to candidates from services without ITfCandidateListUIElement.
// Every call invalidates previous candidate tokens, including failed refreshes.
// At most 32 pairs of native element/identity references are retained until the
// next refresh, action, blur or close; callers must close their document.
func (d *WindowsDocument) Candidates() ([]CandidateList, error) {
	if err := d.enter(false); err != nil {
		return nil, err
	}
	defer d.leave()
	return d.candidates()
}
func (i *WindowsInput) Candidates(t TextFocus) ([]CandidateList, error) {
	if err := i.enter(); err != nil {
		return nil, err
	}
	defer i.leave()
	if err := i.check(t); err != nil {
		return nil, err
	}
	v, err := i.document.candidates()
	if err != nil {
		return nil, err
	}
	if err := i.check(t); err != nil {
		return nil, err
	}
	return v, nil
}
func (d *WindowsDocument) candidates() ([]CandidateList, error) {
	d.dropCandidateTargets()
	version, err := d.store.changes.version()
	if err != nil {
		return nil, err
	}
	revision := d.store.state.revision
	if err = d.commitRevision(revision); err != nil {
		return nil, err
	}
	// All temporary native releases finish before the final generation check.
	v, targets, err := sampleCandidates(d.ui, d.manager)
	installed := false
	defer func() {
		if !installed {
			releaseCandidateTargets(targets)
		}
	}()
	if err != nil {
		return nil, err
	}
	if err = d.commitRevision(revision); err != nil {
		return nil, err
	}
	if err = d.store.changes.check(version); err != nil {
		return nil, err
	}
	for _, target := range targets {
		target.version = version
		target.revision = revision
	}
	d.candidateTargets = targets
	installed = true
	return v, nil
}

func sampleCandidates(ui, document *comObject) (lists []CandidateList, targets map[*candidateLease]*candidateTarget, err error) {
	if ui == nil || document == nil {
		return nil, nil, ErrUnavailable
	}
	identity, err := queryCOM(document, &iidUnknown)
	if err != nil {
		return nil, nil, err
	}
	defer comCall(identity, 2)
	targets = make(map[*candidateLease]*candidateTarget)
	// A failed read must release candidates already collected before a later
	// element failed. Leases are installed in the document only after validation.
	owned := targets
	defer func() {
		if err != nil {
			releaseCandidateTargets(owned)
		}
	}()
	var enumerator *comObject
	hr := comCall(ui, 7, uintptr(unsafe.Pointer(&enumerator)))
	if enumerator != nil {
		defer comCall(enumerator, 2)
	}
	if hr != 0 {
		return nil, nil, hresult("EnumUIElements", hr)
	}
	if enumerator == nil {
		return nil, nil, ErrUnavailable
	}
	budget := candidateBudget{}
	for count := 0; ; count++ {
		var p *comObject
		var got uint32
		hr = comCall(enumerator, 4, 1, uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&got)))
		if hr == 1 && got == 0 && p == nil {
			return lists, targets, nil
		}
		if hr != 0 || got != 1 || p == nil || count >= maxCandidateElements {
			if p != nil {
				comCall(p, 2)
			}
			if int32(hr) < 0 {
				return nil, nil, hresult("UIElements.Next", hr)
			}
			return nil, nil, rail.ErrInvalid
		}
		v, target, e := readCandidateElement(p, identity, &budget)
		comCall(p, 2)
		if e != nil {
			return nil, nil, e
		}
		if target != nil {
			lease := &candidateLease{}
			v.Token = CandidateToken{lease: lease}
			targets[lease] = target
			lists = append(lists, v)
		}
	}
}

type candidateBudget struct{ items, units int }

func readCandidateElement(element, document *comObject, budget *candidateBudget) (CandidateList, *candidateTarget, error) {
	var p *comObject
	hr := comCall(element, 0, uintptr(unsafe.Pointer(&iidCandidates)), uintptr(unsafe.Pointer(&p)))
	keep := false
	defer func() {
		if p != nil && !keep {
			comCall(p, 2)
		}
	}()
	if hr == eNoInterface {
		return CandidateList{}, nil, nil
	}
	if hr != 0 {
		return CandidateList{}, nil, hresult("Candidate QueryInterface", hr)
	}
	if p == nil {
		return CandidateList{}, nil, ErrUnavailable
	}
	belongs, err := candidateDocument(p, document)
	if err != nil || !belongs {
		return CandidateList{}, nil, err
	}
	v, err := readCandidateData(p, budget)
	if err != nil {
		return CandidateList{}, nil, err
	}
	behavior, err := candidateBehavior(p)
	if err != nil && !errors.Is(err, rail.ErrUnsupported) {
		return CandidateList{}, nil, err
	}
	if behavior != nil {
		v.SupportsBehavior = true
		comCall(behavior, 2)
	}
	belongs, err = candidateDocument(p, document)
	if err != nil {
		return CandidateList{}, nil, err
	}
	if !belongs {
		return CandidateList{}, nil, ErrChanged
	}
	identity, err := queryCOM(p, &iidUnknown)
	if err != nil {
		return CandidateList{}, nil, err
	}
	keep = true
	return v, &candidateTarget{element: p, identity: identity, sample: cloneCandidate(v)}, nil
}

func candidateDocument(p, document *comObject) (bool, error) {
	var owner *comObject
	hr := comCall(p, 8, uintptr(unsafe.Pointer(&owner)))
	if owner != nil {
		defer comCall(owner, 2)
	}
	if hr != 0 {
		return false, hresult("Candidate.GetDocumentMgr", hr)
	}
	if owner == nil {
		return false, ErrUnavailable
	}
	id, err := queryCOM(owner, &iidUnknown)
	if err != nil {
		return false, err
	}
	defer comCall(id, 2)
	return id == document, nil
}
func readCandidateData(p *comObject, budget *candidateBudget) (CandidateList, error) {
	v := CandidateList{Selection: -1}
	var shown int32
	var n, selected uint32
	if hr := comCall(p, 4, uintptr(unsafe.Pointer(&v.Kind))); hr != 0 {
		return CandidateList{}, hresult("Candidate.GetGUID", hr)
	}
	if hr := comCall(p, 6, uintptr(unsafe.Pointer(&shown))); hr != 0 {
		return CandidateList{}, hresult("Candidate.IsShown", hr)
	}
	v.NativeShown = shown != 0
	if hr := comCall(p, 9, uintptr(unsafe.Pointer(&n))); hr != 0 {
		return CandidateList{}, hresult("Candidate.GetCount", hr)
	}
	if uint64(n) > uint64(maxCandidateItems-budget.items) {
		return CandidateList{}, rail.ErrInvalid
	}
	budget.items += int(n)
	hr := comCall(p, 10, uintptr(unsafe.Pointer(&selected)))
	if hr == 0 {
		if selected >= n {
			return CandidateList{}, rail.ErrInvalid
		}
		v.Selection = int(selected)
	} else if hr != 1 {
		return CandidateList{}, hresult("Candidate.GetSelection", hr)
	}
	// Supply the largest valid page-index array in one bounded call. This
	// avoids trusting a provider's preliminary required-size report.
	pages := make([]uint32, int(n))
	var pageCount uint32
	if hr = comCall(p, 12, uintptr(unsafe.Pointer(unsafe.SliceData(pages))), uintptr(n), uintptr(unsafe.Pointer(&pageCount))); hr != 0 {
		return CandidateList{}, hresult("Candidate.GetPageIndex", hr)
	}
	if pageCount > n {
		return CandidateList{}, rail.ErrInvalid
	}
	v.PageStarts = pages[:pageCount]
	if pageCount != 0 {
		if hr = comCall(p, 14, uintptr(unsafe.Pointer(&v.CurrentPage))); hr != 0 {
			return CandidateList{}, hresult("Candidate.GetCurrentPage", hr)
		}
	}
	if !validCandidatePages(int(n), v.Selection, v.PageStarts, v.CurrentPage) {
		return CandidateList{}, rail.ErrInvalid
	}
	v.Strings = make([]string, int(n))
	for j := range v.Strings {
		value, units, err := readCandidateString(p, uint32(j), maxCandidateUnits-budget.units)
		if err != nil {
			return CandidateList{}, err
		}
		v.Strings[j] = value
		budget.units += units
	}
	return v, nil
}
func readCandidateString(p *comObject, index uint32, remaining int) (string, int, error) {
	var bstr uintptr
	hr := comCall(p, 11, uintptr(index), uintptr(unsafe.Pointer(&bstr)))
	if bstr != 0 {
		defer candidateBSTRFree.Call(bstr)
	}
	if hr != 0 {
		return "", 0, hresult("Candidate.GetString", hr)
	}
	if bstr == 0 {
		return "", 0, nil
	} // A null BSTR represents an empty string.
	bytes, _, _ := candidateBSTRLen.Call(bstr)
	n := uint64(uint32(bytes)) / 2
	if bytes&1 != 0 || n > maxCandidateString || n > uint64(remaining) {
		return "", 0, rail.ErrInvalid
	}
	units := make([]uint16, int(n))
	if n != 0 {
		copyNative.Call(uintptr(unsafe.Pointer(&units[0])), bstr, uintptr(n*2))
	}
	value, err := candidateString(units)
	return value, int(n), err
}
