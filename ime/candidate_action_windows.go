package ime

import (
	"errors"
	"github.com/hq0101/rdp-go/rail"
	"unsafe"
)

var iidCandidateBehavior = rail.GUID{Data1: 0x85fad185, Data2: 0x58ce, Data3: 0x497a, Data4: [8]byte{0x94, 0x60, 0x35, 0x53, 0x66, 0xb6, 0x4b, 0x9a}}

type candidateTarget struct {
	element, identity *comObject
	sample            CandidateList
	version, revision uint64
}

func (t *candidateTarget) close() {
	if t.element != nil {
		comCall(t.element, 2)
		t.element = nil
	}
	if t.identity != nil {
		comCall(t.identity, 2)
		t.identity = nil
	}
}
func releaseCandidateTargets(targets map[*candidateLease]*candidateTarget) {
	for _, t := range targets {
		t.close()
	}
}
func (d *WindowsDocument) dropCandidateTargets() {
	old := d.candidateTargets
	d.candidateTargets = nil // Invalidate all leases before any native Release.
	releaseCandidateTargets(old)
}
func candidateBehavior(p *comObject) (*comObject, error) {
	var out *comObject
	hr := comCall(p, 0, uintptr(unsafe.Pointer(&iidCandidateBehavior)), uintptr(unsafe.Pointer(&out)))
	if hr != 0 {
		if out != nil {
			comCall(out, 2)
		}
		if hr == eNoInterface {
			return nil, rail.ErrUnsupported
		}
		return nil, hresult("Candidate behavior QueryInterface", hr)
	}
	if out == nil {
		return nil, ErrUnavailable
	}
	// QueryInterface must preserve canonical identity. Never dispatch through
	// a provider's unrelated object even if it claims the behavior IID.
	same, err := sameCandidateIdentity(p, out)
	if err != nil || !same {
		comCall(out, 2)
		if err != nil {
			return nil, err
		}
		return nil, ErrChanged
	}
	return out, nil
}
func sameCandidateIdentity(a, b *comObject) (bool, error) {
	x, err := queryCOM(a, &iidUnknown)
	if err != nil {
		return false, err
	}
	defer comCall(x, 2)
	y, err := queryCOM(b, &iidUnknown)
	if err != nil {
		return false, err
	}
	defer comCall(y, 2)
	return x == y, nil
}

// ApplyCandidate invokes at most one native mutation. invoked reports that the
// method was called, even on failure; never replay an invoked action. Every
// attempt that reaches dispatch consumes all candidate tokens. Drain Pump and
// (for WindowsInput) Flush afterward and resample. Finalize/Abort do not send
// RDP text directly: only actual TSF edits/composition endings can do that.
// Native foreground focus and this document's TSF focus are both required.
func (d *WindowsDocument) ApplyCandidate(token CandidateToken, action CandidateAction) (bool, error) {
	if err := d.enter(false); err != nil {
		return false, err
	}
	defer d.leave()
	invoked, err := d.applyCandidate(token, action, d.candidateFocus)
	if invoked {
		err = errors.Join(err, d.candidateFocus())
	}
	return invoked, err
}
func (i *WindowsInput) ApplyCandidate(focus TextFocus, token CandidateToken, action CandidateAction) (bool, error) {
	if err := i.enter(); err != nil {
		return false, err
	}
	defer i.leave()
	if err := i.check(focus); err != nil {
		return false, err
	}
	if err := i.asyncReady(); err != nil {
		return false, err
	}
	if i.outbox != "" {
		return false, ErrPendingCommit
	}
	if err := i.document.pendingCommit(); err != nil {
		return false, err
	}
	invoked, err := i.document.applyCandidate(token, action, func() error { return i.check(focus) })
	if invoked {
		err = errors.Join(err, i.check(focus))
	}
	return invoked, err
}
func (d *WindowsDocument) candidateFocus() error {
	if err := d.adapter.focused(); err != nil {
		d.dropCandidateTargets()
		return err
	}
	ours, err := d.ownsFocus()
	if err != nil || !ours {
		d.dropCandidateTargets()
		if err != nil {
			return err
		}
		return ErrNotFocused
	}
	if err = d.adapter.focused(); err != nil {
		d.dropCandidateTargets()
	}
	return err
}
func (d *WindowsDocument) checkCandidate(t *candidateTarget) error {
	if err := d.commitRevision(t.revision); err != nil {
		return err
	}
	return d.store.changes.check(t.version)
}
func (d *WindowsDocument) applyCandidate(token CandidateToken, action CandidateAction, focus func() error) (bool, error) {
	t := d.candidateTargets[token.lease]
	if token.lease == nil || t == nil {
		return false, ErrStale
	}
	command, err := candidateCommandFor(t.sample, action)
	if err != nil {
		return false, err
	}
	if err = d.checkCandidate(t); err != nil {
		return false, err
	}
	if err = focus(); err != nil {
		return false, err
	}
	var target *comObject
	if command.behavior {
		target, err = candidateBehavior(t.element)
		if err != nil {
			if !errors.Is(err, rail.ErrUnsupported) {
				d.dropCandidateTargets()
			}
			return false, err
		}
	} else {
		target = t.element
		comCall(target, 1)
	}
	defer comCall(target, 2)
	// Preflight releases all temporary native references before dispatch checks.
	if err = d.preflightCandidate(t); err != nil {
		// A detected silent change must not revive if the provider later
		// returns to the same contents without emitting an update (ABA).
		d.dropCandidateTargets()
		return false, err
	}
	if err = focus(); err != nil {
		return false, err
	}
	if err = d.checkCandidate(t); err != nil {
		return false, err
	}
	// Retain the dispatch interface, consume leases, and allow native Release
	// reentrancy before the final focus/version check. No callback gets a token.
	d.dropCandidateTargets()
	if err = focus(); err != nil {
		return false, err
	}
	if err = d.checkCandidate(t); err != nil {
		return false, err
	}
	var hr uintptr
	switch command.slot {
	case 5, 15:
		hr = comCall(target, command.slot, uintptr(command.value))
	case 13:
		hr = comCall(target, 13, uintptr(unsafe.Pointer(unsafe.SliceData(command.pages))), uintptr(len(command.pages)))
	default:
		hr = comCall(target, command.slot)
	}
	d.store.changes.mark(TextCandidatesChanged)
	if hr != 0 {
		return true, hresult("Candidate action", hr)
	}
	return true, nil
}

func (d *WindowsDocument) preflightCandidate(t *candidateTarget) error {
	if err := candidateIsActive(d.ui, t.identity); err != nil {
		return err
	}
	owner, err := queryCOM(d.manager, &iidUnknown)
	if err != nil {
		return err
	}
	defer comCall(owner, 2)
	v, current, err := readCandidateElement(t.element, owner, &candidateBudget{})
	if current != nil {
		defer current.close()
	}
	if err != nil {
		return err
	}
	if current == nil || current.identity != t.identity {
		return ErrStale
	}
	if !sameCandidate(v, t.sample) {
		return ErrChanged
	}
	return nil
}
func candidateIsActive(ui, identity *comObject) error {
	var enumerator *comObject
	hr := comCall(ui, 7, uintptr(unsafe.Pointer(&enumerator)))
	if enumerator != nil {
		defer comCall(enumerator, 2)
	}
	if hr != 0 {
		return hresult("Enum active candidate", hr)
	}
	if enumerator == nil {
		return ErrUnavailable
	}
	for n := 0; ; n++ {
		var p *comObject
		var fetched uint32
		hr = comCall(enumerator, 4, 1, uintptr(unsafe.Pointer(&p)), uintptr(unsafe.Pointer(&fetched)))
		if hr == 1 && fetched == 0 && p == nil {
			return ErrStale
		}
		if hr != 0 || fetched != 1 || p == nil || n >= maxCandidateElements {
			if p != nil {
				comCall(p, 2)
			}
			if int32(hr) < 0 {
				return hresult("Active candidates.Next", hr)
			}
			return rail.ErrInvalid
		}
		id, err := queryCOM(p, &iidUnknown)
		comCall(p, 2)
		if err != nil {
			return err
		}
		same := id == identity
		comCall(id, 2)
		if same {
			return nil
		}
	}
}
