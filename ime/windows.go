package ime

// WindowsStateBackend selects one native source for the complete IME state.
// Values from different backends are never combined or retried through the other
// backend after a partial write. Both require the caller-owned focused window.
type WindowsStateBackend uint8

const (
	WindowsIMM WindowsStateBackend = iota
	WindowsTSF
)

type WindowsOptions struct {
	StateBackend WindowsStateBackend
	// UIElementOnly explicitly restricts this UI thread to TSF services supporting
	// UIElement integration. It may exclude legacy input services. The caller
	// owns the thread's TSF activation policy. Default false preserves Activate.
	// It does not hide UI: draw a supported list, then ApplyCandidate Show(false).
	UIElementOnly bool
}

// WindowsChanges is a coalesced hint to sample the current state on the UI
// thread. It is not a snapshot, a focus lease, or a count of individual changes.
type WindowsChanges uint32

const (
	WindowsProfileChanged WindowsChanges = 1 << iota
	WindowsOpenChanged
	WindowsConversionChanged
	WindowsSentenceChanged
	WindowsKanaChanged
	WindowsAllChanged = WindowsProfileChanged | WindowsOpenChanged | WindowsConversionChanged | WindowsSentenceChanged | WindowsKanaChanged
)
