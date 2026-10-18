//go:build !windows

package ime

import (
	"context"
	"github.com/hq0101/rdp-go/rail"
)

// WindowsAdapter is unavailable on this platform. Applications can implement
// Host with the platform's native input service and use Coordinator unchanged.
type WindowsAdapter struct{}

func OpenWindows(uintptr) (*WindowsAdapter, error) { return nil, rail.ErrUnsupported }
func (*WindowsAdapter) Profile() (rail.LanguageProfile, error) {
	return rail.LanguageProfile{}, rail.ErrUnsupported
}
func (*WindowsAdapter) Snapshot() (Snapshot, error) { return Snapshot{}, rail.ErrUnsupported }
func (*WindowsAdapter) ApplyIME(rail.LanguageProfile, rail.IMECompartment) error {
	return rail.ErrUnsupported
}
func (*WindowsAdapter) ApplyLanguageBar(rail.LanguageBarStatus) error { return rail.ErrUnsupported }
func (*WindowsAdapter) Close() error                                  { return nil }

func OpenWindowsWithOptions(uintptr, WindowsOptions) (*WindowsAdapter, error) {
	return nil, rail.ErrUnsupported
}
func (*WindowsAdapter) TakeChanges() (WindowsChanges, error) { return 0, rail.ErrUnsupported }
func (*WindowsAdapter) NotifyMessage(uint32, uintptr) error  { return rail.ErrUnsupported }

type WindowsDocument struct{}

func (*WindowsDocument) Presentation() (TextPresentation, error) {
	return TextPresentation{}, rail.ErrUnsupported
}

func (*WindowsAdapter) OpenDocument(WindowsDocumentOptions) (*WindowsDocument, error) {
	return nil, rail.ErrUnsupported
}
func (*WindowsDocument) Pump() (bool, error)                           { return false, rail.ErrUnsupported }
func (*WindowsDocument) Snapshot() (TextSnapshot, error)               { return TextSnapshot{}, rail.ErrUnsupported }
func (*WindowsDocument) SetText(uint64, []uint16, TextSelection) error { return rail.ErrUnsupported }
func (*WindowsDocument) SetLayout(uint64, TextLayout) error            { return rail.ErrUnsupported }
func (*WindowsDocument) Focus() error                                  { return rail.ErrUnsupported }
func (*WindowsDocument) Blur() error                                   { return rail.ErrUnsupported }
func (*WindowsDocument) Close() error                                  { return nil }

type WindowsInput struct{}

func (*WindowsInput) Presentation(TextFocus) (TextPresentation, error) {
	return TextPresentation{}, rail.ErrUnsupported
}

func (*WindowsAdapter) OpenTextInput(WindowsInputOptions, TextDelivery) (*WindowsInput, error) {
	return nil, rail.ErrUnsupported
}
func (*WindowsInput) Focus() (TextFocus, error) { return TextFocus{}, rail.ErrUnsupported }
func (*WindowsInput) Key(TextFocus, WindowsKeyMessage) (bool, error) {
	return false, rail.ErrUnsupported
}
func (*WindowsInput) Pump(TextFocus) (bool, error) { return false, rail.ErrUnsupported }
func (*WindowsInput) Snapshot(TextFocus) (TextSnapshot, error) {
	return TextSnapshot{}, rail.ErrUnsupported
}
func (*WindowsInput) SetLayout(TextFocus, uint64, TextLayout) error { return rail.ErrUnsupported }
func (*WindowsInput) Flush(context.Context, TextFocus) (bool, error) {
	return false, rail.ErrUnsupported
}
func (*WindowsInput) Blur(TextFocus) error { return rail.ErrUnsupported }
func (*WindowsInput) Close() error         { return nil }

func (*WindowsDocument) TakeChanges() (TextChanges, error)          { return 0, rail.ErrUnsupported }
func (*WindowsInput) TakeChanges(TextFocus) (TextChanges, error)    { return 0, rail.ErrUnsupported }
func (*WindowsDocument) Candidates() ([]CandidateList, error)       { return nil, rail.ErrUnsupported }
func (*WindowsInput) Candidates(TextFocus) ([]CandidateList, error) { return nil, rail.ErrUnsupported }

func (*WindowsDocument) ApplyCandidate(CandidateToken, CandidateAction) (bool, error) {
	return false, rail.ErrUnsupported
}
func (*WindowsInput) ApplyCandidate(TextFocus, CandidateToken, CandidateAction) (bool, error) {
	return false, rail.ErrUnsupported
}

func (*WindowsAdapter) OpenAsyncTextInput(WindowsInputOptions, *InputDispatcher) (*WindowsInput, error) {
	return nil, rail.ErrUnsupported
}
func (*WindowsInput) QueueFlush(context.Context, TextFocus) (*DeliveryReceipt, error) {
	return nil, rail.ErrUnsupported
}
func (*WindowsInput) QueueKey(context.Context, TextFocus, WindowsKeyMessage, bool) (*DeliveryReceipt, error) {
	return nil, rail.ErrUnsupported
}
func (*WindowsInput) BlurAsync(TextFocus) (*DeliveryReceipt, error) { return nil, rail.ErrUnsupported }
func (*WindowsInput) Cleanup(context.Context) (*DeliveryReceipt, error) {
	return nil, rail.ErrUnsupported
}
