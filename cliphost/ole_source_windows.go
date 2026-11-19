package cliphost

import (
	"context"
	"errors"
	"runtime"

	"github.com/hq0101/rdp-go/clipole"
	"github.com/hq0101/rdp-go/cliprdr"
)

// Prefer the existing bounded filesystem path when both representations exist.
// Reading OLE file data runs outside the Host's window thread, so another
// application's COM calls cannot stall its clipboard observation or rendering.
func (h *Host) acquireFileSource(ctx context.Context, token Token, o FileSelectionOptions) (cliprdr.FileSourceOffer, error) {
	r := h.call(command{ctx: ctx, kind: 's', token: token})
	if r.err != nil {
		return cliprdr.FileSourceOffer{}, r.err
	}
	if !r.virtual {
		return h.acquireDropSource(ctx, token, o)
	}
	type result struct {
		offer cliprdr.FileSourceOffer
		err   error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread() // never pool a caller-selected desktop
		if ok, _, err := setDesktop.Call(r.desktop); ok == 0 {
			done <- result{err: winerr("SetThreadDesktop source", err)}
			return
		}
		offer, err := clipole.AcquireIfCurrent(ctx, r.oleSnapshot, clipole.SourceOptions{MaxTotalSize: o.MaxTotalSize, MaxFiles: o.MaxFiles})
		done <- result{offer, err}
	}()
	acquired := <-done // join even after cancellation; no abandoned native source
	if acquired.err != nil {
		return cliprdr.FileSourceOffer{}, fileError(acquired.err)
	}
	if err := h.call(command{ctx: ctx, kind: 'v', token: token}).err; err != nil {
		return cliprdr.FileSourceOffer{}, errors.Join(err, acquired.offer.Release())
	}
	return acquired.offer, nil
}

func (w *worker) sourceInfo(token Token) response {
	var r response
	if r.err = w.verifySelection(token); r.err != nil {
		return r
	}
	drop, _, _ := user.NewProc("IsClipboardFormatAvailable").Call(15)
	if drop != 0 {
		return r
	}
	r.virtual, r.desktop = true, w.desktop
	r.oleSnapshot, r.err = clipole.Observe()
	if r.err != nil {
		r.err = fileError(r.err)
		return r
	}
	owner, sequence := nativeStamp()
	if owner != w.owner || sequence != w.sequence {
		r.err = ErrChanged
	}
	return r
}
