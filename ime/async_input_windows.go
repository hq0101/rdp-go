package ime

import (
	"context"
	"github.com/hq0101/rdp-go/keyboard"
	"github.com/hq0101/rdp-go/rail"
)

// OpenAsyncTextInput reserves a native input context whose committed text and
// physical keys are delivered by dispatcher workers. The dispatcher must belong
// exclusively to this input/remote target and must not already have focus.
// It owns no COM objects. Its callbacks must be safe on a worker goroutine.
// The caller owns the dispatcher and closes it after BlurAsync has completed.
func (a *WindowsAdapter) OpenAsyncTextInput(o WindowsInputOptions, d *InputDispatcher) (*WindowsInput, error) {
	if d == nil {
		return nil, rail.ErrInvalid
	}
	return a.openTextInput(o, nil, d)
}

// asyncReady never waits on a worker while holding the native UI guard. A
// result error retires the native interval and schedules original-target cleanup.
func (i *WindowsInput) asyncReady() error {
	if i.delivery == nil {
		return nil
	}
	result, ready := i.delivery.Result()
	if !ready {
		return rail.ErrBusy
	}
	i.delivery = nil
	if result.Err != nil {
		return i.stop(result.Err)
	}
	return nil
}

// QueueFlush removes one committed prefix on the UI thread, then admits its
// immutable text to the worker. The receipt reports actual completion, not just
// queuing. nil,nil means no committed prefix. While a receipt is pending, Key,
// candidate mutation, QueueKey and another QueueFlush return Busy. Pump and
// presentation remain available; native callbacks never wait on network I/O.
// On admission backpressure the removed prefix stays in one bounded outbox;
// retry QueueFlush on the same focus. Other errors retire the interval. Do not
// replay any text from an admitted or failed receipt yourself.
func (i *WindowsInput) QueueFlush(ctx context.Context, t TextFocus) (*DeliveryReceipt, error) {
	if ctx == nil {
		return nil, rail.ErrInvalid
	}
	if err := i.enter(); err != nil {
		return nil, err
	}
	defer i.leave()
	if err := i.check(t); err != nil {
		return nil, err
	}
	return i.queueFlush(ctx, func() error { return i.check(t) })
}
func (i *WindowsInput) queueFlush(ctx context.Context, check func() error) (*DeliveryReceipt, error) {
	if i.dispatcher == nil {
		return nil, rail.ErrUnsupported
	}
	if err := i.asyncReady(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if i.outbox == "" {
		s, err := i.document.snapshot()
		if err != nil {
			return nil, err
		}
		n, err := committedPrefix(s)
		if err != nil {
			return nil, i.stop(err)
		}
		if n == 0 {
			return nil, nil
		}
		text, err := committedText(s.Text[:n])
		if err != nil {
			return nil, i.stop(err)
		}
		if err = i.document.trimCommitted(s, n); err != nil {
			return nil, i.stop(err)
		}
		i.outbox = text
	}
	if err := check(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, i.stop(err)
	}
	receipt, err := i.dispatcher.SubmitText(ctx, i.dispatchFocus, i.outbox)
	if err == rail.ErrBusy {
		return nil, err
	}
	if err != nil {
		return nil, i.stop(err)
	}
	i.outbox = ""
	i.delivery = receipt
	return receipt, nil
}

// QueueKey admits the original message AFTER exactly one successful Key call
// and after all resulting Pump/QueueFlush receipts complete. Save consumed and
// the message while waiting; never call Key again to retry this phase. The
// message's HWND and native focus are rechecked here. This does not filter the
// message again, TranslateMessage it or dispatch it to the window procedure.
func (i *WindowsInput) QueueKey(ctx context.Context, t TextFocus, m WindowsKeyMessage, consumed bool) (*DeliveryReceipt, error) {
	if ctx == nil {
		return nil, rail.ErrInvalid
	}
	in, err := DecodeWindowsKey(m)
	if err != nil {
		return nil, err
	}
	if err = i.enter(); err != nil {
		return nil, err
	}
	defer i.leave()
	if err = i.check(t); err != nil {
		return nil, err
	}
	if m.HWND != i.adapter.wnd {
		return nil, ErrStale
	}
	return i.queueKey(ctx, in, consumed, func() error { return i.check(t) })
}
func (i *WindowsInput) queueKey(ctx context.Context, in keyboard.Input, consumed bool, check func() error) (*DeliveryReceipt, error) {
	if i.dispatcher == nil {
		return nil, rail.ErrUnsupported
	}
	if err := i.asyncReady(); err != nil {
		return nil, err
	}
	if i.outbox != "" {
		return nil, ErrPendingCommit
	}
	if i.document.store.pending != 0 {
		return nil, rail.ErrBusy
	}
	if err := i.document.pendingCommit(); err != nil {
		return nil, err
	}
	if err := check(); err != nil {
		return nil, err
	}
	receipt, err := i.dispatcher.SubmitKey(ctx, i.dispatchFocus, in, consumed)
	if err != nil {
		return nil, err
	}
	i.delivery = receipt
	return receipt, nil
}

// BlurAsync performs native teardown on the UI thread, cancels admitted input
// and returns the asynchronous key-cleanup receipt. No network wait occurs here.
// Its cleanup timeout is independent of an already canceled data operation.
// Normal Blur/Close also schedule cleanup in async mode; use this method to
// observe it before closing the dispatcher. Do not change the remote target
// until the receipt completes. A new target needs a new dispatcher/input.
func (i *WindowsInput) BlurAsync(t TextFocus) (*DeliveryReceipt, error) {
	if err := i.enterCleanup(); err != nil {
		return nil, err
	}
	defer i.leave()
	if i.dispatcher == nil {
		return nil, rail.ErrUnsupported
	}
	if !i.valid(t) {
		return nil, ErrStale
	}
	err := i.discard()
	return i.cleanup, err
}

// Cleanup observes or retries retirement after an async native interval ended.
// It is also available after WindowsInput.Close, on the original UI thread.
// An unfinished cleanup returns the existing receipt. Only releases never
// attempted by an earlier failed cleanup can be sent again by the dispatcher.
func (i *WindowsInput) Cleanup(ctx context.Context) (*DeliveryReceipt, error) {
	if ctx == nil {
		return nil, rail.ErrInvalid
	}
	tid, _, _ := getThread.Call()
	if tid != i.adapter.thread {
		return nil, ErrThread
	}
	if i.adapter.busy || i.adapter.documentBusy() {
		return nil, rail.ErrBusy
	}
	if i.dispatcher == nil {
		return nil, rail.ErrUnsupported
	}
	if i.cleanup != nil {
		result, ready := i.cleanup.Result()
		if !ready || result.Err == nil {
			return i.cleanup, nil
		}
	}
	if i.retiredFocus.lease == nil {
		return nil, nil
	}
	receipt, err := i.dispatcher.Blur(ctx, i.retiredFocus)
	if err == nil {
		i.cleanup = receipt
	}
	return receipt, err
}
