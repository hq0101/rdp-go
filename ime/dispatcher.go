package ime

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/hq0101/rdp-go/keyboard"
	"github.com/hq0101/rdp-go/rail"
)

// DispatchOptions bounds each operation and each best-effort cleanup, including
// any wait for the preceding operation. Zero uses 5s and 2s respectively.
// A callback must honor context cancellation; Go cannot terminate a callback
// that ignores it. Close/Done let a caller observe actual worker termination.
type DispatchOptions struct{ OperationTimeout, CleanupTimeout time.Duration }

// DispatchFocus belongs to one dispatcher and one input ownership interval.
// The token has no reference to the connection or native input context.
type DispatchFocus struct{ lease *dispatchLease }
type dispatchLease struct{ marker byte }

// DeliveryResult distinguishes completion from admission. Invoked means the
// transport callback was called; even an error may follow partial delivery.
type DeliveryResult struct {
	Invoked bool
	Err     error
}

// DeliveryReceipt is immutable after completion. Receiving from Done, or a
// ready Result, synchronizes access to the result. Polling never replays input.
// The receipt does not retain its dispatcher, callback or submitted text.
type DeliveryReceipt struct {
	done   chan struct{}
	result DeliveryResult
}

func (r *DeliveryReceipt) Done() <-chan struct{} {
	if r == nil {
		return nil
	}
	return r.done
}
func (r *DeliveryReceipt) Result() (DeliveryResult, bool) {
	if r == nil || r.done == nil {
		return DeliveryResult{Err: rail.ErrInvalid}, true
	}
	select {
	case <-r.done:
		return r.result, true
	default:
		return DeliveryResult{}, false
	}
}
func (r *DeliveryReceipt) finish(result DeliveryResult) { r.result = result; close(r.done) }

type dispatchJob struct {
	receipt *DeliveryReceipt
	cancel  context.CancelFunc
}

// InputDispatcher runs text and physical-key delivery away from the UI thread.
// One data operation and one retirement request can exist at once; a full slot
// returns rail.ErrBusy without taking ownership of new data. Callbacks run
// serially without dispatcher locks and must not use native/UI-thread objects.
// Bind both callbacks to the SAME immutable connection and input target. Never
// rebind them on reconnect or RemoteApp target changes; create a new dispatcher.
// The zero value is invalid; do not copy a dispatcher.
type InputDispatcher struct {
	mu               sync.Mutex
	wg               sync.WaitGroup
	router           *keyboard.Router
	text             TextDelivery
	options          DispatchOptions
	lease            *dispatchLease
	rawFocus         keyboard.Focus
	active, closed   bool
	failure          error
	pending, cleanup *dispatchJob
	done             chan struct{}
}

func NewInputDispatcher(text TextDelivery, keys keyboard.Delivery, options DispatchOptions) (*InputDispatcher, error) {
	if text == nil || keys == nil {
		return nil, rail.ErrInvalid
	}
	if options.OperationTimeout == 0 {
		options.OperationTimeout = 5 * time.Second
	}
	if options.CleanupTimeout == 0 {
		options.CleanupTimeout = 2 * time.Second
	}
	if options.OperationTimeout <= 0 || options.OperationTimeout > time.Minute || options.CleanupTimeout <= 0 || options.CleanupTimeout > time.Minute {
		return nil, rail.ErrInvalid
	}
	r, err := keyboard.NewRouter(keys)
	if err != nil {
		return nil, err
	}
	return &InputDispatcher{router: r, text: text, options: options, done: make(chan struct{})}, nil
}
func (d *InputDispatcher) usable() error {
	if d.done == nil {
		return rail.ErrInvalid
	}
	if d.closed {
		return rail.ErrClosed
	}
	return nil
}
func (d *InputDispatcher) valid(f DispatchFocus) bool { return f.lease != nil && d.lease == f.lease }

// Focus does no I/O. The caller verifies foreground/remote-target ownership.
// A previous interval must finish Blur before another interval can start.
func (d *InputDispatcher) Focus() (DispatchFocus, error) {
	if d == nil {
		return DispatchFocus{}, rail.ErrInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.usable(); err != nil {
		return DispatchFocus{}, err
	}
	if d.failure != nil {
		return DispatchFocus{}, errors.Join(ErrUnavailable, d.failure)
	}
	if d.lease != nil || d.pending != nil || d.cleanup != nil {
		return DispatchFocus{}, rail.ErrBusy
	}
	raw, err := d.router.Focus()
	if err != nil {
		return DispatchFocus{}, err
	}
	d.lease, d.rawFocus, d.active = &dispatchLease{}, raw, true
	return DispatchFocus{d.lease}, nil
}

func dispatchTextValid(text string) bool {
	if text == "" || len(text) > MaxCommitUnits*3 || !utf8.ValidString(text) {
		return false
	}
	u := utf16.Encode([]rune(text))
	s, err := committedText(u)
	return err == nil && s == text
}

// SubmitText accepts at most MaxCommitUnits of valid UTF-8 committed text.
// A nil receipt with an error means nothing was queued and no callback ran.
// After admission, wait for the receipt; never resubmit uncertain delivery.
func (d *InputDispatcher) SubmitText(ctx context.Context, f DispatchFocus, text string) (*DeliveryReceipt, error) {
	if !dispatchTextValid(text) {
		return nil, rail.ErrInvalid
	}
	text = strings.Clone(text)
	return d.submit(ctx, f, func(ctx context.Context) DeliveryResult { return DeliveryResult{true, d.text(ctx, text)} })
}

// SubmitKey accepts a previously filtered key. Commit text first and wait for
// completion before admitting this key; do not run the native filter twice.
func (d *InputDispatcher) SubmitKey(ctx context.Context, f DispatchFocus, in keyboard.Input, consumed bool) (*DeliveryReceipt, error) {
	if err := in.Validate(); err != nil {
		return nil, err
	}
	return d.submit(ctx, f, func(ctx context.Context) DeliveryResult {
		called, err := d.router.Route(ctx, d.rawFocus, in, consumed)
		return DeliveryResult{called, err}
	})
}
func (d *InputDispatcher) submit(ctx context.Context, f DispatchFocus, run func(context.Context) DeliveryResult) (*DeliveryReceipt, error) {
	if d == nil || ctx == nil {
		return nil, rail.ErrInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.usable(); err != nil {
		return nil, err
	}
	if !d.valid(f) || !d.active {
		return nil, ErrStale
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if d.pending != nil || d.cleanup != nil {
		return nil, rail.ErrBusy
	}
	ctx, cancel := context.WithTimeout(ctx, d.options.OperationTimeout)
	j := &dispatchJob{receipt: &DeliveryReceipt{done: make(chan struct{})}, cancel: cancel}
	d.pending = j
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		result := DeliveryResult{Err: ctx.Err()}
		if result.Err == nil {
			result = run(ctx)
		}
		result.Err = errors.Join(result.Err, ctx.Err())
		cancel()
		d.mu.Lock()
		d.pending = nil
		if result.Err != nil {
			d.active = false
			if result.Invoked {
				d.failure = errors.Join(d.failure, result.Err)
			}
		}
		j.receipt.finish(result)
		d.mu.Unlock()
	}()
	return j.receipt, nil
}

// Blur immediately retires focus and cancels admitted data, then asynchronously
// releases keys to the ORIGINAL target using a separate bounded context. It
// waits for the data callback to return before touching the router. Cancellation
// cannot retract a prefix already sent. Duplicate Blur while cleanup is running
// returns the SAME receipt. On cleanup failure, a later Blur with the old token
// can attempt only the releases not attempted yet. A callback error prevents
// future Focus; retire the connection after best-effort cleanup.
func (d *InputDispatcher) Blur(ctx context.Context, f DispatchFocus) (*DeliveryReceipt, error) {
	if d == nil || ctx == nil {
		return nil, rail.ErrInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.usable(); err != nil {
		return nil, err
	}
	if !d.valid(f) {
		return nil, ErrStale
	}
	if d.cleanup != nil {
		return d.cleanup.receipt, nil
	}
	d.active = false
	previous := d.pending
	if previous != nil {
		previous.cancel()
	}
	ctx, cancel := context.WithTimeout(ctx, d.options.CleanupTimeout)
	j := &dispatchJob{receipt: &DeliveryReceipt{done: make(chan struct{})}, cancel: cancel}
	d.cleanup = j
	d.wg.Add(1)
	go func() {
		defer d.wg.Done()
		if previous != nil {
			<-previous.receipt.Done()
		}
		called, err := d.router.Blur(ctx, d.rawFocus)
		// A preceding failed release may have consumed the last held key.
		// No replacement Focus can run while this lease remains installed.
		if errors.Is(err, keyboard.ErrStale) {
			err = nil
		}
		err = errors.Join(err, ctx.Err())
		cancel()
		d.mu.Lock()
		d.cleanup = nil
		if err == nil {
			d.lease = nil
			d.rawFocus = keyboard.Focus{}
		}
		if called && err != nil {
			d.failure = errors.Join(d.failure, err)
		}
		j.receipt.finish(DeliveryResult{called, err})
		d.mu.Unlock()
	}()
	return j.receipt, nil
}

// Close requests cancellation and discards held-key state after workers stop.
// It does not wait or perform key-release I/O: Blur and wait for its receipt
// first on a healthy target. Done closes only after all callbacks have returned
// and connection callback references are dropped. Safe from a delivery callback.
func (d *InputDispatcher) Close() error {
	if d == nil {
		return rail.ErrInvalid
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.done == nil {
		return rail.ErrInvalid
	}
	if d.closed {
		return nil
	}
	d.closed, d.active = true, false
	if d.pending != nil {
		d.pending.cancel()
	}
	if d.cleanup != nil {
		d.cleanup.cancel()
	}
	go func() {
		d.wg.Wait()
		_ = d.router.Close()
		d.mu.Lock()
		d.router, d.text, d.lease = nil, nil, nil
		d.rawFocus = keyboard.Focus{}
		close(d.done)
		d.mu.Unlock()
	}()
	return nil
}
func (d *InputDispatcher) Done() <-chan struct{} {
	if d == nil {
		return nil
	}
	return d.done
}
