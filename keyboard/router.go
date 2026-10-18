package keyboard

import (
	"context"
	"errors"
	"sync/atomic"
)

// Delivery synchronously delivers a bounded batch to ONE connection/input
// target. Session.SendKeys matches this type. Bind the target for the router's
// lifetime; do not replace it on reconnect or on a RemoteApp target change.
// The slice is borrowed for the call. Success means delivery completed, not
// merely queued. A failure may follow partial delivery and must not be replayed.
type Delivery func(context.Context, []Event) error

// Focus identifies one ownership interval. Tokens from other routers or ended
// intervals are invalid; holding a token does not retain the delivery target.
type Focus struct{ lease *focusLease }
type focusLease struct{ marker byte }
type heldKey struct {
	key    Key
	remote bool
}

// Router tracks physical-key ownership after IME filtering and text commits.
// Use NewRouter; do not copy a Router. Calls must be UI-serialized with the
// filter, text delivery and focus changes. Concurrent/reentrant calls fail with
// ErrBusy, including calls made by Delivery. No worker goroutine is started.
type Router struct {
	busy                   atomic.Bool
	deliver                Delivery
	lease                  *focusLease
	held                   []heldKey
	active, failed, closed bool
}

func NewRouter(deliver Delivery) (*Router, error) {
	if deliver == nil {
		return nil, ErrInvalid
	}
	return &Router{deliver: deliver}, nil
}
func (r *Router) enter() error {
	if r == nil {
		return ErrInvalid
	}
	if !r.busy.CompareAndSwap(false, true) {
		return ErrBusy
	}
	if r.closed || r.deliver == nil {
		r.busy.Store(false)
		return ErrClosed
	}
	return nil
}
func (r *Router) leave()             { r.busy.Store(false) }
func (r *Router) valid(f Focus) bool { return f.lease != nil && f.lease == r.lease }

// Focus begins an empty interval. Blur the old interval before calling again.
// The caller must verify actual foreground/remote-target ownership; this method
// does not focus any window. A delivery failure permanently disables new Focus.
func (r *Router) Focus() (Focus, error) {
	if err := r.enter(); err != nil {
		return Focus{}, err
	}
	defer r.leave()
	if r.failed {
		return Focus{}, ErrFailed
	}
	if r.lease != nil {
		return Focus{}, ErrBusy
	}
	r.lease, r.active = &focusLease{}, true
	return Focus{r.lease}, nil
}

func (r *Router) index(k Key) int {
	for j := range r.held {
		if r.held[j].key == k {
			return j
		}
	}
	return -1
}
func (r *Router) remove(j int) {
	copy(r.held[j:], r.held[j+1:])
	r.held[len(r.held)-1] = heldKey{}
	r.held = r.held[:len(r.held)-1]
}
func (r *Router) send(ctx context.Context, events []Event) error {
	if err := r.deliver(ctx, events); err != nil {
		r.failed, r.active = true, false
		return errors.Join(ErrFailed, err)
	}
	return nil
}

// Route accepts one already-filtered host message. consumed means the local IME
// or shortcut handler consumed it. First-down ownership lasts until key-up:
// locally owned repeats/releases never reach RDP; a remotely owned release is
// sent even when consumed. An unpaired auto-repeat/up cannot create a press.
// Pause sends a complete pulse on a fresh, unconsumed down; repeats/up do nothing.
//
// Drain the IME's pending edits and Flush committed text BEFORE calling Route,
// even for an unhandled key (it may have ended composition). Never filter the
// same message again to retry Route. On success the message is consumed once.
// invoked reports whether Delivery was called. On context/delivery failure the
// interval is retired: do not retry this input, even when invoked is false.
// Blur with the SAME token to release remaining keys to the ORIGINAL target.
func (r *Router) Route(ctx context.Context, f Focus, in Input, consumed bool) (invoked bool, err error) {
	if err = r.enter(); err != nil {
		return
	}
	defer r.leave()
	if !r.valid(f) || !r.active {
		return false, ErrStale
	}
	if ctx == nil || !in.valid() {
		return false, ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		r.active = false
		return
	}
	if in.Key.Pause {
		if !in.Down || in.WasDown || consumed {
			return false, nil
		}
		pulse := PauseEvents()
		for left := int(in.Count); left > 0; {
			if err = ctx.Err(); err != nil {
				r.active = false
				return
			}
			n := min(left, MaxEvents/len(pulse))
			batch := make([]Event, 0, n*len(pulse))
			for j := 0; j < n; j++ {
				batch = append(batch, pulse[:]...)
			}
			invoked = true
			if err = r.send(ctx, batch); err != nil {
				return
			}
			left -= n
		}
		return
	}
	j := r.index(in.Key)
	if !in.Down {
		if j < 0 {
			return false, nil
		}
		remote := r.held[j].remote
		r.remove(j) // consume BEFORE delivery, including uncertain releases
		if !remote {
			return false, nil
		}
		return true, r.send(ctx, []Event{in.Key.event(false, true)})
	}
	wasDown := j >= 0
	if j < 0 {
		// 254 possible ordinary/E0 identities bound this slice without eviction.
		r.held = append(r.held, heldKey{in.Key, !consumed && !in.WasDown})
		j = len(r.held) - 1
	}
	if !r.held[j].remote || consumed {
		return false, nil
	}
	for left := int(in.Count); left > 0; {
		if err = ctx.Err(); err != nil {
			r.active = false
			return
		}
		n := min(left, MaxEvents)
		batch := make([]Event, n)
		for j := range batch {
			batch[j] = in.Key.event(true, wasDown)
			wasDown = true
		}
		invoked = true
		if err = r.send(ctx, batch); err != nil {
			return
		}
		left -= n
	}
	return
}

// Blur retires the interval before releasing remotely held keys in reverse
// press order (usually releasing modifiers last). Local keys are discarded.
// Releases handed to Delivery are never retried, even on failure. If the context
// expires or a batch fails, keys NOT YET attempted remain for a later Blur with
// this same token; no new Focus is allowed until cleanup is done. This cannot
// guarantee release on a failed transport. Retire/close that target afterwards.
func (r *Router) Blur(ctx context.Context, f Focus) (invoked bool, err error) {
	if err = r.enter(); err != nil {
		return
	}
	defer r.leave()
	if !r.valid(f) {
		return false, ErrStale
	}
	if ctx == nil {
		return false, ErrInvalid
	}
	r.active = false
	for j := len(r.held) - 1; j >= 0; j-- {
		if !r.held[j].remote {
			r.remove(j)
		}
	}
	defer func() {
		if len(r.held) == 0 {
			r.lease = nil
		}
	}()
	for len(r.held) != 0 {
		if err = ctx.Err(); err != nil {
			return
		}
		n := min(len(r.held), MaxEvents)
		batch := make([]Event, n)
		for j := range batch {
			last := len(r.held) - 1
			batch[j] = r.held[last].key.event(false, true)
			r.remove(last)
		}
		invoked = true
		if err = r.send(ctx, batch); err != nil {
			return
		}
	}
	return
}

// Close discards state without I/O and drops the delivery target. Call Blur
// first for best-effort key release, unless that connection is already gone.
func (r *Router) Close() error {
	if r == nil {
		return ErrInvalid
	}
	if !r.busy.CompareAndSwap(false, true) {
		return ErrBusy
	}
	defer r.leave()
	r.closed, r.active, r.deliver, r.lease, r.held = true, false, nil, nil, nil
	return nil
}
