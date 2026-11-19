package nativeview

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/ime"
	"github.com/hq0101/rdp-go/rail"
)

var errInputOverflow = errors.New("nativeview: input queue full; focus retired")
var errCompositionClick = errors.New("nativeview: local composition canceled before changing remote pointer focus")

// A deactivation before writing is recoverable after the lifecycle barrier.
// Joined cancellation/transport failures remain terminal even if another leaf
// is ErrDeactivated; errors.Is alone would hide those independent failures.
func onlyDeactivated(err error) bool {
	if err == rdp.ErrDeactivated {
		return true
	}
	if many, ok := err.(interface{ Unwrap() []error }); ok {
		children := many.Unwrap()
		if len(children) == 0 {
			return false
		}
		for _, child := range children {
			if !onlyDeactivated(child) {
				return false
			}
		}
		return true
	}
	if one, ok := err.(interface{ Unwrap() error }); ok {
		return onlyDeactivated(one.Unwrap())
	}
	return false
}

type inputHost interface {
	KeyWithKeyboardState(ime.TextFocus, ime.WindowsKeyMessage, ime.WindowsKeyboardState) (bool, error)
	ApplyCandidate(ime.TextFocus, ime.CandidateToken, ime.CandidateAction) (bool, error)
	Pump(ime.TextFocus) (bool, error)
	QueueFlush(context.Context, ime.TextFocus) (*ime.DeliveryReceipt, error)
	QueueKey(context.Context, ime.TextFocus, ime.WindowsKeyMessage, bool) (*ime.DeliveryReceipt, error)
	Snapshot(ime.TextFocus) (ime.TextSnapshot, error)
	InsertText(ime.TextFocus, string) (bool, error)
}
type mouseAction struct {
	kind    uint8
	x, y    uint16
	button  rdp.MouseButton
	down    bool
	wheel   int16
	toggles uint32
}

const (
	mouseMove uint8 = iota + 1
	mouseButton
	mouseWheel
	mouseSync
)

type inputItem struct {
	packet    *ime.WindowsMessage
	character *characterMessage
	text      characterRun
	key       ime.WindowsKeyMessage
	state     ime.WindowsKeyboardState
	mouse     mouseAction
	candidate *candidateInput
}
type candidateInput struct {
	token  ime.CandidateToken
	action ime.CandidateAction
}
type completion func() (bool, error)

func receiptCompletion(r *ime.DeliveryReceipt) completion {
	return func() (bool, error) { result, ready := r.Result(); return ready, result.Err }
}

type inputLoop struct {
	characters         characterState
	packetWaiting      packetCompletion
	translatePacket    func(ime.WindowsMessage) (packetCompletion, error)
	host               inputHost
	token              ime.TextFocus
	queue              []inputItem
	filtered, consumed bool
	pending            completion
	sendMouse          func(context.Context, mouseAction) (completion, error)
}

func (q *inputLoop) enqueue(item inputItem) error {
	if len(q.queue) > 0 && item.mouse.kind == mouseMove && q.queue[len(q.queue)-1].mouse.kind == mouseMove {
		q.queue[len(q.queue)-1] = item
		return nil
	}
	if len(q.queue) >= 256 {
		return errInputOverflow
	}
	q.queue = append(q.queue, item)
	return nil
}
func (q *inputLoop) pop() {
	copy(q.queue, q.queue[1:])
	q.queue[len(q.queue)-1] = inputItem{}
	q.queue = q.queue[:len(q.queue)-1]
	q.filtered, q.consumed = false, false
}
func busy(err error) bool {
	return errors.Is(err, rail.ErrBusy) || errors.Is(err, ime.ErrPendingCommit)
}

// advance runs only on the UI thread, outside a window/native callback. Each
// pass has a finite work budget. A filtered message remains at the head across
// asynchronous edits and delivery; its native filter is never replayed.
func (q *inputLoop) advance(ctx context.Context) error {
	for steps := 0; steps < 16; steps++ {
		if q.pending != nil {
			ready, err := q.pending()
			if !ready {
				return nil
			}
			q.pending = nil
			if err != nil {
				return err
			}
		}
		more, err := q.host.Pump(q.token)
		if busy(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if more {
			return nil
		}
		r, err := q.host.QueueFlush(ctx, q.token)
		if busy(err) {
			return nil
		}
		if err != nil {
			return err
		}
		if r != nil {
			q.pending = receiptCompletion(r)
			return nil
		}
		if len(q.queue) == 0 {
			return nil
		}
		item := q.queue[0]
		if q.packetWaiting != nil {
			chars, done := q.packetWaiting()
			if !done {
				return nil
			}
			q.packetWaiting = nil
			q.pop()
			if len(chars)+len(q.queue) > 256 {
				return errInputOverflow
			}
			items := make([]inputItem, 0, len(chars)+len(q.queue))
			for _, c := range chars {
				character := c
				items = append(items, inputItem{character: &character})
			}
			q.queue = append(items, q.queue...)
			continue
		}
		if item.character != nil {
			run, err := q.characters.accept(*item.character)
			if err != nil {
				return err
			}
			q.queue[0].character = nil
			q.queue[0].text = run
			if run.remaining == 0 {
				q.pop()
			}
			continue
		}
		if item.text.remaining != 0 {
			text, n := item.text.chunk()
			applied, err := q.host.InsertText(q.token, text)
			if !applied && (busy(err) || errors.Is(err, ime.ErrChanged)) {
				return nil
			}
			if !applied && errors.Is(err, rail.ErrInvalid) {
				return errCharacterInput
			}
			if err != nil {
				return err
			}
			if !applied {
				return ErrInvalid
			}
			q.queue[0].text.remaining -= n
			if q.queue[0].text.remaining == 0 {
				q.pop()
			}
			continue // newly committed local text must flush before any later input
		}
		if q.characters.high != 0 && item.packet == nil {
			return errCharacterInput
		}
		if item.candidate != nil {
			invoked, err := q.host.ApplyCandidate(q.token, item.candidate.token, item.candidate.action)
			if busy(err) && !invoked {
				return nil
			}
			q.pop()
			if errors.Is(err, ime.ErrChanged) || errors.Is(err, ime.ErrStale) {
				return nil
			}
			return err
		}
		if item.mouse.kind != 0 {
			if item.mouse.kind == mouseButton && item.mouse.down {
				s, err := q.host.Snapshot(q.token)
				if busy(err) {
					return nil
				}
				if err != nil {
					return err
				}
				if len(s.Compositions) != 0 {
					return errCompositionClick
				}
			}
			job, err := q.sendMouse(ctx, item.mouse)
			if err != nil {
				return err
			}
			q.pop()
			q.pending = job
			return nil
		}
		if !q.filtered {
			consumed, err := q.host.KeyWithKeyboardState(q.token, item.key, item.state)
			if busy(err) {
				return nil
			}
			if err != nil {
				return err
			}
			q.filtered, q.consumed = true, consumed
			continue // Pump and flush edits produced by this native key first.
		}
		if item.packet != nil {
			if q.consumed || item.key.Message == 0x101 || item.key.Message == 0x105 {
				q.pop()
				continue
			}
			if q.translatePacket == nil {
				return ErrInvalid
			}
			wait, err := q.translatePacket(*item.packet)
			if busy(err) && wait == nil {
				return nil
			}
			if err != nil {
				return err
			}
			if wait == nil {
				return ErrInvalid
			}
			q.packetWaiting = wait
			return nil
		}
		r, err = q.host.QueueKey(ctx, q.token, item.key, q.consumed)
		if busy(err) {
			return nil
		}
		if err != nil {
			return err
		}
		q.pop()
		q.pending = receiptCompletion(r)
		return nil
	}
	return nil
}

// pointerWriter serializes one pointer operation and one retirement. UI state
// never blocks on its network calls. Unknown presses retain cleanup ownership;
// handed-off releases are never retried. It is fixed to the same Remote as the
// IME dispatcher and is replaced only after its retirement completes.
type pointerWriter struct {
	mu               sync.Mutex
	remote           Remote
	pending, cleanup *pointerJob
	retired          bool
	held             [3]bool
	x, y             uint16
}
type pointerJob struct {
	done   chan struct{}
	cancel context.CancelFunc
	err    error
}

func (j *pointerJob) result() (bool, error) {
	select {
	case <-j.done:
		return true, j.err
	default:
		return false, nil
	}
}
func (w *pointerWriter) submit(ctx context.Context, a mouseAction) (completion, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.retired {
		return nil, ime.ErrStale
	}
	if w.pending != nil {
		return nil, rail.ErrBusy
	}
	if ctx == nil {
		return nil, ErrInvalid
	}
	if a.kind < mouseMove || a.kind > mouseSync || a.kind == mouseButton && (a.button < rdp.MouseLeft || a.button > rdp.MouseMiddle) {
		return nil, ErrInvalid
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	j := &pointerJob{done: make(chan struct{}), cancel: cancel}
	w.pending = j
	go func() {
		var err error
		if err = ctx.Err(); err == nil {
			if a.kind == mouseMove || a.kind == mouseButton {
				w.x, w.y = a.x, a.y
			}
			switch a.kind {
			case mouseMove:
				err = w.remote.MovePointer(ctx, a.x, a.y)
			case mouseButton:
				index := int(a.button) - 1
				if a.down {
					w.held[index] = true
					err = w.remote.SendMouseButton(ctx, a.button, true, a.x, a.y)
				} else if w.held[index] {
					w.held[index] = false
					err = w.remote.SendMouseButton(ctx, a.button, false, a.x, a.y)
				}
			case mouseWheel:
				for left := int(a.wheel); left != 0; {
					if err = ctx.Err(); err != nil {
						break
					}
					part := min(255, max(-256, left))
					err = w.remote.Scroll(ctx, int16(part))
					if err != nil {
						break
					}
					left -= part
				}
			case mouseSync:
				err = w.remote.SynchronizeKeys(ctx, a.toggles)
			}
		}
		err = errors.Join(err, ctx.Err())
		cancel()
		w.mu.Lock()
		w.pending = nil
		j.err = err
		close(j.done)
		w.mu.Unlock()
	}()
	return j.result, nil
}
func (w *pointerWriter) retire() completion {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.retired = true
	if w.cleanup != nil {
		return w.cleanup.result
	}
	previous := w.pending
	if previous != nil {
		previous.cancel()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	j := &pointerJob{done: make(chan struct{}), cancel: cancel}
	w.cleanup = j
	go func() {
		if previous != nil {
			<-previous.done
		}
		var result error
		for index := 2; index >= 0; index-- {
			if w.held[index] {
				if err := ctx.Err(); err != nil {
					result = errors.Join(result, err)
					break
				}
				w.held[index] = false
				result = errors.Join(result, w.remote.SendMouseButton(ctx, rdp.MouseButton(index+1), false, w.x, w.y))
			}
		}
		result = errors.Join(result, ctx.Err())
		cancel()
		w.mu.Lock()
		w.remote = nil
		j.err = result
		close(j.done)
		w.mu.Unlock()
	}()
	return j.result
}
