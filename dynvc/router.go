package dynvc

import (
	"context"
	"errors"
	"sync"
)

var ErrTransport = errors.New("dynvc: invalid or unavailable transport")
var ErrClosed = errors.New("dynvc: router closed")

// RouterOptions configures one DVC manager for one authenticated RDP session.
type RouterOptions struct {
	ListenerLimits map[string]int
	MaxBuffered    int // zero uses MaxBuffered
	// SoftSync must be true only if both GCC peers negotiated 0x200.
	SoftSync bool
	// Write sends exactly one DVC PDU, in full, or returns an error. It must
	// honor ctx, must not call Router methods, and must not retain b. TCP writes
	// need static-channel framing; reliable UDP writes need Tunnel Data framing.
	// This must be the only DVC writer for the session. Calls are serialized.
	Write func(ctx context.Context, transport Transport, b []byte) error
}

// Router serializes DVC messages, replies and the TCP-to-reliable-UDP barrier.
// It retains Client's uncompressed version 1 negotiation and listener limits.
// Use a single reader per carrier, delivering complete PDUs in carrier order.
// Soft-Sync is independent of version 3 DVC compression.
//
// Router owns no sockets. The session owner must close it and both carriers on
// main-connection loss. After a wire/protocol failure the manager is terminal:
// uncertain writes are never replayed on TCP. Recreate it for a new session.
// Waiting for the operation gate or for Soft-Sync can be canceled harmlessly;
// cancellation during a wire write is terminal. The zero value is closed.
// A Router must not be copied after construction.
type Router struct {
	client              *Client
	write               func(context.Context, Transport, []byte) error
	softSync            bool
	gate                chan struct{}
	life                context.Context
	cancel              context.CancelFunc
	reliable            chan struct{}
	switchDone          chan struct{}
	confirmed, switched bool // protected by gate
	routes              map[uint32]Transport
	errMu               sync.Mutex
	err                 error
}

func NewRouter(o RouterOptions) (*Router, error) {
	if o.Write == nil {
		return nil, ErrTransport
	}
	if o.MaxBuffered == 0 {
		o.MaxBuffered = MaxBuffered
	}
	c, err := NewWithLimits(o.ListenerLimits, o.MaxBuffered)
	if err != nil {
		return nil, err
	}
	life, cancel := context.WithCancel(context.Background())
	r := &Router{client: c, write: o.Write, softSync: o.SoftSync,
		gate: make(chan struct{}, 1), life: life, cancel: cancel,
		reliable: make(chan struct{}), switchDone: make(chan struct{}), routes: make(map[uint32]Transport)}
	r.gate <- struct{}{}
	return r, nil
}

// Err returns the first terminal error, or nil while usable.
func (r *Router) Err() error {
	if r == nil || r.life == nil {
		return ErrClosed
	}
	r.errMu.Lock()
	defer r.errMu.Unlock()
	return r.err
}

func (r *Router) fail(err error) error {
	if r == nil || r.life == nil {
		return ErrClosed
	}
	r.errMu.Lock()
	if r.err == nil {
		r.err = err
		r.cancel()
	}
	first := r.err
	r.errMu.Unlock()
	// If an operation owns the gate it will discard partial messages on exit.
	select {
	case <-r.gate:
		r.discard()
		r.gate <- struct{}{}
	default:
	}
	return first
}

// Close cancels in-progress writes and unblocks waiters. The carrier owner is
// still responsible for closing transports. It is safe during any operation.
func (r *Router) Close() { r.fail(ErrClosed) }

func (r *Router) enter(ctx context.Context) error {
	if err := r.Err(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.life.Done():
		return r.Err()
	case <-r.gate:
	}
	if err := r.Err(); err != nil {
		r.leave()
		return err
	}
	if err := ctx.Err(); err != nil {
		r.leave()
		return err
	}
	return nil
}
func (r *Router) leave() {
	if r.Err() != nil {
		r.discard()
	}
	r.gate <- struct{}{}
}
func (r *Router) discard() {
	for _, ch := range r.client.channels {
		clear(ch.data)
	}
	r.client.channels, r.routes = nil, nil
	r.client.buffered = 0
	r.client.closedIDs = nil
}

// ConfirmReliable records that the reliable tunnel is bound to the main
// session AND its successful Initiate Multitransport Response has been sent.
// The owner must call it before delivering a Soft-Sync request. Confirmation
// alone never permits DVC traffic on the tunnel. Repeated calls are harmless.
func (r *Router) ConfirmReliable(ctx context.Context) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer r.leave()
	if !r.softSync || (r.switched && !r.confirmed) {
		return ErrTransport
	}
	r.confirmed = true
	return nil
}

// WaitReliable gates the tunnel reader until the Soft-Sync response was fully
// written to TCP. Call before reading Tunnel Data: independent carriers can
// deliver UDP bytes before the earlier TCP request reaches the client.
// Returns ErrTransport if the completed exchange does not enable this tunnel.
func (r *Router) WaitReliable(ctx context.Context) error {
	if err := r.Err(); err != nil {
		return err
	}
	if !r.softSync {
		return ErrTransport
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-r.life.Done():
		return r.Err()
	case <-r.switchDone:
		if err := r.Err(); err != nil {
			return err
		}
		select {
		case <-r.reliable:
			return nil
		default:
			return ErrTransport
		}
	}
}

// Handle consumes one PDU, writes all required replies, then returns an owned
// event. UDP delivery waits for the barrier without holding the operation gate.
// Do not mutate b until this call returns. Malformed or misrouted PDUs close the
// manager; no partially accepted event is exposed when a reply fails.
func (r *Router) Handle(ctx context.Context, tr Transport, b []byte) (Event, error) {
	if err := r.Err(); err != nil {
		return Event{}, err
	}
	if tr != TCP && tr != ReliableUDP {
		return Event{}, r.fail(ErrTransport)
	}
	if len(b) == 0 || len(b) > MaxPDU {
		return Event{}, r.fail(ErrProtocol)
	}
	if tr == ReliableUDP {
		if err := r.WaitReliable(ctx); err != nil {
			if errors.Is(err, ErrTransport) {
				return Event{}, r.fail(err)
			}
			return Event{}, err
		}
	}
	if err := r.enter(ctx); err != nil {
		return Event{}, err
	}
	defer r.leave()
	cmd := b[0] >> 4
	if cmd == 8 {
		if tr != TCP {
			return Event{}, r.fail(ErrTransport)
		}
		return Event{}, r.switchReliable(ctx, b)
	}
	if cmd == 5 {
		if tr != TCP {
			return Event{}, r.fail(ErrTransport)
		}
	} else {
		id, _, err := number(b[1:], b[0]&3)
		if err != nil {
			return Event{}, r.fail(err)
		}
		if _, exists := r.client.channels[id]; exists && r.routes[id] != tr {
			return Event{}, r.fail(ErrTransport)
		}
	}
	replies, event, err := r.client.Handle(b)
	if err != nil {
		return Event{}, r.fail(err)
	}
	if err = r.writeAll(ctx, tr, replies); err != nil {
		return Event{}, err
	}
	switch event.Kind {
	case Opened:
		r.routes[event.ID] = tr
	case Closed:
		delete(r.routes, event.ID)
	}
	return event, nil
}

func (r *Router) switchReliable(ctx context.Context, b []byte) error {
	if !r.softSync || !r.client.ready || r.switched {
		return r.fail(ErrProtocol)
	}
	lists, err := ParseSoftSyncRequest(b)
	if err != nil {
		return r.fail(err)
	}
	for _, list := range lists {
		if list.Transport != ReliableUDP || !r.confirmed {
			return r.fail(ErrTransport)
		}
	}
	var tunnels []Transport
	if r.confirmed {
		tunnels = []Transport{ReliableUDP}
	}
	reply, err := SoftSyncResponse(tunnels)
	if err != nil {
		return r.fail(err)
	}
	if err = r.writeAll(ctx, TCP, [][]byte{reply}); err != nil {
		return err
	}
	// Commit only after all earlier writes and the TCP response succeeded.
	// Preserve partial DVC reassembly across this ordered transport boundary.
	for _, list := range lists {
		for _, id := range list.IDs {
			// The server's snapshot can precede our refused Create or Close
			// response. Only move existing channels; the list never opens one.
			// A later Create selects its own carrier, without a stale route.
			if r.client.channels[id] != nil {
				r.routes[id] = list.Transport
			}
		}
	}
	r.switched = true
	if r.confirmed {
		close(r.reliable)
	}
	close(r.switchDone)
	return nil
}

// Send writes an entire fragmented message on its channel's current carrier.
// Concurrent sends cannot interleave fragments. Local size/channel errors leave
// the router usable. No message copy is made while waiting for the gate.
func (r *Router) Send(ctx context.Context, id uint32, data []byte) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer r.leave()
	packets, err := r.client.Send(id, data)
	if err != nil {
		return err
	}
	return r.writeAll(ctx, r.routes[id], packets)
}

// CloseChannel sends an unsolicited close on the assigned carrier and removes
// the route. The server does not acknowledge client-initiated closes. A later
// Create selects its own carrier, even when it reuses the same channel ID.
func (r *Router) CloseChannel(ctx context.Context, id uint32) error {
	if err := r.enter(ctx); err != nil {
		return err
	}
	defer r.leave()
	b, err := r.client.Close(id)
	if err != nil {
		return err
	}
	tr := r.routes[id]
	delete(r.routes, id)
	return r.writeAll(ctx, tr, [][]byte{b})
}

func (r *Router) writeAll(ctx context.Context, tr Transport, packets [][]byte) error {
	if len(packets) == 0 {
		return r.Err()
	}
	x, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(r.life, cancel)
	defer func() { stop(); cancel() }()
	for _, b := range packets {
		if err := r.Err(); err != nil {
			return err
		}
		if err := x.Err(); err != nil {
			return r.fail(err)
		}
		if err := r.write(x, tr, b); err != nil {
			return r.fail(err)
		}
	}
	if err := x.Err(); err != nil {
		return r.fail(err)
	}
	return r.Err()
}
