package rdp

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/mcs"
	"github.com/hq0101/rdp-go/rdpemt"
	"github.com/hq0101/rdp-go/rdpudp"
	"github.com/hq0101/rdp-go/rdpudp2"
	"github.com/hq0101/rdp-go/vchan"
)

// DynamicChannelOptions opts into Session-managed DVCs. Listener limits and
// aggregate reservations have the same meaning as dynvc.NewWithLimits. Zero
// MaxBuffered selects dynvc.MaxBuffered. drdynvc is added to GCC if necessary.
type DynamicChannelOptions struct {
	Listeners   map[string]int
	MaxBuffered int
	// ReliableUDP offers reliable UDP plus Soft-Sync. Failed setup leaves DVCs
	// on TCP. Bound-side network failure terminates this Session but permits
	// cookie-based Reconnect with TCP renegotiation. No in-place switch or replay
	// occurs. It starts bounded background wire readers.
	ReliableUDP bool
	// ReceiveWindow bounds retained reliable UDP packets. Zero selects 512 for
	// managed sessions; explicit values must be powers of two from 2 through
	// 512. Requires ReliableUDP. The low-level rdpudp default remains 64.
	ReceiveWindow uint16
}

// DynamicChannelInfo is an owned snapshot. Bound is not proof that any channel
// moved. SoftSynced plus UDP receive/send counts distinguish actual DVC use.
// SetupError contains no credentials, cookie or application payload.
type DynamicChannelInfo struct {
	Managed, RequestedUDP, NegotiatedUDP       bool
	Started, Bound, SoftSynced                 bool
	SideFailed, SideNetworkFailure             bool // first terminal sideband failure
	SetupError                                 string
	Version                                    uint16
	TCPReceived, TCPSent, UDPReceived, UDPSent uint64
	UDPReceivedBytes, UDPSentBytes             uint64
	Network                                    rdpemt.TunnelNetworkInfo
	UDP                                        rdpudp.ConnStats
}

func cloneDynamicOptions(o *DynamicChannelOptions) *DynamicChannelOptions {
	if o == nil {
		return nil
	}
	n := *o
	n.Listeners = make(map[string]int, len(o.Listeners))
	for name, limit := range o.Listeners {
		n.Listeners[name] = limit
	}
	return &n
}

func prepareDynamic(o Options, settings gcc.ClientSettings) (Options, gcc.ClientSettings, error) {
	if o.Gateway != nil && (settings.MultitransportFlags != 0 || o.DynamicChannels != nil && o.DynamicChannels.ReliableUDP) {
		return o, settings, ErrGatewayRoute
	}
	o.DynamicChannels = cloneDynamicOptions(o.DynamicChannels)
	if o.DynamicChannels == nil {
		if settings.MultitransportFlags != 0 {
			return o, settings, errors.New("rdp: Session multitransport is not yet integrated without managed DynamicChannels")
		}
		return o, settings, nil
	}
	d := o.DynamicChannels
	if d.MaxBuffered == 0 {
		d.MaxBuffered = dynvc.MaxBuffered
	}
	if _, err := dynvc.NewWithLimits(d.Listeners, d.MaxBuffered); err != nil {
		return o, settings, err
	}
	if settings.MultitransportFlags != 0 && (!d.ReliableUDP || settings.MultitransportFlags != 0x201) {
		return o, settings, errors.New("rdp: managed DVC supports reliable UDP with Soft-Sync only")
	}
	if d.ReliableUDP {
		if d.ReceiveWindow == 0 {
			d.ReceiveWindow = rdpudp2.MaxWindowPackets
		}
		if d.ReceiveWindow < 2 || d.ReceiveWindow > rdpudp2.MaxWindowPackets || d.ReceiveWindow&(d.ReceiveWindow-1) != 0 {
			return o, settings, errors.New("rdp: reliable UDP ReceiveWindow must be a power of two from 2 to 512")
		}
		settings.MultitransportFlags = 0x201
		settings.NetworkAutoDetect = true
	} else if d.ReceiveWindow != 0 {
		return o, settings, errors.New("rdp: ReceiveWindow requires ReliableUDP")
	}
	settings.Channels = append([]gcc.Channel(nil), settings.Channels...)
	found := false
	for _, ch := range settings.Channels {
		if ch.Name == "drdynvc" {
			found = true
		}
	}
	if !found {
		settings.Channels = append(settings.Channels, gcc.Channel{Name: "drdynvc"})
	}
	return o, settings, nil
}

type dynamicFrame struct {
	frame Frame
	err   error
}
type dynamicState struct {
	s                                 *Session
	id                                uint16
	router                            *dynvc.Router
	decoder                           vchan.Decoder // Session read gate
	life, sideLife                    context.Context
	cancel, cancelSide                context.CancelFunc
	frames                            chan dynamicFrame
	messages                          chan rdpemt.Message
	requests                          chan rdpemt.InitiateRequest
	setupDone, sideReady, workersDone chan struct{}
	wg                                sync.WaitGroup
	mainFailed                        atomic.Bool
	mu                                sync.Mutex
	info                              DynamicChannelInfo
	terminal                          error
	tunnel                            *rdpemt.Tunnel
	udp                               dynamicUDP
	receiveWindow                     uint16 // immutable, validated before dialing
	// An injectable private seam keeps session tests independent of UDP timing.
	dial func(context.Context, rdpemt.InitiateRequest) (*rdpemt.Tunnel, uint16, error)
}

func (s *Session) initDynamic(o *DynamicChannelOptions) error {
	if o == nil {
		return nil
	}
	id, ok := s.ChannelID("drdynvc")
	if !ok {
		return dynvc.ErrChannel
	}
	life, cancel := context.WithCancel(context.Background())
	side, cancelSide := context.WithCancel(life)
	m := &dynamicState{s: s, id: id, receiveWindow: o.ReceiveWindow, life: life, cancel: cancel, sideLife: side, cancelSide: cancelSide,
		frames: make(chan dynamicFrame, 1), messages: make(chan rdpemt.Message, 1), requests: make(chan rdpemt.InitiateRequest, 1),
		setupDone: make(chan struct{}), sideReady: make(chan struct{}), workersDone: make(chan struct{})}
	m.info = DynamicChannelInfo{Managed: true, RequestedUDP: o.ReliableUDP, NegotiatedUDP: o.ReliableUDP && s.info.MessageChannel != 0 && s.connection.Server.MultitransportFlags&0x201 == 0x201}
	r, err := dynvc.NewRouter(dynvc.RouterOptions{ListenerLimits: o.Listeners, MaxBuffered: o.MaxBuffered, SoftSync: m.info.NegotiatedUDP, Write: m.write})
	if err != nil {
		cancel()
		return err
	}
	m.router = r
	m.dial = m.dialReliable
	s.dynamic = m
	if m.info.NegotiatedUDP {
		m.wg.Add(4)
		go m.readMain()
		go m.setup()
		go m.readSide()
		go m.watchMain()
		go func() { m.wg.Wait(); close(m.workersDone) }()
	} else {
		close(m.workersDone)
	}
	return nil
}

func (s *Session) DynamicInfo() DynamicChannelInfo {
	if s.dynamic == nil {
		return DynamicChannelInfo{}
	}
	m := s.dynamic
	m.mu.Lock()
	v, t, u := m.info, m.tunnel, m.udp
	m.mu.Unlock()
	if t != nil {
		v.Network = t.NetworkInfo()
	}
	if u != nil {
		v.UDP = u.Stats()
	}
	return v
}

// SendDynamic writes one complete message on the DVC's assigned carrier.
// Protocol replies are automatic; application-specific replies remain the
// caller's responsibility. Virtual channels can run during reactivation.
func (s *Session) SendDynamic(ctx context.Context, id uint32, b []byte) error {
	if s.dynamic == nil {
		return dynvc.ErrChannel
	}
	err := s.dynamic.router.Send(ctx, id, b)
	if s.dynamic.router.Err() != nil {
		s.dynamic.stop(err)
	}
	return err
}

// CloseDynamic closes a managed DVC. Success completes the local close; the
// server sends no acknowledgement and no local dynvc.Closed event is generated.
// A later server Create may reopen the listener using the same or a new ID.
func (s *Session) CloseDynamic(ctx context.Context, id uint32) error {
	if s.dynamic == nil {
		return dynvc.ErrChannel
	}
	err := s.dynamic.router.CloseChannel(ctx, id)
	if s.dynamic.router.Err() != nil {
		s.dynamic.stop(err)
	}
	return err
}

func (m *dynamicState) err() error { m.mu.Lock(); defer m.mu.Unlock(); return m.terminal }

// stop is safe from protocol callbacks: it never waits for its own worker.
func (m *dynamicState) stop(err error) {
	m.s.active.Store(false)
	if err == nil {
		err = net.ErrClosed
	}
	m.mu.Lock()
	if m.terminal == nil {
		m.terminal = err
		var side *sideFailureError
		if errors.As(err, &side) {
			m.info.SideFailed = true
			m.info.SideNetworkFailure = side.network
		}
	}
	t := m.tunnel
	select {
	case pending := <-m.requests:
		clear(pending.Cookie[:])
	default:
	}
	terminal := m.terminal
	m.mu.Unlock()
	var side *sideFailureError
	if errors.As(terminal, &side) && !side.network {
		m.s.discardReconnect()
	}
	m.cancel()
	m.cancelSide()
	m.router.Close()
	if t != nil {
		t.Close()
	}
	m.s.connection.Transport.Close()
}

func (m *dynamicState) write(ctx context.Context, tr dynvc.Transport, b []byte) error {
	var err error
	if tr == dynvc.TCP {
		err = m.s.writeChannel(ctx, m.id, b)
	} else {
		m.mu.Lock()
		t := m.tunnel
		m.mu.Unlock()
		if t == nil {
			return dynvc.ErrTransport
		}
		err = t.WriteMessage(ctx, rdpemt.Message{Data: b})
		if err != nil {
			err = m.sideError(err)
		}
	}
	if err == nil {
		m.mu.Lock()
		if tr == dynvc.TCP {
			m.info.TCPSent++
		} else {
			m.info.UDPSent++
			m.info.UDPSentBytes += uint64(len(b))
		}
		m.mu.Unlock()
	}
	return err
}

func (m *dynamicState) readMain() {
	defer m.wg.Done()
	for {
		f, err := m.s.connection.Transport.ReadFrame(m.life)
		if err != nil {
			// Stop sideband work immediately, but preserve the queued main frame
			// and its following error in order for the Session reader.
			m.mainFailed.Store(true)
			m.cancelSide()
			m.mu.Lock()
			t := m.tunnel
			m.mu.Unlock()
			if t != nil {
				t.Close()
			}
		}
		select {
		case m.frames <- dynamicFrame{f, err}:
		case <-m.life.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func (m *dynamicState) watchMain() {
	defer m.wg.Done()
	select {
	case <-m.s.connection.Transport.closed:
	case <-m.life.Done():
		return
	}
	m.mainFailed.Store(true)
	m.cancelSide()
	m.mu.Lock()
	t := m.tunnel
	m.mu.Unlock()
	if t != nil {
		t.Close()
	}
}

func (m *dynamicState) readSide() {
	defer m.wg.Done()
	select {
	case <-m.sideReady:
	case <-m.sideLife.Done():
		return
	}
	m.mu.Lock()
	t := m.tunnel
	m.mu.Unlock()
	for {
		p, err := t.ReadMessage(m.sideLife)
		if err != nil {
			if !m.mainFailed.Load() && m.life.Err() == nil {
				m.stopSide(err)
			}
			return
		}
		m.mu.Lock()
		m.info.UDPReceived++
		m.info.UDPReceivedBytes += uint64(len(p.Data))
		m.mu.Unlock()
		// Probe replies are processed before this bounded queue. DVC delivery
		// is gated separately so early UDP cannot block the TCP Soft-Sync reader.
		select {
		case m.messages <- p:
		case <-m.sideLife.Done():
			clear(p.Data)
			return
		}
	}
}

func (m *dynamicState) read(ctx context.Context) (Frame, *Event, error) {
	for {
		if err := m.err(); err != nil {
			return Frame{}, nil, err
		}
		m.mu.Lock()
		switched := m.info.SoftSynced
		m.mu.Unlock()
		var side <-chan rdpemt.Message
		if switched {
			side = m.messages
		}
		select {
		case <-ctx.Done():
			return Frame{}, nil, ctx.Err()
		case <-m.life.Done():
			return Frame{}, nil, m.err()
		case f := <-m.frames:
			if f.err != nil {
				m.stop(f.err)
			}
			return f.frame, nil, f.err
		case p := <-side:
			e, err := m.router.Handle(ctx, dynvc.ReliableUDP, p.Data)
			clear(p.Data)
			if err != nil {
				return Frame{}, nil, err
			}
			if e.Kind != dynvc.None {
				return Frame{}, &Event{Kind: EventDynamic, Dynamic: e}, nil
			}
		}
	}
}

func (m *dynamicState) handleTCP(ctx context.Context, b []byte) (*Event, error) {
	p, complete, err := m.decoder.Feed(b)
	if err != nil || !complete {
		return nil, err
	}
	if len(p) > 0 && p[0]>>4 == 8 && m.info.NegotiatedUDP {
		// A fast server may answer S_OK before the setup goroutine records its
		// completed write. Wait here, without holding the router's write gate.
		m.mu.Lock()
		started := m.info.Started
		m.mu.Unlock()
		if !started {
			return nil, dynvc.ErrProtocol
		}
		select {
		case <-m.setupDone:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-m.life.Done():
			return nil, m.err()
		}
		m.mu.Lock()
		bound := m.info.Bound
		m.mu.Unlock()
		if !bound {
			return nil, dynvc.ErrTransport
		}
	}
	e, err := m.router.Handle(ctx, dynvc.TCP, p)
	if err != nil {
		command := -1
		if len(p) > 0 {
			command = int(p[0] >> 4)
		}
		return nil, fmt.Errorf("rdp: TCP DVC command %d: %w", command, err)
	}
	m.mu.Lock()
	m.info.TCPReceived++
	if len(p) > 0 && p[0]>>4 == 8 {
		m.info.SoftSynced = true
	}
	m.mu.Unlock()
	if e.Kind == dynvc.None {
		return nil, nil
	}
	return &Event{Kind: EventDynamic, Dynamic: e}, nil
}

func (m *dynamicState) bootstrap(ctx context.Context, b []byte) error {
	r, err := rdpemt.ParseInitiateRequest(b)
	if err != nil {
		return err
	}
	defer clear(r.Cookie[:])
	defer clear(b[12:])
	if !m.info.RequestedUDP {
		return errors.New("rdp: unsolicited multitransport request")
	}
	if !m.s.info.LicenseAccepted {
		return errors.New("rdp: multitransport request before license acceptance")
	}
	if !m.info.NegotiatedUDP {
		return m.respond(ctx, r.ID, false)
	}
	if r.Protocol != rdpemt.ReliableUDP {
		return errors.New("rdp: unoffered multitransport protocol")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.terminal != nil {
		return m.terminal
	}
	if m.info.Started {
		return errors.New("rdp: duplicate multitransport bootstrap")
	}
	m.info.Started = true
	m.requests <- r // one request, capacity one, while holding the shutdown lock
	return nil
}

func (m *dynamicState) respond(ctx context.Context, id uint32, success bool) error {
	b, err := rdpemt.InitiateResponse(id, success, m.info.NegotiatedUDP)
	if err != nil {
		return err
	}
	p, err := mcs.SendDataRequest(m.s.info.UserChannel, m.s.info.MessageChannel, b)
	if err != nil {
		return err
	}
	return m.s.connection.Transport.WriteMCS(ctx, p)
}

func (m *dynamicState) setup() {
	defer m.wg.Done()
	defer close(m.setupDone)
	var r rdpemt.InitiateRequest
	select {
	case r = <-m.requests:
	case <-m.sideLife.Done():
		return
	}
	defer clear(r.Cookie[:])
	ctx, cancel := context.WithTimeout(m.sideLife, 10*time.Second)
	defer cancel()
	t, version, err := m.dial(ctx, r)
	if err != nil {
		m.mu.Lock()
		m.info.SetupError = err.Error()
		m.mu.Unlock()
		if m.sideLife.Err() == nil {
			x, end := context.WithTimeout(m.sideLife, time.Second)
			defer end()
			if err = m.respond(x, r.ID, false); err != nil {
				m.stop(err)
			}
		}
		m.cancelSide()
		return
	}
	m.mu.Lock()
	if m.sideLife.Err() != nil {
		m.mu.Unlock()
		t.Close()
		return
	}
	m.tunnel = t
	m.info.Version = version
	m.mu.Unlock()
	if err = m.respond(ctx, r.ID, true); err == nil {
		err = m.router.ConfirmReliable(ctx)
	}
	if err != nil {
		m.stop(err)
		return
	}
	m.mu.Lock()
	m.info.Bound = true
	m.mu.Unlock()
	close(m.sideReady)
}

func (m *dynamicState) dialReliable(ctx context.Context, r rdpemt.InitiateRequest) (*rdpemt.Tunnel, uint16, error) {
	defer clear(r.Cookie[:])
	tr := m.s.connection.Transport
	if _, ok := tr.GatewayInfo(); ok {
		return nil, 0, ErrGatewayRoute
	}
	identity, err := rdpemt.IdentityFromTLS(tr.TLSState(), tr.CertificatePinned())
	if err != nil {
		return nil, 0, err
	}
	hash := rdpudp.HashCookie(r.Cookie)
	defer clear(hash[:])
	u, err := rdpudp.DialContext(ctx, "udp", tr.RemoteAddr().String(), rdpudp.DialConfig{Initialization: rdpudp.InitConfig{MaxVersion: rdpudp.Version3, ReceiveWindow: m.receiveWindow, CookieHash: &hash}})
	if err != nil {
		return nil, 0, err
	}
	version := u.Parameters().Version
	m.mu.Lock()
	m.udp = u
	m.mu.Unlock()
	t, err := rdpemt.BindReliable(ctx, tls.Client(u, identity.TLSConfig()), identity, r, rdpemt.TunnelOptions{MaxPayload: dynvc.MaxPDU, HandleNetworkProbes: true})
	if err != nil {
		return nil, version, err
	}
	return t, version, nil
}
