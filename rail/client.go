package rail

import "strings"

// Options describes capabilities already negotiated by the enclosing RDP
// connection and local settings. HandshakeEx is true only when both sides
// offered that capability. Enhanced must reflect the Client Info request and
// an available GFX window consumer; Status.Enhanced reports server acceptance.
// LocalMoveSize requires the application to implement the emitted move/size
// events. Reconnecting sets CLIENTSTATUS_AUTORECONNECT; it does not reconnect
// or relaunch anything. BuildNumber is the application's own version identifier.
type Options struct {
	Language LanguageCapabilities // Confirmed enclosing capabilities; explicit host integration.
	// Cloaking reflects the enclosing connection's negotiated RAIL capability.
	// BidirectionalCloak advertises the application's server-notification consumer.
	// The two directions are independent; neither creates local windows.
	Cloaking, BidirectionalCloak bool
	BuildNumber                  uint32
	HandshakeEx                  bool
	Enhanced                     bool
	// ZOrderSync requires marker-window activation handling in the local UI.
	ZOrderSync    bool
	LocalMoveSize bool
	// ResizeMargins declares support for transparent hit-testable margins.
	// Set WindowOptions.ResizeMargins on the window consumer as well, and include
	// those margins in input hit testing and outgoing WindowMove/WindowSnap bounds.
	ResizeMargins bool
	Reconnecting  bool
	// ShellIntegration reflects the negotiated extended shell-integration RAIL
	// capability. It gates server Taskbar Tab Info notices; tab presentation and
	// overlay icons remain with the application's window consumer.
	ShellIntegration bool
	// PowerDisplaySync advertises CLIENTSTATUS_POWER_DISPLAY_REQUEST_SUPPORTED
	// and gates server Power Display Request notices. The library never changes
	// local power or display settings; the application decides any OS action.
	PowerDisplaySync bool
	Parameters       SystemParameters
	Settings         Settings // optional explicit snapshot; unsupported fields are reported after HandshakeEx
}

type Status struct {
	Cloaking          bool // Ready and permitted to send client-originated Cloak updates.
	MarkerKnown       bool
	MarkerWindowID    uint32 // Connection-local, meaningful only when MarkerKnown.
	ClientFlags       uint32 // Advertised Client Information flags, zero before Ready/after Close.
	Enhanced          bool   // True only after an accepted Enhanced HandshakeEx, until Close.
	Ready, Closed     bool
	Server            Handshake
	PendingExecutions int
}

type requestKey struct {
	flags ExecuteFlags
	exe   string
}

// Client is a single-connection state machine, created with NewClient. All
// methods require caller synchronization. It owns no transport or goroutines.
// Deliver reassembled, decompressed rail channel data to Handle. Send returned
// PDUs in order through the enclosing Session.WriteChannel before calling more
// methods. A write error makes delivery uncertain: close the RDP connection and
// this Client; never replay an Execute automatically. On reconnect use a new
// Client and make an explicit application decision about any unresolved launch.
type Client struct {
	language        LanguageStatus
	options         Options
	initial         [][]byte
	initialSettings []settingPacket
	settingsStatus  SettingsStatus
	ready, closed   bool
	server          Handshake
	clientFlags     uint32
	markerKnown     bool
	markerWindowID  uint32
	pending         map[requestKey]struct{}
}

// NewClient validates and copies an explicit initial settings snapshot. It does
// not send a handshake until the server's handshake arrives through Handle.
func NewClient(o Options) (*Client, error) {
	if err := o.Language.validate(); err != nil {
		return nil, err
	}
	p, err := o.Parameters.packets()
	if err != nil {
		return nil, err
	}
	settings, err := o.Settings.compile()
	if err != nil {
		return nil, err
	}
	o.Settings = Settings{} // only owned encoded bytes are retained
	o.Parameters.HighContrastScheme = strings.Clone(o.Parameters.HighContrastScheme)
	return &Client{language: LanguageStatus{Capabilities: o.Language}, options: o, initial: p, initialSettings: settings, settingsStatus: SettingsStatus{Queued: len(settings) > 0}, pending: make(map[requestKey]struct{})}, nil
}

func (c *Client) Status() Status {
	ready := c.ready && !c.closed
	return Status{Cloaking: ready && c.options.Cloaking, MarkerKnown: c.markerKnown, MarkerWindowID: c.markerWindowID, Ready: ready, Closed: c.closed || c.pending == nil, Server: c.server, ClientFlags: c.clientFlags, PendingExecutions: len(c.pending), Enhanced: ready && c.server.Extended && c.server.Flags&HandshakeEnhanced != 0}
}

// Close discards unresolved requests without relaunching. The caller owns and
// closes the surrounding transport. A closed Client cannot be reused.
func (c *Client) Close() {
	c.ready = false
	c.closed = true
	c.initial = nil
	c.initialSettings = nil
	c.settingsStatus = SettingsStatus{}
	c.clientFlags = 0
	c.markerKnown, c.markerWindowID = false, 0
	clear(c.pending)
	c.options = Options{}
	c.language = LanguageStatus{}
}

func (c *Client) check() error {
	if c.closed || c.pending == nil {
		return ErrClosed
	}
	if !c.ready {
		return ErrNotReady
	}
	return nil
}

// Handle accepts one complete virtual-channel message containing one or more
// complete RAIL PDUs. Limits are MaxMessage bytes and MaxOrders PDUs. It returns
// no events/replies if any PDU is invalid, unexpected or unsupported, and closes
// the state machine. Earlier PDUs in the same call cannot trigger partial local
// side effects. Ready means replies are available; the caller must send them.
// Handshake replies contain status, baseline system settings and the supported
// fields from the optional Settings snapshot. SettingsStatus reports omissions.
// Valid MinMaxInfo and LocalMoveSize are ignored when local move/size was not
// advertised, as required by the receiver profile in MS-RDPERP 3.2.5.2.7.
// Taskbar Tab Info and Power Display Request require Options.ShellIntegration
// and Options.PowerDisplaySync respectively; otherwise they are unsupported.
// Ignored PDUs still count toward MaxOrders and are fully syntax-validated.
// No Execute PDU is generated by this method.
func (c *Client) Handle(data []byte) ([]Event, [][]byte, error) {
	if c.closed || c.pending == nil {
		return nil, nil, ErrClosed
	}
	events, replies, err := c.handle(data)
	if err != nil {
		c.Close()
		return nil, nil, err
	}
	return events, replies, nil
}

func (c *Client) handle(data []byte) ([]Event, [][]byte, error) {
	if len(data) < 4 || len(data) > MaxMessage {
		return nil, nil, ErrInvalid
	}
	var events []Event
	var replies [][]byte
	for count := 0; len(data) > 0; count++ {
		if count >= MaxOrders || len(data) < 4 {
			return nil, nil, ErrInvalid
		}
		n := int(le.Uint16(data[2:]))
		if n < 4 || n > len(data) {
			return nil, nil, ErrInvalid
		}
		e, err := ParseServerPDU(data[:n])
		if err != nil {
			return nil, nil, err
		}
		data = data[n:]
		if e.Order == OrderHandshake || e.Order == OrderHandshakeEx {
			if c.ready {
				return nil, nil, ErrState
			}
			enhanced := e.Handshake.Extended && e.Handshake.Flags&HandshakeEnhanced != 0
			if enhanced && !c.options.Enhanced || e.Handshake.Extended && !c.options.HandshakeEx && !enhanced {
				return nil, nil, ErrUnsupported
			}
			c.server = e.Handshake
			c.ready = true
			flags := uint32(0)
			if c.options.LocalMoveSize {
				flags |= 1
			}
			if c.options.Reconnecting {
				flags |= 2
			}
			if c.options.ZOrderSync {
				flags |= 4
			}
			if c.options.ResizeMargins {
				flags |= 0x10
			}
			if c.options.BidirectionalCloak {
				flags |= 0x200
			}
			if c.options.PowerDisplaySync {
				flags |= 0x80
			}
			c.clientFlags = flags
			replies = append(replies, packet(OrderHandshake, le.AppendUint32(nil, c.options.BuildNumber)), packet(OrderClientStatus, le.AppendUint32(nil, flags)))
			replies = append(replies, c.initial...)
			c.initial = nil
			settings := selectSettings(c.initialSettings, c.server)
			replies = append(replies, settings.Packets...)
			c.settingsStatus = settings.Status
			c.initialSettings = nil
		} else {
			if !c.ready {
				return nil, nil, ErrState
			}
			switch e.Order {
			case OrderExecuteResult:
				key := requestKey{e.Execute.Flags, e.Execute.ExeOrFile}
				if _, ok := c.pending[key]; !ok {
					return nil, nil, ErrState
				}
				delete(c.pending, key)
			case OrderLanguageBar:
				if !c.language.Capabilities.LanguageBar {
					return nil, nil, ErrUnsupported
				}
			case OrderIMECompartment:
				if !c.language.Capabilities.ServerIME {
					return nil, nil, ErrUnsupported
				}
				// Initial or delayed server notices may precede a local profile
				// selection. There is no wire profile ID; emit without guessing.
			case OrderCloak:
				if !c.options.BidirectionalCloak {
					return nil, nil, ErrUnsupported
				}
			case OrderTaskbarInfo:
				if !c.options.ShellIntegration {
					return nil, nil, ErrUnsupported
				}
			case OrderPowerDisplay:
				if !c.options.PowerDisplaySync {
					return nil, nil, ErrUnsupported
				}
			case OrderZOrderSync:
				if !c.options.ZOrderSync {
					return nil, nil, ErrUnsupported
				}
				c.markerKnown, c.markerWindowID = true, e.MarkerWindowID
			case OrderLocalMoveSize, OrderMinMaxInfo:
				if !c.options.LocalMoveSize {
					continue
				}
			}
		}
		events = append(events, e)
	}
	return events, replies, nil
}

// Execute creates an explicitly requested remote launch and records its key.
// Results carry only Flags and ExeOrFile, so a second request with the same key
// is ambiguous even when its arguments differ. Such requests must be serialized.
// Up to MaxPending distinct keys may be outstanding. Only keys are retained.
func (c *Client) Execute(r ExecuteRequest) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	p, err := EncodeExecute(r)
	if err != nil {
		return nil, err
	}
	k := requestKey{r.Flags, r.ExeOrFile}
	if _, ok := c.pending[k]; ok || len(c.pending) >= MaxPending {
		return nil, ErrBusy
	}
	k.exe = strings.Clone(k.exe)
	c.pending[k] = struct{}{}
	return p, nil
}

// UpdateSystemParameters produces the same explicit baseline settings used at
// startup. Invalid local input leaves the Client usable and produces no PDUs.
func (c *Client) UpdateSystemParameters(s SystemParameters) ([][]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	return s.packets()
}

// WorkArea sets one monitor's usable rectangle. It may be used repeatedly for
// multiple monitors. It does not resize the RDP desktop or local windows.
func (c *Client) WorkArea(r Rectangle) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if !r.nonempty() {
		return nil, ErrInvalid
	}
	return systemParameter(0x2f, r.bytes()), nil
}
