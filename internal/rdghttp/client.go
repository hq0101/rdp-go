package rdghttp

// Client is a serial, transport-independent engine for the ordinary HTTP-
// authenticated RDGHTTP 1.0 profile. HTTPS authentication must finish before
// Start. Extended authentication, SoH, idle enforcement, reauthentication and
// UDP are not advertised. This engine starts no goroutines, timers or sockets.
type Client struct {
	state         State
	auth, channel Frame
	info          Info
	setupMessages int
}

type State uint8

const (
	Initial State = iota
	AwaitHandshake
	AwaitTunnel
	AwaitConsent
	AwaitAuthorization
	AwaitPolicy
	AwaitChannel
	Ready
	Closing
	Closed
	Failed
)

const OfferedCapabilities = CapConsent | CapService
const MaxSetupMessages = 32

type Config struct {
	ClientName              string
	Resources, Alternatives []string
	Port                    uint16
}
type Info struct {
	TunnelID, ChannelID, Capabilities uint32
	RedirectionFlags                  uint32
	RedirectionFlagsPresent           bool
}
type EventKind uint8

const (
	NoEvent EventKind = iota
	ConsentRequired
	PolicyRequired
	Connected
	ReceivedData
	ReceivedService
	ReceivedKeepalive
	Disconnected
)

// Step owns all returned buffers. Outbound packets must be sent in order before
// the next operation. A partial or failed send requires Abort and closing both
// HTTP connections; retrying a Step can replay authentication or target actions.
// Service data remains bytes because MS-TSGU does not specify its encoding here.
type Step struct {
	Outbound []Frame
	Event    EventKind
	Consent  string
	Data     []byte `json:"-"`
	Status   uint32
	Info     Info
}

func NewClient(cfg Config) (*Client, error) {
	a, err := NewAuthorization(cfg.ClientName)
	if err != nil {
		return nil, err
	}
	c, err := NewChannel(cfg.Resources, cfg.Alternatives, cfg.Port)
	if err != nil {
		return nil, err
	}
	return &Client{auth: a, channel: c}, nil
}
func (c *Client) State() State { return c.state }
func (c *Client) Info() Info   { return c.info }
func (c *Client) Abort()       { c.release(); c.state = Closed }
func (c *Client) release() {
	clear(c.auth.Body)
	clear(c.channel.Body)
	c.auth = Frame{}
	c.channel = Frame{}
}
func (c *Client) fail(err error) (Step, error) { c.release(); c.state = Failed; return Step{}, err }
func (c *Client) emit(f Frame, state State) Step {
	c.state = state
	return Step{Outbound: []Frame{{f.Type, append([]byte(nil), f.Body...)}}, Info: c.info}
}
func (c *Client) Start() (Step, error) {
	if c.state != Initial || c.auth.Type != TunnelAuth || c.channel.Type != ChannelCreate {
		return Step{}, ErrState
	}
	return c.emit(NewHandshake(), AwaitHandshake), nil
}

// AcceptConsent is the explicit higher-layer response to ConsentRequired. Even
// an empty but present consent field requires a decision. No authorization
// packet is produced until acceptance; denial permanently fails this engine.
func (c *Client) AcceptConsent(accept bool) (Step, error) {
	if c.state != AwaitConsent {
		return Step{}, ErrState
	}
	if !accept {
		return c.fail(ErrDenied)
	}
	return c.emit(c.auth, AwaitAuthorization), nil
}

// AcceptPolicy confirms the caller has applied Info.RedirectionFlags to the
// forthcoming RDP session (including reconnect/resource configuration). Merely
// ignoring unsupported policy flags is not acceptance. Every authorization,
// even one without flags, pauses here. False prevents target channel creation.
func (c *Client) AcceptPolicy(applied bool) (Step, error) {
	if c.state != AwaitPolicy {
		return Step{}, ErrState
	}
	if !applied {
		return c.fail(ErrDenied)
	}
	return c.emit(c.channel, AwaitChannel), nil
}

func (c *Client) Receive(f Frame) (Step, error) {
	if c.state == Initial || c.state == Closed || c.state == Failed {
		return Step{}, ErrState
	}
	if c.state < Ready {
		c.setupMessages++
		if c.setupMessages > MaxSetupMessages {
			return c.fail(ErrLimit)
		}
	}
	r, err := Decode(f)
	if err != nil {
		return c.fail(err)
	}
	if r.Type == Keepalive {
		return Step{Event: ReceivedKeepalive, Info: c.info}, nil
	}
	if r.Type == ServiceMessage && c.state >= AwaitConsent {
		if c.info.Capabilities&CapService == 0 {
			return c.fail(ErrUnsupported)
		}
		return Step{Event: ReceivedService, Data: r.Data, Info: c.info}, nil
	}
	if r.Type == ReauthMessage || r.Type == ExtendedAuth {
		return c.fail(ErrUnsupported)
	}
	switch c.state {
	case AwaitHandshake:
		if r.Type != HandshakeResponse {
			return c.fail(ErrState)
		}
		h := r.Handshake
		if h.Status != 0 {
			return c.fail(&StatusError{r.Type, h.Status})
		}
		if h.Major != 1 || h.Minor != 0 {
			return c.fail(ErrUnsupported)
		}
		// ExtendedAuth in the response advertises server support. The ordinary
		// profile requested NONE and must not switch mechanisms implicitly.
		t, _ := NewTunnel(OfferedCapabilities)
		return c.emit(t, AwaitTunnel), nil
	case AwaitTunnel:
		if r.Type != TunnelResponse {
			return c.fail(ErrState)
		}
		t := r.Tunnel
		if t.Status != 0 {
			return c.fail(&StatusError{r.Type, t.Status})
		}
		if t.Capabilities & ^uint32(OfferedCapabilities) != 0 || t.Fields&4 != 0 {
			return c.fail(ErrUnsupported)
		}
		c.info.TunnelID = t.ID
		c.info.Capabilities = t.Capabilities
		if t.Fields&16 != 0 {
			c.state = AwaitConsent
			return Step{Event: ConsentRequired, Consent: t.Consent, Info: c.info}, nil
		}
		return c.emit(c.auth, AwaitAuthorization), nil
	case AwaitAuthorization:
		if r.Type != TunnelAuthResponse {
			return c.fail(ErrState)
		}
		a := r.Authorization
		if a.Status != 0 {
			return c.fail(&StatusError{r.Type, a.Status})
		}
		if a.Fields&4 != 0 {
			return c.fail(ErrUnsupported)
		}
		// Idle timeout is not negotiated. Per 3.7.5.2 it has no effect here;
		// the gateway can still terminate the channel with a status code.
		c.info.RedirectionFlagsPresent = a.Fields&1 != 0
		c.info.RedirectionFlags = a.RedirectionFlags
		c.state = AwaitPolicy
		return Step{Event: PolicyRequired, Info: c.info}, nil
	case AwaitChannel:
		if r.Type != ChannelResponse {
			return c.fail(ErrState)
		}
		ch := r.Channel
		if ch.Status != 0 {
			return c.fail(&StatusError{r.Type, ch.Status})
		}
		c.info.ChannelID = ch.ID
		// UDP was not offered. Never use the optional port/cookie to open a
		// sideband or substitute the gateway address for the target address.
		clear(ch.Cookie)
		c.release()
		c.state = Ready
		return Step{Event: Connected, Info: c.info}, nil
	case Ready, Closing:
		switch r.Type {
		case Data:
			if c.state == Closing {
				clear(r.Data)
				return Step{}, nil
			}
			return Step{Event: ReceivedData, Data: r.Data, Info: c.info}, nil
		case CloseChannel:
			// Also acknowledge simultaneous close. No data can follow.
			s := c.emit(NewClose(true, 0), Closed)
			s.Event = Disconnected
			s.Status = r.Status
			return s, nil
		case CloseChannelResponse:
			if c.state != Closing {
				return c.fail(ErrState)
			}
			c.state = Closed
			return Step{Event: Disconnected, Status: r.Status, Info: c.info}, nil
		}
	}
	return c.fail(ErrState)
}

func (c *Client) SendData(data []byte) (Frame, error) {
	if c.state != Ready {
		return Frame{}, ErrState
	}
	return NewData(data)
}
func (c *Client) SendKeepalive() (Frame, error) {
	if c.state != Ready {
		return Frame{}, ErrState
	}
	return Frame{Type: Keepalive}, nil
}
func (c *Client) BeginClose() (Step, error) {
	if c.state != Ready {
		return Step{}, ErrState
	}
	return c.emit(NewClose(false, 0), Closing), nil
}
