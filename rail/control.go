package rail

// WindowRectangle uses signed screen coordinates. DesktopLayout also uses it
// for virtual-screen system parameters carried as TS_RECTANGLE_16 words.
// Include any hit-testable resize margins in move/snap coordinates.
type WindowRectangle struct{ Left, Top, Right, Bottom int16 }

type SystemCommand uint16

const (
	CommandSize     SystemCommand = 0xf000
	CommandMove     SystemCommand = 0xf010
	CommandMinimize SystemCommand = 0xf020
	CommandMaximize SystemCommand = 0xf030
	CommandClose    SystemCommand = 0xf060
	CommandKeyMenu  SystemCommand = 0xf100
	CommandRestore  SystemCommand = 0xf120
	CommandDefault  SystemCommand = 0xf160
)

// Activate refers to a remote window ID obtained from window drawing orders.
// All control methods require the caller to maintain that mapping and select
// the intended window. IDs are never treated as local operating-system handles.
func (c *Client) Activate(window uint32, active bool) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	return packet(OrderActivate, append(le.AppendUint32(nil, window), boolean(active))), nil
}

// DeactivateLocal reports activation of a non-RAIL local window. If a marker
// has arrived, MS-RDPERP requires its ID with Enabled=0; otherwise deactivate
// the supplied remote window. The caller validates its connection/lifetime,
// releases held input first, and sends this PDU once without retrying a write.
func (c *Client) DeactivateLocal(window uint32) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if c.markerKnown {
		window = c.markerWindowID
	}
	return c.Activate(window, false)
}

func (c *Client) SystemMenu(window uint32, x, y int16) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	b := le.AppendUint32(nil, window)
	b = le.AppendUint16(b, uint16(x))
	b = le.AppendUint16(b, uint16(y))
	return packet(OrderSystemMenu, b), nil
}

func (c *Client) SystemCommand(window uint32, command SystemCommand) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	switch command {
	case CommandSize, CommandMove, CommandMinimize, CommandMaximize, CommandClose, CommandKeyMenu, CommandRestore, CommandDefault:
	default:
		return nil, ErrInvalid
	}
	return packet(OrderSystemCommand, le.AppendUint16(le.AppendUint32(nil, window), uint16(command))), nil
}

// NotifyEvent forwards a supported Windows notification-icon message. Supported
// values are WM_CONTEXTMENU, the six left/right button messages and NIN_* 0x400
// through 0x405. This method does not access a local notification area.
func (c *Client) NotifyEvent(window, icon, message uint32) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if message != 0x7b && !(message >= 0x201 && message <= 0x206) && !(message >= 0x400 && message <= 0x405) {
		return nil, ErrInvalid
	}
	b := le.AppendUint32(nil, window)
	b = le.AppendUint32(b, icon)
	b = le.AppendUint32(b, message)
	return packet(OrderNotifyEvent, b), nil
}

func (c *Client) WindowMove(window uint32, r WindowRectangle) ([]byte, error) {
	return c.windowPosition(OrderWindowMove, window, r)
}

// WindowSnap requires server HandshakeEx support. Unsupported snapping returns
// ErrUnsupported; the caller may explicitly choose WindowMove instead.
func (c *Client) WindowSnap(window uint32, r WindowRectangle) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if c.server.Flags&HandshakeSnap == 0 {
		return nil, ErrUnsupported
	}
	return c.windowPosition(OrderWindowSnap, window, r)
}

func (c *Client) windowPosition(typ Order, window uint32, r WindowRectangle) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if r.Left >= r.Right || r.Top >= r.Bottom {
		return nil, ErrInvalid
	}
	b := le.AppendUint32(nil, window)
	for _, v := range []int16{r.Left, r.Top, r.Right, r.Bottom} {
		b = le.AppendUint16(b, uint16(v))
	}
	return packet(typ, b), nil
}

// GetApplicationID requests a server identifier. The server may ignore it;
// there is no pending queue or automatic retry. Responses expose the window ID
// for the application's mapping, without creating or launching a local process.
func (c *Client) GetApplicationID(window uint32) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	return packet(OrderGetAppID, le.AppendUint32(nil, window)), nil
}
