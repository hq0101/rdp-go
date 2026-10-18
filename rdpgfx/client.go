package rdpgfx

import (
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/zgfx"
	"image"
)

// MaxWireMessage includes ZGFX packaging/expansion. Pass it as this listener's
// limit to dynvc.NewWithLimits, with dynvc.HardLimit as the aggregate budget.
const MaxWireMessage = zgfx.MaxEncoded

// Client handles one graphics listener, including close/reopen. Calls and reply
// sends must be serialized. Handle returns uncompressed GFX replies: wrap them
// with dynvc.Client.Send, then write each PDU to the drdynvc static channel.
// Publish Snapshot only when Result.FrameReady is true; Resized invalidates
// previously published geometry even if no new frame is ready.
// Any Handle or send error is terminal for the containing connection.
// The zero value is ready. ProfileAVC420 / ProfileAVC444 explicitly enable AVC negotiation.
// Persistent cache import is not offered.
type Client struct {
	// WindowMapping enables decoding after an explicit Enhanced RemoteApp request.
	// Keep it fixed for an open graphics channel. If GFX opens before the RAIL
	// handshake, retain frames privately until rail.Status confirms Enhanced;
	// remoteapp.Scene provides this presentation gate and window association.
	WindowMapping bool
	Profile       Profile
	generation    uint64
	id            uint32
	open          bool
	receiver      Receiver
}

func (c *Client) Handle(e dynvc.Event) (Result, error) {
	if e.Name != ChannelName {
		return Result{}, ErrInvalid
	}
	switch e.Kind {
	case dynvc.Opened:
		if c.open || c.generation == ^uint64(0) {
			return Result{}, ErrInvalid
		}
		caps, err := c.Profile.capabilities()
		if err != nil {
			return Result{}, err
		}
		b, err := Advertise(caps)
		if err != nil {
			return Result{}, err
		}
		*c = Client{Profile: c.Profile, WindowMapping: c.WindowMapping, generation: c.generation + 1, id: e.ID, open: true, receiver: Receiver{Profile: c.Profile, WindowMapping: c.WindowMapping}}
		return Result{Replies: [][]byte{b}}, nil
	case dynvc.Data:
		if !c.open || e.ID != c.id || c.Profile != c.receiver.Profile || c.WindowMapping != c.receiver.WindowMapping {
			return Result{}, ErrInvalid
		}
		return c.receiver.Receive(e.Data)
	case dynvc.Closed:
		if !c.open || e.ID != c.id {
			return Result{}, ErrInvalid
		}
		*c = Client{Profile: c.Profile, WindowMapping: c.WindowMapping, generation: c.generation}
		return Result{}, nil
	default:
		return Result{}, ErrInvalid
	}
}
func (c *Client) Open() bool             { return c.open }
func (c *Client) Stats() Stats           { return c.receiver.Stats() }
func (c *Client) Snapshot() *image.NRGBA { return c.receiver.Snapshot() }

// Monitors reports the last successfully processed RESET's topology. As with
// Snapshot, access must be serialized with Handle. Close/reopen clears it.
func (c *Client) Monitors() []Monitor { return c.receiver.Monitors() }

// Generation identifies the current/last channel lifetime, including when the
// server reuses the same DVC ID. Close preserves it; successful Open increments
// it. This is local metadata, not a protocol field. Do not copy/reset a live Client.
func (c *Client) Generation() uint64 { return c.generation }
