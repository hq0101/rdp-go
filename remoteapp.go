package rdp

import (
	"errors"

	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/pdu"
	"github.com/hq0101/rdp-go/rdpgfx"
)

// RemoteAppOptions configures RemoteApp capability negotiation for
// DialSession. Supply an explicit rail static channel and DrawingOrders, then
// consume it with vchan.Decoder and rail.Client. Configure rail.WindowState
// from SessionInfo.RemoteApp and deliver window drawing updates to it. This
// option launches no application, owns no RAIL reader and creates no local UI.
// Enhanced additionally requires GraphicsPipeline and an explicit rdpgfx DVC
// route. It is a request, not proof of server acceptance: use rail.Status.Enhanced
// before publishing window frames. No RAIL/GFX consumers are created implicitly.
type RemoteAppOptions = pdu.RemoteAppOptions

// RemoteAppInfo contains this activation's confirmed capability subset. It
// does not prove a RAIL handshake, Execute success or local window creation.
// Rebuild RAIL consumers after a new connection. On same-connection reactivation,
// apply the new window capability/cache limits with WindowState.Reconfigure
// before consuming queued drawing events; do not repeat the RAIL handshake.
// Also call rail.Client.ReconfigureLanguage with the new confirmed language
// capabilities and send a fresh local profile before further IME compartments.
type RemoteAppInfo = pdu.RemoteAppCapabilities

func cloneRemoteApp(o *RemoteAppOptions) *RemoteAppOptions {
	if o == nil {
		return nil
	}
	c := *o
	return &c
}

func prepareRemoteApp(o Options, s gcc.ClientSettings) (Options, error) {
	if o.RemoteApp == nil {
		return o, nil
	}
	o.RemoteApp = cloneRemoteApp(o.RemoteApp)
	if err := o.RemoteApp.Validate(); err != nil {
		return o, err
	}
	if !o.DrawingOrders {
		return o, errors.New("rdp: RemoteApp requires DrawingOrders and a window consumer")
	}
	graphics := o.GraphicsPipeline || s.GraphicsPipeline
	if o.RemoteApp.Enhanced {
		if !graphics {
			return o, errors.New("rdp: Enhanced RemoteApp requires GraphicsPipeline")
		}
		route := false
		if o.DynamicChannels != nil {
			// Smaller explicit budgets are allowed; the consumer remains responsible
			// for rejecting messages exceeding them. prepareDynamic validates bounds.
			route = o.DynamicChannels.Listeners[rdpgfx.ChannelName] > 0
		} else {
			for _, c := range s.Channels {
				route = route || c.Name == "drdynvc"
			}
		}
		if !route {
			return o, errors.New("rdp: Enhanced RemoteApp requires an explicit GFX dynamic channel consumer")
		}
	} else if graphics {
		return o, errors.New("rdp: RemoteApp GraphicsPipeline requires Enhanced")
	}
	for _, c := range s.Channels {
		if c.Name == "rail" {
			return o, nil
		}
	}
	return o, errors.New("rdp: RemoteApp requires an explicit rail static channel and consumer")
}
