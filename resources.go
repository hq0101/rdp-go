package rdp

import (
	"strings"

	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/rdgateway"
)

// SessionResources describes this connection's effective resource offer, not
// negotiated channel formats or permission to access local devices. It contains
// no credentials. All collections returned by Resources are owned snapshots.
// Rebuild consumers from each new connection after ARC or redirection. Device
// backends must separately honor GatewayInfo and application permissions.
type SessionResources struct {
	Channels            []gcc.Channel
	StaticChannelLimits map[string]int
	DynamicChannels     *DynamicChannelOptions
	AudioPlayback       bool
	AudioCapture        bool
}

func cloneResourceOptions(o Options) Options {
	o.DynamicChannels = cloneDynamicOptions(o.DynamicChannels)
	if o.StaticChannelLimits != nil {
		m := make(map[string]int, len(o.StaticChannelLimits))
		for name, limit := range o.StaticChannelLimits {
			m[name] = limit
		}
		o.StaticChannelLimits = m
	}
	return o
}

func resourceSettings(o Options, s gcc.ClientSettings) SessionResources {
	o = cloneResourceOptions(o)
	return SessionResources{
		Channels:            append([]gcc.Channel(nil), s.Channels...),
		StaticChannelLimits: o.StaticChannelLimits, DynamicChannels: o.DynamicChannels,
		AudioPlayback: o.AudioPlayback, AudioCapture: o.AudioCapture,
	}
}

func (r SessionResources) clone() SessionResources {
	return resourceSettings(Options{StaticChannelLimits: r.StaticChannelLimits, DynamicChannels: r.DynamicChannels,
		AudioPlayback: r.AudioPlayback, AudioCapture: r.AudioCapture}, gcc.ClientSettings{Channels: r.Channels})
}

// Resources returns the effective offer used for this connection. DialChannels
// records audio intentions only; Client Info and activation occur in DialSession.
// OpenChannels alone records GCC/DVC settings, with no Client Info audio offer.
func (c *ChannelConnection) Resources() SessionResources { return c.resources.clone() }
func (s *Session) Resources() SessionResources           { return s.connection.Resources() }

// Only owned copies may be changed by policy. Keep the requested configuration
// separately for recovery: a fresh gateway policy may be narrower or broader.
func applyGatewayResources(i rdgateway.Info, o Options, s gcc.ClientSettings, adjust bool) (Options, gcc.ClientSettings, error) {
	if !adjust {
		return o, s, checkGatewaySettings(i, o, s)
	}
	p, err := rdgateway.NewPolicy(i)
	if err != nil {
		return o, s, err
	}
	// Adaptation never silently changes the route or takes ownership of a raw
	// DVC implementation, even when it could remove the entire drdynvc channel.
	if s.MultitransportFlags != 0 || o.DynamicChannels != nil && o.DynamicChannels.ReliableUDP {
		return o, s, ErrGatewayRoute
	}
	o = cloneResourceOptions(o)
	s = cloneRedirectSettings(s)
	kept := s.Channels[:0]
	for _, ch := range s.Channels {
		remove := false
		switch strings.ToLower(ch.Name) {
		case "cliprdr":
			remove = !p.ClipboardAllowed()
		case "rdpsnd":
			remove = p.AllDisabled()
		case "rdpdr", "drdynvc", "rail":
		default:
			remove = p.AllDisabled()
		}
		if remove {
			delete(o.StaticChannelLimits, ch.Name)
		} else {
			kept = append(kept, ch)
		}
	}
	clear(s.Channels[len(kept):])
	s.Channels = kept
	if d := o.DynamicChannels; d != nil {
		for name := range d.Listeners {
			if !gatewayListenerAllowed(p, name) {
				delete(d.Listeners, name)
			}
		}
	}
	if p.AllDisabled() {
		o.AudioPlayback, o.AudioCapture = false, false
	}
	return o, s, checkGatewaySettings(i, o, s)
}

func gatewayListenerAllowed(p rdgateway.Policy, name string) bool {
	if p.AllDisabled() {
		return name == "Microsoft::Windows::RDS::Graphics" || name == "Microsoft::Windows::RDS::DisplayControl"
	}
	return p.PnPAllowed() || (name != "PNPDR" && name != "FileRedirectorChannel" && name != "URBDRC")
}
