package main

import (
	"context"
	"errors"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/audin"
	"github.com/hq0101/rdp-go/disp"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/rdpgfx"
)

// The Session owns framing, protocol replies, and carrier selection. The viewer
// only owns the applications carried by those channels (GFX and display).
type managedDynamicRemote interface {
	SendDynamic(context.Context, uint32, []byte) error
	DynamicInfo() rdp.DynamicChannelInfo
}

func viewerDynamicOptions(reliableUDP, graphics, display, microphone bool) (*rdp.DynamicChannelOptions, error) {
	return viewerGatewayDynamicOptions(reliableUDP, graphics, display, microphone, false)
}

func viewerGatewayDynamicOptions(reliableUDP, graphics, display, microphone, gateway bool) (*rdp.DynamicChannelOptions, error) {
	if gateway && reliableUDP {
		return nil, rdp.ErrGatewayRoute
	}
	if !reliableUDP && !microphone && (!gateway || !graphics && !display) {
		return nil, nil
	}
	if reliableUDP && !graphics {
		return nil, errors.New("reliable-udp requires graphics-pipeline")
	}
	listeners := map[string]int{}
	budget := dynvc.MaxBuffered
	if graphics {
		listeners[rdpgfx.ChannelName] = rdpgfx.MaxWireMessage
		budget = dynvc.HardLimit
	}
	if microphone {
		listeners[audin.ChannelName] = audin.MaxMessage
	}
	if display {
		listeners[disp.ChannelName] = dynvc.MaxMessage
	}
	return &rdp.DynamicChannelOptions{Listeners: listeners, MaxBuffered: budget, ReliableUDP: reliableUDP}, nil
}

// connectionMu is held while selecting the current Session.
func (v *viewer) dynamicStatus() *rdp.DynamicChannelInfo {
	if r, ok := v.remote.(managedDynamicRemote); ok {
		info := r.DynamicInfo()
		if info.Managed {
			return &info
		}
	}
	return nil
}

func (v *viewer) dynamicReadyLocked() bool {
	if v.dynamicManaged {
		return v.dynamicReady
	}
	return v.dynamic != nil && v.dynamic.Ready()
}

func (v *viewer) receiveDynamic(ctx context.Context, event dynvc.Event) error {
	if event.Name == audin.ChannelName {
		return v.receiveCapture(ctx, event)
	}
	v.displayMu.Lock()
	defer v.displayMu.Unlock()
	if !v.dynamicManaged {
		return dynvc.ErrProtocol
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return v.handleDynamicEventLocked(writeCtx, event)
}

// displayMu is held across application writes. The managed Session serializes
// fragmentation with Soft-Sync and other DVC traffic. Never send a second copy
// on TCP after a failed UDP write; a partial send has no safe replay boundary.
func (v *viewer) sendDynamicLocked(ctx context.Context, id uint32, data []byte) error {
	if v.dynamicManaged {
		err := v.remote.(managedDynamicRemote).SendDynamic(ctx, id, data)
		if errors.Is(err, dynvc.ErrChannel) || errors.Is(err, dynvc.ErrSize) {
			return err
		}
		return writeFailure(err)
	}
	if v.dynamic == nil {
		return dynvc.ErrChannel
	}
	packets, err := v.dynamic.Send(id, data)
	if err != nil {
		return err
	}
	for _, packet := range packets {
		if err := v.remote.(channelRemote).WriteChannel(ctx, v.dynamicChannel, packet); err != nil {
			return writeFailure(err)
		}
	}
	return nil
}
