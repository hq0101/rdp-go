package main

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/hq0101/rdp-go/internal/gatewayconfig"
	"github.com/hq0101/rdp-go/rdgateway"
	"github.com/hq0101/rdp-go/rdpdr"
	"github.com/hq0101/rdp-go/vchan"
)

// The viewer has one serial connection/recovery chain. Prepare a device policy
// before target creation, then require that exact policy when constructing its
// consumers. A direct successor has its own unrestricted policy. Neither path
// enables resources absent from the original local configuration.
type viewerGatewayAccess struct {
	mu       sync.Mutex
	prepared bool
	info     rdgateway.Info
	policy   rdgateway.Policy
}

func (a *viewerGatewayAccess) prepare(ctx context.Context, info rdgateway.Info) error {
	policy, err := rdgateway.NewPolicy(info)
	if err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	a.info, a.policy, a.prepared = info, policy, true
	return nil
}

func (a *viewerGatewayAccess) check(info rdgateway.Info) (rdgateway.Policy, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	// ChannelID is assigned after ApplyPolicy, and tunnel IDs need not be
	// unique across gateway servers. Only the prepared resource policy matters.
	if !a.prepared || a.info.RedirectionFlagsPresent != info.RedirectionFlagsPresent || a.info.RedirectionFlags != info.RedirectionFlags {
		return rdgateway.Policy{}, errors.New("viewer gateway policy was not prepared for this connection")
	}
	return a.policy, nil
}

// Called on a private viewer before any drive worker or clipboard file source.
func (v *viewer) configureGateway(ctx context.Context, access *viewerGatewayAccess, reporter *gatewayconfig.Reporter) error {
	if info := gatewayconfig.Info(v.remote); info != nil {
		if access == nil {
			return errors.New("viewer gateway resource policy is required")
		}
		policy, err := access.check(*info)
		if err != nil {
			return err
		}
		v.gatewayPolicy = policy
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	v.gatewayAccess, v.gatewayReporter = access, reporter
	v.stopServices = gatewayconfig.WatchServices(ctx, v.remote, reporter)
	return nil
}

// Never join while holding connectionMu: a failed reporter closes its Session.
// WatchServices permits repeated/concurrent stop calls and always joins.
func (v *viewer) stopGatewayServices() error {
	v.connectionMu.RLock()
	stop := v.stopServices
	v.connectionMu.RUnlock()
	if stop != nil {
		return stop()
	}
	return nil
}

func (v *viewer) configureSuccessor(ctx context.Context, next *viewer) error {
	if err := next.configureGateway(ctx, v.gatewayAccess, v.gatewayReporter); err != nil {
		return err
	}
	if err := next.configureChannels(v.gfxProfile, v.displayAllowed); err != nil {
		return err
	}
	if err := next.configureFileClipboard(v.fileClipboardRequested); err != nil {
		return err
	}
	if v.app != nil {
		if err := next.configureRemoteApp(v.app.request, false); err != nil {
			return err
		}
		if err := next.configureAppPreferences(v.app.preferences); err != nil {
			return err
		}
	}
	return next.configureDrive(v.driveConfig)
}

// A private candidate has no HTTP file jobs. Its watcher/worker must finish
// before discarding it or returning an error. Transferred owners are set nil.
func (v *viewer) stopCandidate() error {
	return errors.Join(v.stopGatewayServices(), v.stopDrive())
}

// RDPDR may remain after the gateway removes every local device. Keep its
// empty core handshake alive, without a filesystem backend or device worker.
type viewerEmptyDevices struct {
	channel uint16
	decoder vchan.Decoder
	client  rdpdr.CoreClient
}

func (v *viewer) receiveEmptyDevices(ctx context.Context, chunk []byte) error {
	d := v.emptyDevices
	data, complete, err := d.decoder.Feed(chunk)
	if err != nil || !complete {
		return err
	}
	result, err := d.client.Handle(data)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for _, reply := range result.Replies {
		if err := v.remote.(channelRemote).WriteChannel(ctx, d.channel, reply); err != nil {
			return writeFailure(err)
		}
	}
	return nil
}
