package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/rdpdr"
	"github.com/hq0101/rdp-go/rdpsnd"
	"github.com/hq0101/rdp-go/vchan"
)

const viewerDriveID = 1
const driveQueueBytes = 2 << 20

type viewerDriveConfig struct {
	anchor                  *rdpdr.DirectoryDrive // owner closes after all connection workers join
	name                    string
	writable, compatibility bool
}

func prepareViewerDrive(path, name string, writable, compatibility bool) (*viewerDriveConfig, error) {
	if path == "" {
		if writable || compatibility || name != "FILES" {
			return nil, errors.New("drive options require -drive-dir")
		}
		return nil, nil
	}
	if len(name) < 1 || len(name) > 7 {
		return nil, errors.New("drive-name must contain 1..7 ASCII letters, digits or underscores")
	}
	for _, r := range name {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
			return nil, errors.New("invalid drive-name")
		}
	}
	anchor, err := rdpdr.OpenDirectoryDrive(viewerDriveID, path, rdpdr.DirectoryOptions{Writable: writable, WindowsLockFlagCompatibility: compatibility})
	if err != nil {
		return nil, fmt.Errorf("open shared directory: %w", err)
	}
	return &viewerDriveConfig{anchor: anchor, name: name, writable: writable, compatibility: compatibility}, nil
}

func viewerDeviceChannels(settings *gcc.ClientSettings, limits map[string]int, audio, drive bool) map[string]int {
	if audio || drive {
		settings.Channels = append(settings.Channels, gcc.Channel{Name: rdpsnd.ChannelName, Options: 0x80000000}, gcc.Channel{Name: rdpdr.ChannelName, Options: 0x80000000})
	}
	if drive {
		if limits == nil {
			limits = make(map[string]int)
		}
		limits[rdpdr.ChannelName] = rdpdr.MaxDeviceMessage
	}
	return limits
}

type driveStatus struct {
	Enabled     bool   `json:"enabled"`
	Name        string `json:"name,omitempty"`
	Writable    bool   `json:"writable"`
	Phase       string `json:"phase"`
	Requests    uint64 `json:"requests"`
	Pending     int    `json:"pending"`
	Handles     int    `json:"handles"`
	Locks       int    `json:"locks"`
	Watches     int    `json:"watches"`
	QueuedBytes int    `json:"queued_bytes"`
}

type viewerDrive struct {
	channel  uint16
	input    chan []byte
	cancel   context.CancelFunc
	done     chan struct{}
	mu       sync.Mutex // snapshots and ingress budget; never held during host I/O
	state    driveStatus
	queued   int
	err      error
	closeErr error
	stopped  bool
}

// Configure before receiving events. Configuration is local-process-only: HTTP
// cannot select a directory or enable writes. The worker belongs to one remote.
func (v *viewer) configureDrive(config *viewerDriveConfig) error {
	v.driveConfig = config
	if config == nil || !v.gatewayPolicy.DeviceAllowed(8) {
		return nil
	}
	if v.drive != nil {
		return errors.New("drive already configured")
	}
	r, ok := v.remote.(channelRemote)
	if !ok {
		return errors.New("drive requires static channels")
	}
	id, ok := r.ChannelID(rdpdr.ChannelName)
	if !ok {
		return errors.New("drive requires rdpdr")
	}
	if _, ok = r.ChannelID(rdpsnd.ChannelName); !ok {
		return errors.New("drive requires rdpsnd declaration")
	}
	c, err := rdpdr.NewDriveClient([]rdpdr.Drive{{ID: viewerDriveID, Name: config.name}}, rdpdr.DriveOptions{ASCIINameCompatibility: config.compatibility})
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	d := &viewerDrive{channel: id, input: make(chan []byte, 64), cancel: cancel, done: make(chan struct{}), state: driveStatus{Enabled: true, Name: config.name, Writable: config.writable, Phase: "negotiating"}}
	v.driveConfig, v.drive = config, d
	v.emptyDevices = nil
	transport := v.remote
	go d.run(ctx, c, r, config, func(err error) {
		var writeErr *protocolWriteError
		if errors.As(err, &writeErr) {
			if redirectionPending(transport) {
				return
			}
			if recovery, ok := transport.(reconnectInfoRemote); ok && recovery.ReconnectInfo().NetworkFailure {
				// Session already closed its failed transport, unblocking ReadEvent.
				// Explicit Session.Close would discard the cookie needed for ARC.
				// A candidate without a fresh cookie must also reach the retry loop.
				return
			}
		}
		// No confirmed recoverable transport loss: stop rather than replaying a
		// host/protocol failure or a locally expired/suspended channel write.
		v.stopWithReason("drive redirection failed: " + err.Error())
		transport.Close()
	})
	return nil
}

func (d *viewerDrive) enqueue(chunk []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stopped {
		if d.err != nil {
			return d.err
		}
		return errors.New("drive worker stopped")
	}
	select {
	case <-d.done:
		return errors.New("drive worker stopped")
	default:
	}
	if len(chunk) > rdpdr.MaxDeviceMessage+8 || len(chunk) > driveQueueBytes-d.queued {
		return rdpdr.ErrLimit
	}
	b := append([]byte(nil), chunk...)
	select {
	case d.input <- b:
		d.queued += len(b)
		return nil
	default:
		return rdpdr.ErrLimit
	}
}

func (d *viewerDrive) snapshot() driveStatus {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.state
	s.QueuedBytes = d.queued
	return s
}

// Caller holds connectionMu, excluding all old-connection event admission.
func (v *viewer) stopDrive() error {
	if v.drive == nil {
		return nil
	}
	d := v.drive
	d.cancel()
	<-d.done
	v.drive = nil
	return d.closeErr // done synchronizes final cleanup/error publication
}
func (v *viewer) driveStatus() driveStatus {
	if v.drive != nil {
		return v.drive.snapshot()
	}
	if c := v.driveConfig; c != nil {
		if !v.gatewayPolicy.DeviceAllowed(8) {
			return driveStatus{Name: c.name, Phase: "gateway-policy"}
		}
		return driveStatus{Enabled: true, Name: c.name, Writable: c.writable, Phase: "disconnected"}
	}
	return driveStatus{Phase: "off"}
}

func (d *viewerDrive) run(ctx context.Context, c *rdpdr.DriveClient, r channelRemote, config *viewerDriveConfig, failed func(error)) {
	var backend *rdpdr.DirectoryDrive
	var failure error
	decoder := vchan.Decoder{Limit: rdpdr.MaxDeviceMessage}
	defer func() {
		d.mu.Lock()
		d.stopped = true
		d.err = failure
		d.mu.Unlock()
		if backend != nil {
			d.closeErr = backend.Close()
			failure = errors.Join(failure, d.closeErr)
		}
		c.Reset()
		decoder.Reset()
		d.mu.Lock()
		d.err = failure
		d.state.Phase = "closed"
		if failure != nil {
			d.state.Phase = "failed"
		}
		d.state.Pending, d.state.Handles, d.state.Locks, d.state.Watches = 0, 0, 0, 0
		if backend != nil {
			d.state.Handles = backend.Status().Total
			d.state.Locks = backend.LockStatus().Regions
			d.state.Watches = backend.NotifyStatus().Watches
		}
		for len(d.input) > 0 {
			<-d.input
		}
		d.queued = 0
		d.mu.Unlock()
		// Cancellation initiated by cleanup must not recursively stop/close a
		// new connection. Callbacks never acquire viewer connection locks.
		if failure != nil && ctx.Err() == nil {
			failed(failure)
		}
		close(d.done)
	}()
	send := func(replies [][]byte) error {
		writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		for _, wire := range replies {
			if err := r.WriteChannel(writeCtx, d.channel, wire); err != nil {
				return writeFailure(err)
			}
		}
		return nil
	}
	update := func() {
		protocol := c.Status()
		d.mu.Lock()
		defer d.mu.Unlock()
		d.state.Pending = protocol.Pending
		if protocol.Rejected > 0 {
			d.state.Phase = "rejected"
		} else if protocol.Accepted > 0 {
			d.state.Phase = "ready"
		} else {
			d.state.Phase = "negotiating"
		}
		if backend != nil {
			d.state.Handles = backend.Status().Total
			d.state.Locks = backend.LockStatus().Regions
			d.state.Watches = backend.NotifyStatus().Watches
		}
	}
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case chunk := <-d.input:
			d.mu.Lock()
			d.queued -= len(chunk)
			d.mu.Unlock()
			if ctx.Err() != nil {
				return
			}
			data, complete, err := decoder.Feed(chunk)
			if err != nil {
				failure = err
				return
			}
			if !complete {
				continue
			}
			result, err := c.Handle(data)
			if err != nil {
				failure = err
				return
			}
			if result.Restarted {
				if backend != nil {
					if err := backend.Close(); err != nil {
						failure = err
						return
					}
				}
				backend, err = config.anchor.NewSession()
				if err != nil {
					failure = err
					return
				}
			}
			if err = send(result.Replies); err != nil {
				failure = err
				return
			}
			if result.Request != nil {
				if backend == nil {
					failure = rdpdr.ErrNotReady
					return
				}
				d.mu.Lock()
				d.state.Requests++
				d.mu.Unlock()
				replies, err := backend.Dispatch(ctx, c, *result.Request)
				if err == nil {
					err = send(replies)
				}
				if err != nil {
					if ctx.Err() == nil {
						failure = err
					}
					return
				}
			}
			update()
		case <-ticker.C:
			if backend == nil {
				continue
			}
			replies, err := backend.Poll(c)
			if err == nil {
				err = send(replies)
			}
			if err != nil {
				if ctx.Err() == nil {
					failure = err
				}
				return
			}
			update()
		}
	}
}
