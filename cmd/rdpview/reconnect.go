package main

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/disp"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/graphics"
	"github.com/hq0101/rdp-go/rdpgfx"
	"github.com/hq0101/rdp-go/vchan"
)

var errConnectionChanged = errors.New("connection changed; repeat the action only after recovery")

// Application opt-in only: the protocol Session never stores a password.
// Clearing references is best-effort; Go/runtime copies cannot be erased here.
type credentialsStore struct {
	mu    sync.Mutex
	value rdp.Credentials
}

func (s *credentialsStore) get() rdp.Credentials {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.value
}
func (s *credentialsStore) clear() { s.mu.Lock(); s.value = rdp.Credentials{}; s.mu.Unlock() }

type recoveryEventHandler func(context.Context, remote, rdp.SessionInfo, rdp.Event) error

type recoveryFunc func(context.Context, remote, recoveryEventHandler) (remote, rdp.SessionInfo, error)
type reconnectStatus struct {
	TCPFallback bool   `json:"tcp_fallback"`
	Enabled     bool   `json:"enabled"`
	Phase       string `json:"phase"`
	Recoveries  uint64 `json:"recoveries"`
	Attempts    int    `json:"attempts"`
	Redirection bool   `json:"redirection_enabled"`
	Handoffs    uint64 `json:"handoffs"`
	Hops        int    `json:"hops"`
}
type reconnectInfoRemote interface{ ReconnectInfo() rdp.ReconnectInfo }
type protocolWriteError struct{ error }

func (e *protocolWriteError) Unwrap() error { return e.error }
func writeFailure(err error) error {
	if err == nil {
		return nil
	}
	return &protocolWriteError{err}
}

// connectionMu prevents an HTTP/protocol operation from crossing session
// boundaries. Never hold it across ReadEvent, retries, or a clipboard reply wait.
func (v *viewer) currentRemote() remote {
	v.connectionMu.RLock()
	defer v.connectionMu.RUnlock()
	return v.remote
}
func (v *viewer) closeRemote() {
	v.stopping.Store(true)
	v.currentRemote().Close()
	v.stopGatewayServices() // run returns any reporting error after cleanup
	v.connectionMu.Lock()
	if err := v.stopDrive(); err != nil {
		log.Printf("drive cleanup: %v", err)
	}
	v.resetAudio()
	v.resetCapture()
	v.emptyDevices = nil
	v.clipMu.Lock()
	fileJob := v.fileJob
	v.stopSources()
	if fileJob != nil {
		fileJob.cancel()
	}
	if v.clip != nil {
		v.clip.Reset()
		v.clip = nil
	}
	v.clipDecoder.Reset()
	if v.clipWait != nil {
		v.clipWait <- clipResult{err: errConnectionChanged}
		v.clipWait = nil
	}
	v.clipMu.Unlock()
	v.connectionMu.Unlock()
	if fileJob != nil {
		<-fileJob.done
	}
	if err := v.finishSources(); err != nil {
		log.Printf("viewer cleanup: %v", err)
	}
}

// Caller holds connectionMu (read or write).
func (v *viewer) canRecover() bool {
	if v.recover == nil || v.stopping.Load() {
		return false
	}
	r, ok := v.remote.(reconnectInfoRemote)
	return ok && r.ReconnectInfo().Ready
}

// HTTP writes are never replayed. A recoverable loss is handled by the sole read
// loop; returning true lets the UI remain alive and discard this request.
func (v *viewer) writeInterrupted(reason string) bool {
	if v.canRecover() || v.follow != nil && !v.stopping.Load() && redirectionPending(v.remote) {
		return true
	}
	v.stopWithReason(reason)
	return false
}

// Caller holds connectionMu. A failed clipboard message must never be replayed.
// If the protocol already closed its transport for redirection or network loss,
// leave final shutdown to ReadEvent: public Close would cancel Follow or discard
// ARC credentials. Other errors still close an uncertain channel stream.
func (v *viewer) closeFailedClipboardTransport() {
	if redirectionPending(v.remote) {
		return
	}
	if r, ok := v.remote.(reconnectInfoRemote); ok && r.ReconnectInfo().NetworkFailure {
		return
	}
	v.remote.Close()
}

func (v *viewer) configureChannels(profile rdpgfx.Profile, displayAllowed bool) error {
	v.gfxProfile, v.displayAllowed = profile, displayAllowed
	if v.gfx != nil {
		v.gfx.Profile = profile
	}
	if !displayAllowed {
		v.displayEnabled = false
	}
	if !displayAllowed && v.dynamic != nil {
		limits := map[string]int{}
		if v.gfx != nil {
			limits[rdpgfx.ChannelName] = rdpgfx.MaxWireMessage
		}
		var err error
		v.dynamic, err = dynvc.NewWithLimits(limits, dynvc.HardLimit)
		if err != nil {
			return err
		}
		v.displayEnabled = false
	}
	return nil
}

func (v *viewer) beginRecovery(ctx context.Context) error {
	return v.beginTransition(ctx, false)
}

func (v *viewer) beginTransition(ctx context.Context, redirect bool) error {
	if err := v.stopGatewayServices(); err != nil {
		return err
	}
	v.connectionMu.Lock()
	defer v.connectionMu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if v.stopping.Load() || redirect && v.follow == nil || !redirect && !v.canRecover() {
		return rdp.ErrReconnectUnavailable
	}
	if err := v.stopDrive(); err != nil {
		return err
	}
	v.resetAudio()
	v.resetCapture()
	v.emptyDevices = nil
	v.inputMu.Lock()
	defer v.inputMu.Unlock()
	v.clipMu.Lock()
	defer v.clipMu.Unlock()
	v.displayMu.Lock()
	defer v.displayMu.Unlock()
	v.frameMu.Lock()
	defer v.frameMu.Unlock()
	v.active, v.dirty = false, false
	v.generation++
	v.renderEpoch++
	v.reconnection.Phase = "reconnecting"
	if redirect {
		v.reconnection.Phase = "redirecting"
	}
	v.imageMu.Lock()
	v.png = nil
	v.imageMu.Unlock()
	v.pointer = graphics.PointerDecoder{}
	v.pointerVersion++
	v.positionVersion++
	clear(v.keys)
	clear(v.buttons)
	v.x, v.y = 0, 0
	if v.clipWait != nil {
		v.clipWait <- clipResult{err: errConnectionChanged}
		v.clipWait = nil
	}
	if v.fileJob != nil {
		v.fileJob.cancel()
	}
	v.stopSources()
	if v.clip != nil {
		v.clip.Reset()
	}
	v.clip = nil
	v.clipDecoder = vchan.Decoder{}
	v.clipServed = 0
	v.dynamic = nil
	v.dynamicManaged, v.dynamicReady = false, false
	v.dynamicDecoder = vchan.Decoder{}
	v.gfx = nil
	if v.app != nil {
		v.app.client.Close()
		v.app.scene.Reset()
		v.app.presented = nil
		v.app.presentedToken = ""
		v.app.selected = nil
	}
	v.display = disp.Client{}
	v.displayID = 0
	v.displayOpen = false
	if v.resize.Pending || v.resize.Result == "unconfirmed" {
		v.resize.Pending = false
		v.resize.Result = "interrupted"
	}
	v.resizeDeadline = time.Time{}
	return nil
}

func (v *viewer) installRecovery(ctx context.Context, next remote, info rdp.SessionInfo) error {
	return v.installCandidate(ctx, next, info, nil)
}

func (v *viewer) installCandidate(ctx context.Context, next remote, info rdp.SessionInfo, replacement *viewer) error {
	if err := v.stopGatewayServices(); err != nil {
		return err
	}
	if err := v.finishSources(); err != nil {
		return err
	}
	if replacement == nil {
		var err error
		replacement, err = newViewer(next, info, v.host, v.token, v.stop)
		if err != nil {
			return err
		}
		if err := v.configureSuccessor(ctx, replacement); err != nil {
			return errors.Join(err, replacement.stopCandidate())
		}
	} else if replacement.remote != next {
		return errors.New("reconnect candidate changed without rebuilding state")
	}
	defer replacement.stopCandidate() // no-op after ownership transfers below
	v.connectionMu.Lock()
	defer v.connectionMu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if v.stopping.Load() {
		return context.Canceled
	}
	v.inputMu.Lock()
	defer v.inputMu.Unlock()
	v.clipMu.Lock()
	defer v.clipMu.Unlock()
	v.displayMu.Lock()
	defer v.displayMu.Unlock()
	v.frameMu.Lock()
	defer v.frameMu.Unlock()
	if r, ok := v.remote.(reconnectInfoRemote); ok {
		v.reconnection.Attempts = r.ReconnectInfo().Attempts
	}
	if err := v.stopDrive(); err != nil {
		return err
	}
	v.drive, replacement.drive = replacement.drive, nil
	v.stopServices, replacement.stopServices = replacement.stopServices, nil
	v.gatewayPolicy = replacement.gatewayPolicy
	v.emptyDevices = replacement.emptyDevices
	v.fileClipboardEnabled = replacement.fileClipboardEnabled
	v.remote = next
	if v.audio != nil {
		v.resetAudio()
	}
	v.resetCapture()
	// Candidate audio was consumed privately until the original session was
	// confirmed. It never inherits an old browser lease or pending playback.
	v.audioMu.Lock()
	v.audio = replacement.audio
	v.audioMu.Unlock()
	v.captureMu.Lock()
	v.captureEpoch++
	v.capture = replacement.capture
	v.captureMu.Unlock()
	v.width, v.height = replacement.width, replacement.height
	v.frame = replacement.frame
	v.pointer = replacement.pointer
	v.pointerVersion++
	v.positionVersion++
	v.renderEpoch++
	v.dirty = replacement.dirty
	v.unicodeInput, v.frameAcknowledge = replacement.unicodeInput, replacement.frameAcknowledge
	v.sources, v.uploadJob = nil, nil
	v.clip, v.clipChannel = replacement.clip, replacement.clipChannel
	v.clipDecoder = replacement.clipDecoder
	v.clipServed = replacement.clipServed
	v.dynamic, v.dynamicChannel = replacement.dynamic, replacement.dynamicChannel
	v.dynamicDecoder = replacement.dynamicDecoder
	v.dynamicManaged, v.dynamicReady = replacement.dynamicManaged, replacement.dynamicReady
	v.display, v.displayID, v.displayOpen = replacement.display, replacement.displayID, replacement.displayOpen
	v.gfx = replacement.gfx
	v.app = replacement.app
	v.displayEnabled = replacement.displayEnabled
	v.active = replacement.active
	if v.reconnection.Phase == "redirecting" {
		v.reconnection.Handoffs++
		v.reconnection.Attempts = 0
	} else {
		v.reconnection.Recoveries++
	}
	v.reconnection.Phase = "restoring"
	return nil
}

func (v *viewer) recoverConnection(ctx context.Context, old remote) error {
	if err := v.beginRecovery(ctx); err != nil {
		return err
	}
	if err := v.finishSources(); err != nil {
		return err
	}
	if v.recoveryDelay > 0 {
		timer := time.NewTimer(v.recoveryDelay)
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
	var candidate *viewer
	defer func() {
		if candidate != nil {
			if err := candidate.stopCandidate(); err != nil {
				log.Printf("candidate cleanup: %v", err)
			}
		}
	}()
	// A successful reconnect cancels the handler context. The service reader
	// transfers to the active viewer and must retain the outer receive context.
	lifetimeCtx := ctx
	handle := func(ctx context.Context, session remote, info rdp.SessionInfo, e rdp.Event) error {
		if candidate == nil || candidate.remote != session {
			if candidate != nil {
				if err := candidate.stopCandidate(); err != nil {
					return err
				}
			}
			var err error
			candidate, err = newViewer(session, info, v.host, v.token, v.stop)
			if err != nil {
				return err
			}
			if err := v.configureSuccessor(lifetimeCtx, candidate); err != nil {
				return err
			}
		}
		// Only protocol responses and private state updates here. No publisher,
		// HTTP handlers, keyboard, or external clipboard actions see this candidate.
		return candidate.applyEvent(ctx, e)
	}
	next, info, err := v.recover(ctx, old, handle)
	if err != nil {
		return err
	}
	if err := v.installCandidate(ctx, next, info, candidate); err != nil {
		next.Close()
		return err
	}
	old.Close()
	return refreshReplacement(ctx, next, info)
}

func refreshReplacement(ctx context.Context, next remote, info rdp.SessionInfo) error {
	// Reopen rendering with new codec/cache/channel state. Refresh is a fresh
	// display request; no prior keyboard, clipboard or resize action is replayed.
	if r, ok := next.(interface {
		SetDisplayUpdates(context.Context, bool) error
		Refresh(context.Context) error
	}); ok {
		setupCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if info.SuppressOutput {
			if err := r.SetDisplayUpdates(setupCtx, true); err != nil {
				return writeFailure(err)
			}
		}
		if info.RefreshRect {
			if err := r.Refresh(setupCtx); err != nil {
				return writeFailure(err)
			}
		}
	}
	return nil
}

// frameMu and connectionMu are held by the caller.
func (v *viewer) reconnectStatus() reconnectStatus {
	s := v.reconnection
	s.Enabled = v.recover != nil
	s.Redirection = v.follow != nil
	if r, ok := v.remote.(redirectionInfoRemote); ok {
		s.Hops = r.RedirectionInfo().Hops
	}
	if r, ok := v.remote.(reconnectInfoRemote); ok {
		info := r.ReconnectInfo()
		s.TCPFallback = info.TCPFallback
		if s.Phase == "reconnecting" {
			s.Attempts = info.Attempts
		}
	}
	return s
}
