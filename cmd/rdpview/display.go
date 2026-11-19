package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/disp"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/rdpgfx"
)

type displayStatusType struct {
	Enabled        bool `json:"enabled"`
	Ready          bool `json:"ready"`
	TransportReady bool `json:"transport_ready"`
	ChannelOpen    bool `json:"channel_open"`
	disp.Capabilities
}
type resizeStatus struct {
	Serial  uint64 `json:"serial"`
	Pending bool   `json:"pending"`
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	Result  string `json:"result"`
}

type graphicsOutputRemote interface {
	SetGraphicsOutputSize(context.Context, int, int) error
}

func (v *viewer) displayStatus() displayStatusType {
	v.displayMu.Lock()
	defer v.displayMu.Unlock()
	return displayStatusType{v.displayEnabled, v.displayOpen && v.display.Ready(), v.dynamicReadyLocked(), v.displayOpen, v.display.Capabilities()}
}

func (v *viewer) receiveDisplay(ctx context.Context, chunk []byte) error {
	v.displayMu.Lock()
	defer v.displayMu.Unlock()
	b, complete, err := v.dynamicDecoder.Feed(chunk)
	if err != nil || !complete {
		return err
	}
	replies, event, err := v.dynamic.Handle(b)
	if err != nil {
		return err
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	for _, reply := range replies {
		if err := v.remote.(channelRemote).WriteChannel(writeCtx, v.dynamicChannel, reply); err != nil {
			return writeFailure(err)
		}
	}
	return v.handleDynamicEventLocked(writeCtx, event)
}

// displayMu is held; DVC protocol replies have already been sent by its owner.
func (v *viewer) handleDynamicEventLocked(ctx context.Context, event dynvc.Event) error {
	if event.Kind == dynvc.Ready {
		v.dynamicReady = true
		return nil
	}
	if event.Kind == dynvc.None {
		return nil
	}
	if event.Name == rdpgfx.ChannelName {
		if v.gfx == nil {
			return dynvc.ErrChannel
		}
		result, err := v.gfx.Handle(event)
		if err != nil {
			return err
		}
		// Only complete frames are published. A Reset invalidates old geometry,
		// but does not discard the codec, surface or compression histories.
		if result.Resized {
			remote, ok := v.remote.(graphicsOutputRemote)
			if !ok {
				return errors.New("graphics output bounds unavailable")
			}
			if err := remote.SetGraphicsOutputSize(ctx, result.Width, result.Height); err != nil {
				return writeFailure(err)
			}
		}
		v.frameMu.Lock()
		if result.Resized {
			if v.width != result.Width || v.height != result.Height {
				if err := v.frame.Resize(result.Width, result.Height); err != nil {
					v.frameMu.Unlock()
					return err
				}
				v.width, v.height = result.Width, result.Height
				v.generation++
				v.x, v.y = min(v.x, uint16(v.width-1)), min(v.y, uint16(v.height-1))
			}
			v.dirty = false
			v.renderEpoch++
			v.imageMu.Lock()
			v.png = nil
			v.imageMu.Unlock()
			v.finishResizeLocked(v.width, v.height)
		}
		if v.app != nil {
			if result.Resized {
				if err := v.appGraphicsMonitorsLocked(); err != nil {
					v.frameMu.Unlock()
					return err
				}
			}
			if err := v.syncAppSceneLocked(); err != nil {
				v.frameMu.Unlock()
				return err
			}
		}
		if result.FrameReady && v.active && (v.app == nil || !v.app.client.Status().Enhanced) {
			if err := v.frame.PresentGraphicsFrame(v.gfx.Snapshot()); err != nil {
				v.frameMu.Unlock()
				return err
			}
			v.dirty = true
		}
		v.frameMu.Unlock()
		for _, reply := range result.Replies {
			if err := v.sendDynamicLocked(ctx, event.ID, reply); err != nil {
				return err
			}
		}
		return nil
	}
	if event.Name != disp.ChannelName || !v.displayEnabled {
		return dynvc.ErrChannel
	}
	switch event.Kind {
	case dynvc.Opened:
		v.display, v.displayID, v.displayOpen = disp.Client{}, event.ID, true
	case dynvc.Data:
		if !v.displayOpen || event.ID != v.displayID {
			return dynvc.ErrChannel
		}
		return v.display.Handle(event.Data)
	case dynvc.Closed:
		v.display, v.displayOpen = disp.Client{}, false
		v.frameMu.Lock()
		if v.resize.Pending {
			v.resize.Pending, v.resize.Result = false, "closed"
		}
		v.frameMu.Unlock()
	}
	return nil
}

// frameMu must be held. A timeout means unconfirmed, never success. Keep the
// request dimensions for a late activation; do not automatically resend it.
func (v *viewer) expireResizeLocked(now time.Time) {
	if v.resize.Pending && !now.Before(v.resizeDeadline) {
		v.resize.Pending, v.resize.Result = false, "unconfirmed"
	}
}
func (v *viewer) finishResizeLocked(width, height int) {
	if v.resize.Pending || v.resize.Result == "unconfirmed" {
		v.resize.Pending = false
		v.resize.Result = "adjusted"
		if v.resize.Width == width && v.resize.Height == height {
			v.resize.Result = "applied"
		}
	}
}

func (v *viewer) serveResize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}
	var request struct {
		Width  int `json:"width"`
		Height int `json:"height"`
	}
	d := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256))
	d.DisallowUnknownFields()
	if d.Decode(&request) != nil || d.Decode(new(any)) != io.EOF {
		http.Error(w, "invalid display request", 400)
		return
	}
	// Serialize with input and activation. displayMu is always acquired before
	// frameMu when both are needed; the read loop never acquires inputMu here.
	v.inputMu.Lock()
	defer v.inputMu.Unlock()
	v.displayMu.Lock()
	defer v.displayMu.Unlock()
	if !v.displayEnabled || !v.dynamicReadyLocked() || !v.displayOpen || !v.display.Ready() {
		http.Error(w, "display control unavailable", 409)
		return
	}
	layout, err := v.display.Layout(request.Width, request.Height)
	if err != nil {
		http.Error(w, "unsupported display dimensions", 400)
		return
	}
	v.frameMu.Lock()
	v.expireResizeLocked(time.Now())
	if !v.active || v.reconnection.Phase != "connected" || v.resize.Pending || r.Header.Get("X-RdpGo-Generation") != strconv.FormatUint(v.generation, 10) {
		v.frameMu.Unlock()
		http.Error(w, "session changed or display request pending", 409)
		return
	}
	if v.width == request.Width && v.height == request.Height {
		v.frameMu.Unlock()
		w.WriteHeader(204)
		return
	}
	v.frameMu.Unlock()
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if err := v.send(ctx, input{Kind: "release"}); err != nil {
		if errors.Is(err, rdp.ErrDeactivated) {
			http.Error(w, "session reactivating", 409)
			return
		}
		if v.writeInterrupted("display input release failed") {
			http.Error(w, "connection interrupted", 409)
			return
		}
		http.Error(w, "display request failed", 502)
		return
	}
	v.frameMu.Lock()
	v.resize = resizeStatus{Serial: v.resize.Serial + 1, Pending: true, Width: request.Width, Height: request.Height, Result: "pending"}
	v.resizeDeadline = time.Now().Add(15 * time.Second)
	v.frameMu.Unlock()
	if err = v.sendDynamicLocked(ctx, v.displayID, layout); err != nil {
		v.frameMu.Lock()
		v.resize.Pending, v.resize.Result = false, "failed"
		v.frameMu.Unlock()
		var writeErr *protocolWriteError
		if !errors.As(err, &writeErr) {
			http.Error(w, "display channel unavailable", 409)
			return
		}
		if v.writeInterrupted("display transport write failed") {
			http.Error(w, "connection interrupted", 409)
			return
		}
		http.Error(w, "display request failed", 502)
		return
	}
	// Only means the request was sent. /status reports applied after activation.
	w.WriteHeader(http.StatusAccepted)
}

// Counts are evidence of actual GFX use, separate from the GCC offer.
type graphicsStatusType struct {
	Enabled     bool `json:"enabled"`
	ChannelOpen bool `json:"channel_open"`
	rdpgfx.Stats
}

func (v *viewer) graphicsStatus() graphicsStatusType {
	v.displayMu.Lock()
	defer v.displayMu.Unlock()
	if v.gfx == nil {
		return graphicsStatusType{}
	}
	return graphicsStatusType{true, v.gfx.Open(), v.gfx.Stats()}
}
