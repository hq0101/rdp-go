package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/hq0101/rdp-go/rail"
	"github.com/hq0101/rdp-go/remoteapp"
)

const appNotifyPageSize = 32

type appNotification struct {
	Window           uint32       `json:"window"`
	ID               uint32       `json:"id"`
	Lifetime         string       `json:"lifetime"`
	Revision         string       `json:"revision"`
	InfoSerial       string       `json:"info_serial"`
	Version          uint32       `json:"version"`
	ToolTip          string       `json:"tooltip"`
	Icon             []byte       `json:"icon,omitempty"`
	ImageUnavailable bool         `json:"image_unavailable"`
	Balloon          rail.Balloon `json:"balloon"`
}

func appNotifyImage(i *rail.Icon) ([]byte, error) {
	decoded, err := i.Decode()
	if err != nil {
		return nil, err
	}
	if decoded.Bounds().Empty() {
		return nil, rail.ErrUnsupported
	}
	img, err := decoded.Image()
	var out bytes.Buffer
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	if errors.Is(err, rail.ErrIconBackground) {
		bg := image.NewRGBA(decoded.Bounds())
		draw.Draw(bg, bg.Rect, image.NewUniform(color.RGBA{25, 30, 38, 255}), image.Point{}, draw.Src)
		if err = decoded.Composite(bg, image.Point{}); err != nil {
			return nil, err
		}
		err = encoder.Encode(&out, bg)
	} else if err == nil {
		err = encoder.Encode(&out, img)
	}
	if err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func (v *viewer) pruneAppBalloonsLocked() {
	a := v.app
	if a == nil {
		return
	}
	a.balloons.Reconcile(a.windows)
}

func (v *viewer) serveAppNotifications(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/remoteapp/notifications" {
		if r.Method != http.MethodGet {
			w.WriteHeader(405)
			return
		}
		page := 0
		var err error
		if raw := r.URL.Query().Get("page"); raw != "" {
			page, err = strconv.Atoi(raw)
		}
		if err != nil || page < 0 || page > 255 {
			w.WriteHeader(400)
			return
		}
		v.frameMu.Lock()
		defer v.frameMu.Unlock()
		if v.app == nil || !v.active || r.Header.Get("X-OpenRDP-Generation") != strconv.FormatUint(v.generation, 10) || !v.app.client.Status().Ready {
			w.WriteHeader(409)
			return
		}
		d := v.app.windows.Snapshot()
		if !d.Monitored || d.Syncing {
			w.WriteHeader(409)
			return
		}
		var visible []rail.Notification
		for _, n := range d.Notifications {
			if n.State&1 == 0 {
				visible = append(visible, n)
			}
		}
		page = min(page, max(0, (len(visible)-1)/appNotifyPageSize))
		start := min(page*appNotifyPageSize, len(visible))
		entries := make([]appNotification, 0, min(appNotifyPageSize, len(visible)-start))
		for _, n := range visible[start:min(start+appNotifyPageSize, len(visible))] {
			tooltip := []rune(n.ToolTip)
			if len(tooltip) > 256 {
				tooltip = append(tooltip[:256], '…')
			}
			entry := appNotification{Window: n.WindowID, ID: n.ID, Lifetime: strconv.FormatUint(n.Generation, 10), Revision: strconv.FormatUint(n.Revision, 10), InfoSerial: strconv.FormatUint(n.InfoSerial, 10), Version: n.Version, ToolTip: string(tooltip), Balloon: n.InfoTip}
			entry.Icon, err = appNotifyImage(n.Icon)
			entry.ImageUnavailable = err != nil
			entries = append(entries, entry)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(struct {
			Generation  uint64 `json:"generation"`
			Revision    string `json:"revision"`
			Page, Total int
			Entries     []appNotification `json:"entries"`
		}{v.generation, strconv.FormatUint(v.app.windows.NotificationRevision(), 10), page, len(visible), entries})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(405)
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		w.WriteHeader(415)
		return
	}
	var request struct {
		Window     uint32                       `json:"window"`
		ID         uint32                       `json:"id"`
		Lifetime   string                       `json:"lifetime"`
		Revision   string                       `json:"revision"`
		InfoSerial string                       `json:"info_serial"`
		Action     remoteapp.NotificationAction `json:"action"`
		Balloon    string                       `json:"balloon"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 512))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF {
		w.WriteHeader(400)
		return
	}
	v.inputMu.Lock()
	defer v.inputMu.Unlock()
	v.frameMu.Lock()
	defer v.frameMu.Unlock()
	a := v.app
	if a == nil || !v.active || v.stopping.Load() || r.Header.Get("X-OpenRDP-Generation") != strconv.FormatUint(v.generation, 10) || !a.client.Status().Ready {
		w.WriteHeader(409)
		return
	}
	monitored, syncing := a.windows.Monitoring()
	balloon := strings.HasPrefix(string(request.Action), "balloon_")
	dismiss := balloon && request.Action != remoteapp.NotifyBalloonShow
	if !monitored || syncing || (!dismiss && a.moves.Status().Phase != remoteapp.MoveIdle) {
		w.WriteHeader(409)
		return
	}
	a.balloons.Reconcile(a.windows)
	n, exists := a.windows.Notification(request.Window, request.ID)
	var messages []uint32
	var err error
	interactive := !balloon
	if dismiss {
		generation, e1 := strconv.ParseUint(request.Lifetime, 10, 64)
		serial, e2 := strconv.ParseUint(request.InfoSerial, 10, 64)
		display, e3 := strconv.ParseUint(request.Balloon, 10, 64)
		if e1 != nil || e2 != nil || e3 != nil || generation == 0 || serial == 0 || display == 0 {
			w.WriteHeader(409)
			return
		}
		handle := remoteapp.BalloonHandle{Identity: rail.NotificationIdentity{WindowID: request.Window, ID: request.ID, Generation: generation}, InfoSerial: serial, Display: display}
		var current *rail.Notification
		if exists {
			current = &n
		}
		// The actual local tip disappeared. Keep the old identity only for
		// cleanup; a known ID replacement is never given its predecessor's event.
		reason := request.Action
		if a.moves.Status().Phase != remoteapp.MoveIdle && (reason == remoteapp.NotifyBalloonClick || reason == remoteapp.NotifyBalloonTimeout) {
			reason = remoteapp.NotifyBalloonHide
		}
		event, e := a.balloons.End(handle, reason, current)
		if e != nil {
			w.WriteHeader(409)
			return
		}
		messages = []uint32{event.Message}
		interactive = event.Message == 0x405
	} else {
		if !exists || strconv.FormatUint(n.Generation, 10) != request.Lifetime || request.Revision != strconv.FormatUint(n.Revision, 10) || request.Balloon != "" {
			w.WriteHeader(409)
			return
		}
		if balloon {
			if request.InfoSerial != strconv.FormatUint(n.InfoSerial, 10) {
				w.WriteHeader(409)
				return
			}
			handle, fresh, e := a.balloons.Begin(n)
			if e != nil {
				w.WriteHeader(409)
				return
			}
			w.Header().Set("X-OpenRDP-Balloon", strconv.FormatUint(handle.Display, 10))
			if !fresh {
				w.WriteHeader(204)
				return
			}
			messages = []uint32{0x402}
		} else {
			messages, err = remoteapp.NotificationMessages(n, request.Action)
			if err != nil {
				w.WriteHeader(409)
				return
			}
		}
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()
	if interactive {
		err = v.blurAppLocked(ctx)
	}
	for _, message := range messages {
		if err != nil {
			break
		}
		var packet []byte
		packet, err = a.client.NotifyEvent(request.Window, request.ID, message)
		if err == nil {
			err = v.sendRailLocked(ctx, packet)
		}
	}
	if err != nil {
		var failure *protocolWriteError
		if errors.As(err, &failure) {
			v.stopWithReason("RemoteApp notification write failed")
			w.WriteHeader(502)
		} else {
			w.WriteHeader(409)
		}
		return
	}
	w.WriteHeader(204)
}
