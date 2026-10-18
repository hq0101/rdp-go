package main

import (
	"context"
	"image"
	"slices"
	"time"

	"github.com/hq0101/rdp-go/rail"
	"github.com/hq0101/rdp-go/remoteapp"
)

func appScreenRect(r image.Rectangle) (rail.WindowRectangle, error) {
	if r.Empty() || r.Min.X < -32768 || r.Min.Y < -32768 || r.Max.X > 32767 || r.Max.Y > 32767 {
		return rail.WindowRectangle{}, remoteapp.ErrGeometry
	}
	return rail.WindowRectangle{Left: int16(r.Min.X), Top: int16(r.Min.Y), Right: int16(r.Max.X), Bottom: int16(r.Max.Y)}, nil
}

// This browser presents a remote canvas, with no local OS taskbar inside it.
// Every confirmed remote monitor is fully usable. Browser CSS size, toolbar,
// zoom and devicePixelRatio do not define the remote work area or DPI.
func appDesktopParameters(bounds image.Rectangle, monitors []image.Rectangle) (rail.DesktopLayout, error) {
	display, err := appScreenRect(bounds)
	if err != nil {
		return rail.DesktopLayout{}, err
	}
	d := rail.DesktopLayout{Display: display}
	if len(monitors) < 1 || len(monitors) > 16 {
		return d, remoteapp.ErrGeometry
	}
	for _, m := range monitors {
		r, err := appScreenRect(m)
		if err != nil {
			return d, err
		}
		d.Monitors = append(d.Monitors, rail.MonitorWorkArea{Monitor: r, WorkArea: r})
	}
	return d, d.Validate()
}

// frameMu is held. Validate the entire topology before changing presentation or
// queuing parameters. Bounding size alone cannot identify per-monitor work areas.
func (v *viewer) setAppMonitorsLocked(monitors []image.Rectangle) error {
	var bounds image.Rectangle
	for _, m := range monitors {
		bounds = bounds.Union(m)
	}
	if bounds.Size() != image.Pt(v.width, v.height) {
		return remoteapp.ErrGeometry
	}
	if _, err := appDesktopParameters(bounds, monitors); err != nil {
		return err
	}
	a := v.app
	if bounds != a.desktop || !slices.Equal(monitors, a.monitors) {
		v.renderEpoch++
		a.desktop, a.monitors = bounds, slices.Clone(monitors)
		a.presented, a.presentedToken = nil, ""
		a.parametersDirty = true
		a.parametersState = "pending"
	}
	v.dirty = true
	return nil
}

// Called after event locks and input reconciliation, under connectionMu.
// The frame lock serializes this batch with RAIL activation and HTTP input.
func (v *viewer) syncAppParameters(ctx context.Context) error {
	if v.app == nil {
		return nil
	}
	v.frameMu.Lock()
	defer v.frameMu.Unlock()
	a := v.app
	if !v.active || !a.parametersDirty {
		return nil
	}
	d, err := appDesktopParameters(a.desktop, a.monitors)
	if err != nil {
		return err
	}
	p, err := a.client.UpdateDesktop(d)
	if err != nil {
		return err
	}
	a.parametersDirty = false
	if !a.client.Status().Ready {
		a.parametersState = "waiting"
		return nil
	}
	writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	for _, packet := range p {
		if err := v.sendRailLocked(writeCtx, packet); err != nil {
			a.parametersState = "failed"
			return err
		}
	}
	a.parametersState = "sent"
	return nil
}
