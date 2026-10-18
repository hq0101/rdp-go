package main

import (
	"context"
	"github.com/hq0101/rdp-go/rail"
	"github.com/hq0101/rdp-go/remoteapp"
	"strconv"
	"time"
)

// All helpers run under inputMu then frameMu, except the read-only token query
// which requires frameMu. Generation is independently checked on every HTTP call.
func (v *viewer) appFocusTokenLocked() string {
	epoch, serial := v.app.windows.ActivationVersion()
	s := v.app.client.Status()
	return strconv.FormatUint(epoch, 10) + ":" + strconv.FormatUint(serial, 10) + ":" + strconv.FormatBool(s.MarkerKnown) + ":" + strconv.FormatUint(uint64(s.MarkerWindowID), 10) + ":" + strconv.FormatUint(v.app.windows.CloakRevision(), 10)
}

func (v *viewer) syncAppFocusLocked(ctx context.Context) error {
	a := v.app
	d := a.windows.Snapshot()
	if a.focusEpoch != d.Epoch || a.focusSerial != d.ActivationSerial {
		a.focusEpoch, a.focusSerial = d.Epoch, d.ActivationSerial
		a.focusPending = true
	}
	if !v.active || !a.focusPending {
		return nil
	}
	// Browser forms and other local UI keep ownership. Server notifications may
	// choose an in-workspace target only while the user is controlling the canvas.
	if !a.localFocus {
		a.focusPending = false
		return nil
	}
	plan, err := remoteapp.PlanStacking(a.client.Status(), d)
	if err != nil {
		return err
	}
	// A changed server target immediately ends old input ownership, even when
	// its marker/metadata is still in flight. Do not send activation echoes.
	if a.selected != nil && (!d.Monitored || d.Syncing || !d.ActiveKnown || d.ActiveWindowID != a.selected.Identity().ID || plan.ActivationDecided && plan.Activation.Generation == 0) {
		writeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := v.send(writeCtx, input{Kind: "release"}); err != nil {
			return writeFailure(err)
		}
		a.selected = nil
		a.moveTarget = rail.WindowIdentity{}
	}
	if !plan.ActivationDecided {
		return nil
	}
	a.focusPending = false
	if plan.Activation.Generation == 0 {
		return nil
	}
	w, ok := a.windows.Window(plan.Activation.ID)
	if !ok || w.Generation != plan.Activation.Generation {
		return nil
	}
	mode := remoteapp.BasePresentation
	if a.client.Status().Enhanced {
		mode = remoteapp.EnhancedPresentation
	}
	view, err := remoteapp.NewView(w, a.desktop, mode)
	if err != nil {
		a.focusPending = true
		return nil
	}
	if view.Shown() {
		a.selected = view
		a.selectedServerActive = d.ActiveWindowID
	}
	return nil
}

func (v *viewer) blurAppLocked(ctx context.Context) error {
	a := v.app
	window, known := uint32(0), false
	if a.selected != nil && v.appCurrentLocked(a.selected) {
		window, known = a.selected.Identity().ID, true
	}
	if a.moves.SuppressInput() {
		if err := v.finishAppMoveLocked(ctx, true); err != nil {
			return err
		}
	} else if err := v.send(ctx, input{Kind: "release"}); err != nil {
		return writeFailure(err)
	}
	clear(a.moveKeys)
	owned := a.localFocus
	a.localFocus = false
	a.focusPending = false
	a.moveTarget = rail.WindowIdentity{}
	if !owned || !a.client.Status().Ready || !known && !a.client.Status().MarkerKnown {
		return nil
	}
	b, err := a.client.DeactivateLocal(window)
	if err != nil {
		return err
	}
	return v.sendRailLocked(ctx, b)
}

// Explicit text-panel submission targets the retained, still-current selected
// window. Temporarily activate it without stealing DOM focus, then restore the
// marker/local ownership. A failure never repeats text or an uncertain prefix.
func (v *viewer) sendUnfocusedAppTextLocked(ctx context.Context, e input) error {
	a := v.app
	id := a.selected.Identity().ID
	b, err := a.client.Activate(id, true)
	if err != nil {
		return err
	}
	if err = v.sendRailLocked(ctx, b); err != nil {
		return err
	}
	if err = v.send(ctx, e); err != nil {
		return writeFailure(err)
	}
	b, err = a.client.DeactivateLocal(id)
	if err != nil {
		return err
	}
	return v.sendRailLocked(ctx, b)
}
