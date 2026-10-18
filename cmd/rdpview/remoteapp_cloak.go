package main

import (
	"context"

	"github.com/hq0101/rdp-go/rail"
)

// inputMu and frameMu are held. Local display state is applied on a successful
// single write; there is no server acknowledgement and no automatic replay.
func (v *viewer) setAppCloakLocked(ctx context.Context, w rail.Window, cloaked bool) error {
	a := v.app
	monitored, syncing := a.windows.Monitoring()
	if !monitored || syncing {
		return rail.ErrState
	}
	b, err := a.client.Cloak(w.ID, cloaked)
	if err != nil {
		return err
	}
	if w.Cloaked == cloaked {
		return nil
	}
	if a.selected != nil && a.selected.Identity() == (rail.WindowIdentity{ID: w.ID, Generation: w.Generation}) {
		if err = v.blurAppLocked(ctx); err != nil {
			return err
		}
		a.selected = nil
	}
	if err = v.sendRailLocked(ctx, b); err != nil {
		return err
	}
	if _, err = a.windows.SetCloak(rail.WindowIdentity{ID: w.ID, Generation: w.Generation}, cloaked); err != nil {
		return err
	}
	return v.syncAppSceneLocked()
}
