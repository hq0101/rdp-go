package main

import (
	"errors"
	"strconv"

	"github.com/hq0101/rdp-go/rail"
)

// A value snapshot, with no borrowed pointers, retained across new connections.
// Each new server independently gates it with its actual HandshakeEx flags.
type appPreference struct {
	value uint32
	set   bool
}
type appPreferences struct{ textScale, caretWidth, caretBlink appPreference }

func parseAppPreferences(enabled bool, textScale, caretWidth, caretBlink string) (appPreferences, error) {
	var p appPreferences
	if !enabled && (textScale != "" || caretWidth != "" || caretBlink != "") {
		return p, errors.New("RemoteApp preferences require remote-app")
	}
	for _, e := range []struct {
		s      string
		target *appPreference
		blink  bool
	}{{textScale, &p.textScale, false}, {caretWidth, &p.caretWidth, false}, {caretBlink, &p.caretBlink, true}} {
		if e.s == "" {
			continue
		}
		if e.blink && e.s == "off" {
			*e.target = appPreference{^uint32(0), true}
			continue
		}
		n, err := strconv.ParseUint(e.s, 10, 32)
		if err != nil {
			return appPreferences{}, errors.New("invalid RemoteApp numeric preference")
		}
		*e.target = appPreference{uint32(n), true}
	}
	return p, p.settings().Validate()
}
func (p appPreferences) settings() rail.Settings {
	var s rail.Settings
	if p.textScale.set {
		s.TextScale = &p.textScale.value
	}
	if p.caretWidth.set {
		s.CaretWidth = &p.caretWidth.value
	}
	if p.caretBlink.set {
		s.CaretBlink = &p.caretBlink.value
	}
	return s
}
func (v *viewer) configureAppPreferences(p appPreferences) error {
	if v.app == nil {
		return errors.New("RemoteApp was not negotiated")
	}
	if v.app.client.Status().Ready {
		return rail.ErrState
	}
	if _, err := v.app.client.UpdateSettings(p.settings()); err != nil {
		return err
	}
	v.app.preferences = p
	return nil
}
