package rail

// Cloak encodes a client-originated display-state change. It is permitted only
// after both peers negotiated RAIL's window-cloaking capability. It neither
// changes WindowState nor waits for a reply: the protocol has no acknowledgement.
// Check a current WindowIdentity, update the local window and release its input
// under the same caller lock. An uncertain write must close, never replay.
func (c *Client) Cloak(window uint32, cloaked bool) ([]byte, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if !c.options.Cloaking {
		return nil, ErrUnsupported
	}
	b := le.AppendUint32(nil, window)
	value := byte(0)
	if cloaked {
		value = 1
	}
	return packet(OrderCloak, append(b, value)), nil
}

// ReconfigureCloaking updates the negotiated send capability after same-session
// RDP reactivation. It does not change the independently advertised receiver
// flag or replay existing window state. Call before accepting further UI work.
func (c *Client) ReconfigureCloaking(negotiated bool) error {
	if c == nil || c.closed || c.pending == nil {
		return ErrClosed
	}
	c.options.Cloaking = negotiated
	return nil
}

// CloakRevision changes on any observed cloak transition and on Reset. It lets
// an input queue detect hide/show cycles even when geometry is unchanged.
func (s *WindowState) CloakRevision() uint64 { return s.cloakRevision }

// ApplyCloak consumes an already accepted server notification. Unknown windows
// are ignored rather than queued for a later creation/reuse of that ID. No PDU
// is returned: applications must not echo this transition to the server.
func (s *WindowState) ApplyCloak(change CloakState) (bool, error) {
	if s == nil || s.windows == nil || s.options.MaxBytes == 0 {
		return false, ErrInvalid
	}
	w, ok := s.windows[change.WindowID]
	if !ok {
		return false, nil
	}
	return s.SetCloak(WindowIdentity{ID: w.ID, Generation: w.Generation}, change.Cloaked)
}

// SetCloak records a local display transition for an existing window lifetime.
// It preserves geometry, ShowState, icons, mappings and activation metadata.
// No OS operation or network write occurs. The caller reconciles held input,
// invalidates presentation and handles same-session capability changes.
func (s *WindowState) SetCloak(id WindowIdentity, cloaked bool) (bool, error) {
	if s == nil || s.windows == nil || s.options.MaxBytes == 0 {
		return false, ErrInvalid
	}
	w, ok := s.windows[id.ID]
	if !ok || id.Generation == 0 || w.Generation != id.Generation {
		return false, ErrState
	}
	if w.Cloaked == cloaked {
		return false, nil
	}
	w.Cloaked = cloaked
	w.CloakSerial++
	s.windows[id.ID] = w
	s.cloakRevision++
	s.desktop.Revision++
	return true, nil
}
