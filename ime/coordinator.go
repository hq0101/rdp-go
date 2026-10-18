// Package ime connects RAIL language state to application-owned input-method
// adapters. Windows document/input adapters also provide TSF text storage and
// transient text delivery. Candidate/preedit rendering and the GUI event loop
// belong to the application. Calls are serialized on the host's UI thread.
package ime

import (
	"errors"
	"github.com/hq0101/rdp-go/rail"
)

var (
	ErrStale       = errors.New("ime: stale connection or focus token")
	ErrChanged     = errors.New("ime: local input state changed before server update")
	ErrNotApplied  = errors.New("ime: host did not apply requested state")
	ErrNotFocused  = errors.New("ime: bound window does not own keyboard focus")
	ErrThread      = errors.New("ime: wrong UI thread")
	ErrUnavailable = errors.New("ime: native input state is unavailable")
)

// Snapshot is captured from one focused input context. Unknown optional fields
// are not sent. An ordinary keyboard profile must not have a compartment.
type Snapshot struct {
	Profile          rail.LanguageProfile
	CompartmentKnown bool
	Compartment      rail.IMECompartment
	LanguageBarKnown bool
	LanguageBar      rail.LanguageBarStatus
}

// Host is supplied by the GUI/platform integration. ApplyIME must recheck the
// expected profile and focus immediately before changing native state. A setter
// may fail after partial native changes; callers must not blindly retry it.
// Snapshot must report actual values, not cached copies of setter arguments.
type Host interface {
	Snapshot() (Snapshot, error)
	ApplyIME(expected rail.LanguageProfile, value rail.IMECompartment) error
	ApplyLanguageBar(rail.LanguageBarStatus) error
}

// Token is an opaque lease for one local focus ownership interval. Its identity
// includes the Coordinator instance, so equal counters on new connections do
// not validate old callbacks. It must accompany asynchronous native callbacks.
type Token struct {
	owner  *Coordinator
	serial uint64
}

// Coordinator is bound to exactly one rail.Client and Host. It owns neither.
// Send every returned PDU in order before calling it again. On uncertain writes
// close the transport, rail.Client and Coordinator; do not replay the batch.
// Server notices have no profile ID, so cross-direction wire races remain the
// application's responsibility even when the local token is valid.
type Coordinator struct {
	client                       *rail.Client
	host                         Host
	closed, busy, focused, known bool
	next                         uint64
	caps                         rail.LanguageCapabilities
	profileSerial                uint64
	last                         Snapshot
}

func New(client *rail.Client, host Host) (*Coordinator, error) {
	if client == nil || host == nil {
		return nil, rail.ErrInvalid
	}
	if client.Status().Closed {
		return nil, rail.ErrClosed
	}
	return &Coordinator{client: client, host: host}, nil
}

func (c *Coordinator) enter() error {
	if c.closed || c.client == nil {
		return rail.ErrClosed
	}
	if c.busy {
		return rail.ErrBusy
	}
	if c.client.Status().Closed {
		return rail.ErrClosed
	}
	if !c.client.Status().Ready {
		return rail.ErrNotReady
	}
	c.busy = true
	return nil
}
func (c *Coordinator) invalidate() {
	c.focused = false
	c.known = false
	c.last = Snapshot{}
	c.profileSerial = 0
}
func (c *Coordinator) valid(t Token) bool {
	if t.owner != c || t.serial == 0 || t.serial != c.next || !c.focused {
		return false
	}
	s := c.client.LanguageStatus()
	return s.Capabilities == c.caps && (!c.caps.LanguageIME || s.ProfileKnown && s.ProfileSerial == c.profileSerial && s.Profile == c.last.Profile)
}

// Focus starts a fresh ownership interval and produces an initial state batch.
// Call only when a remote surface owns local input, not when local forms do.
// No token is returned if reading, validation or PDU construction fails.
func (c *Coordinator) Focus() (Token, [][]byte, error) {
	if err := c.enter(); err != nil {
		return Token{}, nil, err
	}
	defer func() { c.busy = false }()
	c.invalidate()
	if c.next == ^uint64(0) {
		return Token{}, nil, rail.ErrBusy
	}
	c.next++
	c.caps = c.client.LanguageStatus().Capabilities
	p, err := c.observe()
	if err != nil {
		c.invalidate()
		return Token{}, nil, err
	}
	c.focused = true
	return Token{c, c.next}, p, nil
}

func (c *Coordinator) Blur(t Token) error {
	if err := c.enter(); err != nil {
		return err
	}
	defer func() { c.busy = false }()
	if !c.valid(t) {
		return ErrStale
	}
	c.invalidate()
	return nil
}

// Reconfigure is used after same-connection activation. It invalidates all old
// focus leases and clears the RAIL profile even when the capability bits match.
func (c *Coordinator) Reconfigure(caps rail.LanguageCapabilities) error {
	if c.closed || c.client == nil {
		return rail.ErrClosed
	}
	if c.busy {
		return rail.ErrBusy
	}
	if err := c.client.ReconfigureLanguage(caps); err != nil {
		return err
	}
	c.invalidate()
	return nil
}

// Close retires this bridge without releasing caller-owned Host/Client/transport.
// Call it after returning from Host callbacks; reentrant close is rejected.
func (c *Coordinator) Close() error {
	if c.busy {
		return rail.ErrBusy
	}
	c.invalidate()
	c.closed = true
	c.client = nil
	c.host = nil
	return nil
}

// Observe samples the current host state on a native notification or UI timer.
// Repeated snapshots emit nothing. Reentrant notifications during native setters
// return ErrBusy; schedule a fresh observation after the setter returns.
func (c *Coordinator) Observe(t Token) ([][]byte, error) {
	if err := c.enter(); err != nil {
		return nil, err
	}
	defer func() { c.busy = false }()
	if !c.valid(t) {
		return nil, ErrStale
	}
	p, err := c.observe()
	if err != nil {
		c.invalidate()
		return nil, err
	}
	return p, nil
}

func validate(s Snapshot, caps rail.LanguageCapabilities) error {
	if caps.LanguageIME {
		if _, err := rail.EncodeLanguageProfile(s.Profile); err != nil {
			return err
		}
		if s.CompartmentKnown {
			if s.Profile.Type != rail.ProfileInputProcessor {
				return rail.ErrInvalid
			}
			if s.Compartment.Kana && s.Profile.LanguageID&0x3ff != 0x11 {
				return rail.ErrInvalid
			}
			if _, err := rail.EncodeIMECompartment(s.Compartment); err != nil {
				return err
			}
		}
	}
	if caps.LanguageBar && s.LanguageBarKnown {
		_, err := rail.EncodeLanguageBar(s.LanguageBar)
		return err
	}
	return nil
}

func (c *Coordinator) observe() ([][]byte, error) {
	s, err := c.host.Snapshot()
	if err != nil {
		return nil, err
	}
	if err = validate(s, c.caps); err != nil {
		return nil, err
	}
	var out [][]byte
	profileChanged := !c.known || s.Profile != c.last.Profile
	if c.caps.LanguageIME && profileChanged {
		p, err := c.client.UpdateLanguageProfile(s.Profile)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
		c.profileSerial = c.client.LanguageStatus().ProfileSerial
	}
	if c.caps.LanguageIME && s.CompartmentKnown && (profileChanged || !c.last.CompartmentKnown || s.Compartment != c.last.Compartment) {
		p, err := c.client.UpdateIMECompartment(c.profileSerial, s.Compartment)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	if c.caps.LanguageBar && s.LanguageBarKnown && (!c.known || !c.last.LanguageBarKnown || s.LanguageBar != c.last.LanguageBar) {
		p, err := c.client.UpdateLanguageBar(s.LanguageBar)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	c.last = s
	c.known = true
	return out, nil
}

// Receive applies one already-validated RAIL event only while the same local
// focus and last-observed state still hold. ErrChanged means an unsent local
// change won; discard this notice and Observe the fresh local state. There is
// no automatic queue or retry. A setter/readback failure invalidates the lease.
// Successful readback suppresses feedback for that field only; unrelated local
// changes observed during the setter remain visible to the next Observe.
func (c *Coordinator) Receive(t Token, e rail.Event) error {
	if err := c.enter(); err != nil {
		return err
	}
	defer func() { c.busy = false }()
	if !c.valid(t) {
		return ErrStale
	}
	s, err := c.host.Snapshot()
	if err != nil {
		c.invalidate()
		return err
	}
	if s != c.last {
		return ErrChanged
	}
	switch e.Order {
	case rail.OrderIMECompartment:
		if !c.caps.ServerIME {
			return rail.ErrUnsupported
		}
		if s.Profile.Type != rail.ProfileInputProcessor || !s.CompartmentKnown {
			return rail.ErrState
		}
		candidate := s
		candidate.Compartment = e.IMECompartment
		if err = validate(candidate, c.caps); err != nil {
			return err
		}
		if e.IMECompartment == s.Compartment {
			return nil
		}
		err = c.host.ApplyIME(s.Profile, e.IMECompartment)
	case rail.OrderLanguageBar:
		if !c.caps.LanguageBar {
			return rail.ErrUnsupported
		}
		if !s.LanguageBarKnown {
			return rail.ErrState
		}
		if _, err = rail.EncodeLanguageBar(e.LanguageBar); err != nil {
			return err
		}
		if e.LanguageBar == s.LanguageBar {
			return nil
		}
		err = c.host.ApplyLanguageBar(e.LanguageBar)
	default:
		return rail.ErrUnsupported
	}
	if err != nil {
		c.invalidate()
		return err
	}
	after, err := c.host.Snapshot()
	if err != nil {
		c.invalidate()
		return err
	}
	if after.Profile != s.Profile {
		c.invalidate()
		return ErrChanged
	}
	if e.Order == rail.OrderIMECompartment {
		if !after.CompartmentKnown || after.Compartment != e.IMECompartment {
			c.invalidate()
			return ErrNotApplied
		}
		c.last.Compartment = after.Compartment
	} else {
		if !after.LanguageBarKnown || after.LanguageBar != e.LanguageBar {
			c.invalidate()
			return ErrNotApplied
		}
		c.last.LanguageBar = after.LanguageBar
	}
	return nil
}
