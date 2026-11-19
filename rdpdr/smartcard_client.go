package rdpdr

import (
	"encoding/binary"
	"errors"
)

type SmartcardOptions struct {
	// ProtocolMinorVersion selects 12 (also the zero default) or 13.
	ProtocolMinorVersion uint16
	// Zero selects 64 requests / 8 MiB. Limits include common request headers.
	MaxPending, MaxBuffered int
}

type smartcardState struct {
	id                 uint32
	announced, replied bool
	status             uint32
}

// SmartcardRequest is an opaque, single-use completion token for a smartcard
// IRP. It remains readable after completion/reset but cannot complete again.
type SmartcardRequest struct {
	owner *SmartcardClient
	entry *pendingIO
}

func (r SmartcardRequest) ProtocolMinorVersion() uint16 {
	if r.entry == nil {
		return 0
	}
	return r.entry.minor
}

func (r SmartcardRequest) Header() IOHeader {
	if r.entry == nil {
		return IOHeader{}
	}
	return r.entry.header
}

func (r SmartcardRequest) Body() []byte {
	if r.entry == nil {
		return nil
	}
	return append([]byte(nil), r.entry.body...)
}

// Decode interprets the immutable request as a device control IRP, reusing
// the drive slice's DR_CONTROL_REQ framing. Only IRP_MJ_DEVICE_CONTROL is
// valid for smartcard devices; other major functions return ErrFileOperation
// so the backend can fail them explicitly. Decoding a stale token is allowed;
// only CompleteControl consumes it.
func (r SmartcardRequest) Decode() (ControlRequest, error) {
	if r.entry == nil {
		return ControlRequest{}, ErrRequest
	}
	if r.entry.header.MajorFunction != MajorDeviceControl {
		return ControlRequest{}, ErrFileOperation
	}
	q, err := DecodeFileRequest(r.entry.header, r.entry.body)
	if err != nil {
		return ControlRequest{}, err
	}
	return *q.Control, nil
}

type SmartcardResult struct {
	Replies [][]byte
	// Ready means the handshake and smartcard device list were emitted, not
	// that the server accepted the device. Send Replies in order.
	Ready bool
	// Restarted is true for every Server Announce, including the first one. It
	// invalidates all previous tokens and backend card contexts.
	Restarted bool
	Device    *DeviceReply
	Request   *SmartcardRequest
	// Ignored marks I/O for unknown, removed or rejected devices.
	Ignored bool
}

type SmartcardStatus struct {
	ProtocolMinorVersion                                      uint16
	Ready, Removal                                            bool
	Devices, Announced, Accepted, Rejected, Pending, Buffered int
}

// SmartcardClient manages explicitly supplied smartcard device messages per
// MS-RDPESC. It performs no reader, winscard or service I/O and starts no
// goroutines: device control tokens are handed to the application, which owns
// card contexts, handles and the per-IOCTL NDR call/return layouts. Use
// NewSmartcardClient, do not copy it, and serialize all methods except
// immutable SmartcardRequest accessors. Handle errors require channel
// teardown; never drop an I/O request and continue. Outputs must be sent in
// order; a send failure also requires teardown, not replay. Reset is only for
// teardown. Configure Options.StaticChannelLimits[ChannelName] and the
// surrounding vchan.Decoder.Limit to MaxDeviceMessage; this client does not
// reassemble.
type SmartcardClient struct {
	core     CoreClient
	options  SmartcardOptions
	devices  []smartcardState
	pending  map[requestKey]*pendingIO
	buffered int
	removal  bool
}

func NewSmartcardClient(ids []uint32, options SmartcardOptions) (*SmartcardClient, error) {
	if options.ProtocolMinorVersion != 0 && options.ProtocolMinorVersion != 12 && options.ProtocolMinorVersion != 13 {
		return nil, ErrUnsupported
	}
	if err := validateSmartcards(ids); err != nil {
		return nil, err
	}
	if options.MaxPending == 0 {
		options.MaxPending = 64
	}
	if options.MaxBuffered == 0 {
		options.MaxBuffered = 8 << 20
	}
	if options.MaxPending < 1 || options.MaxPending > MaxPendingRequests || options.MaxBuffered < 24 || options.MaxBuffered > MaxPendingBytes {
		return nil, ErrLimit
	}
	c := &SmartcardClient{core: CoreClient{preferredMinor: options.ProtocolMinorVersion}, options: options, pending: make(map[requestKey]*pendingIO)}
	for _, id := range ids {
		c.devices = append(c.devices, smartcardState{id: id})
	}
	return c, nil
}

func (c *SmartcardClient) initialized() bool { return c != nil && c.pending != nil }

func (c *SmartcardClient) device(id uint32) *smartcardState {
	for i := range c.devices {
		if c.devices[i].id == id {
			return &c.devices[i]
		}
	}
	return nil
}

func (c *SmartcardClient) configured() []uint32 {
	ids := make([]uint32, 0, len(c.devices))
	for _, d := range c.devices {
		ids = append(ids, d.id)
	}
	return ids
}

func (c *SmartcardClient) Status() SmartcardStatus {
	if !c.initialized() {
		return SmartcardStatus{}
	}
	s := SmartcardStatus{ProtocolMinorVersion: c.core.minor, Ready: c.core.listed, Removal: c.removal, Devices: len(c.devices), Pending: len(c.pending), Buffered: c.buffered}
	for _, d := range c.devices {
		if d.announced {
			s.Announced++
		}
		if d.replied {
			if d.status == 0 {
				s.Accepted++
			} else {
				s.Rejected++
			}
		}
	}
	return s
}

// Reset invalidates protocol requests and device acceptance while preserving
// the configured device list. It neither interrupts card operations nor
// releases contexts; the application must cancel and join that work first.
func (c *SmartcardClient) Reset() {
	if !c.initialized() {
		return
	}
	c.core = CoreClient{preferredMinor: c.options.ProtocolMinorVersion}
	clear(c.pending)
	c.buffered = 0
	c.removal = false
	for i := range c.devices {
		c.devices[i] = smartcardState{id: c.devices[i].id}
	}
}

// smartcardCapabilities runs only after CoreClient validated the full message.
// A server without the smartcard capability set cannot host redirected cards.
func smartcardCapabilities(data []byte) (bool, error) {
	rest := data[8:]
	seenSmartcard, seenGeneral := false, false
	removal := false
	for len(rest) > 0 {
		n := int(binary.LittleEndian.Uint16(rest[2:]))
		kind := binary.LittleEndian.Uint16(rest)
		if kind == 1 {
			seenGeneral = true
			removal = binary.LittleEndian.Uint32(rest[28:])&1 != 0
		}
		if kind == 5 {
			if seenSmartcard || n != 8 {
				return false, ErrProtocol
			}
			if binary.LittleEndian.Uint32(rest[4:]) != 1 {
				return false, ErrUnsupported
			}
			seenSmartcard = true
		}
		rest = rest[n:]
	}
	if !seenGeneral || !seenSmartcard {
		return false, ErrUnsupported
	}
	return removal, nil
}

func (c *SmartcardClient) Handle(data []byte) (SmartcardResult, error) {
	var out SmartcardResult
	if !c.initialized() {
		return out, ErrNotReady
	}
	if len(data) < 4 || len(data) > MaxDeviceMessage || binary.LittleEndian.Uint16(data) != 0x4472 {
		return out, ErrProtocol
	}
	kind := binary.LittleEndian.Uint16(data[2:])
	if kind == 0x6472 {
		r, err := DecodeDeviceReply(data)
		if err != nil {
			return out, err
		}
		d := c.device(r.DeviceID)
		if !c.core.listed || d == nil || !d.announced || d.replied {
			return out, ErrProtocol
		}
		d.replied, d.status = true, r.Status
		out.Device = &r
		out.Ready = true
		return out, nil
	}
	if kind == 0x4952 {
		h, err := DecodeIOHeader(data)
		if err != nil {
			return out, err
		}
		if !c.core.listed {
			return out, ErrProtocol
		}
		d := c.device(h.DeviceID)
		if d == nil || !d.announced || d.replied && d.status != 0 {
			out.Ready = true
			out.Ignored = true
			return out, nil
		}
		key := requestKey{h.DeviceID, h.CompletionID}
		if c.pending[key] != nil {
			return out, ErrProtocol
		}
		if len(c.pending) >= c.options.MaxPending || len(data) > c.options.MaxBuffered-c.buffered {
			return out, ErrLimit
		}
		p := &pendingIO{header: h, body: append([]byte(nil), data[24:]...), minor: c.core.minor}
		c.pending[key] = p
		c.buffered += len(data)
		out.Request = &SmartcardRequest{owner: c, entry: p}
		out.Ready = true
		return out, nil
	}
	// CoreClient is value-only. Negotiate on a copy, then rewrite its empty
	// announcement/capabilities before committing any state or replies.
	trial := c.core
	r, err := trial.Handle(data)
	if err != nil {
		return out, err
	}
	removal := c.removal
	if kind == 0x5350 {
		removal, err = smartcardCapabilities(data)
		if err != nil {
			return out, err
		}
	}
	for i, b := range r.Replies {
		switch binary.LittleEndian.Uint16(b[2:]) {
		case 0x4350:
			binary.LittleEndian.PutUint16(b[4:], 2)
			if removal {
				b[36] |= 1
			}
			r.Replies[i] = append(b, 5, 0, 8, 0, 1, 0, 0, 0)
		case 0x4441:
			r.Replies[i], err = EncodeSmartcardAnnouncements(c.configured())
			if err != nil {
				return out, err
			}
		}
	}
	if kind == 0x496e {
		c.Reset()
		out.Restarted = true
		removal = false
	}
	c.core, c.removal = trial, removal
	if r.Ready {
		for i := range c.devices {
			c.devices[i].announced = true
		}
	}
	out.Replies, out.Ready = r.Replies, r.Ready
	return out, nil
}

// Complete consumes a token exactly once and returns its final wire response.
// Context allocation, card side effects and status choice belong to the
// application. On an encoding error the token stays live. Prefer
// CompleteControl, which enforces the DR_CONTROL_RSP layout rules.
func (c *SmartcardClient) Complete(request SmartcardRequest, status uint32, payload []byte) ([]byte, error) {
	if !c.initialized() || request.owner != c || request.entry == nil {
		return nil, ErrRequest
	}
	h := request.entry.header
	key := requestKey{h.DeviceID, h.CompletionID}
	if c.pending[key] != request.entry {
		return nil, ErrRequest
	}
	b, err := EncodeIOCompletion(h.DeviceID, h.CompletionID, status, payload)
	if err != nil {
		return nil, err
	}
	delete(c.pending, key)
	c.buffered -= 24 + len(request.entry.body)
	return b, nil
}

// CompleteControl validates the original control request and produces a final
// response, consuming its token once. Invalid completions leave it pending.
// For an unsupported major function only an error status with empty output is
// accepted, producing a common failure envelope.
func (c *SmartcardClient) CompleteControl(request SmartcardRequest, status uint32, output []byte) ([]byte, error) {
	if !c.initialized() || request.owner != c || request.entry == nil {
		return nil, ErrRequest
	}
	h := request.entry.header
	if c.pending[requestKey{h.DeviceID, h.CompletionID}] != request.entry {
		return nil, ErrRequest
	}
	q, err := request.Decode()
	if err != nil {
		if errors.Is(err, ErrFileOperation) && status>>30 == 3 && len(output) == 0 {
			return c.Complete(request, status, nil)
		}
		return nil, err
	}
	payload, err := controlResponsePayload(q, status, output)
	if err != nil {
		return nil, err
	}
	return c.Complete(request, status, payload)
}

// Announce adds the smartcard device after initial negotiation. No local
// reader is opened. The fixed "SCARD" DOS name allows at most one device, so
// this succeeds only while no device is configured (e.g. after Remove).
func (c *SmartcardClient) Announce(id uint32) ([]byte, error) {
	if !c.initialized() || !c.core.listed {
		return nil, ErrNotReady
	}
	all := append(c.configured(), id)
	if err := validateSmartcards(all); err != nil {
		return nil, err
	}
	b, err := EncodeSmartcardAnnouncements([]uint32{id})
	if err != nil {
		return nil, err
	}
	c.devices = append(c.devices, smartcardState{id: id, announced: true})
	return b, nil
}

// Remove requires all responses for the device to be sent first. Release
// backend card contexts before calling this. A removed ID may be re-announced.
func (c *SmartcardClient) Remove(id uint32) ([]byte, error) {
	if !c.initialized() || !c.core.listed {
		return nil, ErrNotReady
	}
	if !c.removal {
		return nil, ErrUnsupported
	}
	d := c.device(id)
	if d == nil || !d.announced {
		return nil, ErrDevice
	}
	if !d.replied {
		return nil, ErrBusy
	}
	for key := range c.pending {
		if key.device == id {
			return nil, ErrBusy
		}
	}
	b, err := EncodeDeviceRemoval([]uint32{id})
	if err != nil {
		return nil, err
	}
	for i := range c.devices {
		if c.devices[i].id == id {
			c.devices = append(c.devices[:i], c.devices[i+1:]...)
			break
		}
	}
	return b, nil
}
