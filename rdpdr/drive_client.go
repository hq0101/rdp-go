package rdpdr

import "encoding/binary"

type DriveOptions struct {
	// ProtocolMinorVersion selects 12 (also the zero default) or 13. A server
	// advertising 12 forces 12. Version 13 requires the backend to implement
	// WriteRequest.Append; DirectoryDrive supports this on Windows. This option
	// is preserved across Reset and each request retains its negotiated version.
	ProtocolMinorVersion uint16
	// Zero selects 64 requests / 8 MiB. Limits include common request headers.
	MaxPending, MaxBuffered int
	// AsyncIO advertises concurrent reads/writes to the same file. Enable only
	// when the backend supports the ordering and concurrency it implies.
	AsyncIO bool
	// ASCIINameCompatibility sends v2 full share names as single-byte ASCII
	// instead of the specification's UTF-16LE. Our Windows 10 peer interprets
	// the latter as a first-character name. Enable only for such peers; all
	// full names must be ASCII or construction/Announce returns ErrDevice.
	// No locale conversion, transliteration or automatic downgrade is done.
	ASCIINameCompatibility bool
}

type driveState struct {
	drive              Drive
	announced, replied bool
	status             uint32
}
type requestKey struct{ device, completion uint32 }
type pendingIO struct {
	header IOHeader
	body   []byte
	minor  uint16
}

// Request is an opaque, single-use completion token. It remains readable after
// completion/reset, but cannot then complete another request with reused IDs.
// Header/Body may be read outside the Client lock; Body returns an owned copy.
type Request struct {
	owner *DriveClient
	entry *pendingIO
}

// ProtocolMinorVersion reports the version advertised for this request's
// connection, including for completed/reset tokens. A zero token reports zero.
func (r Request) ProtocolMinorVersion() uint16 {
	if r.entry == nil {
		return 0
	}
	return r.entry.minor
}

func (r Request) Header() IOHeader {
	if r.entry == nil {
		return IOHeader{}
	}
	return r.entry.header
}
func (r Request) Body() []byte {
	if r.entry == nil {
		return nil
	}
	return append([]byte(nil), r.entry.body...)
}

type DriveResult struct {
	Replies [][]byte
	// Ready means the handshake and device list were emitted, not that all
	// devices were accepted. Send Replies in order before another operation.
	Ready bool
	// Restarted is true for every Server Announce, including the first one.
	// It invalidates all previous request tokens and backend handles.
	// The application must cancel/join old work before using a new backend.
	Restarted bool
	Device    *DeviceReply
	Request   *Request
	// Requests for unknown, removed or rejected devices are ignored (3.1.5.2).
	Ignored bool
}

type DriveStatus struct {
	// ProtocolMinorVersion is zero before Server Announce, then 12 or 13.
	ProtocolMinorVersion                                      uint16
	Ready, Removal, AsyncIO                                   bool
	Devices, Announced, Accepted, Rejected, Pending, Buffered int
}

// DriveClient manages explicitly supplied filesystem device messages. It does
// no I/O and starts no goroutines. Handle checks common envelopes; Request's
// DecodeFile and CompleteFile handle file-operation framing. Backend semantics,
// path policy and FileID lifetimes are required before a drive can be useful.
// Use NewDriveClient, do not copy it, and serialize all methods except immutable
// Request accessors. Handle errors require channel teardown; never drop an I/O
// request and continue. Complete/Announce/Remove outputs must be sent in order;
// a send failure also requires teardown, not replay. Reset is only for teardown.
// Configure both Options.StaticChannelLimits[ChannelName] and the surrounding
// vchan.Decoder.Limit to MaxDeviceMessage. This client does not do reassembly.
// Windows also requires an advertised rdpsnd static channel (MS-RDPEFS 6 note 1),
// even when audio playback is disabled. This does not require an audio device.
type DriveClient struct {
	core     CoreClient
	options  DriveOptions
	drives   []driveState
	pending  map[requestKey]*pendingIO
	buffered int
	removal  bool
}

func NewDriveClient(drives []Drive, options DriveOptions) (*DriveClient, error) {
	if options.ProtocolMinorVersion != 0 && options.ProtocolMinorVersion != 12 && options.ProtocolMinorVersion != 13 {
		return nil, ErrUnsupported
	}
	if err := validateDrives(drives); err != nil {
		return nil, err
	}
	if options.ASCIINameCompatibility {
		for _, d := range drives {
			if !asciiDriveName(d.RemoteName()) {
				return nil, ErrDevice
			}
		}
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
	c := &DriveClient{core: CoreClient{preferredMinor: options.ProtocolMinorVersion}, options: options, pending: make(map[requestKey]*pendingIO)}
	for _, d := range drives {
		c.drives = append(c.drives, driveState{drive: d})
	}
	return c, nil
}

func (c *DriveClient) initialized() bool { return c != nil && c.pending != nil }
func (c *DriveClient) device(id uint32) *driveState {
	for i := range c.drives {
		if c.drives[i].drive.ID == id {
			return &c.drives[i]
		}
	}
	return nil
}
func (c *DriveClient) configured() []Drive {
	ds := make([]Drive, 0, len(c.drives))
	for _, d := range c.drives {
		ds = append(ds, d.drive)
	}
	return ds
}

func (c *DriveClient) Status() DriveStatus {
	if !c.initialized() {
		return DriveStatus{}
	}
	s := DriveStatus{ProtocolMinorVersion: c.core.minor, Ready: c.core.listed, Removal: c.removal, AsyncIO: c.options.AsyncIO, Devices: len(c.drives), Pending: len(c.pending), Buffered: c.buffered}
	for _, d := range c.drives {
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
// the current configured drive list, including explicit additions/removals.
// It neither interrupts physical I/O nor closes backend file handles. The
// application must cancel and join that work before closing/reusing resources.
// Retained Request tokens/body copies keep their memory until the caller drops
// them; the protocol budget does not account for detached application storage.
func (c *DriveClient) Reset() {
	if !c.initialized() {
		return
	}
	c.core = CoreClient{preferredMinor: c.options.ProtocolMinorVersion}
	clear(c.pending)
	c.buffered = 0
	c.removal = false
	for i := range c.drives {
		c.drives[i] = driveState{drive: c.drives[i].drive}
	}
}

// driveCapabilities runs only after CoreClient validated the full message. The
// drive profile implements version 2 (the current Drive Capability Set format).
// Missing/older drive capabilities are unsupported, not an empty successful map.
func driveCapabilities(data []byte) (bool, error) {
	rest := data[8:]
	seenDrive, seenGeneral := false, false
	removal := false
	for len(rest) > 0 {
		n := int(binary.LittleEndian.Uint16(rest[2:]))
		kind := binary.LittleEndian.Uint16(rest)
		if kind == 1 {
			seenGeneral = true
			removal = binary.LittleEndian.Uint32(rest[28:])&1 != 0
		}
		if kind == 4 {
			if seenDrive || n != 8 {
				return false, ErrProtocol
			}
			if binary.LittleEndian.Uint32(rest[4:]) != 2 {
				return false, ErrUnsupported
			}
			seenDrive = true
		}
		rest = rest[n:]
	}
	if !seenGeneral || !seenDrive {
		return false, ErrUnsupported
	}
	return removal, nil
}

func (c *DriveClient) Handle(data []byte) (DriveResult, error) {
	var out DriveResult
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
		out.Request = &Request{owner: c, entry: p}
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
		removal, err = driveCapabilities(data)
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
			if c.options.AsyncIO {
				b[40] |= 1
			}
			r.Replies[i] = append(b, 4, 0, 8, 0, 2, 0, 0, 0)
		case 0x4441:
			r.Replies[i], err = encodeDriveAnnouncements(c.configured(), 2, c.options.ASCIINameCompatibility)
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
		for i := range c.drives {
			c.drives[i].announced = true
		}
	}
	out.Replies, out.Ready = r.Replies, r.Ready
	return out, nil
}

// Complete consumes a token exactly once and returns its final wire response.
// Body validation, FileID allocation/close, status and backend side effects are
// the application's responsibility. On an encoding error the token stays live.
// Returned bytes own their storage; send them before allowing request ID reuse.
func (c *DriveClient) Complete(request Request, status uint32, payload []byte) ([]byte, error) {
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

// Announce adds one explicitly supplied device after initial negotiation. It
// changes the configured list used after Reset; no backend is opened or created.
// Use a fresh ID for a different backend. The wire has no generation field to
// distinguish a late request for a removed ID from a request after ID reuse.
func (c *DriveClient) Announce(drive Drive) ([]byte, error) {
	if !c.initialized() || !c.core.listed {
		return nil, ErrNotReady
	}
	all := append(c.configured(), drive)
	if err := validateDrives(all); err != nil {
		return nil, err
	}
	b, err := encodeDriveAnnouncements([]Drive{drive}, 2, c.options.ASCIINameCompatibility)
	if err != nil {
		return nil, err
	}
	c.drives = append(c.drives, driveState{drive: drive, announced: true})
	return b, nil
}

// Remove requires all responses for the device to be sent first; otherwise a
// completion after removal would be invalid on the server. Close/join backend
// handles before calling this. A removed ID may then be explicitly re-announced.
func (c *DriveClient) Remove(id uint32) ([]byte, error) {
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
	for i := range c.drives {
		if c.drives[i].drive.ID == id {
			c.drives = append(c.drives[:i], c.drives[i+1:]...)
			break
		}
	}
	return b, nil
}
