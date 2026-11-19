package rdpdr

import (
	"encoding/binary"
	"errors"
)

type PrinterOptions struct {
	// ProtocolMinorVersion selects 12 (also the zero default) or 13. Printer
	// writes ignore Offset in both versions, so no append backend is required.
	ProtocolMinorVersion uint16
	// Zero selects 64 requests / 8 MiB. Limits include common request headers.
	MaxPending, MaxBuffered int
}

type printerState struct {
	printer            Printer
	announced, replied bool
	status             uint32
}

// PrinterRequest is an opaque, single-use completion token for a printer IRP.
// It remains readable after completion/reset but cannot complete again.
type PrinterRequest struct {
	owner *PrinterClient
	entry *pendingIO
}

func (r PrinterRequest) ProtocolMinorVersion() uint16 {
	if r.entry == nil {
		return 0
	}
	return r.entry.minor
}

func (r PrinterRequest) Header() IOHeader {
	if r.entry == nil {
		return IOHeader{}
	}
	return r.entry.header
}

func (r PrinterRequest) Body() []byte {
	if r.entry == nil {
		return nil
	}
	return append([]byte(nil), r.entry.body...)
}

// Decode interprets the immutable request as a printer IRP. Decoding a stale
// token is allowed; only CompletePrinter consumes it.
func (r PrinterRequest) Decode() (PrinterIO, error) {
	if r.entry == nil {
		return PrinterIO{}, ErrRequest
	}
	return DecodePrinterIO(r.entry.header, r.entry.body)
}

type PrinterResult struct {
	Replies [][]byte
	// Ready means the handshake and printer device list were emitted, not that
	// the server accepted every queue. Send Replies in order.
	Ready bool
	// Restarted is true for every Server Announce, including the first one. It
	// invalidates all previous tokens and backend job handles.
	Restarted bool
	Device    *DeviceReply
	Request   *PrinterRequest
	// Ignored marks I/O or XPS notices for unknown, removed or rejected devices.
	Ignored bool
	XPS     *PrinterXPS
	Cache   *PrinterCacheEvent
}

type PrinterStatus struct {
	ProtocolMinorVersion                                      uint16
	Ready, Removal                                            bool
	Devices, Announced, Accepted, Rejected, Pending, Buffered int
}

// PrinterClient manages explicitly supplied printer device messages per
// MS-RDPEPC. It performs no printing, spooler, port or registry I/O and starts
// no goroutines: create/write/close tokens and cache/XPS notices are handed to
// the application, which owns job handles, spool data and cache persistence.
// Use NewPrinterClient, do not copy it, and serialize all methods except
// immutable PrinterRequest accessors. Handle errors require channel teardown;
// never drop an I/O request and continue. Outputs must be sent in order; a send
// failure also requires teardown, not replay. Reset is only for teardown.
// Configure Options.StaticChannelLimits[ChannelName] and the surrounding
// vchan.Decoder.Limit to MaxDeviceMessage; this client does not reassemble.
type PrinterClient struct {
	core     CoreClient
	options  PrinterOptions
	printers []printerState
	pending  map[requestKey]*pendingIO
	buffered int
	removal  bool
}

func NewPrinterClient(printers []Printer, options PrinterOptions) (*PrinterClient, error) {
	if options.ProtocolMinorVersion != 0 && options.ProtocolMinorVersion != 12 && options.ProtocolMinorVersion != 13 {
		return nil, ErrUnsupported
	}
	if err := validatePrinters(printers); err != nil {
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
	c := &PrinterClient{core: CoreClient{preferredMinor: options.ProtocolMinorVersion}, options: options, pending: make(map[requestKey]*pendingIO)}
	for _, p := range printers {
		c.printers = append(c.printers, printerState{printer: p})
	}
	return c, nil
}

func (c *PrinterClient) initialized() bool { return c != nil && c.pending != nil }

func (c *PrinterClient) device(id uint32) *printerState {
	for i := range c.printers {
		if c.printers[i].printer.ID == id {
			return &c.printers[i]
		}
	}
	return nil
}

func (c *PrinterClient) configured() []Printer {
	ps := make([]Printer, 0, len(c.printers))
	for _, p := range c.printers {
		ps = append(ps, p.printer)
	}
	return ps
}

func (c *PrinterClient) Status() PrinterStatus {
	if !c.initialized() {
		return PrinterStatus{}
	}
	s := PrinterStatus{ProtocolMinorVersion: c.core.minor, Ready: c.core.listed, Removal: c.removal, Devices: len(c.printers), Pending: len(c.pending), Buffered: c.buffered}
	for _, p := range c.printers {
		if p.announced {
			s.Announced++
		}
		if p.replied {
			if p.status == 0 {
				s.Accepted++
			} else {
				s.Rejected++
			}
		}
	}
	return s
}

// Reset invalidates protocol requests and device acceptance while preserving
// the configured printer list. It neither interrupts spooling nor closes job
// handles; the application must cancel and join that work first.
func (c *PrinterClient) Reset() {
	if !c.initialized() {
		return
	}
	c.core = CoreClient{preferredMinor: c.options.ProtocolMinorVersion}
	clear(c.pending)
	c.buffered = 0
	c.removal = false
	for i := range c.printers {
		c.printers[i] = printerState{printer: c.printers[i].printer}
	}
}

// printerCapabilities runs only after CoreClient validated the full message.
// A server without the printer capability set cannot host redirected queues.
func printerCapabilities(data []byte) (bool, error) {
	rest := data[8:]
	seenPrinter, seenGeneral := false, false
	removal := false
	for len(rest) > 0 {
		n := int(binary.LittleEndian.Uint16(rest[2:]))
		kind := binary.LittleEndian.Uint16(rest)
		if kind == 1 {
			seenGeneral = true
			removal = binary.LittleEndian.Uint32(rest[28:])&1 != 0
		}
		if kind == 2 {
			if seenPrinter || n != 8 {
				return false, ErrProtocol
			}
			if binary.LittleEndian.Uint32(rest[4:]) != 1 {
				return false, ErrUnsupported
			}
			seenPrinter = true
		}
		rest = rest[n:]
	}
	if !seenGeneral || !seenPrinter {
		return false, ErrUnsupported
	}
	return removal, nil
}

func (c *PrinterClient) Handle(data []byte) (PrinterResult, error) {
	var out PrinterResult
	if !c.initialized() {
		return out, ErrNotReady
	}
	if len(data) < 4 || len(data) > MaxDeviceMessage || binary.LittleEndian.Uint16(data) != 0x4472 && binary.LittleEndian.Uint16(data) != componentPRN {
		return out, ErrProtocol
	}
	kind := binary.LittleEndian.Uint16(data[2:])
	if binary.LittleEndian.Uint16(data) == componentPRN {
		if !c.core.listed {
			return out, ErrProtocol
		}
		body := data[4:]
		switch kind {
		case packetPRNUsingXPS:
			if len(body) != 8 {
				return out, ErrProtocol
			}
			id := binary.LittleEndian.Uint32(body)
			d := c.device(id)
			if d == nil || !d.announced || d.replied && d.status != 0 {
				out.Ready = true
				out.Ignored = true
				return out, nil
			}
			out.XPS = &PrinterXPS{DeviceID: id}
		case packetPRNCache:
			e, err := DecodePrinterCacheEvent(body)
			if err != nil {
				return out, err
			}
			out.Cache = &e
		default:
			return out, ErrProtocol
		}
		out.Ready = true
		return out, nil
	}
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
		out.Request = &PrinterRequest{owner: c, entry: p}
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
		removal, err = printerCapabilities(data)
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
			r.Replies[i] = append(b, 2, 0, 8, 0, 1, 0, 0, 0)
		case 0x4441:
			r.Replies[i], err = EncodePrinterAnnouncements(c.configured())
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
		for i := range c.printers {
			c.printers[i].announced = true
		}
	}
	out.Replies, out.Ready = r.Replies, r.Ready
	return out, nil
}

// Complete consumes a token exactly once and returns its final wire response.
// Job-handle allocation, spool side effects and status choice belong to the
// application. On an encoding error the token stays live.
func (c *PrinterClient) Complete(request PrinterRequest, status uint32, payload []byte) ([]byte, error) {
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

// CompletePrinter validates the original printer operation and produces a
// final response, consuming its token once. Invalid completions leave it
// pending. For an unsupported major function only an error status with a zero
// completion is accepted, producing a common failure envelope.
func (c *PrinterClient) CompletePrinter(request PrinterRequest, status uint32, result PrinterCompletion) ([]byte, error) {
	if !c.initialized() || request.owner != c || request.entry == nil {
		return nil, ErrRequest
	}
	h := request.entry.header
	if c.pending[requestKey{h.DeviceID, h.CompletionID}] != request.entry {
		return nil, ErrRequest
	}
	q, err := request.Decode()
	if err != nil {
		if errors.Is(err, ErrFileOperation) && status>>30 == 3 && result.empty() {
			return c.Complete(request, status, nil)
		}
		return nil, err
	}
	payload, err := printerResponsePayload(q, status, result)
	if err != nil {
		return nil, err
	}
	return c.Complete(request, status, payload)
}

// Announce adds one explicitly supplied queue after initial negotiation. No
// local printer is opened. Use a fresh ID for a different backend queue.
func (c *PrinterClient) Announce(printer Printer) ([]byte, error) {
	if !c.initialized() || !c.core.listed {
		return nil, ErrNotReady
	}
	all := append(c.configured(), printer)
	if err := validatePrinters(all); err != nil {
		return nil, err
	}
	b, err := EncodePrinterAnnouncements([]Printer{printer})
	if err != nil {
		return nil, err
	}
	c.printers = append(c.printers, printerState{printer: printer, announced: true})
	return b, nil
}

// Remove requires all responses for the device to be sent first. Close/join
// backend job handles before calling this. A removed ID may be re-announced.
func (c *PrinterClient) Remove(id uint32) ([]byte, error) {
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
	for i := range c.printers {
		if c.printers[i].printer.ID == id {
			c.printers = append(c.printers[:i], c.printers[i+1:]...)
			break
		}
	}
	return b, nil
}
