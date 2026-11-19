package rdpdr

import (
	"bytes"
	"encoding/binary"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Printer budgets and constants are implementation limits plus the MS-RDPEPC
// wire values; they add no new protocol restrictions.
const (
	deviceTypePrint uint32 = 4 // RDPDR_DTYP_PRINT (MS-RDPEFS 2.2.1.3)

	PrinterFlagASCII   uint32 = 0x01 // DriverName is ASCII instead of UTF-16
	PrinterFlagDefault uint32 = 0x02 // at most one printer per announcement
	PrinterFlagNetwork uint32 = 0x04
	PrinterFlagTS      uint32 = 0x08 // nested terminal-session client printer
	PrinterFlagXPS     uint32 = 0x10 // client accepts XPS spool format
	printerFlagMask    uint32 = 0x1f

	PrinterCacheAdd    uint32 = 1 // SERVER_PRINTER_CACHE_EVENT (MS-RDPEPC 2.2.1.1)
	PrinterCacheUpdate uint32 = 2
	PrinterCacheDelete uint32 = 3
	PrinterCacheRename uint32 = 4

	componentPRN      uint16 = 0x5052 // RDPDR_CTYP_PRN
	packetPRNCache    uint16 = 0x5043 // PAKID_PRN_CACHE_DATA
	packetPRNUsingXPS uint16 = 0x5543 // PAKID_PRN_USING_XPS

	MaxPrinterNameUnits  = 255
	MaxPrinterCachedData = 1 << 20
)

// Printer describes one application-supplied redirected queue. Port is the
// DOS port name "PRN" followed by digits (MS-RDPEPC 2.2.2.1); Name is the
// user-assigned queue name the server mirrors, Driver selects the server-side
// driver match, and PnP is ignored by the server. CachedData is an opaque blob
// previously received from a cache event; the library never interprets, stores
// or persists it, and no local printer or spooler is opened.
type Printer struct {
	ID         uint32
	Port       string
	Name       string
	Driver     string
	PnP        string
	Flags      uint32
	CachedData []byte
}

func printerText(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	units := 0
	for _, ch := range s {
		if ch < 32 || ch == 127 {
			return false
		}
		units++
		if ch > 0xffff {
			units++
		}
		if units > MaxPrinterNameUnits {
			return false
		}
	}
	return true
}

func validPrinter(p Printer) bool {
	if len(p.Port) < 4 || len(p.Port) > 8 || p.Port[:3] != "PRN" {
		return false
	}
	for _, ch := range []byte(p.Port[3:]) {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	if p.Name == "" || !printerText(p.Name) || p.Driver == "" {
		return false
	}
	if p.Flags&PrinterFlagASCII != 0 {
		if !asciiDriveName(p.Driver) || strings.ContainsRune(p.Driver, 0) {
			return false
		}
	} else if !printerText(p.Driver) {
		return false
	}
	if p.PnP != "" && !printerText(p.PnP) {
		return false
	}
	if p.Flags & ^printerFlagMask != 0 || len(p.CachedData) > MaxPrinterCachedData {
		return false
	}
	return true
}

func validatePrinters(printers []Printer) error {
	if len(printers) > MaxDevices {
		return ErrLimit
	}
	defaults := 0
	for i, p := range printers {
		if !validPrinter(p) {
			return ErrDevice
		}
		if p.Flags&PrinterFlagDefault != 0 {
			defaults++
		}
		for _, old := range printers[:i] {
			if old.ID == p.ID || strings.EqualFold(old.Port, p.Port) || strings.EqualFold(old.Name, p.Name) {
				return ErrDevice
			}
		}
	}
	if defaults > 1 {
		return ErrDevice
	}
	return nil
}

func printerUTF16(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return append(b, 0, 0)
}

// EncodePrinterAnnouncements encodes DR_PRN_DEVICE_ANNOUNCE entries inside a
// Client Device List Announce. It accesses no local printer, port or registry.
func EncodePrinterAnnouncements(printers []Printer) ([]byte, error) {
	if err := validatePrinters(printers); err != nil {
		return nil, err
	}
	b := []byte{0x72, 0x44, 0x41, 0x44}
	b = binary.LittleEndian.AppendUint32(b, uint32(len(printers)))
	for _, p := range printers {
		var port [8]byte
		copy(port[:], p.Port)
		pnp := printerUTF16(p.PnP)
		driver := printerUTF16(p.Driver)
		if p.Flags&PrinterFlagASCII != 0 {
			driver = append([]byte(p.Driver), 0)
		}
		name := printerUTF16(p.Name)
		data := binary.LittleEndian.AppendUint32(nil, p.Flags)
		data = binary.LittleEndian.AppendUint32(data, 0) // CodePage reserved
		data = binary.LittleEndian.AppendUint32(data, uint32(len(pnp)))
		data = binary.LittleEndian.AppendUint32(data, uint32(len(driver)))
		data = binary.LittleEndian.AppendUint32(data, uint32(len(name)))
		data = binary.LittleEndian.AppendUint32(data, uint32(len(p.CachedData)))
		data = append(data, pnp...)
		data = append(data, driver...)
		data = append(data, name...)
		data = append(data, p.CachedData...)
		b = binary.LittleEndian.AppendUint32(b, deviceTypePrint)
		b = binary.LittleEndian.AppendUint32(b, p.ID)
		b = append(b, port[:]...)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(data)))
		b = append(b, data...)
	}
	if len(b) > MaxDeviceMessage {
		return nil, ErrLimit
	}
	return b, nil
}

// PrinterIO is the printer-specific interpretation of an IRP. Only CREATE,
// WRITE and CLOSE exist for printer devices; CREATE carries no path and WRITE
// carries no meaningful offset (MS-RDPEPC 2.2.2.7/2.2.2.9). Other major
// functions decode to ErrFileOperation so the backend can fail them explicitly.
type PrinterIO struct {
	Header IOHeader
	Create bool
	Close  bool
	Write  []byte
}

func DecodePrinterIO(h IOHeader, b []byte) (PrinterIO, error) {
	var q PrinterIO
	if len(b) > MaxDeviceMessage-24 {
		return q, ErrLimit
	}
	q.Header = h
	switch h.MajorFunction {
	case MajorCreate:
		// PathLength MUST be zero; the remaining create fields are unused.
		if len(b) != 32 {
			return PrinterIO{}, ErrProtocol
		}
		q.Create = true
	case MajorClose:
		if len(b) != 32 {
			return PrinterIO{}, ErrProtocol
		}
		q.Close = true
	case MajorWrite:
		r, err := DecodeFileRequest(h, b)
		if err != nil {
			return PrinterIO{}, err
		}
		q.Write = r.Write.Data
	default:
		return PrinterIO{}, ErrFileOperation
	}
	return q, nil
}

// PrinterCompletion supplies a job operation's output. CREATE uses FileID (the
// printer create response has no Information byte); the ID must be reused only
// after its close response was sent, which the backend owns. WRITE uses
// Written, CLOSE requires a zero value. Failure statuses require a zero value.
type PrinterCompletion struct {
	FileID  uint32
	Written uint32
}

func (r PrinterCompletion) empty() bool { return r.FileID == 0 && r.Written == 0 }

func printerResponsePayload(q PrinterIO, status uint32, r PrinterCompletion) ([]byte, error) {
	if status == StatusPending {
		return nil, ErrProtocol
	}
	switch {
	case q.Create:
		if r.Written != 0 || status != StatusSuccess && r.FileID != 0 {
			return nil, ErrProtocol
		}
		return binary.LittleEndian.AppendUint32(nil, r.FileID), nil
	case q.Close:
		if !r.empty() {
			return nil, ErrProtocol
		}
		return make([]byte, 4), nil
	case q.Write != nil:
		if r.FileID != 0 || uint64(r.Written) > uint64(len(q.Write)) {
			return nil, ErrProtocol
		}
		b := binary.LittleEndian.AppendUint32(nil, r.Written)
		return append(b, 0), nil
	default:
		if status>>30 != 3 || !r.empty() {
			return nil, ErrProtocol
		}
		return nil, nil
	}
}

// EncodePrinterCompletion encodes a reply for a decoded printer IRP without
// consuming a token or performing I/O. Use CompletePrinter on PrinterClient so
// correlation comes from the original immutable request.
func EncodePrinterCompletion(q PrinterIO, status uint32, r PrinterCompletion) ([]byte, error) {
	b, err := printerResponsePayload(q, status, r)
	if err != nil {
		return nil, err
	}
	return EncodeIOCompletion(q.Header.DeviceID, q.Header.CompletionID, status, b)
}

// PrinterXPS reports DR_PRN_USING_XPS: subsequent writes for DeviceID use the
// XPS spool format. The wire Flags field is unused and ignored. The library
// only reports the mode; rendering or driver selection belongs to the backend.
type PrinterXPS struct{ DeviceID uint32 }

// PrinterCacheEvent is a decoded server printer-cache notification. The library
// never stores it: Add carries Port/PnP/Driver/Name/CachedData, Update carries
// Name/CachedData, Delete carries Name, Rename carries Name (old) and NewName.
// Persisting or applying the cache is an application decision.
type PrinterCacheEvent struct {
	Event      uint32
	Port       string
	PnP        string
	Driver     string
	Name       string
	NewName    string
	CachedData []byte
}

func decodePrinterString(b []byte) (string, error) {
	s, err := decodeFileText(b, true, false)
	if err != nil {
		return "", err
	}
	if s == "" || !printerText(s) {
		return "", ErrProtocol
	}
	return s, nil
}

func decodePrinterPort(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

// DecodePrinterCacheEvent decodes the body of a PAKID_PRN_CACHE_DATA packet
// (after the 4-byte shared header). Lengths are exact and UTF-16 is validated.
func DecodePrinterCacheEvent(b []byte) (PrinterCacheEvent, error) {
	var e PrinterCacheEvent
	if len(b) < 4 {
		return e, ErrProtocol
	}
	e.Event = binary.LittleEndian.Uint32(b)
	rest := b[4:]
	take := func(n uint32) ([]byte, error) {
		if uint64(n) > uint64(len(rest)) {
			return nil, ErrProtocol
		}
		v := rest[:n]
		rest = rest[n:]
		return v, nil
	}
	switch e.Event {
	case PrinterCacheAdd:
		if len(rest) < 24 {
			return e, ErrProtocol
		}
		e.Port = decodePrinterPort(rest[:8])
		pnpLen := binary.LittleEndian.Uint32(rest[8:])
		driverLen := binary.LittleEndian.Uint32(rest[12:])
		nameLen := binary.LittleEndian.Uint32(rest[16:])
		cachedLen := binary.LittleEndian.Uint32(rest[20:])
		rest = rest[24:]
		pnp, err := take(pnpLen)
		if err != nil {
			return e, err
		}
		if e.PnP, err = decodeFileText(pnp, true, false); err != nil {
			return e, err
		}
		driver, err := take(driverLen)
		if err != nil {
			return e, err
		}
		if e.Driver, err = decodePrinterString(driver); err != nil {
			return e, err
		}
		name, err := take(nameLen)
		if err != nil {
			return e, err
		}
		if e.Name, err = decodePrinterString(name); err != nil {
			return e, err
		}
		if cachedLen > MaxPrinterCachedData {
			return e, ErrLimit
		}
		if e.CachedData, err = take(cachedLen); err != nil {
			return e, err
		}
		e.CachedData = append([]byte(nil), e.CachedData...)
	case PrinterCacheUpdate:
		if len(rest) < 8 {
			return e, ErrProtocol
		}
		nameLen := binary.LittleEndian.Uint32(rest)
		cachedLen := binary.LittleEndian.Uint32(rest[4:])
		rest = rest[8:]
		name, err := take(nameLen)
		if err != nil {
			return e, err
		}
		if e.Name, err = decodePrinterString(name); err != nil {
			return e, err
		}
		if cachedLen > MaxPrinterCachedData {
			return e, ErrLimit
		}
		if e.CachedData, err = take(cachedLen); err != nil {
			return e, err
		}
		e.CachedData = append([]byte(nil), e.CachedData...)
	case PrinterCacheDelete:
		if len(rest) < 4 {
			return e, ErrProtocol
		}
		nameLen := binary.LittleEndian.Uint32(rest)
		rest = rest[4:]
		name, err := take(nameLen)
		if err != nil {
			return e, err
		}
		if e.Name, err = decodePrinterString(name); err != nil {
			return e, err
		}
	case PrinterCacheRename:
		if len(rest) < 8 {
			return e, ErrProtocol
		}
		oldLen := binary.LittleEndian.Uint32(rest)
		newLen := binary.LittleEndian.Uint32(rest[4:])
		rest = rest[8:]
		old, err := take(oldLen)
		if err != nil {
			return e, err
		}
		if e.Name, err = decodePrinterString(old); err != nil {
			return e, err
		}
		newName, err := take(newLen)
		if err != nil {
			return e, err
		}
		if e.NewName, err = decodePrinterString(newName); err != nil {
			return e, err
		}
	default:
		return PrinterCacheEvent{}, ErrUnsupported
	}
	if len(rest) != 0 {
		return PrinterCacheEvent{}, ErrProtocol
	}
	return e, nil
}
