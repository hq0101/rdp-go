// Package tpkt implements RFC 1006 packet framing over a byte stream.
// Callers must serialize reads and writes separately and discard a stream
// after an I/O or framing error, since its packet boundary may be lost.
package tpkt

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	HeaderSize    = 4
	MinPacketSize = 7
	MaxPacketSize = 65535
)

var ErrInvalidPacket = errors.New("tpkt: invalid packet")

// Read reads exactly one packet, without reading ahead into the next packet.
// maxSize includes the four-byte header; zero means MaxPacketSize.
// The returned slice owns its storage and excludes the header.
func Read(r io.Reader, maxSize int) ([]byte, error) {
	if maxSize == 0 {
		maxSize = MaxPacketSize
	}
	if maxSize < MinPacketSize || maxSize > MaxPacketSize {
		return nil, fmt.Errorf("%w: invalid size limit %d", ErrInvalidPacket, maxSize)
	}
	var h [HeaderSize]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[2:]))
	if h[0] != 3 || h[1] != 0 || n < MinPacketSize || n > maxSize {
		return nil, fmt.Errorf("%w: version=%d reserved=%d length=%d", ErrInvalidPacket, h[0], h[1], n)
	}
	b := make([]byte, n-HeaderSize)
	_, err := io.ReadFull(r, b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Marshal wraps an X.224 TPDU in a TPKT header.
func Marshal(payload []byte) ([]byte, error) {
	if len(payload) < MinPacketSize-HeaderSize || len(payload) > MaxPacketSize-HeaderSize {
		return nil, fmt.Errorf("%w: payload length %d", ErrInvalidPacket, len(payload))
	}
	b := make([]byte, HeaderSize+len(payload))
	b[0] = 3
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	copy(b[HeaderSize:], payload)
	return b, nil
}

// Write writes a complete packet, including when the writer makes short writes.
func Write(w io.Writer, payload []byte) error {
	b, err := Marshal(payload)
	if err != nil {
		return err
	}
	for len(b) != 0 {
		n, err := w.Write(b)
		if n < 0 || n > len(b) {
			return io.ErrShortWrite
		}
		b = b[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}
