// Package cliphost adapts the system clipboard to bounded, delayed RDP format
// transfers. Opening a host observes format metadata; it does not read content
// or send anything to a network. Callers explicitly Read or Offer representations.
package cliphost

import (
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"time"

	"github.com/hq0101/rdp-go/cliprdr"
)

var (
	ErrUnsupported = errors.New("cliphost: system clipboard unavailable on this platform")
	ErrInvalid     = errors.New("cliphost: invalid options, format or data")
	ErrClosed      = errors.New("cliphost: closed")
	ErrChanged     = errors.New("cliphost: clipboard ownership changed")
	ErrBusy        = errors.New("cliphost: clipboard is held by another application")
)

type identity struct{ marker byte }

// Token identifies one observed clipboard item. It retains no host or content.
// Tokens are invalid after replacement or shutdown, even if format IDs repeat.
type Token struct{ id *identity }

// FileLease keeps a published file source alive for its native consumers.
// Done closes after actual native cleanup; only then may its source be freed.
// Close is nonblocking and cancels this publication, including retained streams.
// The owning Host also closes all its leases on shutdown. On Windows a lease
// may additionally expose Shell copy outcomes through an
// Operations() <-chan clipole.Operation method; clipsync forwards those.
type FileLease interface {
	Close()
	Done() <-chan struct{}
	Err() error
}

// NewToken creates an item identity for a custom clipboard Host implementation.
// Renew it on each ownership/content change, even if formats repeat. Reuse it
// while materializing the same delayed item. It grants no access to a native
// Host, which accepts only its own current token and rechecks native ownership.
func NewToken() Token { return Token{new(identity)} }

// Snapshot contains a copy of the available supported formats, in OS order.
// External is false for our own delayed offer; do not echo it to the remote peer.
// A snapshot is metadata, not proof that a subsequent read will succeed.
type Snapshot struct {
	Token    Token
	Formats  []cliprdr.Format
	External bool
	// Files indicates a CF_HDROP or Unicode OLE virtual-file selection. This is
	// metadata only; AcquireFileSource explicitly acquires the local files or
	// virtual media. AcquireFiles remains the filesystem-only API.
	Files bool
}

type Options struct {
	// RenderTimeout limits each delayed rendering callback (default five seconds,
	// range 100ms..15s). Provider must honor the context and must not call Host.
	RenderTimeout time.Duration
}

// Provider returns one requested representation, using the original advertised
// format ID/name. It runs serially on the clipboard thread, outside caller locks.
// It MUST honor cancellation, must not call this Host, and must return owned
// immutable bytes. Keep the transport reader running while waiting for data.
type Provider func(context.Context, cliprdr.Format) ([]byte, error)

func options(o Options) (Options, error) {
	if o.RenderTimeout == 0 {
		o.RenderTimeout = 5 * time.Second
	}
	if o.RenderTimeout < 100*time.Millisecond || o.RenderTimeout > 15*time.Second {
		return Options{}, ErrInvalid
	}
	return o, nil
}

func supported(f cliprdr.Format) bool {
	if f.ID < 0xc000 {
		return f.ID == cliprdr.UnicodeText || f.ID == cliprdr.DIB || f.ID == cliprdr.DIBV5
	}
	return f.ID <= 0xffff && (strings.EqualFold(f.Name, cliprdr.HTMLName) || strings.EqualFold(f.Name, cliprdr.PNGName))
}

// Supported reports whether this adapter can transfer a format as bounded bytes.
// Registered format IDs are endpoint-local; their names determine support.
func Supported(f cliprdr.Format) bool { return supported(f) }

func validateFormats(fs []cliprdr.Format) error {
	if len(fs) > 5 {
		return ErrInvalid
	}
	for i, f := range fs {
		if !supported(f) {
			return ErrInvalid
		}
		for _, prev := range fs[:i] {
			if f.ID == prev.ID || (f.ID >= 0xc000 && prev.ID >= 0xc000 && strings.EqualFold(f.Name, prev.Name)) {
				return ErrInvalid
			}
		}
	}
	return nil
}

// Validate before exposing bytes to another application. Handle-only formats,
// arbitrary registered data and filesystem/OLE objects are not byte buffers.
func validateData(f cliprdr.Format, b []byte) error {
	if !supported(f) || len(b) == 0 || len(b) > cliprdr.MaxDataBytes {
		return ErrInvalid
	}
	switch {
	case f.ID == cliprdr.UnicodeText:
		_, err := cliprdr.DecodeText(b)
		return err
	case f.ID == cliprdr.DIB || f.ID == cliprdr.DIBV5:
		if f.ID == cliprdr.DIBV5 && (len(b) < 124 || binary.LittleEndian.Uint32(b) != 124) {
			return ErrInvalid
		}
		_, err := cliprdr.DecodeDIB(b)
		return err
	case strings.EqualFold(f.Name, cliprdr.HTMLName):
		_, err := cliprdr.DecodeHTML(b)
		return err
	case strings.EqualFold(f.Name, cliprdr.PNGName):
		_, err := cliprdr.DecodePNG(b)
		return err
	}
	return ErrInvalid
}
