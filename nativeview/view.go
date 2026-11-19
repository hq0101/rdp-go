// Package nativeview hosts an RDP desktop and local TSF input in a Windows
// window. The protocol, frame decoding and queue policy remain pure Go.
package nativeview

import (
	"context"
	"errors"
	"image"
	"math"
	"time"
	"unicode/utf8"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/clipsync"
	"github.com/hq0101/rdp-go/keyboard"
	"github.com/hq0101/rdp-go/rdpgfx"
)

var ErrUnsupported = errors.New("nativeview: native window is unavailable on this platform")
var ErrInvalid = errors.New("nativeview: invalid options")

// Remote is implemented by *rdp.Session. Run takes ownership after validating the options and closes it
// on exit. Calls must honor context cancellation; Close must unblock ReadEvent.
// Invalid options or an unsupported platform leave ownership with the caller. It must represent one desktop connection, not a seamless RemoteApp
// target. Do not run other event readers or input writers concurrently with Run.
type Remote interface {
	Info() rdp.SessionInfo
	ReadEvent(context.Context) (rdp.Event, error)
	SendText(context.Context, string) error
	SendKeys(context.Context, []keyboard.Event) error
	SynchronizeKeys(context.Context, uint32) error
	MovePointer(context.Context, uint16, uint16) error
	SendMouseButton(context.Context, rdp.MouseButton, bool, uint16, uint16) error
	Scroll(context.Context, int16) error
	AcknowledgeFrame(context.Context, uint32) error
	SendDynamic(context.Context, uint32, []byte) error
	SetGraphicsOutputSize(context.Context, int, int) error
	SetDisplayUpdates(context.Context, bool) error
	Refresh(context.Context) error
	DynamicInfo() rdp.DynamicChannelInfo
	Close() error
}

type Options struct {
	Title           string
	Width, Height   int
	GraphicsProfile rdpgfx.Profile
	// ClipboardMode explicitly enables session-wide clipboard synchronization,
	// including when this window is unfocused. Zero is off. The session must
	// negotiate cliprdr and allow cliprdr.MaxMessage in StaticChannelLimits.
	ClipboardMode clipsync.Mode
	// ClipboardHost optionally supplies an existing/custom system adapter. Once
	// Run validates the session it takes ownership and closes/joins the Host.
	// Nil opens the Windows adapter only when clipboard is enabled. The default
	// supports Unicode, HTML, PNG, DIB/DIBV5 and optional remote virtual files.
	ClipboardHost clipsync.Host
	// ClipboardFiles explicitly enables remote-to-local virtual files with an
	// aggregate size quota. Requires a ClipboardMode containing ToLocal.
	// Nil leaves file receiving disabled; use ClipboardUpload for local sources.
	ClipboardFiles *clipsync.FileOptions
	// ClipboardUpload explicitly enables local-to-remote files. Requires a
	// ClipboardMode containing ToRemote and a LocalFileHost when customized.
	// Its quota includes sources retained by older remote clipboard locks.
	ClipboardUpload *clipsync.FileOptions
	// Fullscreen initially covers the current monitor. Ctrl+Alt+Break or the
	// local button toggles it and restores the preceding window placement.
	// With DynamicResolution disabled, this only scales the desktop locally.
	Fullscreen bool
	// DynamicResolution requests one primary monitor matching the local client
	// area (excluding the fixed input/status rows) after resizing settles. The
	// session must use managed DVCs with a disp.ChannelName listener whose limit
	// is at least 56 bytes (one monitor layout, in addition to 20-byte caps). Server
	// activation/graphics RESET, rather than the request, defines actual bounds.
	// Unsupported or unconfirmed requests keep the last actual resolution.
	DynamicResolution bool
	// LocalCandidateUI requests TSF UI-element integration on the window's
	// private thread. Only supporting input services can activate in this mode;
	// leave false for compatibility with other services. Native candidate UI is
	// hidden only after a complete, actionable replacement has been painted.
	LocalCandidateUI bool
	// RefreshInterval bounds frame publication, not network packet processing.
	// Zero selects 50ms. It must be between 16ms and one second.
	RefreshInterval time.Duration
}

func normalize(o Options) (Options, error) {
	if o.ClipboardMode > clipsync.Both || (o.ClipboardMode == clipsync.Off && o.ClipboardHost != nil) {
		return Options{}, ErrInvalid
	}
	if o.ClipboardFiles != nil {
		if o.ClipboardMode&clipsync.ToLocal == 0 || o.ClipboardFiles.MaxTotalSize > math.MaxInt64 {
			return Options{}, ErrInvalid
		}
		if o.ClipboardHost != nil {
			if _, ok := o.ClipboardHost.(clipsync.FileHost); !ok {
				return Options{}, ErrInvalid
			}
		}
		files := *o.ClipboardFiles
		o.ClipboardFiles = &files
	}
	if o.ClipboardUpload != nil {
		if o.ClipboardMode&clipsync.ToRemote == 0 || o.ClipboardUpload.MaxTotalSize > math.MaxInt64 {
			return Options{}, ErrInvalid
		}
		if o.ClipboardHost != nil {
			if _, ok := o.ClipboardHost.(clipsync.LocalFileHost); !ok {
				return Options{}, ErrInvalid
			}
		}
		files := *o.ClipboardUpload
		o.ClipboardUpload = &files
	}
	if o.Title == "" {
		o.Title = "rdp-go"
	}
	if !utf8.ValidString(o.Title) || len(o.Title) > 512 {
		return Options{}, ErrInvalid
	}
	for _, r := range o.Title {
		if r == 0 {
			return Options{}, ErrInvalid
		}
	}
	if o.Width == 0 {
		o.Width = 1280
	}
	if o.Height == 0 {
		o.Height = 800
	}
	if o.Width < 480 || o.Height < 320 || o.Width > 8192 || o.Height > 8192 {
		return Options{}, ErrInvalid
	}
	if o.GraphicsProfile > rdpgfx.ProfileAVC444 {
		return Options{}, ErrInvalid
	}
	if o.RefreshInterval == 0 {
		o.RefreshInterval = 50 * time.Millisecond
	}
	if o.RefreshInterval < 16*time.Millisecond || o.RefreshInterval > time.Second {
		return Options{}, ErrInvalid
	}
	return o, nil
}

// viewport uses integer aspect-fit geometry; letterbox points never map to a
// remote pixel. No coordinate outside the negotiated desktop is generated.
func viewport(area image.Rectangle, width, height int) image.Rectangle {
	if width <= 0 || height <= 0 || area.Empty() {
		return image.Rectangle{}
	}
	w, h := area.Dx(), area.Dy()
	if int64(w)*int64(height) > int64(h)*int64(width) {
		w = int(int64(h) * int64(width) / int64(height))
	} else {
		h = int(int64(w) * int64(height) / int64(width))
	}
	if w <= 0 || h <= 0 {
		return image.Rectangle{}
	}
	x, y := area.Min.X+(area.Dx()-w)/2, area.Min.Y+(area.Dy()-h)/2
	return image.Rect(x, y, x+w, y+h)
}
func remotePoint(p image.Point, v image.Rectangle, width, height int) (uint16, uint16, bool) {
	if !p.In(v) || v.Empty() || width < 1 || height < 1 || width > 65535 || height > 65535 {
		return 0, 0, false
	}
	x := int64(p.X-v.Min.X) * int64(width) / int64(v.Dx())
	y := int64(p.Y-v.Min.Y) * int64(height) / int64(v.Dy())
	return uint16(x), uint16(y), true
}

func localPoint(p image.Point, v image.Rectangle, width, height int) (image.Point, bool) {
	if v.Empty() || width < 1 || height < 1 || !p.In(image.Rect(0, 0, width, height)) {
		return image.Point{}, false
	}
	x := int((2*int64(p.X) + 1) * int64(v.Dx()) / (2 * int64(width)))
	y := int((2*int64(p.Y) + 1) * int64(v.Dy()) / (2 * int64(height)))
	return v.Min.Add(image.Pt(min(x, v.Dx()-1), min(y, v.Dy()-1))), true
}
