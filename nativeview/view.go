// Package nativeview hosts an RDP desktop and local TSF input in a Windows
// window. The protocol, frame decoding and queue policy remain pure Go.
package nativeview

import (
	"context"
	"errors"
	"image"
	"time"
	"unicode/utf8"

	"github.com/hq0101/rdp-go"
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
	// RefreshInterval bounds frame publication, not network packet processing.
	// Zero selects 50ms. It must be between 16ms and one second.
	RefreshInterval time.Duration
}

func normalize(o Options) (Options, error) {
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
