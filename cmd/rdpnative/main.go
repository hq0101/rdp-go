// rdpnative presents one authenticated RDP desktop in a native Windows window.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/signal"
	"runtime"
	"time"

	rdp "github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/cliprdr"
	"github.com/hq0101/rdp-go/clipsync"
	"github.com/hq0101/rdp-go/disp"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/nativeview"
	"github.com/hq0101/rdp-go/rdpgfx"
)

func run(ctx context.Context, args []string, stderr io.Writer) error {
	f := flag.NewFlagSet("rdpnative", flag.ContinueOnError)
	f.SetOutput(stderr)
	addr := f.String("addr", "", "RDP server host:port")
	user := f.String("user", "", "account name")
	domain := f.String("domain", "", "domain or computer name")
	pin := f.String("cert-sha256", "", "independently verified certificate SHA-256; empty uses system trust")
	passwordEnv := f.String("password-env", "RDPGO_PASSWORD", "password environment variable")
	width := f.Int("width", 1920, "remote desktop width")
	height := f.Int("height", 1080, "remote desktop height")
	gfx := f.Bool("graphics-pipeline", false, "enable managed RDPGFX")
	profileName := f.String("graphics-profile", "thin", "thin, progressive, avc420 or avc444")
	candidateUI := f.Bool("local-candidate-ui", false, "integrate candidate lists; restricts local input methods to those supporting this mode")
	fullscreen := f.Bool("fullscreen", false, "start full screen; toggle with Ctrl+Alt+Break or the local button")
	resize := f.Bool("dynamic-resolution", false, "request remote desktop resolution matching the settled local window size")
	clipboard := f.String("clipboard", "off", "session-wide clipboard synchronization: off, both, to-remote or to-local (includes unfocused windows)")
	clipboardFileLimit := f.Uint64("clipboard-file-limit", 0, "enable remote-to-local file clipboard with this aggregate byte limit; zero disables files; requires both or to-local")
	clipboardUploadLimit := f.Uint64("clipboard-upload-limit", 0, "enable local-to-remote file clipboard with this aggregate byte limit including retained sources; zero disables upload; requires both or to-remote")
	timeout := f.Duration("connect-timeout", 15*time.Second, "connection and authentication deadline")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *addr == "" || *user == "" || *passwordEnv == "" || *width < 200 || *height < 200 || *width > 8192 || *height > 8192 || *timeout <= 0 {
		return errors.New("supply addr/user and valid dimensions/timeout")
	}
	profile, err := rdpgfx.ParseProfile(*profileName)
	if err != nil {
		return err
	}
	if !*gfx && profile != rdpgfx.ProfileThinClient {
		return errors.New("graphics-profile requires graphics-pipeline")
	}
	clipboardMode, err := clipsync.ParseMode(*clipboard)
	if err != nil {
		return err
	}
	var clipboardFiles *clipsync.FileOptions
	if *clipboardFileLimit != 0 {
		if clipboardMode&clipsync.ToLocal == 0 || *clipboardFileLimit > math.MaxInt64 {
			return errors.New("clipboard-file-limit requires to-local or both and a limit no greater than 9223372036854775807")
		}
		clipboardFiles = &clipsync.FileOptions{MaxTotalSize: *clipboardFileLimit}
	}
	var clipboardUpload *clipsync.FileOptions
	if *clipboardUploadLimit != 0 {
		if clipboardMode&clipsync.ToRemote == 0 || *clipboardUploadLimit > math.MaxInt64 {
			return errors.New("clipboard-upload-limit requires to-remote or both and a limit no greater than 9223372036854775807")
		}
		clipboardUpload = &clipsync.FileOptions{MaxTotalSize: *clipboardUploadLimit}
	}
	if runtime.GOOS != "windows" {
		return nativeview.ErrUnsupported
	}
	password, ok := os.LookupEnv(*passwordEnv)
	if !ok {
		return errors.New("password environment variable is not set")
	}
	opts := rdp.Options{CertificateSHA256: *pin, HandshakeTimeout: *timeout, BulkCompression: true, NewPointer: true, LargePointer: true, DrawingOrders: true, BitmapCacheV2: true, BitmapCacheV3: true, SurfaceCommands: true, NSCodec: true, BrushCache: true, OffscreenCache: true, ExtendedOrders: true, ShapeOrders: true, GlyphCache: true, GlyphCacheV2: true, GraphicsPipeline: *gfx}
	opts.DynamicChannels = nativeChannels(*gfx, *resize)
	settings := gcc.ClientSettings{Width: uint16(*width), Height: uint16(*height), ColorDepth: 32}
	configureClipboard(&opts, &settings, clipboardMode)
	s, err := rdp.DialSession(ctx, *addr, rdp.Credentials{Username: *user, Domain: *domain, Password: password}, opts, settings)
	password = ""
	if err != nil {
		return err
	}
	defer s.Close()
	return nativeview.Run(ctx, s, nativeview.Options{Title: "rdp-go — " + *addr, GraphicsProfile: profile, LocalCandidateUI: *candidateUI, Fullscreen: *fullscreen, DynamicResolution: *resize, ClipboardMode: clipboardMode, ClipboardFiles: clipboardFiles, ClipboardUpload: clipboardUpload})
}

func configureClipboard(o *rdp.Options, s *gcc.ClientSettings, mode clipsync.Mode) {
	if mode == clipsync.Off {
		return
	}
	s.Channels = append(s.Channels, gcc.Channel{Name: "cliprdr", Options: gcc.ChannelShowProtocol | 0x80000000})
	if o.StaticChannelLimits == nil {
		o.StaticChannelLimits = make(map[string]int)
	}
	o.StaticChannelLimits["cliprdr"] = cliprdr.MaxMessage
}

func nativeChannels(gfx, resize bool) *rdp.DynamicChannelOptions {
	if !gfx && !resize {
		return nil
	}
	listeners := make(map[string]int)
	budget := dynvc.MaxBuffered
	if resize {
		listeners[disp.ChannelName] = 56 // incoming caps and outgoing layout
	}
	if gfx {
		listeners[rdpgfx.ChannelName] = rdpgfx.MaxWireMessage
		budget = dynvc.HardLimit
	}
	return &rdp.DynamicChannelOptions{Listeners: listeners, MaxBuffered: budget}
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
