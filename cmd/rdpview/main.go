// rdpview exposes one RDP session to an authenticated loopback-only browser UI.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/bulk"
	"github.com/hq0101/rdp-go/cliprdr"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/graphics"
	"github.com/hq0101/rdp-go/internal/gatewayconfig"
	"github.com/hq0101/rdp-go/internal/kdcproxyconfig"
	"github.com/hq0101/rdp-go/internal/licenseconfig"
	"github.com/hq0101/rdp-go/internal/redirectconfig"
	"github.com/hq0101/rdp-go/rail"
	"github.com/hq0101/rdp-go/rdgateway"
	"github.com/hq0101/rdp-go/rdpgfx"
)

func run(args []string) (runErr error) {
	f := flag.NewFlagSet("rdpview", flag.ContinueOnError)
	addr := f.String("addr", "", "RDP server:3389")
	user := f.String("user", "", "account name")
	domain := f.String("domain", "", "domain or computer name")
	pin := f.String("cert-sha256", "", "verified server certificate SHA-256")
	passwordEnv := f.String("password-env", "RDPGO_PASSWORD", "local password environment variable")
	redirectFile := f.String("redirection-config", "", "explicit local JSON hop plan; target credentials remain in memory until viewer exit")
	ready := f.String("ready-file", "", "optional new JSON file for the local viewer URL")
	appName := f.String("remote-app", "", "published RemoteApp alias (for example ||notepad) or server executable; starts once after the initial handshake")
	appArgs := f.String("remote-app-args", "", "verbatim remote application arguments")
	appDir := f.String("remote-app-dir", "", "remote application working directory")
	appTextScale := f.String("remote-app-text-scale", "", "explicit RemoteApp text scale: 100..225 percent, sent only if supported")
	appCaretWidth := f.String("remote-app-caret-width", "", "explicit RemoteApp caret width in pixels, at least 1, sent only if supported")
	appCaretBlink := f.String("remote-app-caret-blink", "", "explicit RemoteApp caret interval in milliseconds, or off; sent only if supported")
	width := f.Int("width", 1280, "requested remote desktop width in pixels")
	height := f.Int("height", 720, "requested remote desktop height in pixels")
	bpp := f.Int("bpp", 32, "requested color depth: 15, 16, 24 or 32")
	reliableUDP := f.Bool("reliable-udp", false, "manage DVCs and offer reliable UDP with Soft-Sync (requires graphics-pipeline)")
	gfx := f.Bool("graphics-pipeline", false, "enable RDPGFX Version 8 at 32 bpp")
	gfxProfile := f.String("graphics-profile", "thin", "RDPGFX profile: thin, progressive, avc420 or avc444 (requires -graphics-pipeline)")
	orders := f.Bool("drawing-orders", true, "enable basic GDI orders and volatile bitmap caching at 24/32 bpp")
	compression := f.Bool("bulk-compression", true, "enable negotiated RDP bulk compression")
	compressionLevel := f.String("bulk-compression-level", "auto", "maximum package: auto, 8k, 64k, rdp6 or rdp61")
	networkDetection := f.Bool("network-detection", false, "respond to RTT/bandwidth probes (also enabled by graphics-pipeline)")
	heartbeat := f.Bool("heartbeat", false, "receive server heartbeat hints without automatic disconnect")
	newPointer := f.Bool("new-pointer", true, "enable arbitrary-depth and alpha pointers")
	largePointer := f.Bool("large-pointer", true, "enable negotiated 96/384 pixel pointers")
	shapes := f.Bool("shape-orders", true, "enable solid/pattern polygon and ellipse drawing")
	glyphCache := f.Bool("glyph-cache", true, "enable glyph and text fragment caching")
	glyphV2 := f.Bool("glyph-cache-v2", true, "request compact Revision 2 glyph cache encoding")
	extended := f.Bool("extended-orders", true, "enable multi-rectangle orders, solid LineTo and Polyline")
	brushCache := f.Bool("brush-cache", true, "enable cached 8x8 mono/color pattern brushes")
	offscreenCache := f.Bool("offscreen-cache", true, "enable bounded writable offscreen bitmap caching")
	cacheV2 := f.Bool("bitmap-cache-v2", true, "prefer volatile Revision 2 bitmap caching when supported")
	cacheV3 := f.Bool("bitmap-cache-v3", true, "enable volatile Revision 3 codec-aware bitmap caching when supported")
	surface := f.Bool("surface-commands", true, "enable raw Surface Commands and frame acknowledgement at 32 bpp")
	nscodec := f.Bool("nscodec", true, "enable NSCodec Surface bitmaps with minimum color loss and no subsampling")
	autoReconnect := f.Bool("auto-reconnect", false, "recover network failures; retain supplied credentials in process memory until viewer exit")
	microphone := f.Bool("microphone", false, "offer a virtual PCM microphone; browser capture requires an explicit click and permission")
	clipboard := f.Bool("clipboard", false, "enable text/HTML/image clipboard actions (initially publishes an empty clipboard)")
	clipboardFiles := f.Bool("clipboard-files", false, "enable explicit file upload and ZIP download (implies -clipboard; max 64 MiB / 128 entries)")
	audio := f.Bool("audio", false, "enable PCM/ADPCM audio redirection; browser playback starts only after clicking Enable sound")
	driveDir := f.String("drive-dir", "", "share exactly this local directory; disabled by default")
	driveName := f.String("drive-name", "FILES", "remote share name: 1..7 ASCII letters, digits or underscores")
	driveWritable := f.Bool("drive-writable", false, "allow remote writes/deletes inside the selected directory")
	driveCompatibility := f.Bool("drive-windows-compat", false, "use tested Windows 10 ASCII share names and lock flag semantics")
	dynamicDisplay := f.Bool("dynamic-display", true, "enable single-monitor resolution changes during the session")
	spnego := f.Bool("spnego", false, "use SPNEGO with NTLMv2 and mechanism-list MICs; does not enable Kerberos")
	krbRealm := f.String("kerberos-realm", "", "explicit Kerberos realm; requires a direct KDC or HTTPS proxy; no NTLM fallback")
	krbKDC := f.String("kerberos-kdc", "", "Kerberos KDC host:port, normally port 88")
	krbSPN := f.String("kerberos-spn", "", "optional TERMSRV/host override; requires realm and KDC/proxy")
	var proxyFlags kdcproxyconfig.Flags
	proxyFlags.Register(f, "kerberos-proxy-")
	var gatewayFlags gatewayconfig.Flags
	gatewayFlags.Register(f)
	var licensingFlags licenseconfig.Flags
	licensingFlags.Register(f)
	if err := f.Parse(args); err != nil {
		return err
	}
	appRequest := rail.ExecuteRequest{ExeOrFile: *appName, Arguments: *appArgs, WorkingDirectory: *appDir}
	if *appName != "" {
		if _, err := rail.EncodeExecute(appRequest); err != nil {
			return err
		}
		if !*orders || (*bpp != 24 && *bpp != 32) {
			return errors.New("remote-app requires drawing-orders at 24/32 bpp")
		}
	} else if *appArgs != "" || *appDir != "" {
		return errors.New("remote-app arguments require remote-app")
	}
	appPreferences, preferencesErr := parseAppPreferences(*appName != "", *appTextScale, *appCaretWidth, *appCaretBlink)
	if preferencesErr != nil {
		return preferencesErr
	}
	proxyOptions, proxyErr := proxyFlags.Options(f)
	if proxyErr != nil {
		return proxyErr
	}
	gatewayConfig, err := gatewayFlags.Config(f)
	if err != nil {
		return err
	}
	var kerberosOptions *rdp.KerberosOptions
	if *krbRealm != "" || *krbKDC != "" || *krbSPN != "" || proxyOptions != nil {
		if *krbRealm == "" || ((*krbKDC != "") == (proxyOptions != nil)) {
			return errors.New("Kerberos requires -kerberos-realm and -kerberos-kdc, or -kerberos-proxy-url instead of -kerberos-kdc (exactly one transport)")
		}
		kerberosOptions = &rdp.KerberosOptions{Realm: *krbRealm, KDC: *krbKDC, ServicePrincipal: *krbSPN, Proxy: proxyOptions}
	}
	if *bpp != 15 && *bpp != 16 && *bpp != 24 && *bpp != 32 {
		return errors.New("color depth must be 15, 16, 24 or 32")
	}
	profile, err := rdpgfx.ParseProfile(*gfxProfile)
	if err != nil {
		return err
	}
	if profile != rdpgfx.ProfileThinClient && !*gfx {
		return errors.New("graphics-profile requires -graphics-pipeline")
	}
	if *width < 200 || *height < 200 || *width > 8192 || *height > 8192 || *width**height > graphics.MaxPixels {
		return errors.New("desktop dimensions must be 200..8192 pixels per side and at most 16M pixels in total")
	}
	level, err := bulk.ParseLevel(*compressionLevel)
	if err != nil {
		return err
	}
	dynamicOptions, err := viewerDynamicOptions(*reliableUDP, *gfx, *dynamicDisplay, *microphone)
	if err != nil {
		return err
	}
	driveConfig, err := prepareViewerDrive(*driveDir, *driveName, *driveWritable, *driveCompatibility)
	if err != nil {
		return err
	}
	if driveConfig != nil {
		defer driveConfig.anchor.Close()
	}
	initialLicensing, err := licensingFlags.Config(f, "session", *user)
	if err != nil {
		return err
	}
	password, ok := os.LookupEnv(*passwordEnv)
	if *addr == "" || *user == "" || !ok || f.NArg() != 0 {
		return errors.New("provide -addr, -user and a local password environment variable")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	gatewayAccess := &viewerGatewayAccess{}
	gatewayReporter := gatewayconfig.NewReporter(os.Stderr)
	connections, err := redirectconfig.LoadConnections(ctx, *redirectFile, *addr, *clipboard || *clipboardFiles || *audio || *microphone || driveConfig != nil, initialLicensing, *passwordEnv, redirectconfig.GatewaySetup{Config: gatewayConfig, Reporter: gatewayReporter, ApplyPolicy: gatewayAccess.prepare, ReliableUDP: *reliableUDP})
	if err != nil {
		return err
	}
	defer connections.Close()
	plan, licenseOptions := connections.Plan, connections.Licensing
	if connections.Gateway != nil || plan != nil && plan.UsesGateway() {
		dynamicOptions, err = viewerGatewayDynamicOptions(*reliableUDP, *gfx, *dynamicDisplay, *microphone, true)
		if err != nil {
			return err
		}
	}
	// The password is never included in HTTP responses, URLs or logs.
	if err := os.Unsetenv(*passwordEnv); err != nil {
		return err
	}
	settings := gcc.ClientSettings{Width: uint16(*width), Height: uint16(*height), ColorDepth: uint16(*bpp)}
	var clipboardLimits map[string]int
	if *clipboard || *clipboardFiles {
		clipboardLimits = map[string]int{"cliprdr": cliprdr.MaxMessage}
		settings.Channels = []gcc.Channel{{Name: "cliprdr", Options: 0x80000000 | gcc.ChannelShowProtocol}}
	}
	if *dynamicDisplay || *gfx {
		settings.Channels = append(settings.Channels, gcc.Channel{Name: "drdynvc", Options: 0x80000000})
	}
	clipboardLimits = viewerDeviceChannels(&settings, clipboardLimits, *audio, driveConfig != nil)
	sessionOptions := rdp.Options{Gateway: connections.Gateway, Licensing: licenseOptions, Kerberos: kerberosOptions, SPNEGO: *spnego, StaticChannelLimits: clipboardLimits, AudioCapture: *microphone, AudioPlayback: *audio, DynamicChannels: dynamicOptions, NetworkAutoDetect: *networkDetection, Heartbeat: *heartbeat, AutoReconnect: *autoReconnect, GraphicsPipeline: *gfx, BulkCompression: *compression, BulkCompressionLevel: level, NewPointer: *newPointer, LargePointer: *largePointer, CertificateSHA256: *pin, HandshakeTimeout: 30 * time.Second, DrawingOrders: *orders, BitmapCacheV2: *cacheV2, BitmapCacheV3: *cacheV3, SurfaceCommands: *surface, NSCodec: *nscodec, BrushCache: *brushCache, OffscreenCache: *offscreenCache, ExtendedOrders: *extended, ShapeOrders: *shapes, GlyphCache: *glyphCache, GlyphCacheV2: *glyphV2}
	if *appName != "" {
		settings.Channels = append([]gcc.Channel{{Name: "rail", Options: 0x80000000}}, settings.Channels...)
		sessionOptions.RemoteApp = &rdp.RemoteAppOptions{Cloaking: true, Enhanced: *gfx, HandshakeEx: true, ExtendedWindows: true, IconCaches: 3, IconEntries: 12}
		if sessionOptions.StaticChannelLimits == nil {
			sessionOptions.StaticChannelLimits = make(map[string]int)
		}
		sessionOptions.StaticChannelLimits["rail"] = rail.MaxMessage
	}
	credentials := rdp.Credentials{Username: *user, Domain: *domain, Password: password}
	var s *rdp.Session
	if plan != nil {
		settings.ServerRedirectionVersion = 6
		s, err = rdp.DialSessionWithRedirection(ctx, *addr, credentials, sessionOptions, settings, plan.Policy())
	} else {
		s, err = rdp.DialSession(ctx, *addr, credentials, sessionOptions, settings)
	}
	credentials = rdp.Credentials{}
	var stored *credentialsStore
	if *autoReconnect && err == nil {
		stored = &credentialsStore{}
		if s.RedirectionInfo().Hops == 0 {
			stored.value = rdp.Credentials{Username: *user, Domain: *domain, Password: password}
		}
		defer stored.clear()
	}
	password = ""
	if err != nil {
		return err
	}
	defer s.Close()
	setupCtx, setupCancel := context.WithTimeout(ctx, 5*time.Second)
	if s.Info().SuppressOutput {
		err = s.SetDisplayUpdates(setupCtx, true)
	}
	if err == nil && s.Info().RefreshRect {
		err = s.Refresh(setupCtx)
	}
	setupCancel()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return err
	}
	token := base64.RawURLEncoding.EncodeToString(secret[:])
	v, err := newViewer(s, s.Info(), listener.Addr().String(), token, cancel)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, v.stopGatewayServices()) }()
	if err := v.configureGateway(ctx, gatewayAccess, gatewayReporter); err != nil {
		return err
	}
	if err := v.configureFileClipboard(*clipboardFiles); err != nil {
		return err
	}
	if err := v.configureChannels(profile, *dynamicDisplay); err != nil {
		return err
	}
	if err := v.configureDrive(driveConfig); err != nil {
		return err
	}
	if *appName != "" {
		if err := v.configureRemoteApp(appRequest, true); err != nil {
			return err
		}
		if err := v.configureAppPreferences(appPreferences); err != nil {
			return err
		}
	}
	configureTransitions(v, stored, plan)
	receiveDone := make(chan struct{})
	go func() { defer close(receiveDone); v.receive(ctx) }()
	defer func() { cancel(); v.closeRemote(); <-receiveDone }()
	go v.publish(ctx)
	go v.watch(ctx)
	go v.watchAudio(ctx)
	if *microphone {
		go v.watchCapture(ctx)
	}
	server := &http.Server{Handler: v, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 8192}
	go func() {
		<-ctx.Done()
		v.closeRemote()
		shutdownCtx, done := context.WithTimeout(context.Background(), 2*time.Second)
		defer done()
		server.Shutdown(shutdownCtx)
	}()
	url := "http://" + listener.Addr().String() + "/#" + token
	metadata := struct {
		Gateway              *rdgateway.Info      `json:"gateway,omitempty"`
		Resources            rdp.SessionResources `json:"resources"`
		Licensing            rdp.LicensingState   `json:"licensing"`
		DriveRequested       bool                 `json:"drive_requested"`
		MicrophoneRequested  bool                 `json:"microphone_requested"`
		AudioRequested       bool                 `json:"audio_requested"`
		ReliableUDPRequested bool                 `json:"reliable_udp_requested"`
		AutoReconnect        bool                 `json:"auto_reconnect"`
		Redirection          bool                 `json:"redirection"`
		RedirectionHops      int                  `json:"redirection_hops"`
		BulkCompressionType  byte                 `json:"bulk_compression_type"`
		BulkCompression      bool                 `json:"bulk_compression"`
		NewPointer           bool                 `json:"new_pointer"`
		LargePointerFlags    uint16               `json:"large_pointer_flags"`
		URL                  string               `json:"url"`
		PID                  int                  `json:"pid"`
		Width                uint16               `json:"width"`
		Height               uint16               `json:"height"`
		BitsPerPixel         uint16               `json:"bits_per_pixel"`
		DrawingOrders        bool                 `json:"drawing_orders"`
		BitmapCacheV2        bool                 `json:"bitmap_cache_v2"`
		SurfaceCommands      bool                 `json:"surface_commands"`
		FrameAcknowledge     bool                 `json:"frame_acknowledge"`
		NSCodec              bool                 `json:"nscodec"`
		BitmapCacheV3        bool                 `json:"bitmap_cache_v3"`
		BrushCache           bool                 `json:"brush_cache"`
		OffscreenCache       bool                 `json:"offscreen_cache"`
		ExtendedOrders       bool                 `json:"extended_orders"`
		ShapeOrders          bool                 `json:"shape_orders"`
		GlyphCache           bool                 `json:"glyph_cache"`
		GlyphCacheV2         bool                 `json:"glyph_cache_v2"`
	}{gatewayconfig.Info(s), s.Resources(), s.LicensingState(), driveConfig != nil, *microphone, *audio, *reliableUDP, *autoReconnect, plan != nil, s.RedirectionInfo().Hops, s.Info().BulkCompressionType, s.Info().BulkCompression, s.Info().NewPointer, s.Info().LargePointerFlags, url, os.Getpid(), s.Info().Width, s.Info().Height, s.Info().BitsPerPixel, s.Info().DrawingOrders, s.Info().BitmapCacheV2, s.Info().SurfaceCommands, s.Info().FrameAcknowledge, s.Info().NSCodec, s.Info().BitmapCacheV3, s.Info().BrushCache, s.Info().OffscreenCache, s.Info().ExtendedOrders, s.Info().ShapeOrders, s.Info().GlyphCache, s.Info().GlyphCacheV2}
	if *ready != "" {
		f, err := os.OpenFile(*ready, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		writeErr := json.NewEncoder(f).Encode(metadata)
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	} else {
		if err := json.NewEncoder(os.Stdout).Encode(metadata); err != nil {
			return err
		}
	}
	fmt.Fprintln(os.Stderr, "viewer ready; waiting up to 30 minutes for first page access; use Disconnect to end the session")
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		err = nil
	}
	fmt.Fprintln(os.Stderr, "viewer stopped; RDP connection closed")
	return err
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
