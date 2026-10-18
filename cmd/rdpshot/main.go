// rdpshot captures RDP bitmaps and basic drawing orders into a PNG without input.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image/png"
	"io"
	"os"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/bulk"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/graphics"
	"github.com/hq0101/rdp-go/internal/gatewayconfig"
	"github.com/hq0101/rdp-go/internal/kdcproxyconfig"
	"github.com/hq0101/rdp-go/internal/licenseconfig"
	"github.com/hq0101/rdp-go/internal/redirectconfig"
	"github.com/hq0101/rdp-go/rdpgfx"
)

func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("rdpshot", flag.ContinueOnError)
	f.SetOutput(stderr)
	addr := f.String("addr", "", "server:3389")
	user := f.String("user", "", "account name")
	domain := f.String("domain", "", "domain or computer name")
	pin := f.String("cert-sha256", "", "independently verified leaf SHA-256; otherwise system CA verification")
	passwordEnv := f.String("password-env", "OPENRDP_PASSWORD", "local password environment variable")
	redirectFile := f.String("redirection-config", "", "explicit local JSON hop plan; fresh capture window after each target switch")
	output := f.String("out", "", "PNG file to create (must not exist)")
	timeout := f.Duration("timeout", 30*time.Second, "total connection/capture timeout")
	captureFor := f.Duration("capture-for", 10*time.Second, "receive updates for this long per activated target; total timeout still applies")
	bpp := f.Int("bpp", 32, "requested color depth: 15, 16, 24 or 32")
	width := f.Int("width", 1280, "requested desktop width")
	height := f.Int("height", 720, "requested desktop height")
	gfx := f.Bool("graphics-pipeline", false, "enable RDPGFX at 32 bpp")
	reliableUDP := f.Bool("reliable-udp", false, "manage DVCs and offer reliable UDP with Soft-Sync (requires graphics-pipeline)")
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
	spnego := f.Bool("spnego", false, "use SPNEGO NTLMv2; does not enable Kerberos")
	krbRealm := f.String("kerberos-realm", "", "explicit Kerberos realm; requires a direct KDC or HTTPS proxy")
	krbKDC := f.String("kerberos-kdc", "", "explicit KDC host:port; no NTLM fallback")
	krbSPN := f.String("kerberos-spn", "", "optional TERMSRV/host override")
	var proxyFlags kdcproxyconfig.Flags
	proxyFlags.Register(f, "kerberos-proxy-")
	var gatewayFlags gatewayconfig.Flags
	gatewayFlags.Register(f)
	var licensingFlags licenseconfig.Flags
	licensingFlags.Register(f)
	if err := f.Parse(args); err != nil {
		return err
	}
	proxyOptions, proxyErr := proxyFlags.Options(f)
	if proxyErr != nil {
		return proxyErr
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
	if *reliableUDP && !*gfx {
		return errors.New("reliable-udp requires graphics-pipeline")
	}
	profile, err := rdpgfx.ParseProfile(*gfxProfile)
	if err != nil {
		return err
	}
	if profile != rdpgfx.ProfileThinClient && !*gfx {
		return errors.New("graphics-profile requires -graphics-pipeline")
	}
	level, err := bulk.ParseLevel(*compressionLevel)
	if err != nil {
		return err
	}
	if *width < 200 || *width > 8192 || *height < 200 || *height > 8192 || *width**height > graphics.MaxPixels {
		return errors.New("invalid desktop dimensions")
	}
	gatewayConfig, err := gatewayFlags.Config(f)
	if err != nil {
		return err
	}
	initialLicensing, err := licensingFlags.Config(f, "session", *user)
	if err != nil {
		return err
	}
	password, ok := os.LookupEnv(*passwordEnv)
	if *addr == "" || *user == "" || *output == "" || !ok || *timeout <= 0 || *captureFor <= 0 || f.NArg() != 0 {
		return errors.New("provide -addr, -user, -out, positive timeouts and a local password environment variable")
	}
	if _, err := os.Stat(*output); err == nil {
		return errors.New("output file already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	reporter := gatewayconfig.NewReporter(stderr)
	connections, err := redirectconfig.LoadConnections(ctx, *redirectFile, *addr, false, initialLicensing, *passwordEnv, redirectconfig.GatewaySetup{Config: gatewayConfig, Reporter: reporter, ApplyPolicy: gatewayconfig.NoLocalResources, ReliableUDP: *reliableUDP})
	if err != nil {
		return err
	}
	defer connections.Close()
	plan := connections.Plan
	if err := os.Unsetenv(*passwordEnv); err != nil {
		return errors.New("cannot clear initial password environment variable")
	}
	settings := gcc.ClientSettings{Width: uint16(*width), Height: uint16(*height), ColorDepth: uint16(*bpp)}
	if *gfx {
		settings.Channels = []gcc.Channel{{Name: "drdynvc", Options: 0x80000000}}
	}
	sessionOptions := rdp.Options{Gateway: connections.Gateway, Licensing: connections.Licensing, SPNEGO: *spnego, Kerberos: kerberosOptions, NetworkAutoDetect: *networkDetection, Heartbeat: *heartbeat, GraphicsPipeline: *gfx, BulkCompression: *compression, BulkCompressionLevel: level, NewPointer: *newPointer, LargePointer: *largePointer, CertificateSHA256: *pin, HandshakeTimeout: *timeout, DrawingOrders: *orders, BitmapCacheV2: *cacheV2, BitmapCacheV3: *cacheV3, SurfaceCommands: *surface, NSCodec: *nscodec, BrushCache: *brushCache, OffscreenCache: *offscreenCache, ExtendedOrders: *extended, ShapeOrders: *shapes, GlyphCache: *glyphCache, GlyphCacheV2: *glyphV2}
	if *reliableUDP || *gfx && (connections.Gateway != nil || plan != nil && plan.UsesGateway()) {
		sessionOptions.DynamicChannels = &rdp.DynamicChannelOptions{Listeners: map[string]int{rdpgfx.ChannelName: rdpgfx.MaxWireMessage}, MaxBuffered: dynvc.HardLimit, ReliableUDP: *reliableUDP}
	}
	credentials := rdp.Credentials{Username: *user, Domain: *domain, Password: password}
	var s *rdp.Session
	var follow captureFollow
	if plan != nil {
		settings.ServerRedirectionVersion = 6
		s, err = rdp.DialSessionWithRedirection(ctx, *addr, credentials, sessionOptions, settings, plan.Policy())
		follow = followCapture
	} else {
		s, err = rdp.DialSession(ctx, *addr, credentials, sessionOptions, settings)
	}
	password = ""
	credentials = rdp.Credentials{}
	if err != nil {
		return err
	}
	result, err := capture(ctx, s, captureOptions{duration: *captureFor, profile: profile, gatewayReporter: reporter}, follow, func(current captureRemote) {
		if *reliableUDP {
			v := current.DynamicInfo()
			fmt.Fprintf(stderr, "managed_udp negotiated=%t started=%t bound=%t synced=%t tcp_rx=%d tcp_tx=%d udp_rx=%d udp_tx=%d setup_error=%q\n", v.NegotiatedUDP, v.Started, v.Bound, v.SoftSynced, v.TCPReceived, v.TCPSent, v.UDPReceived, v.UDPSent, v.SetupError)
			fmt.Fprintf(stderr, "udp_transport=%+v\n", v.UDP)
		}
		logon, received := current.LastLogonInfo()
		fmt.Fprintf(stderr, "logon_notice=%t logon=%t type=%d warning=%t error_type=0x%x error_data=0x%x\n", received, logon.Logon, logon.Type, logon.ErrorNotification, logon.ErrorType, logon.ErrorData)
	})
	if err != nil {
		return err
	}
	return writeCapture(*output, result, stdout)
}

func writeCapture(output string, result *captureResult, stdout io.Writer) error {
	file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	encodeErr := png.Encode(file, result.image)
	closeErr := file.Close()
	if encodeErr != nil {
		return fmt.Errorf("write PNG: %w", encodeErr)
	}
	if closeErr != nil {
		return closeErr
	}
	result.metadata["output"] = output
	return json.NewEncoder(stdout).Encode(result.metadata)
}
func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
