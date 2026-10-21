// rdpnative presents one authenticated RDP desktop in a native Windows window.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"runtime"
	"time"

	rdp "github.com/hq0101/rdp-go"
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
	passwordEnv := f.String("password-env", "OPENRDP_PASSWORD", "password environment variable")
	width := f.Int("width", 1920, "remote desktop width")
	height := f.Int("height", 1080, "remote desktop height")
	gfx := f.Bool("graphics-pipeline", false, "enable managed RDPGFX")
	profileName := f.String("graphics-profile", "thin", "thin, progressive, avc420 or avc444")
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
	if runtime.GOOS != "windows" {
		return nativeview.ErrUnsupported
	}
	password, ok := os.LookupEnv(*passwordEnv)
	if !ok {
		return errors.New("password environment variable is not set")
	}
	opts := rdp.Options{CertificateSHA256: *pin, HandshakeTimeout: *timeout, BulkCompression: true, NewPointer: true, LargePointer: true, DrawingOrders: true, BitmapCacheV2: true, BitmapCacheV3: true, SurfaceCommands: true, NSCodec: true, BrushCache: true, OffscreenCache: true, ExtendedOrders: true, ShapeOrders: true, GlyphCache: true, GlyphCacheV2: true, GraphicsPipeline: *gfx}
	if *gfx {
		opts.DynamicChannels = &rdp.DynamicChannelOptions{Listeners: map[string]int{rdpgfx.ChannelName: rdpgfx.MaxWireMessage}}
	}
	s, err := rdp.DialSession(ctx, *addr, rdp.Credentials{Username: *user, Domain: *domain, Password: password}, opts, gcc.ClientSettings{Width: uint16(*width), Height: uint16(*height), ColorDepth: 32})
	password = ""
	if err != nil {
		return err
	}
	defer s.Close()
	return nativeview.Run(ctx, s, nativeview.Options{Title: "rdp-go — " + *addr, GraphicsProfile: profile})
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stderr); err != nil && !errors.Is(err, context.Canceled) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
