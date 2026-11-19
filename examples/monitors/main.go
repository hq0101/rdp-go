// monitors requests initial and/or sequential dynamic monitor layouts. It uses
// the RDPGO_* environment variables documented by examples/session. This
// Graphics mode can also capture completed output frames for each layout.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/disp"
	"github.com/hq0101/rdp-go/display"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/pdu"
	"github.com/hq0101/rdp-go/rdpgfx"
	"github.com/hq0101/rdp-go/vchan"
)

type layoutPaths []string

func (p *layoutPaths) String() string { return fmt.Sprint([]string(*p)) }
func (p *layoutPaths) Set(v string) error {
	if len(*p) >= 16 {
		return errors.New("at most 16 layout changes")
	}
	*p = append(*p, v)
	return nil
}

func readLayout(path string) ([]display.Monitor, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil {
		return nil, err
	}
	if len(b) > 65536 {
		return nil, errors.New("layout JSON exceeds 64 KiB")
	}
	var ms []display.Monitor
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&ms); err != nil {
		return nil, err
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return nil, errors.New("extra JSON after monitor array")
	}
	ms, _, err = display.Normalize(ms)
	return ms, err
}

// Layout ordering is not significant; primary identity and signed geometry are.
func matches(want []display.Monitor, got []pdu.Monitor) bool {
	if len(want) != len(got) {
		return false
	}
	used := make([]bool, len(got))
	for _, w := range want {
		found := false
		for i, g := range got {
			if !used[i] && w.Primary == g.Primary && w.Left == g.Left && w.Top == g.Top && int64(w.Left)+int64(w.Width)-1 == int64(g.Right) && int64(w.Top)+int64(w.Height)-1 == int64(g.Bottom) {
				used[i] = true
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func run(args []string, out io.Writer) error {
	f := flag.NewFlagSet("monitors", flag.ContinueOnError)
	initialPath := f.String("initial", "", "initial JSON array of display.Monitor values")
	var paths layoutPaths
	f.Var(&paths, "layout", "target monitor JSON; may be repeated for sequential changes")
	timeout := f.Duration("timeout", 60*time.Second, "total connection and geometry verification timeout")
	graphicsProfile := f.String("graphics-profile", "", "enable RDPGFX: thin, progressive, avc420 or avc444; empty uses basic Monitor Layout PDUs")
	captureDir := f.String("capture-dir", "", "create per-layout PNG files in this directory (graphics mode only; never overwrite)")
	settle := f.Duration("settle", 10*time.Second, "receive graphics updates after the first completed frame; this is an observation interval, not a Windows desktop-ready acknowledgement")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *timeout <= 0 || (*initialPath == "" && len(paths) == 0) {
		return errors.New("provide -initial and/or -layout JSON files and a positive timeout")
	}
	var initial []display.Monitor
	var err error
	var profile rdpgfx.Profile
	if *graphicsProfile != "" {
		profile, err = rdpgfx.ParseProfile(*graphicsProfile)
		if err != nil {
			return err
		}
	}
	if *settle < 0 || (*captureDir != "" && *graphicsProfile == "") {
		return errors.New("settle must be nonnegative; capture-dir requires graphics-profile")
	}
	if *initialPath != "" {
		initial, err = readLayout(*initialPath)
		if err != nil {
			return fmt.Errorf("initial layout: %w", err)
		}
	}
	var layouts [][]display.Monitor
	for _, path := range paths {
		ms, e := readLayout(path)
		if e != nil {
			return fmt.Errorf("target layout: %w", e)
		}
		layouts = append(layouts, ms)
	}
	if *captureDir != "" {
		if err := prepareCaptures(*captureDir, len(layouts)); err != nil {
			return err
		}
	}
	address, username := os.Getenv("RDPGO_ADDR"), os.Getenv("RDPGO_USER")
	password, ok := os.LookupEnv("RDPGO_PASSWORD")
	os.Unsetenv("RDPGO_PASSWORD")
	if address == "" || username == "" || !ok {
		return errors.New("set RDPGO_ADDR, RDPGO_USER and RDPGO_PASSWORD")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	settings := gcc.ClientSettings{Monitors: initial, Channels: []gcc.Channel{{Name: "drdynvc", Options: 0x80000000}}}
	if *graphicsProfile != "" {
		settings.ColorDepth = 32
	}
	s, err := rdp.DialSession(ctx, address, rdp.Credentials{Username: username, Domain: os.Getenv("RDPGO_DOMAIN"), Password: password}, rdp.Options{CertificateSHA256: os.Getenv("RDPGO_CERT_SHA256"), GraphicsPipeline: *graphicsProfile != ""}, settings)
	password = ""
	if err != nil {
		return err
	}
	defer s.Close()
	if *graphicsProfile != "" {
		return runGraphics(ctx, s, initial, layouts, profile, *captureDir, *settle, out)
	}
	id, _ := s.ChannelID("drdynvc")
	dynamic, err := dynvc.New(disp.ChannelName)
	if err != nil {
		return err
	}
	var decoder vchan.Decoder
	var control disp.Client
	var controlID uint32
	initialDone := len(initial) == 0
	next, sent := 0, false
	changed := false
	emit := func(phase string, requested []display.Monitor) error {
		info := s.Info()
		_, bounds, err := display.Normalize(requested)
		if err != nil {
			return err
		}
		if !info.Active || int(info.Width) != bounds.Dx() || int(info.Height) != bounds.Dy() {
			return fmt.Errorf("server activation differs from monitor bounds: %dx%d, active=%t", info.Width, info.Height, info.Active)
		}
		return json.NewEncoder(out).Encode(map[string]any{"phase": phase, "geometry_confirmed": true, "width": info.Width, "height": info.Height, "monitors": s.MonitorLayout(), "dpi_confirmed": false, "notice": "Monitor Layout confirms geometry only; DPI/orientation attributes have no acknowledgement."})
	}
	for {
		if !initialDone && len(s.MonitorLayout()) > 0 {
			if !matches(initial, s.MonitorLayout()) {
				return fmt.Errorf("server initial geometry differs: %+v", s.MonitorLayout())
			}
			initialDone = true
			if err := emit("initial", initial); err != nil {
				return err
			}
		}
		if initialDone && next == len(layouts) {
			return nil
		}
		if initialDone && control.Ready() && !sent {
			b, err := control.LayoutMonitors(layouts[next])
			if err != nil {
				return err
			}
			packets, err := dynamic.Send(controlID, b)
			if err != nil {
				return err
			}
			for _, packet := range packets {
				if err := s.WriteChannel(ctx, id, packet); err != nil {
					return err
				}
			}
			sent = true
			changed = false
		}
		e, err := s.ReadEvent(ctx)
		if err != nil {
			return fmt.Errorf("await server topology (target %d): %w", next, err)
		}
		if sent && e.Kind == rdp.EventDeactivated {
			changed = true
		}
		if sent && changed && e.Kind == rdp.EventData && e.DataType == pdu.MonitorLayout {
			if !matches(layouts[next], s.MonitorLayout()) {
				return fmt.Errorf("server target geometry differs: %+v", s.MonitorLayout())
			}
			if err := emit(fmt.Sprintf("layout-%d", next+1), layouts[next]); err != nil {
				return err
			}
			next++
			sent = false
		}
		if e.Kind != rdp.EventData || e.Channel != id || e.DataType != 0 {
			continue
		}
		b, complete, err := decoder.Feed(e.Payload)
		if err != nil {
			return err
		}
		if !complete {
			continue
		}
		replies, event, err := dynamic.Handle(b)
		if err != nil {
			return err
		}
		for _, reply := range replies {
			if err := s.WriteChannel(ctx, id, reply); err != nil {
				return err
			}
		}
		if event.Name != disp.ChannelName {
			continue
		}
		switch event.Kind {
		case dynvc.Opened:
			control = disp.Client{}
			controlID = event.ID
		case dynvc.Closed:
			return errors.New("server closed DisplayControl")
		case dynvc.Data:
			if err := control.Handle(event.Data); err != nil {
				return err
			}
		}
	}
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
