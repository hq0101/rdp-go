// resize demonstrates one single-monitor change on the existing RDP connection.
// It uses the same RDPGO_* environment variables as examples/session.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/disp"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/vchan"
)

func run() error {
	w := flag.Int("width", 1920, "target desktop width")
	h := flag.Int("height", 1080, "target desktop height")
	flag.Parse()
	if *w < 200 || *w > 8192 || *w%2 != 0 || *h < 200 || *h > 8192 || *w**h > disp.MaxPixels || flag.NArg() != 0 {
		return errors.New("invalid single-monitor dimensions")
	}
	address, username := os.Getenv("RDPGO_ADDR"), os.Getenv("RDPGO_USER")
	password, ok := os.LookupEnv("RDPGO_PASSWORD")
	os.Unsetenv("RDPGO_PASSWORD")
	if address == "" || username == "" || !ok {
		return errors.New("set RDPGO_ADDR, RDPGO_USER and RDPGO_PASSWORD")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := rdp.DialSession(ctx, address, rdp.Credentials{Username: username, Domain: os.Getenv("RDPGO_DOMAIN"), Password: password}, rdp.Options{CertificateSHA256: os.Getenv("RDPGO_CERT_SHA256")}, gcc.ClientSettings{Width: 1280, Height: 720, Channels: []gcc.Channel{{Name: "drdynvc", Options: 0x80000000}}})
	password = ""
	if err != nil {
		return err
	}
	defer s.Close()
	staticID, _ := s.ChannelID("drdynvc")
	dynamic, err := dynvc.New(disp.ChannelName)
	if err != nil {
		return err
	}
	var decoder vchan.Decoder
	var display disp.Client
	var displayID uint32
	sent := false
	for {
		e, err := s.ReadEvent(ctx)
		if err != nil {
			return err
		}
		if e.Kind == rdp.EventActivated && sent {
			if int(e.Info.Width) != *w || int(e.Info.Height) != *h {
				return fmt.Errorf("server used %dx%d instead of the requested size", e.Info.Width, e.Info.Height)
			}
			fmt.Printf("Resolution applied: %dx%d on the same connection\n", e.Info.Width, e.Info.Height)
			return nil
		}
		if e.Kind != rdp.EventData || e.Channel != staticID {
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
			if err := s.WriteChannel(ctx, staticID, reply); err != nil {
				return err
			}
		}
		switch event.Kind {
		case dynvc.Opened:
			displayID = event.ID
		case dynvc.Closed:
			return errors.New("server closed the display control channel")
		case dynvc.Data:
			if err := display.Handle(event.Data); err != nil {
				return err
			}
			if sent {
				continue
			}
			if info := s.Info(); int(info.Width) == *w && int(info.Height) == *h {
				fmt.Printf("Desktop is already %dx%d\n", *w, *h)
				return nil
			}
			layout, err := display.Layout(*w, *h)
			if err != nil {
				return err
			}
			packets, err := dynamic.Send(displayID, layout)
			if err != nil {
				return err
			}
			for _, packet := range packets {
				if err := s.WriteChannel(ctx, staticID, packet); err != nil {
					return err
				}
			}
			sent = true
			// Keep reading until actual activation; a successful write isn't an ACK.
		}
	}
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
