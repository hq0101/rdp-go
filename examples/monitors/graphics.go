package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/disp"
	"github.com/hq0101/rdp-go/display"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/pdu"
	"github.com/hq0101/rdp-go/rdpgfx"
	"github.com/hq0101/rdp-go/vchan"
)

func phaseName(index int) string {
	if index == 0 {
		return "initial"
	}
	return fmt.Sprintf("layout-%d", index)
}

func prepareCaptures(dir string, changes int) error {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	for i := 0; i <= changes; i++ {
		_, err := os.Stat(filepath.Join(dir, phaseName(i)+".png"))
		if err == nil {
			return errors.New("capture file already exists")
		}
		if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func saveCapture(dir, phase string, img image.Image) (string, error) {
	if dir == "" {
		return "", nil
	}
	path, err := filepath.Abs(filepath.Join(dir, phase+".png"))
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	encodeErr := png.Encode(f, img)
	closeErr := f.Close()
	return path, errors.Join(encodeErr, closeErr)
}

// A matching geometry left over from an earlier request is not confirmation.
// RESET must arrive after the phase begins, then a complete frame must follow
// that RESET. A same-size RESET invalidates the previously completed image.
type graphicsProgress struct {
	want           []display.Monitor
	resetBaseline  uint64
	matched, ready bool
}

func graphicsMonitors(ms []rdpgfx.Monitor) []pdu.Monitor {
	result := make([]pdu.Monitor, len(ms))
	for i, m := range ms {
		result[i] = pdu.Monitor{Left: m.Left, Top: m.Top, Right: m.Right, Bottom: m.Bottom, Primary: m.Flags&1 != 0}
	}
	return result
}

func (p *graphicsProgress) observe(r rdpgfx.Result, resets uint64, monitors []rdpgfx.Monitor) {
	if r.Resized {
		p.matched, p.ready = false, false
		if resets > p.resetBaseline {
			if len(p.want) == 0 {
				p.matched = len(monitors) > 0
			} else {
				_, bounds, err := display.Normalize(p.want)
				p.matched = err == nil && r.Width == bounds.Dx() && r.Height == bounds.Dy() && matches(p.want, graphicsMonitors(monitors))
			}
		}
	}
	if r.FrameReady && p.matched {
		p.ready = true
	}
}

func runGraphics(ctx context.Context, s *rdp.Session, initial []display.Monitor, layouts [][]display.Monitor, profile rdpgfx.Profile, captureDir string, settle time.Duration, out io.Writer) error {
	id, _ := s.ChannelID("drdynvc")
	dynamic, err := dynvc.NewWithLimits(map[string]int{disp.ChannelName: 4096, rdpgfx.ChannelName: rdpgfx.MaxWireMessage}, dynvc.HardLimit)
	if err != nil {
		return err
	}
	var decoder vchan.Decoder
	var control disp.Client
	var controlID uint32
	gfx := rdpgfx.Client{Profile: profile}
	phase, sent := 0, true // always observe initial RESET/frame, even without -initial
	progress := graphicsProgress{want: initial}
	var timer *time.Timer
	var timerC <-chan time.Time
	stopTimer := func() {
		if timer != nil {
			timer.Stop()
		}
		timer, timerC = nil, nil
	}
	defer stopTimer()
	// Do not poll ReadEvent with short deadlines: an interrupted packet closes
	// the connection. The reader blocks normally while the settle timer runs.
	// It waits for acknowledgement after each event so the consumer can apply
	// RESET before the next ReadEvent changes session activation state.
	readCtx, cancel := context.WithCancel(ctx)
	type received struct {
		event rdp.Event
		err   error
	}
	events := make(chan received)
	advance, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for {
			e, err := s.ReadEvent(readCtx)
			select {
			case events <- received{e, err}:
			case <-readCtx.Done():
				return
			}
			if err != nil {
				return
			}
			select {
			case <-advance:
			case <-readCtx.Done():
				return
			}
		}
	}()
	defer func() { cancel(); s.Close(); <-done }()
	write := func(packets [][]byte) error {
		for _, packet := range packets {
			if err := s.WriteChannel(ctx, id, packet); err != nil {
				return err
			}
		}
		return nil
	}
	deactivations := 0
	for {
		if !sent && control.Ready() && s.Info().Active {
			b, err := control.LayoutMonitors(layouts[phase-1])
			if err != nil {
				return err
			}
			packets, err := dynamic.Send(controlID, b)
			if err != nil {
				return err
			}
			progress = graphicsProgress{want: layouts[phase-1], resetBaseline: gfx.Stats().Resets}
			if err := write(packets); err != nil {
				return err
			}
			sent = true
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("await graphics %s (matching RESET=%t, complete frame=%t): %w", phaseName(phase), progress.matched, progress.ready, ctx.Err())
		case <-timerC:
			stopTimer()
			info := s.Info()
			if !sent || !progress.ready || !info.Active {
				continue
			}
			img := gfx.Snapshot()
			if img == nil || img.Bounds().Dx() != int(info.Width) || img.Bounds().Dy() != int(info.Height) {
				return errors.New("graphics/session output dimensions differ")
			}
			path, err := saveCapture(captureDir, phaseName(phase), img)
			if err != nil {
				return err
			}
			if err := json.NewEncoder(out).Encode(map[string]any{
				"phase": phaseName(phase), "geometry_source": "RDPGFX RESET", "geometry_confirmed": true,
				"width": info.Width, "height": info.Height, "monitors": gfx.Monitors(), "graphics": gfx.Stats(),
				"complete_frame": true, "deactivations": deactivations, "capture": path, "dpi_confirmed": false,
				"notice": "RESET confirms geometry only; DPI/orientation attributes have no acknowledgement. A completed protocol frame does not guarantee that the Windows desktop has settled.",
			}); err != nil {
				return err
			}
			if phase == len(layouts) {
				return nil
			}
			phase++
			sent = false
			progress = graphicsProgress{}
		case received := <-events:
			if received.err != nil {
				return fmt.Errorf("graphics %s: %w", phaseName(phase), received.err)
			}
			e := received.event
			err := func() error {
				if e.Kind == rdp.EventDeactivated {
					deactivations++
					progress.matched, progress.ready = false, false
					stopTimer()
				}
				if e.Kind != rdp.EventData || e.Channel != id || e.DataType != 0 {
					return nil
				}
				b, complete, err := decoder.Feed(e.Payload)
				if err != nil || !complete {
					return err
				}
				replies, event, err := dynamic.Handle(b)
				if err != nil {
					return err
				}
				if err := write(replies); err != nil {
					return err
				}
				switch event.Name {
				case disp.ChannelName:
					switch event.Kind {
					case dynvc.Opened:
						control, controlID = disp.Client{}, event.ID
					case dynvc.Closed:
						return errors.New("server closed DisplayControl")
					case dynvc.Data:
						return control.Handle(event.Data)
					}
				case rdpgfx.ChannelName:
					r, err := gfx.Handle(event)
					if err != nil {
						return err
					}
					if event.Kind == dynvc.Closed {
						return errors.New("server closed graphics channel during layout verification")
					}
					if r.Resized {
						if err := s.SetGraphicsOutputSize(ctx, r.Width, r.Height); err != nil {
							return err
						}
						stopTimer()
					}
					if sent {
						progress.observe(r, gfx.Stats().Resets, gfx.Monitors())
					}
					for _, reply := range r.Replies {
						packets, err := dynamic.Send(event.ID, reply)
						if err != nil {
							return err
						}
						if err := write(packets); err != nil {
							return err
						}
					}
					if sent && progress.ready && timer == nil && s.Info().Active {
						timer = time.NewTimer(settle)
						timerC = timer.C
					}
				}
				return nil
			}()
			if err != nil {
				return err
			}
			select {
			case advance <- struct{}{}:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
