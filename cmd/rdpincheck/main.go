// rdpincheck verifies audio input using optional synthetic PCM, never a microphone.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image/png"
	"io"
	"math"
	"os"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/audin"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/graphics"
	"github.com/hq0101/rdp-go/pdu"
)

type report struct {
	Source                                                  string `json:"source"`
	Requested, Logon                                        bool
	Channels, Negotiations, Opens, Changes, Closes, Ignored int
	ServerVersion                                           uint32
	Formats                                                 []audin.Format
	Requests                                                []audin.Request
	Packets, PCMBytes                                       uint64
	PCMSeconds                                              float64
	LocalCloseRequests                                      int
	PacingResets                                            int
}

func tone(r audin.Request, start uint64) []byte {
	b := make([]byte, r.PacketBytes())
	for i := uint32(0); i < r.FramesPerPacket; i++ {
		x := int16(math.Round(4096 * math.Sin(2*math.Pi*440*float64(start+uint64(i))/float64(r.Format.SampleRate))))
		for ch := 0; ch < int(r.Format.Channels); ch++ {
			binary.LittleEndian.PutUint16(b[int(i)*r.Format.BlockAlign()+ch*2:], uint16(x))
		}
	}
	return b
}
func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("rdpincheck", flag.ContinueOnError)
	f.SetOutput(stderr)
	addr := f.String("addr", "", "server:3389")
	user := f.String("user", "", "account")
	domain := f.String("domain", "", "domain")
	pin := f.String("cert-sha256", "", "verified leaf SHA-256; otherwise system trust")
	passwordEnv := f.String("password-env", "RDPGO_PASSWORD", "local password environment variable")
	duration := f.Duration("duration", 20*time.Second, "duration after activation, maximum 2 minutes")
	timeout := f.Duration("timeout", 60*time.Second, "total timeout, maximum 3 minutes")
	synthetic := f.Bool("tone", false, "explicitly send a synthesized 440 Hz PCM tone after server Open")
	panel := f.Bool("open-recording-panel", false, "explicitly open Windows Sound Recording panel after login, then close it at exit")
	output := f.String("out", "", "optional new PNG path; also creates path.closed.png after cleanup")
	if err := f.Parse(args); err != nil {
		return err
	}
	password, ok := os.LookupEnv(*passwordEnv)
	if *addr == "" || *user == "" || !ok || *passwordEnv == "" || f.NArg() != 0 || *duration <= 0 || *duration > 2*time.Minute || *timeout <= *duration || *timeout > 3*time.Minute {
		return errors.New("provide server, user, password environment variable and valid duration/timeout")
	}
	if *output != "" {
		for _, name := range []string{*output, *output + ".closed.png"} {
			if _, err := os.Stat(name); err == nil {
				return errors.New("output already exists")
			} else if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	s, err := rdp.DialSession(ctx, *addr, rdp.Credentials{Username: *user, Domain: *domain, Password: password}, rdp.Options{CertificateSHA256: *pin, AudioCapture: true, DynamicChannels: &rdp.DynamicChannelOptions{Listeners: map[string]int{audin.ChannelName: audin.MaxMessage}}}, gcc.ClientSettings{Width: 1280, Height: 720, ColorDepth: 32})
	password = ""
	if err != nil {
		return err
	}
	defer s.Close()
	frame, err := graphics.NewFramebuffer(int(s.Info().Width), int(s.Info().Height))
	if err != nil {
		return err
	}
	rpt := report{Requested: s.Info().AudioCapture, Source: "none; Open requests explicitly refused"}
	if *synthetic {
		rpt.Source = "synthetic 440 Hz signed 16-bit PCM; no microphone"
	}
	defer func() { _ = json.NewEncoder(stdout).Encode(rpt) }()
	type received struct {
		event rdp.Event
		err   error
	}
	events := make(chan received, 16)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			e, err := s.ReadEvent(ctx)
			select {
			case events <- received{e, err}:
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
		}
	}()
	defer func() { cancel(); s.Close(); <-done }()
	var capture *audin.Client
	var captureID uint32
	captureStopped := false
	stopCapture := func(id uint32) error {
		if captureStopped {
			return nil
		}
		captureStopped = true
		if capture != nil {
			capture.Close()
		}
		// ReadEvent may process a server Close before its queued event reaches
		// this loop. That race is distinct from an actual transport failure.
		err := s.CloseDynamic(ctx, id)
		if err == nil {
			rpt.LocalCloseRequests++
		}
		if errors.Is(err, dynvc.ErrChannel) {
			return nil
		}
		return err
	}
	defer func() {
		if capture != nil {
			capture.Close()
		}
	}()
	key := func(code uint8, ext bool) error {
		if err := s.SendKey(ctx, code, true, ext); err != nil {
			return err
		}
		return s.SendKey(ctx, code, false, ext)
	}
	openedPanel := false
	defer func() {
		if openedPanel && ctx.Err() == nil {
			_ = s.SendKey(ctx, 0x38, true, false)
			_ = key(0x3e, false)
			_ = s.SendKey(ctx, 0x38, false, false)
		}
	}()
	closing := false
	snapshot := func(name string) error {
		if *output == "" {
			return nil
		}
		file, err := os.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return err
		}
		err = png.Encode(file, frame.Snapshot())
		closeErr := file.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	finish := time.NewTimer(*duration)
	defer finish.Stop()
	tick := time.NewTicker(5 * time.Millisecond)
	defer tick.Stop()
	var loggedAt, next time.Time
	var sample uint64
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-finish.C:
			if !closing {
				if err = snapshot(*output); err != nil {
					return err
				}
				closing = true
				if capture != nil {
					if err = stopCapture(captureID); err != nil {
						return err
					}
				}
				if openedPanel {
					if err = s.SendKey(ctx, 0x38, true, false); err != nil {
						return err
					}
					if err = key(0x3e, false); err != nil {
						return err
					}
					if err = s.SendKey(ctx, 0x38, false, false); err != nil {
						return err
					}
					openedPanel = false
				}
				finish.Reset(2 * time.Second)
				continue
			}
			if err = snapshot(*output + ".closed.png"); err != nil {
				return err
			}
			if rpt.Opens == 0 {
				return errors.New("server did not request audio input; negotiation alone is not recording")
			}
			if *synthetic && rpt.Packets == 0 {
				return errors.New("no synthetic audio sent")
			}
			return nil
		case now := <-tick.C:
			if !closing && *panel && !openedPanel && !loggedAt.IsZero() && now.Sub(loggedAt) > 3*time.Second {
				if err = s.SendKey(ctx, 0x5b, true, true); err != nil {
					return err
				}
				if err = key(0x13, false); err != nil {
					return err
				}
				if err = s.SendKey(ctx, 0x5b, false, true); err != nil {
					return err
				}
				timer := time.NewTimer(time.Second)
				select {
				case <-timer.C:
				case <-ctx.Done():
					timer.Stop()
					return ctx.Err()
				}
				if err = s.SendText(ctx, "control mmsys.cpl,,1"); err != nil {
					return err
				}
				if err = key(0x1c, false); err != nil {
					return err
				}
				openedPanel = true
			}
			if !closing && !captureStopped && capture != nil && *synthetic {
				r := capture.State().Stream
				// Follow the sample clock instead of adding scheduler/write latency
				// to every packet. Bound catch-up so a pause cannot flush old audio.
				for burst := 0; burst < 4 && r != nil && !now.Before(next); burst++ {
					if err = capture.WritePCM(ctx, r.Token, tone(*r, sample)); err != nil {
						return err
					}
					sample += uint64(r.FramesPerPacket)
					d := time.Duration(r.FramesPerPacket) * time.Second / time.Duration(r.Format.SampleRate)
					next = next.Add(d)
					rpt.Packets++
					rpt.PCMBytes += uint64(r.PacketBytes())
					rpt.PCMSeconds += d.Seconds()
				}
				if r != nil && !now.Before(next) {
					next = now.Add(time.Duration(r.FramesPerPacket) * time.Second / time.Duration(r.Format.SampleRate))
					rpt.PacingResets++
				}
			}
		case incoming := <-events:
			if incoming.err != nil {
				return incoming.err
			}
			e := incoming.event
			if e.Kind == rdp.EventLogonInfo && e.Logon.Logon {
				rpt.Logon = true
				if loggedAt.IsZero() {
					loggedAt = time.Now()
				}
			}
			if e.Kind == rdp.EventActivated {
				if err = frame.Resize(int(e.Info.Width), int(e.Info.Height)); err != nil {
					return err
				}
			}
			if e.Kind == rdp.EventData && e.DataType == pdu.Update {
				if _, err = frame.Apply(e.Payload); err != nil {
					return err
				}
			}
			if e.Kind != rdp.EventDynamic || e.Dynamic.Name != audin.ChannelName {
				continue
			}
			switch e.Dynamic.Kind {
			case dynvc.Opened:
				if closing {
					if err = s.CloseDynamic(ctx, e.Dynamic.ID); err != nil {
						return err
					}
					continue
				}
				if capture != nil {
					capture.Close()
				}
				rpt.Channels++
				if rpt.Channels > 16 {
					return errors.New("too many audio channel restarts")
				}
				id := e.Dynamic.ID
				captureID = id
				captureStopped = false
				capture, err = audin.New(audin.Config{}, func(ctx context.Context, b []byte) error { return s.SendDynamic(ctx, id, b) })
				if err != nil {
					return err
				}
			case dynvc.Closed:
				if capture != nil {
					capture.Close()
					capture = nil
				}
				rpt.Closes++
			case dynvc.Data:
				if closing || captureStopped {
					continue
				}
				if capture == nil {
					return errors.New("audio data without channel")
				}
				result, err := capture.Handle(ctx, e.Dynamic.Data)
				if err != nil {
					if errors.Is(err, audin.ErrProtocol) || errors.Is(err, audin.ErrSequence) || errors.Is(err, audin.ErrLimit) {
						rpt.Ignored++
						if rpt.Ignored <= 16 {
							continue
						}
					}
					return err
				}
				if result.ServerVersion != 0 {
					rpt.ServerVersion = result.ServerVersion
				}
				if result.Negotiated {
					rpt.Negotiations++
					rpt.Formats = result.Formats
				}
				if r := result.Request; r != nil {
					if len(rpt.Requests) >= 64 {
						return errors.New("too many format requests")
					}
					rpt.Requests = append(rpt.Requests, *r)
					sample = 0
					next = time.Now()
					if r.Change {
						rpt.Changes++
						err = capture.ConfirmFormat(ctx, r.Token)
					} else {
						rpt.Opens++
						code := uint32(0x80070005)
						if *synthetic {
							code = 0
						}
						err = capture.CompleteOpen(ctx, r.Token, code)
					}
					if err != nil {
						return err
					}
					if !*synthetic {
						if err = stopCapture(e.Dynamic.ID); err != nil {
							return err
						}
					}
				}
			}
		}
	}
}
func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
