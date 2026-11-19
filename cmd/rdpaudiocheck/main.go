// rdpaudiocheck verifies PCM/ADPCM redirection without speaker playback or recording.
// Audio is decoded and deliberately discarded before sending Wave Confirm.
package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/rdpdr"
	"github.com/hq0101/rdp-go/rdpsnd"
	"github.com/hq0101/rdp-go/vchan"
)

type report struct {
	Kind             string            `json:"kind"`
	AudioRequested   bool              `json:"audio_requested"`
	Logon            bool              `json:"logon_notification"`
	Negotiations     int               `json:"negotiations"`
	ServerVersion    uint16            `json:"server_version"`
	Formats          []rdpsnd.Format   `json:"pcm_formats"`
	Encodings        []rdpsnd.Encoding `json:"wire_encodings"`
	CompressedBlocks int               `json:"compressed_blocks"`
	EncodedBytes     int64             `json:"encoded_bytes"`
	Training         int               `json:"training_confirmations"`
	DeviceCoreReady  bool              `json:"device_core_ready_no_devices"`
	Blocks           int               `json:"decoded_discarded_blocks"`
	Wave2Blocks      int               `json:"wave2_blocks"`
	PCMBytes         int64             `json:"pcm_bytes"`
	PCMSeconds       float64           `json:"pcm_seconds"`
	Peak             float64           `json:"peak"`
	Ignored          int               `json:"ignored_messages"`
	StreamCloses     int               `json:"stream_closes"`
	Playback         string            `json:"playback"`
}

func run(args []string, stdout, stderr io.Writer) error {
	f := flag.NewFlagSet("rdpaudiocheck", flag.ContinueOnError)
	f.SetOutput(stderr)
	addr := f.String("addr", "", "server:3389")
	user := f.String("user", "", "account name")
	domain := f.String("domain", "", "domain or computer name")
	pin := f.String("cert-sha256", "", "independently verified leaf SHA-256; otherwise system trust")
	passwordEnv := f.String("password-env", "RDPGO_PASSWORD", "local password environment variable")
	codec := f.String("codec", "pcm", "wire codec: pcm, adpcm, ima, auto")
	version := f.Int("version", 8, "audio protocol version 2..8; below 8 selects legacy WaveInfo/Wave")
	duration := f.Duration("duration", 15*time.Second, "receive duration after activation, maximum 2 minutes")
	timeout := f.Duration("timeout", 45*time.Second, "overall timeout, maximum 3 minutes")
	if err := f.Parse(args); err != nil {
		return err
	}
	password, ok := os.LookupEnv(*passwordEnv)
	if *addr == "" || *user == "" || !ok || f.NArg() != 0 || *version < 2 || *version > 8 || *duration <= 0 || *duration > 2*time.Minute || *timeout <= *duration || *timeout > 3*time.Minute {
		return errors.New("provide server, user, local password environment variable, version 2..8 and valid duration/timeout")
	}
	codecs := map[string][]rdpsnd.Encoding{
		"pcm": {rdpsnd.PCM}, "adpcm": {rdpsnd.MSADPCM}, "ima": {rdpsnd.IMAADPCM},
		"auto": {rdpsnd.PCM, rdpsnd.MSADPCM, rdpsnd.IMAADPCM},
	}[*codec]
	if codecs == nil {
		return errors.New("codec must be pcm, adpcm, ima or auto")
	}
	audio, err := rdpsnd.New(rdpsnd.Config{Version: uint16(*version), Quality: rdpsnd.HighQuality, Codecs: codecs})
	if err != nil {
		return err
	}
	defer audio.Close()
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	s, err := rdp.DialSession(ctx, *addr, rdp.Credentials{Username: *user, Domain: *domain, Password: password}, rdp.Options{CertificateSHA256: *pin, AudioPlayback: true}, gcc.ClientSettings{Width: 1280, Height: 720, Channels: []gcc.Channel{{Name: rdpsnd.ChannelName, Options: 0x80000000}, {Name: rdpdr.ChannelName, Options: 0x80000000}}})
	password = ""
	if err != nil {
		return err
	}
	defer s.Close()
	id, ok := s.ChannelID(rdpsnd.ChannelName)
	if !ok {
		return errors.New("rdpsnd channel missing")
	}
	deviceID, ok := s.ChannelID(rdpdr.ChannelName)
	if !ok {
		return errors.New("rdpdr channel missing")
	}
	var device rdpdr.CoreClient
	var deviceDecoder vchan.Decoder
	readCtx, stop := context.WithTimeout(ctx, *duration)
	defer stop()
	var decoder vchan.Decoder
	rpt := report{Kind: "summary", AudioRequested: s.Info().AudioPlayback, Playback: "none; decoded and discarded; no audio file saved"}
	output := json.NewEncoder(stdout)
	defer func() { _ = output.Encode(rpt) }()
	for {
		e, err := s.ReadEvent(readCtx)
		if err != nil {
			if readCtx.Err() != nil && rpt.Negotiations > 0 && rpt.Training > 0 {
				return nil
			}
			return err
		}
		if e.Kind == rdp.EventLogonInfo && e.Logon.Logon {
			rpt.Logon = true
		}
		if e.Kind != rdp.EventData {
			continue
		}
		if e.Channel == deviceID {
			data, complete, err := deviceDecoder.Feed(e.Payload)
			if err != nil {
				return err
			}
			if !complete {
				continue
			}
			result, err := device.Handle(data)
			if err != nil {
				// Only public protocol fields, never device names or I/O payloads.
				if len(data) >= 4 {
					meta := map[string]any{"kind": "ignored_device_core", "packet_id": binary.LittleEndian.Uint16(data[2:]), "bytes": len(data)}
					if (binary.LittleEndian.Uint16(data[2:]) == 0x496e || binary.LittleEndian.Uint16(data[2:]) == 0x4343) && len(data) >= 8 {
						meta["major"] = binary.LittleEndian.Uint16(data[4:])
						meta["minor"] = binary.LittleEndian.Uint16(data[6:])
					}
					if err := output.Encode(meta); err != nil {
						return err
					}
				}
				rpt.Ignored++
				if rpt.Ignored > 16 {
					return err
				}
				continue
			}
			for _, reply := range result.Replies {
				if err = s.WriteChannel(readCtx, deviceID, reply); err != nil {
					return err
				}
			}
			rpt.DeviceCoreReady = result.Ready
			continue
		}
		if e.Channel != id {
			continue
		}
		data, complete, err := decoder.Feed(e.Payload)
		if err != nil {
			return err
		}
		if !complete {
			continue
		}
		result, err := audio.Handle(data, time.Now())
		if err != nil {
			if errors.Is(err, rdpsnd.ErrProtocol) || errors.Is(err, rdpsnd.ErrSequence) || errors.Is(err, rdpsnd.ErrLimit) {
				rpt.Ignored++
				if rpt.Ignored <= 16 {
					continue
				}
			}
			return err
		}
		for _, reply := range result.Replies {
			if err = s.WriteChannel(readCtx, id, reply); err != nil {
				return err
			}
		}
		if result.Negotiated {
			rpt.Negotiations++
			rpt.ServerVersion = result.ServerVersion
			rpt.Formats = result.Formats
			rpt.Encodings = result.Encodings
			if err = output.Encode(struct {
				Kind      string            `json:"kind"`
				Version   uint16            `json:"server_version"`
				Formats   []rdpsnd.Format   `json:"pcm_formats"`
				Encodings []rdpsnd.Encoding `json:"wire_encodings"`
			}{"negotiated", result.ServerVersion, result.Formats, result.Encodings}); err != nil {
				return err
			}
			if len(result.Formats) == 0 {
				return errors.New("server offered no supported format for the selected codec")
			}
		}
		if result.Trained {
			rpt.Training++
		}
		if result.StreamClosed {
			rpt.StreamCloses++
		}
		if frame := result.Frame; frame != nil {
			rpt.EncodedBytes += int64(frame.EncodedBytes)
			if frame.Encoding != rdpsnd.PCM {
				rpt.CompressedBlocks++
			}
			samples, err := rdpsnd.DecodePCM(frame.Format, frame.PCM)
			if err != nil {
				return err
			}
			for _, sample := range samples {
				rpt.Peak = math.Max(rpt.Peak, math.Abs(float64(sample)))
			}
			d, _ := frame.Format.Duration(len(frame.PCM))
			rpt.PCMSeconds += d.Seconds()
			rpt.PCMBytes += int64(len(frame.PCM))
			rpt.Blocks++
			if frame.Wave2 {
				rpt.Wave2Blocks++
			}
			clear(samples)
			clear(frame.PCM) // deliberate discard, not queued playback
			ack, err := audio.Confirm(frame.Token, time.Now())
			if err != nil {
				return err
			}
			if err = s.WriteChannel(readCtx, id, ack); err != nil {
				return err
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
