package nativeview

import (
	"context"
	"encoding/binary"
	"errors"
	"image"
	"sync"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/disp"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/graphics"
	"github.com/hq0101/rdp-go/pdu"
	"github.com/hq0101/rdp-go/rdpgfx"
)

type desktopUpdate struct {
	retire        chan struct{}
	image         *image.RGBA
	pointer       graphics.PointerState
	pointerSerial uint64
	info          rdp.SessionInfo
	generation    uint64
	ready         bool
	err           error
	display       displayStatus
}
type desktopMailbox struct {
	mu            sync.Mutex
	latest        *desktopUpdate
	displayTarget displayRequest
}

func consumePointerPosition(u *desktopUpdate, serial *uint64) (image.Point, bool) {
	if u.pointerSerial == *serial {
		return image.Point{}, false
	}
	*serial = u.pointerSerial
	p := u.pointer.Position
	if !u.ready || !u.info.Active || !u.pointer.HasPosition || !p.In(image.Rect(0, 0, int(u.info.Width), int(u.info.Height))) {
		return image.Point{}, false
	}
	return p, true
}

func (m *desktopMailbox) put(v desktopUpdate) { m.mu.Lock(); m.latest = &v; m.mu.Unlock() }
func (m *desktopMailbox) take() *desktopUpdate {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.latest
	m.latest = nil
	return v
}

func configureFrame(f *graphics.Framebuffer, info rdp.SessionInfo) {
	f.AllowNSCodec = info.NSCodec
	f.AllowBitmapCacheV3 = info.BitmapCacheV3
	f.AllowBrushCache, f.AllowOffscreen, f.OffscreenDepth = info.BrushCache, info.OffscreenCache, info.BitsPerPixel
	f.AllowExtendedOrders, f.AllowShapeOrders = info.ExtendedOrders, info.ShapeOrders
	f.AllowGlyphCache, f.AllowGlyphCacheV2 = info.GlyphCache, info.GlyphCacheV2
}

// The reader waits for consumption before advancing ReadEvent, so a later
// activation cannot change Session geometry while the previous event is applied.
// A separate presentation timer publishes a final dirty frame even if the peer
// stops sending packets. Only one copied desktop waits for the UI.
func receiveDesktop(ctx context.Context, s Remote, o Options, mailbox *desktopMailbox) (err error) {
	info := s.Info()
	frame, err := graphics.NewFramebuffer(int(info.Width), int(info.Height))
	if err != nil {
		return err
	}
	configureFrame(frame, info)
	pointer := graphics.PointerDecoder{AllowNewPointer: info.NewPointer, LargePointerFlags: info.LargePointerFlags}
	gfx := rdpgfx.Client{Profile: o.GraphicsProfile}
	display := displayControl{status: displayStatus{enabled: o.DynamicResolution}}
	if info.GraphicsPipeline && !s.DynamicInfo().Managed {
		return errors.New("nativeview: graphics pipeline requires managed dynamic channels")
	}
	if o.DynamicResolution && !s.DynamicInfo().Managed {
		return errors.New("nativeview: dynamic resolution requires managed dynamic channels")
	}
	if info.SuppressOutput {
		if err = s.SetDisplayUpdates(ctx, true); err != nil {
			return err
		}
	}
	if info.RefreshRect {
		if err = s.Refresh(ctx); err != nil {
			return err
		}
	}
	readCtx, cancel := context.WithCancel(ctx)
	type received struct {
		event rdp.Event
		err   error
	}
	events := make(chan received)
	advance := make(chan struct{})
	done := make(chan struct{})
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
	defer func() { cancel(); _ = s.Close(); <-done }()
	ticker := time.NewTicker(o.RefreshInterval)
	defer ticker.Stop()
	generation := uint64(1)
	ready, dirty := false, true
	publish := func(retire chan struct{}) {
		v := desktopUpdate{retire: retire, info: info, generation: generation, ready: ready, pointer: pointer.Snapshot(), pointerSerial: pointer.Stats().Position, display: display.status}
		if ready && info.Active {
			v.image = frame.Snapshot()
		}
		mailbox.put(v)
		dirty = false
	}
	quiesce := func() error {
		ack := make(chan struct{})
		publish(ack)
		select {
		case <-ack:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	publish(nil)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if o.DynamicResolution {
				before := display.status
				display.expire(time.Now())
				request := mailbox.requestedDisplay()
				packet := display.prepare(request, time.Now(), image.Pt(int(info.Width), int(info.Height)), info.Active && ready)
				if packet != nil {
					if err := quiesce(); err != nil {
						return err
					}
					// Native cleanup may outlive a local resize or a server-side
					// deactivation already observed by the one in-flight reader.
					if mailbox.requestedDisplay() != request || !s.Info().Active {
						display.status.phase = displayIdle
					} else {
						writeCtx, stopWrite := context.WithTimeout(ctx, 3*time.Second)
						display.sent(request, time.Now())
						err := s.SendDynamic(writeCtx, display.id, packet)
						stopWrite()
						if err == dynvc.ErrChannel {
							// A close can be observed by the managed reader before its
							// event reaches us. This error precedes any wire write.
							display.status.available = false
							display.status.phase = displayIdle
						} else if err != nil {
							return err
						}
					}
				}
				if before != display.status {
					dirty = true
				}
			}
			if dirty {
				publish(nil)
			}
		case r := <-events:
			if r.err != nil {
				return r.err
			}
			e := r.event
			err = func() error {
				switch e.Kind {
				case rdp.EventDeactivated:
					info.Active = false
					generation++
					ready = false
					return quiesce()
				case rdp.EventActivated:
					info = e.Info
					display.observed(image.Pt(int(info.Width), int(info.Height)))
					generation++
					ready = false
					if err := frame.Resize(int(info.Width), int(info.Height)); err != nil {
						return err
					}
					configureFrame(frame, info)
					pointer.AllowNewPointer, pointer.LargePointerFlags = info.NewPointer, info.LargePointerFlags
					return quiesce()
				case rdp.EventDynamic:
					if e.Dynamic.Name == disp.ChannelName && o.DynamicResolution {
						if err := display.event(e.Dynamic); err != nil {
							return err
						}
						dirty = true
						return nil
					}
					if e.Dynamic.Name != rdpgfx.ChannelName {
						return nil
					}
					result, err := gfx.Handle(e.Dynamic)
					if err != nil {
						return err
					}
					if e.Dynamic.Kind == dynvc.Closed {
						generation++
						ready = false
						if err = quiesce(); err != nil {
							return err
						}
					}
					if result.Resized {
						generation++
						ready = false
						if err = quiesce(); err != nil {
							return err
						}
						if err = s.SetGraphicsOutputSize(ctx, result.Width, result.Height); err != nil {
							return err
						}
						info.Width, info.Height = uint16(result.Width), uint16(result.Height)
						display.observed(image.Pt(result.Width, result.Height))
						ready = false
						if err = frame.Resize(result.Width, result.Height); err != nil {
							return err
						}
						publish(nil)
					}
					if result.FrameReady {
						if err = frame.PresentGraphicsFrame(gfx.Snapshot()); err != nil {
							return err
						}
						ready, dirty = true, true
					}
					for _, reply := range result.Replies {
						if err = s.SendDynamic(ctx, e.Dynamic.ID, reply); err != nil {
							return err
						}
					}
					return nil
				case rdp.EventLargePointer:
					dirty = true
					return pointer.ApplyLarge(e.Payload)
				case rdp.EventSurfaceCommands:
					if !info.Active {
						return nil
					}
					result, err := frame.ApplySurfaceCommands(e.Payload)
					if err != nil {
						return err
					}
					if len(result.Dirty) > 0 {
						ready, dirty = true, true
					}
					if info.FrameAcknowledge {
						for _, id := range result.CompletedFrames {
							if err = s.AcknowledgeFrame(ctx, id); err != nil {
								return err
							}
						}
					}
					return nil
				case rdp.EventData:
					if !info.Active {
						return nil
					}
					switch e.DataType {
					case pdu.Update:
						regions, err := frame.Apply(e.Payload)
						if err != nil {
							return err
						}
						if len(e.Payload) >= 2 && binary.LittleEndian.Uint16(e.Payload) == 2 {
							if err = pointer.ApplyPalette(e.Payload); err != nil {
								return err
							}
						}
						if len(regions) > 0 {
							ready, dirty = true, true
						}
					case pdu.Pointer:
						dirty = true
						return pointer.Apply(e.Payload)
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
