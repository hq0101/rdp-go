package main

import (
	"context"
	"encoding/binary"
	"errors"
	"image"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/graphics"
	"github.com/hq0101/rdp-go/internal/gatewayconfig"
	"github.com/hq0101/rdp-go/pdu"
	"github.com/hq0101/rdp-go/rdpgfx"
	"github.com/hq0101/rdp-go/vchan"
)

// The capture path has no keyboard, mouse, clipboard or local-device methods.
type captureRemote interface {
	Info() rdp.SessionInfo
	ReadEvent(context.Context) (rdp.Event, error)
	ChannelID(string) (uint16, bool)
	SetDisplayUpdates(context.Context, bool) error
	Refresh(context.Context) error
	SetGraphicsOutputSize(context.Context, int, int) error
	WriteChannel(context.Context, uint16, []byte) error
	SendDynamic(context.Context, uint32, []byte) error
	AcknowledgeFrame(context.Context, uint32) error
	NetworkInfo() rdp.NetworkInfo
	DynamicInfo() rdp.DynamicChannelInfo
	CompressionStats() rdp.CompressionStats
	LastLogonInfo() (rdp.LogonInfo, bool)
	RedirectionInfo() rdp.RedirectionStatus
	Close() error
}

type captureOptions struct {
	gatewayReporter *gatewayconfig.Reporter
	duration        time.Duration
	profile         rdpgfx.Profile
}
type captureResult struct {
	image    *image.RGBA
	metadata map[string]any
}
type captureFollow func(context.Context, captureRemote, *rdp.RedirectionError) (captureRemote, error)

// capture owns initial and every successful successor. A hop discards the entire
// former result, including statistics. The global context bounds all handshakes
// and capture windows; each new activated server gets a new local window.
func capture(ctx context.Context, initial captureRemote, options captureOptions, follow captureFollow, report func(captureRemote)) (*captureResult, error) {
	current := initial
	defer func() {
		defer current.Close()
		if report != nil {
			report(current)
		}
	}()
	for {
		result, err := captureOne(ctx, current, options)
		if err == nil {
			return result, nil
		}
		var request *rdp.RedirectionError
		if !errors.As(err, &request) {
			return nil, err
		}
		next, followErr := func() (captureRemote, error) {
			if request.Request != nil {
				defer request.Request.Clear()
			}
			if follow == nil {
				return nil, err
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return follow(ctx, current, request)
		}()
		if followErr != nil {
			return nil, followErr
		}
		current.Close() // Follow must run before public Close, which cancels it.
		current = next
	}
}

func followCapture(ctx context.Context, old captureRemote, request *rdp.RedirectionError) (captureRemote, error) {
	s, ok := old.(*rdp.Session)
	if !ok {
		return nil, rdp.ErrRedirectionUnavailable
	}
	return s.FollowRedirection(ctx, request)
}

func captureDeadline(ctx context.Context, err error, updates int) bool {
	return updates > 0 && errors.Is(ctx.Err(), context.DeadlineExceeded) && errors.Is(err, context.DeadlineExceeded)
}

// All caches, fragments and counters below belong to this one Session. Reuse
// Framebuffer.Resize only for same-session reactivation, never for a new target.
func captureOne(ctx context.Context, s captureRemote, options captureOptions) (result *captureResult, captureErr error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if options.duration <= 0 {
		return nil, errors.New("capture duration must be positive")
	}
	stopServices := gatewayconfig.WatchServices(ctx, s, options.gatewayReporter)
	defer func() {
		if e := stopServices(); captureErr == nil && e != nil {
			result = nil
			captureErr = e
		}
	}()
	var dynamic *dynvc.Client
	var dynamicDecoder vchan.Decoder
	gfxClient := rdpgfx.Client{Profile: options.profile}
	managed := s.DynamicInfo().Managed
	if _, ok := s.ChannelID("drdynvc"); ok && !managed {
		limits := map[string]int{}
		if s.Info().GraphicsPipeline {
			limits[rdpgfx.ChannelName] = rdpgfx.MaxWireMessage
		}
		var err error
		dynamic, err = dynvc.NewWithLimits(limits, dynvc.HardLimit)
		if err != nil {
			return nil, err
		}
	}
	dynamicID, _ := s.ChannelID("drdynvc")
	info := s.Info()
	pointer := graphics.PointerDecoder{AllowNewPointer: info.NewPointer, LargePointerFlags: info.LargePointerFlags}
	frame, err := graphics.NewFramebuffer(int(info.Width), int(info.Height))
	if err != nil {
		return nil, err
	}
	frame.AllowNSCodec = info.NSCodec
	frame.AllowBitmapCacheV3 = info.BitmapCacheV3
	frame.AllowBrushCache, frame.AllowOffscreen, frame.OffscreenDepth = info.BrushCache, info.OffscreenCache, info.BitsPerPixel
	frame.AllowExtendedOrders = info.ExtendedOrders
	frame.AllowShapeOrders = info.ShapeOrders
	frame.AllowGlyphCache, frame.AllowGlyphCacheV2 = info.GlyphCache, info.GlyphCacheV2
	if info.SuppressOutput {
		if err := s.SetDisplayUpdates(ctx, true); err != nil {
			return nil, err
		}
	}
	if info.RefreshRect {
		if err := s.Refresh(ctx); err != nil {
			return nil, err
		}
	}
	covered := make([]bool, int(info.Width)*int(info.Height))
	coverage, updates := 0, 0
	bitmapUpdates, orderUpdates, orderCount := 0, 0, 0
	captureCtx, captureCancel := context.WithTimeout(ctx, options.duration)
	defer captureCancel()
captureLoop:
	for {
		e, err := s.ReadEvent(captureCtx)
		if err != nil {
			if captureDeadline(captureCtx, err, updates) {
				break
			}
			return nil, err
		}
		if e.Kind == rdp.EventDynamic || (dynamic != nil && e.Kind == rdp.EventData && e.DataType == 0 && e.Channel == dynamicID) {
			event := e.Dynamic
			if e.Kind != rdp.EventDynamic {
				b, complete, err := dynamicDecoder.Feed(e.Payload)
				if err != nil {
					return nil, err
				}
				if !complete {
					continue
				}
				var replies [][]byte
				replies, event, err = dynamic.Handle(b)
				if err != nil {
					return nil, err
				}
				for _, reply := range replies {
					if err := s.WriteChannel(captureCtx, dynamicID, reply); err != nil {
						return nil, err
					}
				}
			}
			if event.Name == rdpgfx.ChannelName {
				result, err := gfxClient.Handle(event)
				if err != nil {
					return nil, err
				}

				if result.Resized {
					if err := s.SetGraphicsOutputSize(ctx, result.Width, result.Height); err != nil {
						return nil, err
					}
					info.Width, info.Height = uint16(result.Width), uint16(result.Height)
					if err := frame.Resize(result.Width, result.Height); err != nil {
						return nil, err
					}
					covered = make([]bool, result.Width*result.Height)
					updates, coverage = 0, 0 // require a frame for the new output
				}
				if result.FrameReady {
					if err := frame.PresentGraphicsFrame(gfxClient.Snapshot()); err != nil {
						return nil, err
					}
					updates += len(result.Presented)
				}
				// A synchronous decode can finish as the capture timer expires.
				// Keep its completed image before attempting the frame ACK.
				if errors.Is(captureCtx.Err(), context.DeadlineExceeded) && updates > 0 {
					break captureLoop
				}
				for _, reply := range result.Replies {
					if managed {
						if err := s.SendDynamic(captureCtx, event.ID, reply); err != nil {
							if errors.Is(err, context.DeadlineExceeded) && errors.Is(captureCtx.Err(), context.DeadlineExceeded) && updates > 0 {
								break captureLoop
							}
							return nil, err
						}
						continue
					}
					packets, err := dynamic.Send(event.ID, reply)
					if err != nil {
						return nil, err
					}
					for _, packet := range packets {
						if err := s.WriteChannel(captureCtx, dynamicID, packet); err != nil {
							if errors.Is(err, context.DeadlineExceeded) && errors.Is(captureCtx.Err(), context.DeadlineExceeded) && updates > 0 {
								break captureLoop
							}
							return nil, err
						}
					}
				}
			}
			continue
		}
		if e.Kind == rdp.EventDeactivated {
			updates, coverage = 0, 0
			continue
		}
		if e.Kind == rdp.EventActivated {
			info = e.Info
			pointer.AllowNewPointer, pointer.LargePointerFlags = info.NewPointer, info.LargePointerFlags
			err = frame.Resize(int(info.Width), int(info.Height))
			if err != nil {
				return nil, err
			}
			frame.AllowNSCodec = info.NSCodec
			frame.AllowBitmapCacheV3 = info.BitmapCacheV3
			frame.AllowBrushCache, frame.AllowOffscreen, frame.OffscreenDepth = info.BrushCache, info.OffscreenCache, info.BitsPerPixel
			frame.AllowExtendedOrders = info.ExtendedOrders
			frame.AllowShapeOrders = info.ShapeOrders
			frame.AllowGlyphCache, frame.AllowGlyphCacheV2 = info.GlyphCache, info.GlyphCacheV2
			covered = make([]bool, int(info.Width)*int(info.Height))
			updates, coverage = 0, 0
			continue
		}
		if e.Kind == rdp.EventLargePointer {
			if err := pointer.ApplyLarge(e.Payload); err != nil {
				return nil, err
			}
			continue
		}
		if e.Kind == rdp.EventData && e.DataType == pdu.Pointer {
			if err := pointer.Apply(e.Payload); err != nil {
				return nil, err
			}
			continue
		}
		if e.Kind != rdp.EventSurfaceCommands && e.DataType != pdu.Update {
			continue
		}
		var dirty []image.Rectangle
		var completedFrames []uint32
		if e.Kind == rdp.EventSurfaceCommands {
			var result graphics.SurfaceResult
			result, err = frame.ApplySurfaceCommands(e.Payload)
			dirty = result.Dirty
			if err == nil && info.FrameAcknowledge {
				completedFrames = result.CompletedFrames
			}
		} else {
			dirty, err = frame.Apply(e.Payload)
			if err == nil && len(e.Payload) >= 2 && binary.LittleEndian.Uint16(e.Payload) == 2 {
				err = pointer.ApplyPalette(e.Payload)
			}
		}
		if err != nil {
			return nil, err
		}
		if len(dirty) > 0 {
			updates++
		}
		if e.Kind == rdp.EventData {
			switch binary.LittleEndian.Uint16(e.Payload) {
			case 0:
				orderUpdates++
				orderCount += int(binary.LittleEndian.Uint16(e.Payload[4:]))
			case 1:
				bitmapUpdates++
			}
		}
		for _, r := range dirty {
			for y := r.Min.Y; y < r.Max.Y; y++ {
				for x := r.Min.X; x < r.Max.X; x++ {
					i := y*int(info.Width) + x
					if !covered[i] {
						covered[i] = true
						coverage++
					}
				}
			}
		}
		// Pixels are committed before the ACK. Only expiry of our own capture
		// context permits saving that image after a failed acknowledgement.
		for _, id := range completedFrames {
			if err := s.AcknowledgeFrame(captureCtx, id); err != nil {
				if captureDeadline(captureCtx, err, updates) {
					break captureLoop
				}
				return nil, err
			}
		}

	}
	if updates == 0 {
		return nil, errors.New("no decoded graphics updates received")
	}
	return &captureResult{image: frame.Snapshot(), metadata: map[string]any{"gateway": gatewayconfig.Info(s), "licensing": captureLicensing(s), "network": s.NetworkInfo(), "multitransport": s.DynamicInfo(), "graphics_pipeline_offered": info.GraphicsPipeline, "graphics_pipeline": gfxClient.Stats(), "coverage_source": "legacy_dirty_bounds", "bulk_compression": info.BulkCompression, "bulk_compression_type": info.BulkCompressionType, "compression": s.CompressionStats(), "width": info.Width, "height": info.Height, "bits_per_pixel": info.BitsPerPixel, "pointers": pointer.Stats(), "new_pointer": info.NewPointer, "large_pointer_flags": info.LargePointerFlags, "drawing_orders": info.DrawingOrders, "bitmap_cache_v2": info.BitmapCacheV2, "surface_commands": info.SurfaceCommands, "frame_acknowledge": info.FrameAcknowledge, "nscodec": info.NSCodec, "brush_cache": info.BrushCache, "offscreen_cache": info.OffscreenCache, "extended_orders": info.ExtendedOrders, "shape_orders": info.ShapeOrders, "glyph_cache": info.GlyphCache, "glyph_cache_v2": info.GlyphCacheV2, "bitmap_cache_v3": info.BitmapCacheV3, "surface": frame.SurfaceStats(), "graphics_updates": updates, "bitmap_updates": bitmapUpdates, "order_updates": orderUpdates, "orders": orderCount, "orders_by_type": frame.OrderStats(), "updated_pixels": coverage, "total_pixels": len(covered), "full_coverage": coverage == len(covered), "input_sent": false, "redirection_enabled": s.RedirectionInfo().Enabled, "redirection_hops": s.RedirectionInfo().Hops}}, nil
}

func captureLicensing(s captureRemote) *rdp.LicensingState {
	if source, ok := s.(interface{ LicensingState() rdp.LicensingState }); ok {
		state := source.LicensingState()
		return &state
	}
	return nil
}
