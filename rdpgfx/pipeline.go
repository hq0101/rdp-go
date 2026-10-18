package rdpgfx

import (
	"encoding/binary"
	"fmt"
	"image"
	"maps"
	"sort"

	"github.com/hq0101/rdp-go/graphics"
	"github.com/hq0101/rdp-go/zgfx"
)

const maxPixels = 16 << 20
const maxSurfaceCount = 1024
const maxCacheBytes = 16 << 20
const maxWork = 64 << 20 // pixel operations and copy-on-write snapshots per message

type surface struct {
	window           WindowMapping
	windowMapped     bool
	image            *image.NRGBA
	format           byte
	origin           image.Point
	target           image.Point // mapped size; ordinary mapping uses the surface size
	mapped, dirty    bool
	mappingOrder     uint64
	progressive      graphics.ProgressiveDecoder
	progressiveFrame progressiveFrame
	avc              *AVCDecoder // immutable until copied for a transaction
}
type cacheEntry struct {
	image *image.NRGBA
	key   uint64
}

// Pipeline is a bounded graphics pipeline. Its zero-value profile is
// ThinClient; ProfileProgressive enables WIRETOSURFACE2. Surface/cache/frame
// operations are implemented. No network I/O or capability advertisement occurs here.
// Calls must be serialized, including snapshots. The zero value is ready.
type Pipeline struct {
	// WindowMapping opts into Enhanced RemoteApp window PDUs. Set it before
	// CAPS_CONFIRM, only when the application handles RAIL/window presentation.
	// It does not advertise INFO_HIDEF_RAIL_SUPPORTED or perform a RAIL handshake.
	WindowMapping                                                  bool
	confirmedWindowMapping                                         bool
	windowFrames                                                   map[uint16]windowFrame
	windowGeneration, windowRevision                               uint64
	windowPixels                                                   int // aggregate full target geometry, separate from surface storage
	Profile                                                        Profile
	confirmedProfile                                               Profile
	confirmedVersion, confirmedFlags                               uint32
	avcPixels, avcContexts, avcMainPixels                          int
	surfaces                                                       map[uint16]surface
	cache                                                          map[uint16]cacheEntry
	output                                                         *image.NRGBA
	surfacePixels, cacheBytes                                      int
	confirmed, inFrame                                             bool
	frameID, totalFrames                                           uint32
	monitors                                                       []Monitor
	clear                                                          graphics.ClearDecoder
	remoteFX                                                       graphics.RemoteFXDecoder
	stats                                                          Stats
	mappingOrder                                                   uint64
	progressiveTiles, progressiveContexts, progressiveAssociations int
	progressiveRects                                               int // across all surfaces in the current logical frame
}

// Result reports frames actually presented, with acknowledgements ready to send
// only after Apply/Receive succeeds. No reply is emitted for a partial frame.
type Result struct {
	Presented     []uint32
	Replies       [][]byte
	Resized       bool
	Width, Height int
	// FrameReady means Snapshot contains a completed frame from this call.
	// A later Reset in the same message clears it without removing earlier ACKs.
	FrameReady bool
	// WindowsChanged means WindowMappings/WindowSnapshot changed, including
	// removal outside a frame. It does not imply local window creation.
	WindowsChanged bool
}

func cloneImage(src *image.NRGBA) *image.NRGBA {
	dst := image.NewNRGBA(src.Rect)
	copy(dst.Pix, src.Pix)
	return dst
}

// Snapshot returns a caller-owned image. An uninitialized output returns nil.
func (p *Pipeline) Snapshot() *image.NRGBA {
	if p.output == nil {
		return nil
	}
	return cloneImage(p.output)
}
func (p *Pipeline) Surface(id uint16) *image.NRGBA {
	s, ok := p.surfaces[id]
	if !ok {
		return nil
	}
	return cloneImage(s.image)
}
func (p *Pipeline) Frames() uint32 { return p.totalFrames }

// Monitors returns an owned copy of the topology in the last successful RESET.
// Coordinates remain relative to the primary monitor; rendering/input use the
// zero-origin output rectangle. No requested topology or DPI is inferred here.
func (p *Pipeline) Monitors() []Monitor { return append([]Monitor(nil), p.monitors...) }

// Apply takes decompressed GFX PDUs and validates the full message before
// committing pixel/state changes. Previously presented output stays unchanged
// while a new frame is being assembled across messages.
func (p *Pipeline) Apply(data []byte) (Result, error) {
	if _, err := p.Profile.flags(); err != nil {
		return Result{}, err
	}
	if p.confirmed && (p.Profile != p.confirmedProfile || p.WindowMapping != p.confirmedWindowMapping) {
		return Result{}, ErrInvalid
	}
	commands, err := Parse(data)
	if err != nil {
		return Result{}, err
	}
	next := *p
	next.windowFrames = maps.Clone(p.windowFrames)
	next.surfaces = maps.Clone(p.surfaces)
	if next.surfaces == nil {
		next.surfaces = make(map[uint16]surface)
	}
	next.cache = maps.Clone(p.cache)
	if next.cache == nil {
		next.cache = make(map[uint16]cacheEntry)
	}
	t := transaction{p: &next, copied: make(map[uint16]bool)}
	var result Result
	for _, c := range commands {
		if err = t.apply(c, &result); err != nil {
			return Result{}, fmt.Errorf("rdpgfx command %d (surface %d, codec %d): %w", c.ID, c.SurfaceID, c.CodecID, err)
		}
	}
	*p = next
	return result, nil
}

type transaction struct {
	p            *Pipeline
	copied       map[uint16]bool
	outputCopied bool
	work         int
}

func (t *transaction) spend(pixels int) error {
	if pixels < 0 || pixels > maxWork-t.work {
		return ErrInvalid
	}
	t.work += pixels
	return nil
}
func area(r image.Rectangle) int { return r.Dx() * r.Dy() }
func validSize(w, h int) bool    { return w > 0 && h > 0 && w <= 8192 && h <= 8192 && w*h <= maxPixels }
func (t *transaction) writable(id uint16) (surface, error) {
	s, ok := t.p.surfaces[id]
	if !ok {
		return surface{}, ErrInvalid
	}
	if !t.copied[id] {
		if err := t.spend(area(s.image.Rect)); err != nil {
			return surface{}, err
		}
		s.image = cloneImage(s.image)
		t.copied[id] = true
	}
	s.dirty = true
	t.p.surfaces[id] = s
	return s, nil
}
func copyPixels(dst *image.NRGBA, point image.Point, src *image.NRGBA, rect image.Rectangle, rgbOnly bool) {
	for y := 0; y < rect.Dy(); y++ {
		s := src.PixOffset(rect.Min.X, rect.Min.Y+y)
		d := dst.PixOffset(point.X, point.Y+y)
		if !rgbOnly {
			copy(dst.Pix[d:d+rect.Dx()*4], src.Pix[s:s+rect.Dx()*4])
			continue
		}
		for x := 0; x < rect.Dx(); x++ {
			copy(dst.Pix[d+x*4:d+x*4+3], src.Pix[s+x*4:s+x*4+3])
		}
	}
}
func contained(r, bounds image.Rectangle) bool {
	return r.Min.X >= bounds.Min.X && r.Min.Y >= bounds.Min.Y && r.Max.X <= bounds.Max.X && r.Max.Y <= bounds.Max.Y
}

func (t *transaction) apply(c Command, result *Result) error {
	p := t.p
	if c.ID == CapsConfirm {
		if p.confirmed || !p.Profile.accepts(c.Capability) {
			return fmt.Errorf("capability version %#08x, data %x, profile %s, already confirmed %t: %w", c.Capability.Version, c.Capability.Data, p.Profile, p.confirmed, ErrUnsupported)
		}
		p.confirmed = true
		p.confirmedProfile = p.Profile
		p.confirmedWindowMapping = p.WindowMapping
		p.confirmedVersion, p.confirmedFlags = c.Capability.Version, binary.LittleEndian.Uint32(c.Capability.Data)
		p.stats.CapabilityVersion, p.stats.CapabilityFlags = p.confirmedVersion, p.confirmedFlags
		p.stats.Confirmed = true
		p.stats.Profile = p.Profile.String()
		return nil
	}
	if !p.confirmed {
		return ErrInvalid
	}
	s, exists := p.surfaces[c.SurfaceID]
	switch c.ID {
	case ResetGraphics:
		if p.inFrame || !validSize(c.Width, c.Height) {
			return ErrInvalid
		}
		if err := t.spend(c.Width * c.Height); err != nil {
			return err
		}
		p.output = image.NewNRGBA(image.Rect(0, 0, c.Width, c.Height))
		for i := 3; i < len(p.output.Pix); i += 4 {
			p.output.Pix[i] = 255
		}
		t.outputCopied = true
		p.monitors = c.Monitors
		result.Resized = true
		result.FrameReady = false
		result.Width, result.Height = c.Width, c.Height
		p.stats.Resets++
		// Resize alone does not delete surfaces/caches or ZGFX history.
		for id, s := range p.surfaces {
			s.dirty = true
			p.surfaces[id] = s
		}
	case CreateSurface:
		if exists || len(p.surfaces) >= maxSurfaceCount || !validSize(c.Width, c.Height) || c.Width*c.Height > maxPixels-p.surfacePixels {
			return ErrInvalid
		}
		if err := t.spend(c.Width * c.Height); err != nil {
			return err
		}
		img := image.NewNRGBA(image.Rect(0, 0, c.Width, c.Height))
		for i := 3; i < len(img.Pix); i += 4 {
			img.Pix[i] = 255
		}
		p.surfaces[c.SurfaceID] = surface{image: img, format: c.PixelFormat, dirty: true}
		t.copied[c.SurfaceID] = true
		p.surfacePixels += c.Width * c.Height
	case DeleteSurface:
		if !exists {
			return ErrInvalid
		}
		if s.windowMapped {
			p.windowPixels -= s.window.Target.X * s.window.Target.Y
		}
		if !p.inFrame {
			if _, ok := p.windowFrames[c.SurfaceID]; ok {
				delete(p.windowFrames, c.SurfaceID)
				result.WindowsChanged = true
			}
		}
		p.surfacePixels -= area(s.image.Rect)
		p.progressiveTiles -= s.progressive.TileCount()
		p.progressiveContexts -= s.progressive.ContextCount()
		p.progressiveAssociations -= s.progressive.AssociationCount()
		p.progressiveRects -= len(s.progressiveFrame.rectangles)
		if s.avc != nil {
			p.avcPixels -= s.avc.ReferencePixels()
			p.avcMainPixels -= s.avc.MainPixels()
			p.avcContexts--
		}
		delete(p.surfaces, c.SurfaceID)
		delete(t.copied, c.SurfaceID)
	case MapSurfaceToWindow, MapSurfaceToScaledWindow:
		return t.mapWindow(c)
	case MapSurfaceToOutput, MapSurfaceToScaledOutput:
		if !exists || p.output == nil {
			return ErrInvalid
		}
		if c.ID == MapSurfaceToScaledOutput && !scaledOutputAllowed(p.confirmedVersion, p.confirmedFlags) {
			return ErrUnsupported
		}
		s.target = s.image.Rect.Size()
		if c.ID == MapSurfaceToScaledOutput {
			if !validSize(c.Width, c.Height) {
				return ErrInvalid
			}
			s.target = image.Pt(c.Width, c.Height)
			p.stats.ScaledMappings++
		}
		// The protocol does not prohibit padded, off-output or overlapping
		// mappings. Clip at presentation and copy updated surfaces in mapping
		// order so overlaps do not depend on Go map iteration.
		if p.mappingOrder == ^uint64(0) {
			return ErrInvalid
		}
		p.mappingOrder++
		s.mappingOrder = p.mappingOrder
		s.origin, s.mapped, s.dirty = c.Origin, true, true
		p.surfaces[c.SurfaceID] = s
	case StartFrame:
		if p.inFrame || p.output == nil {
			return ErrInvalid
		}
		p.inFrame = true
		p.frameID = c.FrameID
		p.progressiveRects = 0
		for id, s := range p.surfaces {
			s.progressiveFrame = progressiveFrame{}
			p.surfaces[id] = s
		}
	case EndFrame:
		if !p.inFrame || c.FrameID != p.frameID {
			return ErrInvalid
		}
		if err := t.present(result); err != nil {
			return err
		}
		p.inFrame = false
		p.totalFrames++
		p.stats.Frames++
		result.FrameReady = true
		result.Presented = append(result.Presented, c.FrameID)
		result.Replies = append(result.Replies, Acknowledge(c.FrameID, p.totalFrames, 0))
	case WireToSurface1:
		if c.CodecID == CodecAVC420 || c.CodecID == CodecAVC444 || c.CodecID == CodecAVC444V2 {
			return t.avc(c)
		}
		switch c.CodecID {
		case CodecRaw:
			p.stats.Raw++
		case CodecPlanar:
			p.stats.Planar++
		case CodecClear:
			p.stats.Clear++
		case CodecAlpha:
			p.stats.Alpha++
		case CodecRemoteFX:
			p.stats.RemoteFX++
		}
		if !exists {
			return fmt.Errorf("surface does not exist: %w", ErrInvalid)
		}
		if !p.inFrame {
			return fmt.Errorf("bitmap outside frame: %w", ErrInvalid)
		}
		if c.Rect.Empty() || !contained(c.Rect, s.image.Rect) {
			return fmt.Errorf("bitmap rectangle %v outside surface %v: %w", c.Rect, s.image.Rect, ErrInvalid)
		}
		// The wire bitmap format describes the source, independently of the
		// destination's XRGB/ARGB format. RGB writes preserve destination alpha.
		if err := t.spend(area(c.Rect)); err != nil {
			return err
		}
		var img *image.NRGBA
		var alpha []byte
		var remoteFrames []graphics.RemoteFXFrame
		switch c.CodecID {
		case CodecRaw:
			if len(c.Data) != area(c.Rect)*4 {
				return ErrInvalid
			}
			img = image.NewNRGBA(image.Rect(0, 0, c.Rect.Dx(), c.Rect.Dy()))
			for i := 0; i < len(c.Data); i += 4 {
				img.Pix[i], img.Pix[i+1], img.Pix[i+2], img.Pix[i+3] = c.Data[i+2], c.Data[i+1], c.Data[i], c.Data[i+3]
			}
		case CodecPlanar:
			var err error
			img, err = graphics.DecodePlanar(c.Data, c.Rect.Dx(), c.Rect.Dy())
			if err != nil {
				return err
			}
		case CodecClear:
			var err error
			var work int
			img, work, err = p.clear.DecodeWithBudget(c.Data, c.Rect.Dx(), c.Rect.Dy(), maxWork-t.work)
			if err != nil {
				return err
			}
			t.work += work
		case CodecAlpha:
			var err error
			alpha, err = graphics.DecodeAlpha(c.Data, c.Rect.Dx(), c.Rect.Dy())
			if err != nil {
				return err
			}
		case CodecRemoteFX:
			var err error
			var work int
			remoteFrames, work, err = p.remoteFX.DecodeWithBudget(c.Data, c.Rect.Dx(), c.Rect.Dy(), maxWork-t.work)
			if err != nil {
				return fmt.Errorf("RemoteFX rectangle %v: %w", c.Rect, err)
			}
			t.work += work
		default:
			return ErrUnsupported
		}
		dst, err := t.writable(c.SurfaceID)
		if err != nil {
			return err
		}
		// MS-RDPEGFX 3.3.5.1: AlphaCodec changes opacity only; all other
		// codecs change RGB only. Presenting an output still forces opaque alpha.
		if c.CodecID == CodecRemoteFX {
			// RemoteFX tiles may cover only part of destRect. Both region
			// clipping and tile placement are relative to destRect's origin.
			bounds := image.Rect(0, 0, c.Rect.Dx(), c.Rect.Dy())
			for _, frame := range remoteFrames {
				for _, tile := range frame.Tiles {
					for _, rect := range frame.Rectangles {
						clipped := rect.Intersect(tile.Image.Rect.Add(tile.Origin)).Intersect(bounds)
						if err := t.spend(1 + area(clipped)); err != nil {
							return err
						}
						if clipped.Empty() {
							continue
						}
						copyPixels(dst.image, clipped.Min.Add(c.Rect.Min), tile.Image, clipped.Sub(tile.Origin), true)
					}
				}
			}
		} else if alpha != nil {
			for y := 0; y < c.Rect.Dy(); y++ {
				for x := 0; x < c.Rect.Dx(); x++ {
					dst.image.Pix[dst.image.PixOffset(c.Rect.Min.X+x, c.Rect.Min.Y+y)+3] = alpha[y*c.Rect.Dx()+x]
				}
			}
		} else {
			copyPixels(dst.image, c.Rect.Min, img, img.Rect, true)
		}
	case SolidFill:
		if !exists || !p.inFrame {
			return ErrInvalid
		}
		for _, r := range c.Rects {
			if !contained(r, s.image.Rect) {
				return ErrInvalid
			}
			if err := t.spend(area(r)); err != nil {
				return err
			}
		}
		dst, err := t.writable(c.SurfaceID)
		if err != nil {
			return err
		}
		for _, r := range c.Rects {
			for y := r.Min.Y; y < r.Max.Y; y++ {
				for x := r.Min.X; x < r.Max.X; x++ {
					i := dst.image.PixOffset(x, y)
					dst.image.Pix[i], dst.image.Pix[i+1], dst.image.Pix[i+2], dst.image.Pix[i+3] = c.Color[2], c.Color[1], c.Color[0], c.Color[3]
				}
			}
		}
	case SurfaceToSurface, CacheToSurface:
		if !p.inFrame {
			return ErrInvalid
		}
		var src *image.NRGBA
		destID := c.SurfaceID
		if c.ID == SurfaceToSurface {
			if !exists || c.Rect.Empty() || !contained(c.Rect, s.image.Rect) {
				return ErrInvalid
			}
			destID = c.DestSurfaceID
			if err := t.spend(area(c.Rect)); err != nil {
				return err
			}
			src = image.NewNRGBA(image.Rect(0, 0, c.Rect.Dx(), c.Rect.Dy()))
			copyPixels(src, image.Point{}, s.image, c.Rect, false)
		} else {
			entry, ok := p.cache[c.CacheSlot]
			if !ok {
				return ErrInvalid
			}
			src = entry.image
		}
		dst, ok := p.surfaces[destID]
		if !ok {
			return ErrInvalid
		}
		for _, point := range c.Points {
			if !contained(src.Rect.Add(point), dst.image.Rect) {
				return ErrInvalid
			}
			if err := t.spend(area(src.Rect)); err != nil {
				return err
			}
		}
		dst, err := t.writable(destID)
		if err != nil {
			return err
		}
		for _, point := range c.Points {
			copyPixels(dst.image, point, src, src.Rect, false)
		}
	case SurfaceToCache:
		if !exists || c.CacheSlot > 4096 || c.Rect.Empty() || !contained(c.Rect, s.image.Rect) {
			return ErrInvalid
		}
		old := p.cache[c.CacheSlot]
		oldSize := 0
		if old.image != nil {
			oldSize = len(old.image.Pix)
		}
		if area(c.Rect)*4 > maxCacheBytes-p.cacheBytes+oldSize {
			return ErrInvalid
		}
		if err := t.spend(area(c.Rect)); err != nil {
			return err
		}
		img := image.NewNRGBA(image.Rect(0, 0, c.Rect.Dx(), c.Rect.Dy()))
		copyPixels(img, image.Point{}, s.image, c.Rect, false)
		p.cache[c.CacheSlot] = cacheEntry{img, c.CacheKey}
		p.cacheBytes += len(img.Pix) - oldSize
	case EvictCacheEntry:
		entry, ok := p.cache[c.CacheSlot]
		if !ok {
			return ErrInvalid
		}
		p.cacheBytes -= len(entry.image.Pix)
		delete(p.cache, c.CacheSlot)
	case DeleteEncodingContext:
		if !exists {
			return ErrInvalid
		}
		contexts, associations := s.progressive.ContextCount(), s.progressive.AssociationCount()
		s.progressive.DeleteContext(c.ContextID)
		p.progressiveContexts += s.progressive.ContextCount() - contexts
		p.progressiveAssociations += s.progressive.AssociationCount() - associations
		p.surfaces[c.SurfaceID] = s
	case WireToSurface2:
		return t.progressive(c)
	default:
		return ErrUnsupported
	}
	return nil
}

func (t *transaction) present(result *Result) error {
	p := t.p
	changed, err := t.presentWindows()
	if err != nil {
		return err
	}
	if changed {
		result.WindowsChanged = true
	}
	var ids []int
	for id, s := range p.surfaces {
		if s.mapped && s.dirty {
			ids = append(ids, int(id))
		}
	}
	if len(ids) == 0 {
		return nil
	}
	if !t.outputCopied {
		if err := t.spend(area(p.output.Rect)); err != nil {
			return err
		}
		p.output = cloneImage(p.output)
		t.outputCopied = true
	}
	sort.Slice(ids, func(i, j int) bool {
		return p.surfaces[uint16(ids[i])].mappingOrder < p.surfaces[uint16(ids[j])].mappingOrder
	})
	for _, id := range ids {
		s := p.surfaces[uint16(id)]
		dst := image.Rectangle{Min: s.origin, Max: s.origin.Add(s.target)}.Intersect(p.output.Rect)
		if err := t.spend(area(dst)); err != nil {
			return err
		}
		if !dst.Empty() {
			if s.target == s.image.Rect.Size() {
				copyPixels(p.output, dst.Min, s.image, dst.Sub(s.origin), true)
			} else {
				copyScaledRGB(p.output, dst, s.image, s.origin, s.target)
			}
		}
		s.dirty = false
		p.surfaces[uint16(id)] = s
	}
	return nil
}

// Receiver composes the independent ZGFX history with the software pipeline.
// Each Receive is one reassembled Graphics DVC message. Any error is terminal:
// compressed history may have advanced before a later graphics validation fails.
// Replace the Receiver only when a new graphics channel is established.
type Receiver struct {
	WindowMapping                        bool
	Profile                              Profile
	bulk                                 zgfx.Decoder
	pipeline                             Pipeline
	failed                               bool
	messages, encodedBytes, decodedBytes uint64
}

func (r *Receiver) Receive(data []byte) (Result, error) {
	if r.failed {
		return Result{}, ErrInvalid
	}
	r.pipeline.Profile = r.Profile
	r.pipeline.WindowMapping = r.WindowMapping
	plain, err := r.bulk.Decode(data, MaxMessage)
	var result Result
	if err == nil {
		result, err = r.pipeline.Apply(plain)
	}
	if err != nil {
		r.failed = true
		return Result{}, err
	}
	r.messages++
	r.encodedBytes += uint64(len(data))
	r.decodedBytes += uint64(len(plain))
	return result, nil
}
func (r *Receiver) Snapshot() *image.NRGBA { return r.pipeline.Snapshot() }
func (r *Receiver) Monitors() []Monitor    { return r.pipeline.Monitors() }

// Stats reports successfully processed GFX messages and actual codec use.
// Counts describe this channel lifetime; a resize does not reset them.
type Stats struct {
	WindowMappings         uint64 `json:"window_mappings"`
	ScaledWindowMappings   uint64 `json:"scaled_window_mappings"`
	WindowFrames           uint64 `json:"window_frames"`
	AVC444                 uint64 `json:"avc444"`
	AVC444V2               uint64 `json:"avc444v2"`
	AVCSubframes           uint64 `json:"avc_subframes"`
	AVCMainPixels          int    `json:"avc_main_pixels"`
	ScaledMappings         uint64 `json:"scaled_mappings"`
	CapabilityVersion      uint32 `json:"capability_version"`
	CapabilityFlags        uint32 `json:"capability_flags"`
	AVC420                 uint64 `json:"avc420"`
	AVCContexts            int    `json:"avc_contexts"`
	AVCReferencePixels     int    `json:"avc_reference_pixels"`
	Profile                string `json:"profile"`
	Confirmed              bool   `json:"confirmed"`
	Frames                 uint64 `json:"frames"`
	Resets                 uint64 `json:"resets"`
	Raw                    uint64 `json:"raw"`
	Planar                 uint64 `json:"planar"`
	Clear                  uint64 `json:"clear"`
	Alpha                  uint64 `json:"alpha"`
	RemoteFX               uint64 `json:"remotefx"`
	Progressive            uint64 `json:"progressive"`
	ProgressiveSimple      uint64 `json:"progressive_simple"`
	ProgressiveFirst       uint64 `json:"progressive_first"`
	ProgressiveUpgrade     uint64 `json:"progressive_upgrade"`
	ProgressiveDifference  uint64 `json:"progressive_difference"`
	ProgressiveReduced     uint64 `json:"progressive_reduced"`
	ProgressiveReused      uint64 `json:"progressive_reused_tiles"` // region intersections reusing a tile from a previous frame
	ProgressiveCachedTiles int    `json:"progressive_cached_tiles"`
	ProgressiveContexts    int    `json:"progressive_contexts"`
	Messages               uint64 `json:"messages"`
	EncodedBytes           uint64 `json:"encoded_bytes"`
	DecodedBytes           uint64 `json:"decoded_bytes"`
}

func (r *Receiver) Stats() Stats {
	s := r.pipeline.stats
	s.AVCContexts, s.AVCReferencePixels, s.AVCMainPixels = r.pipeline.avcContexts, r.pipeline.avcPixels, r.pipeline.avcMainPixels
	s.ProgressiveCachedTiles, s.ProgressiveContexts = r.pipeline.progressiveTiles, r.pipeline.progressiveContexts
	s.Messages, s.EncodedBytes, s.DecodedBytes = r.messages, r.encodedBytes, r.decodedBytes
	return s
}
