package graphics

import (
	"encoding/binary"
	"fmt"
	"image"
	"maps"
)

const maxProgressiveContexts = 1024
const maxProgressiveAssociations = 65536
const maxProgressiveWork = 64 << 20

type progressiveStoredTile struct {
	data       *progressiveTile
	pixels     *image.NRGBA
	contexts   map[uint32]bool
	refinement bool
}

// ProgressiveDecoder owns the coefficient references and progressive state for
// one offscreen surface. The zero value is ready. Calls must be serialized.
// Value copies are independent: maps, tiles and images are copied on write.
// This codec API does not advertise a GFX profile or process network framing.
// GFX logical frames, surface copying and frame acknowledgements are external.
type ProgressiveDecoder struct {
	// MaxTiles is a local resource cap, not a capability flag. Zero selects
	// 2048; the hard limit is 4096. Each cached tile owns approximately 124 KiB
	// of coefficient/sign/pixel data, excluding maps and transaction copies.
	MaxTiles      int
	width, height int
	contexts      map[uint32]byte
	tiles         map[image.Point]progressiveStoredTile
	associations  int
}

// ProgressiveResult describes regions to copy and tiles actually decoded.
// A region can reference a tile received in an earlier message of the same
// outer GFX frame. Tile supplies its current pixels; the caller must enforce
// the outer frame's coverage/presentation rules before publishing the frame.
type ProgressiveResult struct {
	Rectangles                                                           []image.Rectangle
	UpdatedTiles                                                         []image.Point
	SimpleTiles, FirstTiles, UpgradeTiles, DifferenceTiles, ReducedTiles int
	// Regions preserves wire order so a caller can validate coverage using only
	// tiles received in this or earlier regions of the outer graphics frame.
	// Repeated tile origins remain visible; they are not silently deduplicated.
	Regions []ProgressiveRegion
}

// ProgressiveRegion describes one region block in wire order. Its slices are
// views of this call's owned result metadata, not of the decoder's state.
type ProgressiveRegion struct {
	Rectangles   []image.Rectangle
	UpdatedTiles []image.Point
}

// Reset releases this surface's reference and refinement state while retaining
// its configured resource cap. Use on surface deletion, not output resizing.
func (d *ProgressiveDecoder) Reset() { limit := d.MaxTiles; *d = ProgressiveDecoder{MaxTiles: limit} }

// DeleteContext releases its associations and invalidates refinement when no
// other context uses a tile. Coefficient storage and reconstructed DWT references
// survive for sub-band diffs; Reset releases that storage.
// An unknown ID is a no-op. Calls, including snapshots, must be serialized.
func (d *ProgressiveDecoder) DeleteContext(id uint32) {
	if _, ok := d.contexts[id]; !ok {
		return
	}
	d.contexts = maps.Clone(d.contexts)
	delete(d.contexts, id)
	d.tiles = maps.Clone(d.tiles)
	for point, tile := range d.tiles {
		if !tile.contexts[id] {
			continue
		}
		tile.contexts = maps.Clone(tile.contexts)
		delete(tile.contexts, id)
		d.associations--
		if len(tile.contexts) == 0 {
			tile.refinement = false
		}
		d.tiles[point] = tile
	}
}

// Tile returns an owned 64x64 opaque tile at the given pixel-aligned origin,
// or nil if no reference exists. Crop edge tiles to the surface dimensions.
func (d *ProgressiveDecoder) Tile(origin image.Point) *image.NRGBA {
	tile, ok := d.tiles[origin]
	if !ok {
		return nil
	}
	img := image.NewNRGBA(tile.pixels.Rect)
	copy(img.Pix, tile.pixels.Pix)
	return img
}
func (d *ProgressiveDecoder) TileCount() int        { return len(d.tiles) }
func (d *ProgressiveDecoder) ContextCount() int     { return len(d.contexts) }
func (d *ProgressiveDecoder) AssociationCount() int { return d.associations }

// HasTile reports whether this surface has reconstructed the tile before.
func (d *ProgressiveDecoder) HasTile(origin image.Point) bool {
	_, ok := d.tiles[origin]
	return ok
}

func (d *ProgressiveDecoder) Decode(contextID uint32, data []byte, width, height int) (ProgressiveResult, error) {
	r, _, err := d.DecodeWithBudget(contextID, data, width, height, maxProgressiveWork)
	return r, err
}

// DecodeWithBudget consumes one complete RFX_PROGRESSIVE_BITMAP_STREAM. It
// requires complete inner frames if FRAME_BEGIN is present; header-only input
// and multiple inner frames are allowed. Each decoded tile costs 8*4096 work
// units, with extra bounded parsing work. Any failure rolls back coefficients,
// signs, images and contexts.
func (d *ProgressiveDecoder) DecodeWithBudget(contextID uint32, data []byte, width, height, budget int) (ProgressiveResult, int, error) {
	limit := d.MaxTiles
	if limit == 0 {
		limit = 2048
	}
	if limit < 1 || limit > 4096 || !codecDimensions(width, height) || len(data) == 0 || len(data) > 64<<20 || budget < 0 || budget > maxProgressiveWork {
		return ProgressiveResult{}, 0, ErrInvalid
	}
	if d.width != 0 && (d.width != width || d.height != height) {
		return ProgressiveResult{}, 0, ErrInvalid
	}
	next := *d
	next.contexts = maps.Clone(d.contexts)
	if next.contexts == nil {
		next.contexts = make(map[uint32]byte)
	}
	next.tiles = maps.Clone(d.tiles)
	if next.tiles == nil {
		next.tiles = make(map[image.Point]progressiveStoredTile)
	}
	_, known := next.contexts[contextID]
	if !known && len(next.contexts) >= maxProgressiveContexts {
		return ProgressiveResult{}, 0, ErrInvalid
	}
	next.contexts[contextID] = next.contexts[contextID]
	next.width, next.height = width, height
	t := progressiveTransaction{decoder: &next, id: contextID, known: known, limit: limit, budget: budget}
	active := false
	regions, advertised := 0, 0
	for len(data) > 0 {
		if err := t.spend(1); err != nil || len(data) < 6 || t.blocks >= 4096 {
			return ProgressiveResult{}, 0, ErrInvalid
		}
		t.blocks++
		kind, size := binary.LittleEndian.Uint16(data), uint64(binary.LittleEndian.Uint32(data[2:]))
		if size < 6 || size > uint64(len(data)) {
			return ProgressiveResult{}, 0, ErrInvalid
		}
		body := data[6:int(size)]
		data = data[int(size):]
		var err error
		switch kind {
		case 0xccc0: // Optional SYNC: magic/version are ignored as specified.
			if len(body) != 6 {
				err = ErrInvalid
			}
		case 0xccc3: // Optional CONTEXT, even after FRAME_BEGIN.
			if len(body) != 4 || binary.LittleEndian.Uint16(body[1:]) != 64 {
				err = ErrInvalid
				break
			}
			// ctxId is advisory. Tile flags determine whether data is a diff;
			// omitted CONTEXT does not prevent decoding explicit difference tiles.
			next.contexts[contextID] = body[3] & 1
		case 0xccc1:
			if active || len(body) != 6 {
				err = ErrInvalid
				break
			}
			active, regions = true, 0
			advertised = int(binary.LittleEndian.Uint16(body[4:])) // frameIndex ignored
		case 0xccc2:
			if len(body) != 0 {
				err = ErrInvalid
				break
			}
			active = false // Duplicate FRAME_END is ignored.
		case 0xccc4:
			if !active {
				continue
			} // MUST ignore out-of-frame regions.
			regions++
			if regions > advertised {
				err = ErrInvalid
				break
			}
			err = t.region(body)
		default:
			// Unknown blocks are skipped inside their validated outer length.
		}
		if err != nil {
			return ProgressiveResult{}, 0, fmt.Errorf("progressive block 0x%04x: %w", kind, err)
		}
	}
	if active {
		return ProgressiveResult{}, 0, ErrInvalid
	}
	// The spec explicitly permits an advertised region count greater than the
	// number actually sent. No allocation or iteration uses that count.
	*d = next
	return t.result, t.work, nil
}

type progressiveTransaction struct {
	decoder                     *ProgressiveDecoder
	id                          uint32
	known                       bool
	limit, budget, work, blocks int
	result                      ProgressiveResult
}

func (t *progressiveTransaction) spend(n int) error {
	if n < 0 || n > t.budget-t.work {
		return ErrInvalid
	}
	t.work += n
	return nil
}
func progressiveQuant(r *clearReader, maximum byte) ([10]byte, error) {
	var q [10]byte
	for i := 0; i < 5; i++ {
		v := r.u8()
		q[2*i], q[2*i+1] = v&15, v>>4
		if q[2*i] > maximum || q[2*i+1] > maximum {
			return q, ErrInvalid
		}
	}
	if r.bad {
		return q, ErrInvalid
	}
	return q, nil
}
func (t *progressiveTransaction) region(body []byte) error {
	firstRect, firstTile := len(t.result.Rectangles), len(t.result.UpdatedTiles)
	r := clearReader{data: body}
	if r.u8() != 64 {
		return ErrInvalid
	}
	nrect, nquant, nprog, flags := int(r.u16()), int(r.u8()), int(r.u8()), r.u8()
	ntiles, size := int(r.u16()), r.u32()
	if r.bad || nrect == 0 || nrect > 4096-len(t.result.Rectangles) || nquant > 7 || ntiles > 4096-t.blocks {
		return ErrInvalid
	}
	if err := t.spend(nrect + nquant + nprog); err != nil {
		return err
	}
	for i := 0; i < nrect; i++ {
		x, y, w, h := int(r.u16()), int(r.u16()), int(r.u16()), int(r.u16())
		if r.bad || w == 0 || h == 0 || x+w > t.decoder.width || y+h > t.decoder.height {
			return ErrInvalid
		}
		t.result.Rectangles = append(t.result.Rectangles, image.Rect(x, y, x+w, y+h))
	}
	quants := make([][10]byte, nquant)
	for i := range quants {
		q, err := progressiveQuant(&r, 15)
		if err != nil {
			return err
		}
		quants[i] = q
	}
	prog := make([][3][10]byte, nprog)
	for i := range prog {
		r.u8() // quality is advisory; the actual bit positions control refinement
		for c := range prog[i] {
			q, err := progressiveQuant(&r, 8)
			if err != nil {
				return err
			}
			prog[i][c] = q
		}
	}
	if r.bad || uint64(size) != uint64(len(r.data)) {
		return ErrInvalid
	}
	for i := 0; i < ntiles; i++ {
		kind, length := r.u16(), r.u32()
		if r.bad || length < 6 || uint64(length-6) > uint64(len(r.data)) {
			return ErrInvalid
		}
		if err := t.spend(8 * 4096); err != nil {
			return err
		}
		t.blocks++
		if err := t.tile(kind, r.take(int(length)-6), quants, prog, flags&1 != 0); err != nil {
			return fmt.Errorf("tile %d type 0x%04x: %w", i, kind, err)
		}
	}
	if r.bad || len(r.data) != 0 {
		return ErrInvalid
	}
	t.result.Regions = append(t.result.Regions, ProgressiveRegion{
		Rectangles: t.result.Rectangles[firstRect:], UpdatedTiles: t.result.UpdatedTiles[firstTile:],
	})
	return nil
}
func (t *progressiveTransaction) tile(kind uint16, body []byte, quants [][10]byte, prog [][3][10]byte, reduce bool) error {
	if kind < 0xccc5 || kind > 0xccc7 {
		return ErrUnsupported
	}
	r := clearReader{data: body}
	var base, extra [3][10]byte
	for c := range base {
		index := int(r.u8())
		if index >= len(quants) {
			return ErrInvalid
		}
		base[c] = quants[index]
	}
	point := image.Pt(int(r.u16())*64, int(r.u16())*64)
	if r.bad || point.X >= t.decoder.width || point.Y >= t.decoder.height {
		return ErrInvalid
	}
	flags := byte(0)
	if kind != 0xccc7 {
		flags = r.u8()
	}
	if kind != 0xccc5 {
		quality := int(r.u8())
		if quality != 255 {
			if quality >= len(prog) {
				return ErrInvalid
			}
			extra = prog[quality]
		}
	}
	old, exists := t.decoder.tiles[point]
	if !exists && len(t.decoder.tiles) >= t.limit {
		return ErrInvalid
	}
	var tile *progressiveTile
	var err error
	if kind == 0xccc7 {
		if !t.known || !exists || !old.refinement || old.data.reduce != reduce {
			return ErrInvalid
		}
		var sizes [3][2]int
		for c := range sizes {
			sizes[c] = [2]int{int(r.u16()), int(r.u16())}
		}
		var srl, raw [3][]byte
		for c := range srl {
			srl[c], raw[c] = r.take(sizes[c][0]), r.take(sizes[c][1])
		}
		if r.bad || len(r.data) != 0 {
			return ErrInvalid
		}
		tile, err = upgradeProgressiveTile(old.data, srl, raw, base, extra)
	} else {
		lengths := [3]int{int(r.u16()), int(r.u16()), int(r.u16())}
		tail := int(r.u16())
		var data [3][]byte
		for c := range data {
			data[c] = r.take(lengths[c])
		}
		r.take(tail) // Optional tail data SHOULD be ignored.
		if r.bad || len(r.data) != 0 {
			return ErrInvalid
		}
		tile, err = firstProgressiveTile(old.data, data, base, extra, reduce, flags&1 != 0)
	}
	if err != nil {
		return fmt.Errorf("tile at %v: %w", point, err)
	}
	contexts := maps.Clone(old.contexts)
	if contexts == nil {
		contexts = make(map[uint32]bool)
	}
	if !contexts[t.id] {
		if t.decoder.associations >= maxProgressiveAssociations {
			return ErrInvalid
		}
		contexts[t.id] = true
		t.decoder.associations++
	}
	t.decoder.tiles[point] = progressiveStoredTile{tile, renderProgressiveTile(tile), contexts, true}
	switch kind {
	case 0xccc5:
		t.result.SimpleTiles++
	case 0xccc6:
		t.result.FirstTiles++
	case 0xccc7:
		t.result.UpgradeTiles++
	}
	if flags&1 != 0 {
		t.result.DifferenceTiles++
	}
	if reduce {
		t.result.ReducedTiles++
	}
	t.known = true // A subsequent upgrade in this same stream can use this context.
	t.result.UpdatedTiles = append(t.result.UpdatedTiles, point)
	return nil
}
