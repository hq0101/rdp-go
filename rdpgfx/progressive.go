package rdpgfx

import (
	"fmt"
	"image"
	"maps"
)

// These limits are shared by all offscreen surfaces, not multiplied by their
// count. Coefficient/sign/pixel storage is approximately 124 KiB per tile.
const maxProgressiveTiles = 4096
const maxProgressiveContexts = 1024
const maxProgressiveAssociations = 65536
const maxProgressiveRectangles = 4096

type progressiveFrame struct {
	tiles      map[image.Point]bool
	rectangles map[image.Rectangle]bool
}

func (t *transaction) progressive(c Command) error {
	p := t.p
	if p.confirmedFlags&ThinClient != 0 || c.CodecID != CodecProgressive {
		return ErrUnsupported
	}
	s, exists := p.surfaces[c.SurfaceID]
	if !exists || !p.inFrame {
		return ErrInvalid
	}
	previousTiles := s.progressive.TileCount()
	previousContexts := s.progressive.ContextCount()
	previousAssociations := s.progressive.AssociationCount()
	previous := s.progressive
	// MaxTiles=0 means default in the standalone codec. If the global budget is
	// exhausted, allow at most one temporary tile and reject it before commit;
	// this still permits header-only messages and updates to existing tiles.
	s.progressive.MaxTiles = max(1, maxProgressiveTiles-p.progressiveTiles+previousTiles)
	decoded, work, err := s.progressive.DecodeWithBudget(c.ContextID, c.Data, s.image.Rect.Dx(), s.image.Rect.Dy(), maxWork-t.work)
	if err != nil {
		return err
	}
	t.work += work
	p.progressiveTiles += s.progressive.TileCount() - previousTiles
	p.progressiveContexts += s.progressive.ContextCount() - previousContexts
	p.progressiveAssociations += s.progressive.AssociationCount() - previousAssociations
	if p.progressiveTiles > maxProgressiveTiles || p.progressiveContexts > maxProgressiveContexts || p.progressiveAssociations > maxProgressiveAssociations {
		return fmt.Errorf("progressive aggregate resource limit: %w", ErrInvalid)
	}
	previousFrameTiles := s.progressiveFrame.tiles
	s.progressiveFrame.tiles = maps.Clone(s.progressiveFrame.tiles)
	if s.progressiveFrame.tiles == nil {
		s.progressiveFrame.tiles = make(map[image.Point]bool)
	}
	s.progressiveFrame.rectangles = maps.Clone(s.progressiveFrame.rectangles)
	if s.progressiveFrame.rectangles == nil {
		s.progressiveFrame.rectangles = make(map[image.Rectangle]bool)
	}
	// Validate coverage in wire order: later regions cannot retroactively fill
	// holes in earlier regions. Windows also sends rectangle-only refinements
	// without retransmitting tiles in a new frame. Such regions still request a
	// copy of the previously decoded tile, which may not have been presented in
	// that rectangle yet. Never accept unknown tiles or use future refinements.
	for _, region := range decoded.Regions {
		for _, point := range region.UpdatedTiles {
			if s.progressiveFrame.tiles[point] {
				return fmt.Errorf("repeated progressive tile in frame at %v: %w", point, ErrInvalid)
			}
			s.progressiveFrame.tiles[point] = true
		}
		for _, rect := range region.Rectangles {
			if s.progressiveFrame.rectangles[rect] || p.progressiveRects >= maxProgressiveRectangles {
				return fmt.Errorf("repeated progressive rectangle or frame region limit: %w", ErrInvalid)
			}
			s.progressiveFrame.rectangles[rect] = true
			p.progressiveRects++
			for y := rect.Min.Y / 64 * 64; y < rect.Max.Y; y += 64 {
				for x := rect.Min.X / 64 * 64; x < rect.Max.X; x += 64 {
					if err := t.spend(1); err != nil {
						return err
					}
					if !s.progressiveFrame.tiles[image.Pt(x, y)] {
						if !previous.HasTile(image.Pt(x, y)) {
							return fmt.Errorf("progressive rectangle %v lacks initialized tile (%d,%d): %w", rect, x, y, ErrInvalid)
						}
						p.stats.ProgressiveReused++
					}
				}
			}
		}
	}
	p.surfaces[c.SurfaceID] = s
	if len(decoded.Rectangles) > 0 {
		dst, err := t.writable(c.SurfaceID)
		if err != nil {
			return err
		}
		snapshots := make(map[image.Point]*image.NRGBA)
		previousSnapshots := make(map[image.Point]*image.NRGBA)
		available := maps.Clone(previousFrameTiles)
		if available == nil {
			available = make(map[image.Point]bool)
		}
		// Mirror the wire-order coverage check when presenting. A later tile
		// cannot change an earlier rectangle using a previous tile's pixels.
		for _, region := range decoded.Regions {
			for _, point := range region.UpdatedTiles {
				available[point] = true
			}
			for _, rect := range region.Rectangles {
				for y := rect.Min.Y / 64 * 64; y < rect.Max.Y; y += 64 {
					for x := rect.Min.X / 64 * 64; x < rect.Max.X; x += 64 {
						point := image.Pt(x, y)
						cache, decoder := snapshots, &s.progressive
						if !available[point] {
							cache, decoder = previousSnapshots, &previous
						}
						tile := cache[point]
						if tile == nil {
							if err := t.spend(4096); err != nil {
								return err
							}
							tile = decoder.Tile(point)
							if tile == nil {
								return ErrInvalid
							}
							cache[point] = tile
						}
						clipped := tile.Rect.Add(point).Intersect(rect)
						if err := t.spend(area(clipped)); err != nil {
							return err
						}
						copyPixels(dst.image, clipped.Min, tile, clipped.Sub(point), true)
					}
				}
			}
		}
	}
	p.stats.Progressive++
	p.stats.ProgressiveSimple += uint64(decoded.SimpleTiles)
	p.stats.ProgressiveFirst += uint64(decoded.FirstTiles)
	p.stats.ProgressiveUpgrade += uint64(decoded.UpgradeTiles)
	p.stats.ProgressiveDifference += uint64(decoded.DifferenceTiles)
	p.stats.ProgressiveReduced += uint64(decoded.ReducedTiles)
	return nil
}
