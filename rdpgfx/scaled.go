package rdpgfx

import "image"

type scaleSample struct {
	lo, hi int
	weight int64
}

// Pixel-center bilinear interpolation in fixed-point arithmetic. MS-RDPEGFX
// specifies the target geometry, not a required resampling kernel. Sampling is
// relative to the full target mapping so clipping never changes its phase.
func scaleCoordinate(at, source, target int) scaleSample {
	position := (int64(2*at+1)*int64(source)*65536)/(int64(target)*2) - 32768
	if position <= 0 {
		return scaleSample{}
	}
	lo := int(position >> 16)
	if lo >= source-1 {
		return scaleSample{source - 1, source - 1, 0}
	}
	return scaleSample{lo, lo + 1, position & 65535}
}

func copyScaledRGB(dst *image.NRGBA, clip image.Rectangle, src *image.NRGBA, origin, target image.Point) {
	xs := make([]scaleSample, clip.Dx())
	for x := range xs {
		xs[x] = scaleCoordinate(clip.Min.X+x-origin.X, src.Rect.Dx(), target.X)
	}
	for y := clip.Min.Y; y < clip.Max.Y; y++ {
		sy := scaleCoordinate(y-origin.Y, src.Rect.Dy(), target.Y)
		for i, sx := range xs {
			x := clip.Min.X + i
			a, b := src.PixOffset(sx.lo, sy.lo), src.PixOffset(sx.hi, sy.lo)
			c, d := src.PixOffset(sx.lo, sy.hi), src.PixOffset(sx.hi, sy.hi)
			out := dst.PixOffset(x, y)
			for component := 0; component < 3; component++ {
				top := int64(src.Pix[a+component])*(65536-sx.weight) + int64(src.Pix[b+component])*sx.weight
				bottom := int64(src.Pix[c+component])*(65536-sx.weight) + int64(src.Pix[d+component])*sx.weight
				dst.Pix[out+component] = byte((top*(65536-sy.weight) + bottom*sy.weight + (1 << 31)) >> 32)
			}
		}
	}
}
