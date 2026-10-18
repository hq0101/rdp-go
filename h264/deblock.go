package h264

import "image"

type deblockParams struct {
	disable     byte
	alpha, beta int // offsets after multiplication by two (7.4.3)
}

// H.264 (01/2012), Tables 8-16 and 8-17. Eight-bit thresholds.
var deblockAlpha = [52]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 4, 5, 6, 7, 8, 9, 10, 12, 13, 15, 17, 20, 22, 25, 28, 32, 36, 40, 45, 50, 56, 63, 71, 80, 90, 101, 113, 127, 144, 162, 182, 203, 226, 255, 255}
var deblockBeta = [52]int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14, 15, 15, 16, 16, 17, 17, 18, 18}
var deblockTC = [52][3]int{
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0},
	{0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0}, {0, 0, 0},
	{0, 0, 0}, {0, 0, 1}, {0, 0, 1}, {0, 0, 1}, {0, 0, 1}, {0, 1, 1}, {0, 1, 1}, {1, 1, 1}, {1, 1, 1}, {1, 1, 1},
	{1, 1, 1}, {1, 1, 2}, {1, 1, 2}, {1, 1, 2}, {1, 1, 2}, {1, 2, 3}, {1, 2, 3}, {2, 2, 3}, {2, 2, 4}, {2, 3, 4},
	{2, 3, 4}, {3, 3, 5}, {3, 4, 6}, {3, 4, 6}, {4, 5, 7}, {4, 5, 8}, {4, 6, 9}, {5, 7, 10}, {6, 8, 11}, {6, 8, 13},
	{7, 10, 14}, {8, 11, 16}, {9, 12, 18}, {10, 13, 20}, {11, 15, 23}, {13, 17, 25},
}

// filterEdgeSamples implements 8.7.2.2..8.7.2.4 for one set of eight samples,
// ordered p3 p2 p1 p0 | q0 q1 q2 q3. All decisions use the original samples.
func filterEdgeSamples(v [8]byte, strength, qp, alphaOffset, betaOffset int, chroma bool) [8]byte {
	out := v
	if strength == 0 {
		return out
	}
	ia, ib := max(0, min(51, qp+alphaOffset)), max(0, min(51, qp+betaOffset))
	a, b := deblockAlpha[ia], deblockBeta[ib]
	p3, p2, p1, p0 := int(v[0]), int(v[1]), int(v[2]), int(v[3])
	q0, q1, q2, q3 := int(v[4]), int(v[5]), int(v[6]), int(v[7])
	if abs(p0-q0) >= a || abs(p1-p0) >= b || abs(q1-q0) >= b {
		return out
	}
	ap, aq := abs(p2-p0) < b, abs(q2-q0) < b
	if strength < 4 {
		tc0 := deblockTC[ia][strength-1]
		tc := tc0
		if chroma {
			tc++
		} else {
			if ap {
				tc++
				out[2] = byte(p1 + max(-tc0, min(tc0, (p2+((p0+q0+1)>>1)-2*p1)>>1)))
			}
			if aq {
				tc++
				out[5] = byte(q1 + max(-tc0, min(tc0, (q2+((p0+q0+1)>>1)-2*q1)>>1)))
			}
		}
		delta := max(-tc, min(tc, (4*(q0-p0)+(p1-q1)+4)>>3))
		out[3], out[4] = byte(clipSample(p0+delta)), byte(clipSample(q0-delta))
		return out
	}
	strong := !chroma && abs(p0-q0) < ((a>>2)+2)
	if strong && ap {
		out[3] = byte((p2 + 2*p1 + 2*p0 + 2*q0 + q1 + 4) >> 3)
		out[2] = byte((p2 + p1 + p0 + q0 + 2) >> 2)
		out[1] = byte((2*p3 + 3*p2 + p1 + p0 + q0 + 4) >> 3)
	} else {
		out[3] = byte((2*p1 + p0 + q1 + 2) >> 2)
	}
	if strong && aq {
		out[4] = byte((p1 + 2*p0 + 2*q0 + 2*q1 + q2 + 4) >> 3)
		out[5] = byte((p0 + q0 + q1 + q2 + 2) >> 2)
		out[6] = byte((2*q3 + 3*q2 + q1 + q0 + p0 + 4) >> 3)
	} else {
		out[4] = byte((2*q1 + q0 + p1 + 2) >> 2)
	}
	return out
}

// Progressive pictures use intra strengths 4/3, residual strength 2 and
// reference/motion-dependent inter strengths 0/1.
// Run only after reconstruction, so intra prediction always sees unfiltered
// samples. Picture order, vertical-before-horizontal order, and q-side slice
// parameters matter even when slices were delivered in a different order.
func deblockIntra(dst *image.YCbCr, blocks []*intraMB) {
	columns := dst.Rect.Dx() / 16
	for address, q := range blocks {
		if q.filter.disable == 1 {
			continue
		}
		for component, plane := range [][]byte{dst.Y, dst.Cb, dst.Cr} {
			n, stride := 16, dst.YStride
			if component != 0 {
				n, stride = 8, dst.CStride
			}
			mx, my := address%columns*n, address/columns*n
			for axis := 0; axis < 2; axis++ {
				for edge := 0; edge < n; edge += 4 {
					if component == 0 && q.transform8 && edge%8 != 0 {
						continue
					}
					p := q
					if edge == 0 {
						neighbour := address - 1
						if axis == 0 {
							if mx == 0 {
								continue
							}
						} else {
							if my == 0 {
								continue
							}
							neighbour = address - columns
						}
						p = blocks[neighbour]
						if q.filter.disable == 2 && p.firstMB != q.firstMB {
							continue
						}
					}
					qp := (p.qp[component] + q.qp[component] + 1) / 2
					for k := 0; k < n; k++ {
						off, step := (my+k)*stride+mx+edge, 1
						if axis != 0 {
							off, step = (my+edge)*stride+mx+k, stride
						}
						// Chroma uses the strength of its collocated luma edge.
						scale := 16 / n
						x, y := edge*scale, k*scale
						if axis != 0 {
							x, y = y, x
						}
						px, py := x-1, y
						if axis != 0 {
							px, py = x, y-1
						}
						pi, qi := (py+16)%16/4*4+(px+16)%16/4, y/4*4+x/4
						strength := boundaryStrength(p, q, pi, qi, edge == 0)
						if strength == 0 {
							continue
						}
						var samples [8]byte
						for i := range samples {
							samples[i] = plane[off+(i-4)*step]
						}
						filtered := filterEdgeSamples(samples, strength, qp, q.filter.alpha, q.filter.beta, component != 0)
						for i := 1; i <= 6; i++ {
							plane[off+(i-4)*step] = filtered[i]
						}
					}
				}
			}
		}
	}
}

// Filtering compares picture identity, not slice-local reference indices.
func boundaryStrength(p, q *intraMB, pi, qi int, external bool) int {
	if p.inter == nil || q.inter == nil {
		if external {
			return 4
		}
		return 3
	}
	nonzero := func(b *intraMB, index int) bool {
		if !b.transform8 {
			return b.totals[index] != 0
		}
		start := index/8*8 + (index%4)/2*2
		return b.totals[start] != 0 || b.totals[start+1] != 0 || b.totals[start+4] != 0 || b.totals[start+5] != 0
	}
	if nonzero(p, pi) || nonzero(q, qi) {
		return 2
	}
	if !equivalentPrediction(p.inter, q.inter, pi, qi) {
		return 1
	}
	return 0
}

func equivalentPrediction(p, q *interMB, pi, qi int) bool {
	type use struct {
		picture *referencePicture
		m       motion
	}
	collect := func(b *interMB, index int) ([2]use, int) {
		var result [2]use
		count := 0
		m, pool := b.cells[index], b.list
		if m.ref >= 0 {
			result[count] = use{pool[m.ref].picture, m}
			count++
		}
		if b.back != nil {
			m, pool = b.back.cells[index], b.back.list
			if m.ref >= 0 {
				result[count] = use{pool[m.ref].picture, m}
				count++
			}
		}
		return result, count
	}
	a, ac := collect(p, pi)
	b, bc := collect(q, qi)
	if ac != bc {
		return false
	}
	close := func(x, y use) bool {
		return x.picture == y.picture && abs(int(x.m.x)-int(y.m.x)) < 4 && abs(int(x.m.y)-int(y.m.y)) < 4
	}
	if ac == 1 {
		return close(a[0], b[0])
	}
	return ac == 2 && (close(a[0], b[0]) && close(a[1], b[1]) || close(a[0], b[1]) && close(a[1], b[0]))
}
