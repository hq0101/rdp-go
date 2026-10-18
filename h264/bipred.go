package h264

func bipredSample(a, b int, mode, component int, current PictureOrder, first, second predictionReference) (int32, error) {
	if mode == 0 {
		return int32((a + b + 1) >> 1), nil
	}
	w0, w1 := first.weights[component], second.weights[component]
	if mode == 2 {
		left, right := 32, 32
		if !first.longTerm && !second.longTerm {
			diff, e := orderDifference(second.order, first.order)
			if e != nil {
				return 0, e
			}
			if diff != 0 {
				scale, e := distanceScale(current, first.order, second.order)
				if e != nil {
					return 0, e
				}
				weight := scale >> 2
				if weight >= -64 && weight <= 128 {
					left, right = 64-weight, weight
				}
			}
		}
		w0, w1 = predictionWeight{5, left, 0}, predictionWeight{5, right, 0}
	} else {
		limit := 128
		if w0.denom == 7 {
			limit = 127
		}
		if w0.denom != w1.denom || w0.weight+w1.weight < -128 || w0.weight+w1.weight > limit {
			return 0, ErrInvalid
		}
	}
	value := ((a*w0.weight + b*w1.weight + (1 << w0.denom)) >> (w0.denom + 1)) + ((w0.offset + w1.offset + 1) >> 1)
	return int32(clipSample(value)), nil
}

func interPrediction(b *interMB, index, component, mx, my, x, y int) (int32, error) {
	var samples [2]int
	var refs [2]predictionReference
	var used [2]bool
	for list := 0; list < 2; list++ {
		m, pool := b.cells[index], b.list
		if list == 1 {
			if b.back == nil {
				continue
			}
			m, pool = b.back.cells[index], b.back.list
		}
		if !m.ready {
			return 0, ErrInvalid
		}
		if m.ref < 0 {
			continue
		}
		if int(m.ref) >= len(pool) || pool[m.ref].picture == nil {
			return 0, ErrInvalid
		}
		refs[list], used[list] = pool[m.ref], true
		src := refs[list].picture.samples
		if component == 0 {
			samples[list] = lumaSample(src.Y, src.YStride, src.Rect.Dx(), src.Rect.Dy(), 4*(mx+x)+int(m.x), 4*(my+y)+int(m.y))
		} else {
			plane := src.Cb
			if component == 2 {
				plane = src.Cr
			}
			samples[list] = chromaSample(plane, src.CStride, src.Rect.Dx()/2, src.Rect.Dy()/2, 8*(mx/2+x)+int(m.x), 8*(my/2+y)+int(m.y))
		}
	}
	if used[0] && used[1] {
		return bipredSample(samples[0], samples[1], b.biWeight, component, b.order, refs[0], refs[1])
	}
	list := 0
	if !used[0] {
		list = 1
	}
	if !used[list] {
		return 0, ErrInvalid
	}
	if b.back == nil || b.biWeight == 1 {
		return weightSample(samples[list], refs[list].weights[component]), nil
	}
	return int32(samples[list]), nil
}
