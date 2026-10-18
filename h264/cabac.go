package h264

// The arithmetic engine follows H.264 9.3 directly, reading only the bits
// required by renormalization. No implicit zero padding is supplied at EOF.
type cabac struct {
	r            *bitReader
	span, offset uint32
	contexts     [436]cabacContext
	stopped      bool
}
type cabacContext struct{ state, mps byte }

func newCABAC(r *bitReader, qp int) *cabac {
	return newCABACWithInit(r, qp, &cabacInitI)
}

func newCABACWithInit(r *bitReader, qp int, init *[436][2]int8) *cabac {
	c := &cabac{r: r}
	for i, pair := range init {
		pre := max(1, min(126, (int(pair[0])*qp>>4)+int(pair[1])))
		if pre <= 63 {
			c.contexts[i] = cabacContext{state: byte(63 - pre)}
		} else {
			c.contexts[i] = cabacContext{state: byte(pre - 64), mps: 1}
		}
	}
	for r.pos%8 != 0 && !r.bad {
		if r.read(1) != 1 {
			r.bad = true
		}
	}
	c.restart()
	return c
}

// PCM restarts the engine but preserves all adaptive context states.
func (c *cabac) restart() {
	c.span, c.offset, c.stopped = 510, c.r.read(9), false
	if c.offset >= 510 {
		c.r.bad = true
	}
}

func (c *cabac) renormalize() {
	for c.span < 256 && !c.r.bad {
		c.span <<= 1
		c.offset = c.offset<<1 | c.r.read(1)
	}
}

func (c *cabac) decision(index int) int {
	if c.r.bad {
		return 0
	}
	if c.stopped || index < 0 || index >= len(c.contexts) {
		c.r.bad = true
		return 0
	}
	ctx := &c.contexts[index]
	lps := uint32(cabacRangeLPS[ctx.state][(c.span>>6)&3])
	c.span -= lps
	bin := ctx.mps
	if c.offset >= c.span {
		c.offset -= c.span
		c.span = lps
		bin ^= 1
		if ctx.state == 0 {
			ctx.mps ^= 1
		}
		ctx.state = cabacNextLPS[ctx.state]
	} else {
		ctx.state = cabacNextMPS[ctx.state]
	}
	c.renormalize()
	return int(bin)
}

func (c *cabac) bypass() int {
	if c.r.bad {
		return 0
	}
	if c.stopped {
		c.r.bad = true
		return 0
	}
	c.offset = c.offset<<1 | c.r.read(1)
	if c.offset >= c.span {
		c.offset -= c.span
		return 1
	}
	return 0
}

func (c *cabac) terminate() bool {
	if c.r.bad || c.stopped {
		c.r.bad = true
		return false
	}
	c.span -= 2
	if c.offset >= c.span {
		// 9.3.3.2.4 requires the final bit to be one for both PCM and EOS.
		// Only EOS interprets it as rbsp_stop_one_bit.
		if c.r.pos == 0 || c.r.data[(c.r.pos-1)/8]>>(7-(c.r.pos-1)%8)&1 == 0 {
			c.r.bad = true
			return false
		}
		c.stopped = true
		return true
	}
	c.renormalize()
	return false
}

func (c *cabac) finish() error {
	r := c.r
	if r.bad || !c.stopped || r.pos == 0 {
		return ErrInvalid
	}
	// DecodeTerminate has already consumed rbsp_stop_one_bit (9.3.3.2.4).
	if r.data[(r.pos-1)/8]>>(7-(r.pos-1)%8)&1 != 1 {
		return ErrInvalid
	}
	for r.pos%8 != 0 && !r.bad {
		if r.read(1) != 0 {
			return ErrInvalid
		}
	}
	if r.bad || (len(r.data)-r.pos/8)%2 != 0 {
		return ErrInvalid
	}
	for r.pos < len(r.data)*8 {
		if r.read(16) != 0 {
			return ErrInvalid
		}
	}
	return nil
}

// A residual block returns scan-order coefficients. Its coded_block_flag is
// handled by the macroblock layer, which knows neighbouring block categories.
func (c *cabac) residual(category, count int) (out [64]int32) {
	sigBase, lastBase, levelBase := 402, 417, 426
	if category < 5 {
		delta := [5]int{0, 15, 29, 44, 47}[category]
		sigBase, lastBase = 105+delta, 166+delta
		levelBase = 227 + [5]int{0, 10, 20, 30, 39}[category]
	}
	var positions [64]int
	n, last := 0, count-1
	for i := 0; i < count-1 && !c.r.bad; i++ {
		sigCtx, lastCtx := i, i
		if category == 5 {
			sigCtx, lastCtx = int(cabacSig8[i]), int(cabacLast8[i])
		}
		if c.decision(sigBase+sigCtx) == 1 {
			if c.decision(lastBase+lastCtx) == 1 {
				last = i
				break
			}
			positions[n] = i
			n++
		}
	}
	positions[n] = last
	n++ // The final coefficient is implicitly significant.
	eq1, gt1 := 0, 0
	for i := n - 1; i >= 0 && !c.r.bad; i-- {
		inc := 0
		if gt1 == 0 {
			inc = min(4, 1+eq1)
		}
		v := 0
		if c.decision(levelBase+inc) != 0 {
			v = 1
			limit := 4
			if category == 3 {
				limit = 3
			}
			ctx := levelBase + 5 + min(limit, gt1)
			for v < 14 && !c.r.bad && c.decision(ctx) != 0 {
				v++
			}
			if v == 14 {
				// Bound UEG0 before shifting; check the signed coefficient below.
				k := 0
				for !c.r.bad && c.bypass() != 0 {
					if k >= 15 {
						c.r.bad = true
						break
					}
					v += 1 << k
					k++
				}
				for j := k - 1; j >= 0 && !c.r.bad; j-- {
					v += c.bypass() << j
				}
			}
		}
		v++
		if c.bypass() != 0 {
			v = -v
		}
		if !in16(int64(v)) {
			c.r.bad = true
			break
		}
		out[positions[i]] = int32(v)
		if abs(v) == 1 {
			eq1++
		} else {
			gt1++
		}
	}
	return
}
