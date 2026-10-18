package h264

import "strings"

// Normative VLCs from ITU-T H.264 (01/2012), Tables 9-5 and 9-7..9-10.
// Entries are indexed by TotalCoeff*4+TrailingOnes, or by the decoded value.
// A small immutable prefix tree bounds both memory and work for malformed input.
type vlcNode struct {
	next  [2]int
	value int // decoded value + 1; zero is not a leaf
}
type vlc []vlcNode

func makeVLC(codes string) vlc {
	t := vlc{{}}
	for value, code := range strings.Fields(codes) {
		if code == "-" {
			continue
		}
		n := 0
		for _, c := range code {
			if c != '0' && c != '1' || t[n].value != 0 {
				panic("h264: invalid static VLC")
			}
			b := int(c - '0')
			if t[n].next[b] == 0 {
				t[n].next[b] = len(t)
				t = append(t, vlcNode{})
			}
			n = t[n].next[b]
		}
		if t[n].value != 0 || t[n].next != [2]int{} {
			panic("h264: duplicate static VLC")
		}
		t[n].value = value + 1
	}
	return t
}

func (t vlc) read(r *bitReader) int {
	n := 0
	for i := 0; i < 16 && !r.bad; i++ {
		n = t[n].next[r.read(1)]
		if n == 0 {
			break
		}
		if t[n].value != 0 {
			return t[n].value - 1
		}
	}
	r.bad = true
	return 0
}

var coeffTokens = [4]vlc{
	makeVLC(`
1 - - -
000101 01 - -
00000111 000100 001 -
000000111 00000110 0000101 00011
0000000111 000000110 00000101 000011
00000000111 0000000110 000000101 0000100
0000000001111 00000000110 0000000101 00000100
0000000001011 0000000001110 00000000101 000000100
0000000001000 0000000001010 0000000001101 0000000100
00000000001111 00000000001110 0000000001001 00000000100
00000000001011 00000000001010 00000000001101 0000000001100
000000000001111 000000000001110 00000000001001 00000000001100
000000000001011 000000000001010 000000000001101 00000000001000
0000000000001111 000000000000001 000000000001001 000000000001100
0000000000001011 0000000000001110 0000000000001101 000000000001000
0000000000000111 0000000000001010 0000000000001001 0000000000001100
0000000000000100 0000000000000110 0000000000000101 0000000000001000`),
	makeVLC(`
11 - - -
001011 10 - -
000111 00111 011 -
0000111 001010 001001 0101
00000111 000110 000101 0100
00000100 0000110 0000101 00110
000000111 00000110 00000101 001000
00000001111 000000110 000000101 000100
00000001011 00000001110 00000001101 0000100
000000001111 00000001010 00000001001 000000100
000000001011 000000001110 000000001101 00000001100
000000001000 000000001010 000000001001 00000001000
0000000001111 0000000001110 0000000001101 000000001100
0000000001011 0000000001010 0000000001001 0000000001100
0000000000111 00000000001011 0000000000110 0000000001000
00000000001001 00000000001000 00000000001010 0000000000001
00000000000111 00000000000110 00000000000101 00000000000100`),
	makeVLC(`
1111 - - -
001111 1110 - -
001011 01111 1101 -
001000 01100 01110 1100
0001111 01010 01011 1011
0001011 01000 01001 1010
0001001 001110 001101 1001
0001000 001010 001001 1000
00001111 0001110 0001101 01101
00001011 00001110 0001010 001100
000001111 00001010 00001101 0001100
000001011 000001110 00001001 00001100
000001000 000001010 000001101 00001000
0000001101 000000111 000001001 000001100
0000001001 0000001100 0000001011 0000001010
0000000101 0000001000 0000000111 0000000110
0000000001 0000000100 0000000011 0000000010`),
	makeVLC(`01 - - -
000111 1 - -
000100 000110 001 -
000011 0000011 0000010 000101
000010 00000011 00000010 0000000`),
}

var totalZeros = [...]vlc{
	nil,
	makeVLC(`1 011 010 0011 0010 00011 00010 000011 000010 0000011 0000010 00000011 00000010 000000011 000000010 000000001`),
	makeVLC(`111 110 101 100 011 0101 0100 0011 0010 00011 00010 000011 000010 000001 000000`),
	makeVLC(`0101 111 110 101 0100 0011 100 011 0010 00011 00010 000001 00001 000000`),
	makeVLC(`00011 111 0101 0100 110 101 100 0011 011 0010 00010 00001 00000`),
	makeVLC(`0101 0100 0011 111 110 101 100 011 0010 00001 0001 00000`),
	makeVLC(`000001 00001 111 110 101 100 011 010 0001 001 000000`),
	makeVLC(`000001 00001 101 100 011 11 010 0001 001 000000`),
	makeVLC(`000001 0001 00001 011 11 10 010 001 000000`),
	makeVLC(`000001 000000 0001 11 10 001 01 00001`),
	makeVLC(`00001 00000 001 11 10 01 0001`),
	makeVLC(`0000 0001 001 010 1 011`),
	makeVLC(`0000 0001 01 1 001`),
	makeVLC(`000 001 1 01`),
	makeVLC(`00 01 1`),
	makeVLC(`0 1`),
}
var chromaZeros = [...]vlc{nil, makeVLC(`1 01 001 000`), makeVLC(`1 01 00`), makeVLC(`1 0`)}
var runBefore = [...]vlc{
	nil, makeVLC(`1 0`), makeVLC(`1 01 00`), makeVLC(`11 10 01 00`),
	makeVLC(`11 10 01 001 000`), makeVLC(`11 10 011 010 001 000`),
	makeVLC(`11 000 001 011 010 101 100`),
	makeVLC(`111 110 101 100 011 010 001 0001 00001 000001 0000001 00000001 000000001 0000000001 00000000001`),
}

// residualCAVLC returns coefficients in scan order (15 entries omit DC).
// nC=-1 selects the 4:2:0 chroma-DC table. Eight-bit coefficients and level
// prefixes are bounded before any scaling or shifts; failure poisons the reader.
func residualCAVLC(r *bitReader, nC, count int) (out [16]int32, total int) {
	if count != 4 && count != 15 && count != 16 || (nC == -1) != (count == 4) || nC < -1 || nC > 16 {
		r.bad = true
		return
	}
	token := 0
	switch {
	case nC == -1:
		token = coeffTokens[3].read(r)
	case nC < 2:
		token = coeffTokens[0].read(r)
	case nC < 4:
		token = coeffTokens[1].read(r)
	case nC < 8:
		token = coeffTokens[2].read(r)
	default:
		x := int(r.read(6))
		if x == 3 {
			token = 0
		} else {
			token = (x/4+1)*4 + x%4
		}
	}
	total, trailing := token/4, token%4
	if r.bad || total > count || trailing > total {
		r.bad = true
		return
	}
	if total == 0 {
		return
	}
	var levels [16]int32
	suffix := 0
	if total > 10 && trailing < 3 {
		suffix = 1
	}
	for i := 0; i < total && !r.bad; i++ {
		if i < trailing {
			levels[i] = 1 - 2*int32(r.read(1))
			continue
		}
		prefix := 0
		for !r.bad && r.read(1) == 0 {
			prefix++
			if prefix > 19 {
				r.bad = true
			}
		}
		if r.bad {
			return
		}
		n := suffix
		if prefix == 14 && suffix == 0 {
			n = 4
		}
		if prefix >= 15 {
			n = prefix - 3
		}
		code := (min(15, prefix) << suffix) + int(r.read(n))
		if prefix >= 15 && suffix == 0 {
			code += 15
		}
		if prefix >= 16 {
			code += (1 << (prefix - 3)) - 4096
		}
		if i == trailing && trailing < 3 {
			code += 2
		}
		v := (code + 2) / 2
		if code&1 != 0 {
			v = -(code + 1) / 2
		}
		if v < -32768 || v > 32767 {
			r.bad = true
			return
		}
		levels[i] = int32(v)
		if suffix == 0 {
			suffix = 1
		}
		if abs(v) > 3<<(suffix-1) && suffix < 6 {
			suffix++
		}
	}
	zeros := 0
	if total < count {
		if count == 4 {
			zeros = chromaZeros[total].read(r)
		} else {
			zeros = totalZeros[total].read(r)
		}
	}
	if r.bad || zeros+total > count {
		r.bad = true
		return
	}
	position := zeros + total - 1
	for i := 0; i < total && !r.bad; i++ {
		if position < 0 || position >= count {
			r.bad = true
			return
		}
		out[position] = levels[i]
		run := 0
		if zeros > 0 && i < total-1 {
			run = runBefore[min(zeros, 7)].read(r)
		}
		if run > zeros {
			r.bad = true
			return
		}
		zeros -= run
		position -= run + 1
	}
	return
}

func abs(v int) int {
	if v < 0 {
		return -v
	}
	return v
}
