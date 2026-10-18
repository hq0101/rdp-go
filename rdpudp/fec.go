package rdpudp

import (
	"bytes"
	"encoding/binary"
	"errors"
)

const (
	MaxFECSources = 255 // one of the 256 field values must remain for the index
	MaxFECBlocks  = 32  // bounds Gaussian elimination work, not a wire limit
)

// ErrIncomplete means more source/parity packets are needed. Reliable callers
// retain ordinary retransmission as a fallback; this is not a connection error.
var ErrIncomplete = errors.New("rdpudp: insufficient independent FEC equations")

// FECBlock covers Range+1 consecutive source packets, including uint32 wrap.
// Payload contains the encoded length prefix and zero-padded source bytes.
// FEC is erasure correction, not authentication or a checksum.
type FECBlock struct {
	First   uint32
	Range   byte
	Index   byte
	Payload []byte
}

var gfExp, gfLog = makeField()

func makeField() ([510]byte, [256]byte) {
	var exp [510]byte
	var log [256]byte
	x := uint16(1)
	for i := 0; i < 255; i++ {
		exp[i], log[x] = byte(x), byte(i)
		x <<= 1
		if x&256 != 0 {
			x ^= 0x11d
		}
	}
	copy(exp[255:], exp[:255])
	return exp, log
}

func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

func gfInverse(a byte) byte { return gfExp[255-int(gfLog[a])] } // requires a != 0

func fecIndexValid(first uint32, count int, index byte) bool {
	for i := 0; i < count; i++ {
		if byte(first+uint32(i)) == index {
			return false
		}
	}
	return true
}

// EncodeFEC creates an owned parity block using MS-RDPEUDP 3.1.1.6. If index
// collides with a source low byte it is advanced to the byte after the group.
// Different parity equations must use different returned indices. Source bytes
// are never changed. Reserve two bytes of the negotiated payload MTU for FEC.
func EncodeFEC(first uint32, index byte, sources [][]byte) (FECBlock, error) {
	if len(sources) == 0 {
		return FECBlock{}, ErrInvalid
	}
	if len(sources) > MaxFECSources {
		return FECBlock{}, ErrLimit
	}
	n := 0
	for _, s := range sources {
		if len(s) == 0 || len(s) > MaxMTU-2 {
			return FECBlock{}, ErrInvalid
		}
		n = max(n, len(s)+2)
	}
	if !fecIndexValid(first, len(sources), index) {
		index = byte(first + uint32(len(sources)))
	}
	b := FECBlock{First: first, Range: byte(len(sources) - 1), Index: index, Payload: make([]byte, n)}
	for i, s := range sources {
		c := gfInverse(index ^ byte(first+uint32(i)))
		b.Payload[0] ^= gfMul(c, byte(len(s)>>8))
		b.Payload[1] ^= gfMul(c, byte(len(s)))
		for j, v := range s {
			b.Payload[j+2] ^= gfMul(c, v)
		}
	}
	return b, nil
}

func validateFEC(b FECBlock) error {
	if int(b.Range)+1 > MaxFECSources || len(b.Payload) > MaxMTU {
		return ErrLimit
	}
	if len(b.Payload) < 3 || !fecIndexValid(b.First, int(b.Range)+1, b.Index) {
		return ErrInvalid
	}
	return nil
}

// RecoverFEC returns only the missing source packets, keyed by source sequence.
// A nil source denotes an erasure. Blocks must cover exactly the supplied group
// and have equal padded lengths. Duplicate identical equations are harmless;
// contradictory equations, invalid lengths or nonzero decoded padding fail
// atomically. At most 32 missing sources can be solved in one call. Rank shortage
// (including more erasures than this budget) returns ErrIncomplete, not loss of
// the reliable connection. All returned bytes are owned by the caller.
func RecoverFEC(first uint32, sources [][]byte, blocks []FECBlock) (map[uint32][]byte, error) {
	if len(sources) == 0 {
		return nil, ErrInvalid
	}
	if len(sources) > MaxFECSources || len(blocks) > MaxFECBlocks {
		return nil, ErrLimit
	}
	var missing []int
	for i, s := range sources {
		if s == nil {
			missing = append(missing, i)
		} else if len(s) == 0 || len(s) > MaxMTU-2 {
			return nil, ErrInvalid
		}
	}
	width := 0
	unique := make(map[byte][]byte, len(blocks))
	var equations []FECBlock
	for _, b := range blocks {
		if err := validateFEC(b); err != nil {
			return nil, err
		}
		if b.First != first || int(b.Range)+1 != len(sources) || width != 0 && width != len(b.Payload) {
			return nil, ErrInvalid
		}
		width = len(b.Payload)
		if old, ok := unique[b.Index]; ok {
			if !bytes.Equal(old, b.Payload) {
				return nil, ErrInvalid
			}
			continue
		}
		unique[b.Index] = b.Payload
		equations = append(equations, b)
	}
	for _, s := range sources {
		if s != nil && width != 0 && len(s)+2 > width {
			return nil, ErrInvalid
		}
	}
	if len(missing) > len(equations) {
		return nil, ErrIncomplete
	}
	if len(equations) == 0 {
		return map[uint32][]byte{}, nil // all sources are already present
	}
	// Form A*x = b after subtracting all known source terms. Work is bounded by
	// 32*255*1232 for forming rows and 32*32*1232 for elimination.
	m := len(missing)
	rows := make([][]byte, len(equations))
	for r, b := range equations {
		row := make([]byte, m+width)
		copy(row[m:], b.Payload)
		for j, i := range missing {
			row[j] = gfInverse(b.Index ^ byte(first+uint32(i)))
		}
		for i, s := range sources {
			if s == nil {
				continue
			}
			c := gfInverse(b.Index ^ byte(first+uint32(i)))
			row[m] ^= gfMul(c, byte(len(s)>>8))
			row[m+1] ^= gfMul(c, byte(len(s)))
			for j, v := range s {
				row[m+j+2] ^= gfMul(c, v)
			}
		}
		rows[r] = row
	}
	for col := 0; col < m; col++ {
		pivot := col
		for pivot < len(rows) && rows[pivot][col] == 0 {
			pivot++
		}
		if pivot == len(rows) {
			return nil, ErrIncomplete
		}
		rows[col], rows[pivot] = rows[pivot], rows[col]
		inv := gfInverse(rows[col][col])
		for j := col; j < m+width; j++ {
			rows[col][j] = gfMul(rows[col][j], inv)
		}
		for r := range rows {
			if r == col || rows[r][col] == 0 {
				continue
			}
			c := rows[r][col]
			for j := col; j < m+width; j++ {
				rows[r][j] ^= gfMul(c, rows[col][j])
			}
		}
	}
	for _, row := range rows[m:] {
		if !zeros(row[m:]) {
			return nil, ErrInvalid
		}
	}
	out := make(map[uint32][]byte, m)
	for j, i := range missing {
		v := rows[j][m:]
		n := int(binary.BigEndian.Uint16(v))
		if n == 0 || n > len(v)-2 || !zeros(v[2+n:]) {
			return nil, ErrInvalid
		}
		out[first+uint32(i)] = append([]byte(nil), v[2:2+n]...)
	}
	return out, nil
}
