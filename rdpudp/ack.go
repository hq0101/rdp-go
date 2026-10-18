package rdpudp

// AckSpan validates the RLE ACK vector and returns its sequence-number span.
// Only received (0) and not-yet-received (3) states are defined. A run length is
// literal 1..63, not length-minus-one. Empty vectors carry no selective ACKs.
func AckSpan(vector []byte) (uint32, error) {
	if len(vector) > MaxAckVector {
		return 0, ErrLimit
	}
	var total uint32
	for _, v := range vector {
		if v&63 == 0 || v>>6 != 0 && v>>6 != 3 {
			return 0, ErrInvalid
		}
		total += uint32(v & 63)
	}
	return total, nil
}

// AckRange is an inclusive run. Sequence numbers wrap modulo 2^32. ACK vectors
// are traversed newest to oldest, starting with the basic header's SourceAck.
type AckRange struct {
	First, Last uint32
	Received    bool
}

func AckRanges(sourceAck uint32, vector []byte) ([]AckRange, error) {
	if _, err := AckSpan(vector); err != nil {
		return nil, err
	}
	var out []AckRange
	for _, v := range vector {
		first := sourceAck - uint32(v&63) + 1
		out = append(out, AckRange{First: first, Last: sourceAck, Received: v>>6 == 0})
		sourceAck = first - 1
	}
	return out, nil
}

// EncodeACK accepts newest-to-oldest receive states. The caller owns its receive
// window and must not retract an earlier received state when applying reordered
// acknowledgments. The bounded wire encoder does not maintain that window.
func EncodeACK(received []bool) ([]byte, error) {
	if len(received) > MaxAckVector*63 {
		return nil, ErrLimit
	}
	var out []byte
	for i := 0; i < len(received); {
		n := 1
		for i+n < len(received) && n < 63 && received[i+n] == received[i] {
			n++
		}
		if len(out) == MaxAckVector {
			return nil, ErrLimit
		}
		v := byte(n)
		if !received[i] {
			v |= 0xc0
		}
		out = append(out, v)
		i += n
	}
	return out, nil
}

// SequenceCompare orders serial numbers within a half-range. Exactly half of
// the uint32 space is ambiguous and must never be accepted as an in-window ACK.
func SequenceCompare(a, b uint32) (order int, comparable bool) {
	d := a - b
	if d == 1<<31 {
		return 0, false
	}
	if d == 0 {
		return 0, true
	}
	if int32(d) < 0 {
		return -1, true
	}
	return 1, true
}
