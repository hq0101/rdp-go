package dtls

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"sync"
)

// Each object belongs to one direction and one nonzero epoch. Its key and
// fixed IV MUST be freshly derived by the handshake. Do not copy these objects
// or construct another writer with the same key/IV; sequence reuse is unsafe.
type RecordWriter struct {
	mu     sync.Mutex
	aead   cipher.AEAD
	salt   [4]byte
	epoch  uint16
	next   uint64
	sealed uint64
}

type RecordReader struct {
	mu         sync.Mutex
	aead       cipher.AEAD
	salt       [4]byte
	epoch      uint16
	high, seen uint64 // authenticated sliding window; bit zero is high
}

func (w *RecordWriter) String() string   { return "dtls.RecordWriter{private state}" }
func (w *RecordWriter) GoString() string { return w.String() }
func (r *RecordReader) String() string   { return "dtls.RecordReader{private state}" }
func (r *RecordReader) GoString() string { return r.String() }

func newGCM(epoch uint16, key, salt []byte) (cipher.AEAD, error) {
	if epoch == 0 || len(salt) != 4 || len(key) != 16 && len(key) != 32 {
		return nil, ErrInvalid
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(b)
}

func NewRecordWriter(epoch uint16, key, salt []byte) (*RecordWriter, error) {
	a, err := newGCM(epoch, key, salt)
	if err != nil {
		return nil, err
	}
	w := &RecordWriter{aead: a, epoch: epoch}
	copy(w.salt[:], salt)
	return w, nil
}

func NewRecordReader(epoch uint16, key, salt []byte) (*RecordReader, error) {
	a, err := newGCM(epoch, key, salt)
	if err != nil {
		return nil, err
	}
	r := &RecordReader{aead: a, epoch: epoch}
	copy(r.salt[:], salt)
	return r, nil
}

// GCMExpansion excludes the 13-byte record header: explicit nonce plus tag.
const GCMExpansion = 8 + 16

// A conservative per-key usage budget for full-size AES-GCM records. A future
// rekey implementation must derive fresh keys, never reset this counter.
const maxSealedRecords = 1 << 24

func additionalData(r Record, length int) [13]byte {
	var b [13]byte
	binary.BigEndian.PutUint64(b[:8], uint64(r.Epoch)<<48|r.Sequence)
	b[8] = r.Type
	binary.BigEndian.PutUint16(b[9:11], r.Version)
	binary.BigEndian.PutUint16(b[11:13], uint16(length))
	return b
}

// Seal reserves its sequence even if the caller later fails to send the record.
// Retransmitted handshake messages must be sealed again with a new sequence.
// All methods are safe concurrently; input bytes must remain unchanged in-call.
func (w *RecordWriter) Seal(typ uint8, plaintext []byte) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.aead == nil {
		return nil, ErrClosed
	}
	if !validType(typ) {
		return nil, ErrInvalid
	}
	if len(plaintext) > MaxPlaintext {
		return nil, ErrLimit
	}
	if w.next > MaxSequence {
		return nil, ErrSequence
	}
	if w.sealed >= maxSealedRecords {
		return nil, ErrLimit
	}
	r := Record{Type: typ, Version: Version12, Epoch: w.epoch, Sequence: w.next}
	var nonce [12]byte
	copy(nonce[:4], w.salt[:])
	binary.BigEndian.PutUint64(nonce[4:], uint64(w.epoch)<<48|w.next)
	ad := additionalData(r, len(plaintext))
	b := make([]byte, RecordHeader+8, RecordHeader+GCMExpansion+len(plaintext))
	putHeader(b, r, GCMExpansion+len(plaintext))
	copy(b[13:21], nonce[4:])
	b = w.aead.Seal(b, nonce[:], plaintext, ad[:])
	w.next++ // the 48-bit maximum advances to an exhausted sentinel, never zero
	w.sealed++
	return b, nil
}

// Open authenticates before moving the 64-record replay window. A forged high
// sequence cannot evict valid records. Invalid/replayed records return no data;
// the owner may discard them without terminating a DTLS association.
func (r *RecordReader) Open(record Record) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.aead == nil {
		return nil, ErrClosed
	}
	if err := record.validate(); err != nil {
		return nil, err
	}
	if record.Version != Version12 {
		return nil, ErrVersion
	}
	if record.Epoch != r.epoch {
		return nil, ErrEpoch
	}
	if len(record.Payload) < GCMExpansion {
		return nil, ErrAuthentication
	}
	n := len(record.Payload) - GCMExpansion
	if n > MaxPlaintext {
		return nil, ErrLimit
	}
	seq := record.Sequence
	if r.seen != 0 && seq <= r.high && (r.high-seq >= 64 || r.seen&(uint64(1)<<(r.high-seq)) != 0) {
		return nil, ErrReplay
	}
	var nonce [12]byte
	copy(nonce[:4], r.salt[:])
	// Peers may use a unique explicit nonce different from their record sequence.
	copy(nonce[4:], record.Payload[:8])
	ad := additionalData(record, n)
	p, err := r.aead.Open(nil, nonce[:], record.Payload[8:], ad[:])
	if err != nil {
		return nil, ErrAuthentication
	}
	if r.seen == 0 {
		r.high, r.seen = seq, 1
	} else if seq > r.high {
		r.seen = r.seen<<(seq-r.high) | 1
		r.high = seq
	} else {
		r.seen |= uint64(1) << (r.high - seq)
	}
	return p, nil
}

// Close drops cipher references. Go/crypto-internal key copies cannot be wiped
// by this package. A closed writer cannot be reset to reuse its key/sequence.
func (w *RecordWriter) Close() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.aead = nil
	clear(w.salt[:])
}
func (r *RecordReader) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aead = nil
	clear(r.salt[:])
}
