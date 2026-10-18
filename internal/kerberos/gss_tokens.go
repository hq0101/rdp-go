package kerberos

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"

	"github.com/hq0101/rdp-go/internal/krbcrypto"
)

// MaxGSSMessage bounds the application plaintext; incoming sealed tokens may
// additionally contain up to 65535 filler bytes (the RFC 4121 EC field).
const MaxGSSMessage = 1 << 20
const maxGSSWire = MaxGSSMessage + 16 + 65535 + 16 + 16 + 24

func gssMACSize(e krbcrypto.Enctype) int {
	switch e {
	case 17, 18:
		return 12
	case 19:
		return 16
	case 20:
		return 24
	}
	return 0
}
func (m *gssMaterial) header(mic, sealed bool) [16]byte {
	h := [16]byte{5, 4, 0, 0xff}
	if mic {
		h[0] = 4
		for i := 4; i < 8; i++ {
			h[i] = 0xff
		}
	}
	if sealed {
		h[2] |= 2
	}
	if m.acceptorSubkey {
		h[2] |= 4
	}
	binary.BigEndian.PutUint64(h[8:], m.send)
	return h
}
func (m *gssMaterial) sendReady(length int) error {
	if err := m.usable(); err != nil {
		return err
	}
	if length > MaxGSSMessage {
		return ErrInvalid
	}
	if m.sendExhausted {
		return m.fail(ErrSequence)
	}
	return nil
}
func (m *gssMaterial) advanceSend() {
	if m.send == ^uint64(0) {
		m.sendExhausted = true
	} else {
		m.send++
	}
}
func (m *gssMaterial) advanceReceive() {
	if m.receive == ^uint64(0) {
		m.receiveExhausted = true
	} else {
		m.receive++
	}
}
func (m *gssMaterial) receiveHeader(token []byte, mic bool) error {
	if err := m.usable(); err != nil {
		return err
	}
	if len(token) < 16 || len(token) > maxGSSWire {
		return m.fail(ErrInvalid)
	}
	want := byte(5)
	if mic {
		want = 4
	}
	// Unknown flag bits are authenticated but ignored, per RFC 4121.
	if token[0] != want || token[1] != 4 || token[3] != 0xff || token[2]&1 != 1 || (token[2]&4 != 0) != m.acceptorSubkey {
		return m.fail(ErrInvalid)
	}
	if mic && (token[2]&2 != 0 || !bytes.Equal(token[4:8], []byte{0xff, 0xff, 0xff, 0xff})) {
		return m.fail(ErrInvalid)
	}
	if m.receiveExhausted || binary.BigEndian.Uint64(token[8:16]) != m.receive {
		return m.fail(ErrSequence)
	}
	return nil
}

// GetMIC and Wrap share one sending sequence. The MIC covers data followed by
// the full 16-byte token header, with initiator signing key usage 25.
func (s *ServiceContext) GetMIC(data []byte) ([]byte, error) {
	if s == nil || s.material == nil {
		return nil, ErrContext
	}
	m := s.material
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.sendReady(len(data)); err != nil {
		return nil, err
	}
	h := m.header(true, false)
	input := append(append(make([]byte, 0, len(data)+16), data...), h[:]...)
	defer clear(input)
	sum, err := m.key.Checksum(25, input)
	if err != nil {
		return nil, m.fail(err)
	}
	defer clear(sum)
	token := append(h[:], sum...)
	m.advanceSend()
	return token, nil
}
func (s *ServiceContext) VerifyMIC(data, token []byte) error {
	if s == nil || s.material == nil {
		return ErrContext
	}
	m := s.material
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.receiveHeader(token, true); err != nil {
		return err
	}
	if len(data) > MaxGSSMessage || len(token) != 16+gssMACSize(m.key.Type()) {
		return m.fail(ErrInvalid)
	}
	input := append(append(make([]byte, 0, len(data)+16), data...), token[:16]...)
	defer clear(input)
	if err := m.key.VerifyChecksum(23, input, token[16:]); err != nil {
		return m.fail(err)
	}
	m.advanceReceive()
	return nil
}

// Wrap emits RFC 4121 with RRC=0. AES CTS needs no filler, so sealed EC=0.
// Integrity-only Wrap still uses the sealing usage (24), not the MIC usage.
func (s *ServiceContext) Wrap(data []byte, confidential bool) ([]byte, error) {
	if s == nil || s.material == nil {
		return nil, ErrContext
	}
	m := s.material
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.sendReady(len(data)); err != nil {
		return nil, err
	}
	h := m.header(false, confidential)
	input := append(append(make([]byte, 0, len(data)+16), data...), h[:]...)
	defer clear(input)
	var body []byte
	var err error
	if confidential {
		body, err = m.key.Encrypt(24, input)
	} else {
		var sum []byte
		sum, err = m.key.Checksum(24, input)
		if err == nil {
			binary.BigEndian.PutUint16(h[4:6], uint16(len(sum)))
			body = append(append([]byte(nil), data...), sum...)
		}
		clear(sum)
	}
	if err != nil {
		return nil, m.fail(err)
	}
	defer clear(body)
	token := append(h[:], body...)
	m.advanceSend()
	return token, nil
}
func (s *ServiceContext) Seal(data []byte) ([]byte, error) { return s.Wrap(data, true) }

// Unwrap accepts every 16-bit rotation count, including counts larger than the
// body. No plaintext escapes until integrity, the encrypted header/EC, bounds,
// key choice, direction and sequence have all been verified.
func (s *ServiceContext) Unwrap(token []byte) ([]byte, bool, error) { return s.unwrap(token, false) }
func (s *ServiceContext) Unseal(token []byte) ([]byte, error) {
	p, _, err := s.unwrap(token, true)
	return p, err
}
func (s *ServiceContext) unwrap(token []byte, requireConfidential bool) ([]byte, bool, error) {
	if s == nil || s.material == nil {
		return nil, false, ErrContext
	}
	m := s.material
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.receiveHeader(token, false); err != nil {
		return nil, false, err
	}
	sealed := token[2]&2 != 0
	if requireConfidential && !sealed {
		return nil, false, m.fail(ErrInvalid)
	}
	ec := int(binary.BigEndian.Uint16(token[4:6]))
	rrc := int(binary.BigEndian.Uint16(token[6:8]))
	if len(token) == 16 {
		return nil, false, m.fail(ErrInvalid)
	}
	raw := token[16:]
	rrc %= len(raw)
	body := make([]byte, 0, len(raw))
	body = append(body, raw[rrc:]...)
	body = append(body, raw[:rrc]...)
	defer clear(body)
	h := [16]byte{}
	copy(h[:], token[:16])
	h[6] = 0
	h[7] = 0
	if sealed {
		plain, err := m.key.Decrypt(22, body)
		if err != nil {
			return nil, false, m.fail(err)
		}
		defer clear(plain)
		if len(plain) < 16+ec || len(plain)-16-ec > MaxGSSMessage {
			return nil, false, m.fail(ErrInvalid)
		}
		if !hmac.Equal(h[:], plain[len(plain)-16:]) {
			return nil, false, m.fail(krbcrypto.ErrIntegrity)
		}
		data := append([]byte{}, plain[:len(plain)-16-ec]...)
		m.advanceReceive()
		return data, true, nil
	}
	if ec != gssMACSize(m.key.Type()) || len(body) < ec || len(body)-ec > MaxGSSMessage {
		return nil, false, m.fail(ErrInvalid)
	}
	h[4] = 0
	h[5] = 0
	input := append(append(make([]byte, 0, len(body)-ec+16), body[:len(body)-ec]...), h[:]...)
	defer clear(input)
	if err := m.key.VerifyChecksum(22, input, body[len(body)-ec:]); err != nil {
		return nil, false, m.fail(err)
	}
	data := append([]byte{}, body[:len(body)-ec]...)
	m.advanceReceive()
	return data, false, nil
}
