package rdp

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"sync"
)

// MemoryLicenseStore is an explicitly owned, bounded cache shared by sessions.
// It does not survive process exit. Close clears records and makes it terminal;
// Session.Close never closes it. No eviction silently consumes another license.
// Do not copy a MemoryLicenseStore after first use.
type MemoryLicenseStore struct {
	licenseRedacted
	mu                   sync.Mutex
	records              map[[32]byte]LicenseRecord
	entries, limit, used int
	closed               bool
}

// NewMemoryLicenseStore uses 64 entries and 4 MiB when arguments are zero.
// Limits are at most 4096 entries and 64 MiB, counting CALs and record metadata.
func NewMemoryLicenseStore(maxEntries, maxBytes int) (*MemoryLicenseStore, error) {
	maxEntries, maxBytes, err := licenseStoreLimits(maxEntries, maxBytes)
	if err != nil {
		return nil, err
	}
	return &MemoryLicenseStore{records: make(map[[32]byte]LicenseRecord), entries: maxEntries, limit: maxBytes}, nil
}

func licenseStoreLimits(maxEntries, maxBytes int) (int, int, error) {
	if maxEntries == 0 {
		maxEntries = 64
	}
	if maxBytes == 0 {
		maxBytes = 4 << 20
	}
	if maxEntries < 1 || maxEntries > 4096 || maxBytes < 1 || maxBytes > 64<<20 {
		return 0, 0, ErrLicenseConfiguration
	}
	return maxEntries, maxBytes, nil
}
func licenseRecordKey(namespace [32]byte, hw [20]byte, p LicenseProduct, scope []byte) [32]byte {
	h := sha256.New()
	h.Write(namespace[:])
	h.Write(hw[:])
	h.Write(binary.LittleEndian.AppendUint32(nil, p.Version))
	licenseHashPart(h, []byte(p.Company))
	licenseHashPart(h, []byte(p.ID))
	licenseHashPart(h, scope)
	var key [32]byte
	copy(key[:], h.Sum(nil))
	return key
}
func licenseRecordSize(r LicenseRecord) int {
	return 256 + len(r.Product.Company) + len(r.Product.ID) + len(r.Scope) + len(r.Data)
}
func (s *MemoryLicenseStore) Load(ctx context.Context, q LicenseQuery) (*LicenseRecord, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if !validLicenseQuery(q) {
		return nil, ErrLicenseStore
	}
	if s == nil {
		return nil, ErrLicenseStoreClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.records == nil {
		return nil, ErrLicenseStoreClosed
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	for _, scope := range q.Scopes {
		if r, ok := s.records[licenseRecordKey(q.Namespace, q.HardwareID, q.Product, scope)]; ok {
			if !licenseRecordMatches(&r, q) {
				return nil, ErrLicenseStore
			}
			out := r.Clone()
			return &out, nil
		}
	}
	return nil, nil
}
func (s *MemoryLicenseStore) Save(ctx context.Context, r LicenseRecord) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if !validLicenseRecord(r) {
		return ErrLicenseStore
	}
	if s == nil {
		return ErrLicenseStoreClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.records == nil {
		return ErrLicenseStoreClosed
	}
	if e := ctx.Err(); e != nil {
		return e
	}
	key := licenseRecordKey(r.Namespace, r.HardwareID, r.Product, r.Scope)
	old, exists := s.records[key]
	size := licenseRecordSize(r)
	previous := 0
	if exists {
		previous = licenseRecordSize(old)
	}
	if !exists && len(s.records) >= s.entries || size > s.limit-s.used+previous {
		return ErrLicenseStoreLimit
	}
	copy := r.Clone()
	s.records[key] = copy
	s.used += size - previous
	old.Clear()
	return nil
}
func (s *MemoryLicenseStore) Close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, r := range s.records {
		r.Clear()
		delete(s.records, key)
	}
	s.records = nil
	s.used = 0
	s.closed = true
	return nil
}
