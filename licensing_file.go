package rdp

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

var (
	ErrLicenseStoreBusy     = fmt.Errorf("%w: store already open", ErrLicenseStore)
	ErrLicenseStoreCorrupt  = fmt.Errorf("%w: invalid encrypted store or key", ErrLicenseStore)
	ErrLicenseStoreIO       = fmt.Errorf("%w: file operation failed", ErrLicenseStore)
	ErrLicenseStoreCommit   = fmt.Errorf("%w: commit outcome uncertain; close and reopen store", ErrLicenseStore)
	ErrLicenseStorePlatform = fmt.Errorf("%w: file store unsupported on this platform", ErrLicenseStore)
)

// FileLicenseStoreOptions requires an application-managed random AES-256 key.
// Use a separate key per store, retain it outside the store, and reuse it when
// opening. This is not a password KDF or OS keychain. Defaults and capacity limits
// match MemoryLicenseStore. Smaller limits on reopen reject excess data.
// Follow GCM's per-key limit of at most 2^32 encryptions, including failed saves,
// backups and other uses of the key. The persisted generation bounds successful
// snapshots only; it cannot count attempts lost in a crash or detect rollback.
type FileLicenseStoreOptions struct {
	licenseRedacted
	Key                  [32]byte
	MaxEntries, MaxBytes int
}

// FileLicenseStore holds an exclusive OS lock for its lifetime. It encrypts all
// records and its stable installation ID with AES-256-GCM; no key or password is
// written to disk. Use an application-controlled directory on a local filesystem.
// Do not replace its files externally while open or copy this value after use.
// The live process keeps decrypted records in memory. A crash can leave encrypted
// pending files; opening ignores them and never automatically deletes or recovers
// them. Logical capacity excludes pending files, which need explicit maintenance.
//
// Save writes and syncs a new encrypted snapshot before replacing the old name.
// Unix also syncs the directory. Windows rename atomicity and power-loss durability
// depend on the filesystem; this is not a guarantee against power loss or rollback
// to an older correctly authenticated snapshot. Rename/directory-sync failures
// make further operations fail until Close and reopen. Before-commit cancellation
// leaves the old snapshot; cancellation during commit may complete successfully.
// OS file operations are synchronous and cannot be interrupted by ctx mid-call.
//
// Close releases the lock and clears owned buffers but cannot erase Go runtime
// copies or expanded AES keys. Session.Close does not close this application store.
type FileLicenseStore struct {
	licenseRedacted
	gate                 chan struct{}
	done                 chan struct{}
	closeOnce            sync.Once
	closeErr             error
	root                 licenseDiskRoot
	lock                 *os.File
	lockHeld             bool
	aead                 cipher.AEAD
	id                   [16]byte
	generation           uint64
	records              map[[32]byte]LicenseRecord
	entries, limit, used int
	poisoned             bool
}

const licenseSnapshotName = "licenses.bin"
const licenseLockName = "store.lock"

// CreateFileLicenseStore exclusively creates a new directory (parent must exist)
// and a fresh random installation ID. It never overwrites or repairs an existing
// store. A failed creation can leave that directory for explicit inspection.
func CreateFileLicenseStore(ctx context.Context, directory string, o FileLicenseStoreOptions) (*FileLicenseStore, error) {
	return openFileLicenseStore(ctx, directory, o, true)
}

// OpenFileLicenseStore opens an existing encrypted store. Missing, damaged or
// wrongly keyed data never triggers automatic creation of a new identity/cache.
func OpenFileLicenseStore(ctx context.Context, directory string, o FileLicenseStoreOptions) (*FileLicenseStore, error) {
	return openFileLicenseStore(ctx, directory, o, false)
}

func openFileLicenseStore(ctx context.Context, directory string, o FileLicenseStoreOptions, create bool) (*FileLicenseStore, error) {
	defer clear(o.Key[:])
	entries, limit, e := licenseStoreLimits(o.MaxEntries, o.MaxBytes)
	if e != nil || directory == "" || o.Key == ([32]byte{}) {
		return nil, ErrLicenseConfiguration
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if !fileLicenseSupported() {
		return nil, ErrLicenseStorePlatform
	}
	block, e := aes.NewCipher(o.Key[:])
	if e != nil {
		return nil, ErrLicenseConfiguration
	}
	aead, e := cipher.NewGCMWithRandomNonce(block)
	if e != nil {
		return nil, ErrLicenseConfiguration
	}
	if create {
		if e = os.Mkdir(directory, 0700); e != nil {
			if errors.Is(e, os.ErrExist) {
				return nil, fmt.Errorf("%w: %w", ErrLicenseStore, os.ErrExist)
			}
			return nil, ErrLicenseStoreIO
		}
	}
	r, e := os.OpenRoot(directory)
	if e != nil {
		return nil, ErrLicenseStoreIO
	}
	s := &FileLicenseStore{gate: make(chan struct{}, 1), done: make(chan struct{}), root: realLicenseRoot{r}, aead: aead, entries: entries, limit: limit}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	if e = checkLicenseFile(r, licenseLockName, true); e != nil {
		return nil, e
	}
	s.lock, e = r.OpenFile(licenseLockName, os.O_RDWR|os.O_CREATE|fileLicenseOpenFlags(), 0600)
	if e != nil {
		return nil, ErrLicenseStoreIO
	}
	if e = checkLicenseOpened(r, licenseLockName, s.lock); e != nil {
		return nil, e
	}
	if e = lockFileLicense(s.lock); e != nil {
		return nil, e
	}
	s.lockHeld = true
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if create {
		if _, e = rand.Read(s.id[:]); e != nil || s.id == ([16]byte{}) {
			return nil, ErrLicenseStoreIO
		}
		s.records = make(map[[32]byte]LicenseRecord)
		if e = s.commit(ctx, s.records, 1); e != nil {
			return nil, e
		}
		s.generation = 1
	} else {
		if e = checkLicenseFile(r, licenseSnapshotName, false); e != nil {
			return nil, e
		}
		f, e := r.OpenFile(licenseSnapshotName, os.O_RDONLY|fileLicenseOpenFlags(), 0)
		if e != nil {
			return nil, ErrLicenseStoreIO
		}
		data, e := readLicenseSnapshot(ctx, r, f, limit)
		closeErr := f.Close()
		defer clear(data)
		if e != nil {
			return nil, e
		}
		if closeErr != nil {
			return nil, ErrLicenseStoreIO
		}
		if len(data) < len(fileLicenseMagic)+aead.Overhead() || string(data[:len(fileLicenseMagic)]) != fileLicenseMagic {
			return nil, ErrLicenseStoreCorrupt
		}
		plain, e := aead.Open(nil, nil, data[len(fileLicenseMagic):], []byte(fileLicenseMagic))
		if e != nil {
			return nil, ErrLicenseStoreCorrupt
		}
		defer clear(plain)
		s.id, s.generation, s.records, s.used, e = decodeFileLicenses(ctx, plain, entries, limit)
		if e != nil {
			return nil, e
		}
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	ok = true
	return s, nil
}

func checkLicenseFile(r *os.Root, name string, allowMissing bool) error {
	i, e := r.Lstat(name)
	if e != nil {
		if allowMissing && errors.Is(e, os.ErrNotExist) {
			return nil
		}
		return ErrLicenseStoreIO
	}
	if !i.Mode().IsRegular() {
		return ErrLicenseStoreCorrupt
	}
	return nil
}
func checkLicenseOpened(r *os.Root, name string, f *os.File) error {
	i, e := f.Stat()
	if e != nil {
		return ErrLicenseStoreIO
	}
	j, e := r.Lstat(name)
	if e != nil {
		return ErrLicenseStoreIO
	}
	if !i.Mode().IsRegular() || !j.Mode().IsRegular() || !os.SameFile(i, j) {
		return ErrLicenseStoreCorrupt
	}
	return nil
}
func readLicenseSnapshot(ctx context.Context, r *os.Root, f *os.File, limit int) ([]byte, error) {
	if e := checkLicenseOpened(r, licenseSnapshotName, f); e != nil {
		return nil, e
	}
	i, e := f.Stat()
	if e != nil {
		return nil, ErrLicenseStoreIO
	}
	max := int64(limit + fileLicensePlainHeader + len(fileLicenseMagic) + 28)
	if i.Size() < 0 || i.Size() > max {
		return nil, ErrLicenseStoreLimit
	}
	b := make([]byte, int(i.Size()))
	for off := 0; off < len(b); {
		if e = ctx.Err(); e != nil {
			clear(b)
			return nil, e
		}
		n, readErr := io.ReadFull(f, b[off:min(len(b), off+65536)])
		off += n
		if readErr != nil {
			clear(b)
			return nil, ErrLicenseStoreCorrupt
		}
	}
	var extra [1]byte
	if n, e := f.Read(extra[:]); n != 0 || e != io.EOF {
		clear(b)
		return nil, ErrLicenseStoreCorrupt
	}
	return b, nil
}

func (s *FileLicenseStore) acquire(ctx context.Context) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if s == nil || s.gate == nil {
		return ErrLicenseStoreClosed
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-s.done:
		return ErrLicenseStoreClosed
	case s.gate <- struct{}{}:
	}
	select {
	case <-s.done:
		<-s.gate
		return ErrLicenseStoreClosed
	default:
	}
	if e := ctx.Err(); e != nil {
		<-s.gate
		return e
	}
	if s.poisoned {
		<-s.gate
		return ErrLicenseStoreCommit
	}
	return nil
}

// HardwareID returns the persisted installation identity for LicensingOptions.
// Records and queries must use these 16 bytes after their four-byte PlatformID.
func (s *FileLicenseStore) HardwareID(ctx context.Context) ([16]byte, error) {
	if e := s.acquire(ctx); e != nil {
		return [16]byte{}, e
	}
	defer func() { <-s.gate }()
	return s.id, nil
}
func (s *FileLicenseStore) Load(ctx context.Context, q LicenseQuery) (*LicenseRecord, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	if !validLicenseQuery(q) {
		return nil, ErrLicenseStore
	}
	if e := s.acquire(ctx); e != nil {
		return nil, e
	}
	defer func() { <-s.gate }()
	if !bytes.Equal(q.HardwareID[4:], s.id[:]) {
		return nil, ErrLicenseStore
	}
	for _, scope := range q.Scopes {
		if r, ok := s.records[licenseRecordKey(q.Namespace, q.HardwareID, q.Product, scope)]; ok {
			if !licenseRecordMatches(&r, q) {
				return nil, ErrLicenseStoreCorrupt
			}
			v := r.Clone()
			return &v, nil
		}
	}
	return nil, nil
}
func (s *FileLicenseStore) Save(ctx context.Context, r LicenseRecord) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	if !validLicenseRecord(r) {
		return ErrLicenseStore
	}
	if e := s.acquire(ctx); e != nil {
		return e
	}
	defer func() { <-s.gate }()
	if !bytes.Equal(r.HardwareID[4:], s.id[:]) {
		return ErrLicenseStore
	}
	key := licenseRecordKey(r.Namespace, r.HardwareID, r.Product, r.Scope)
	old, exists := s.records[key]
	previous := 0
	if exists {
		previous = licenseRecordSize(old)
	}
	size := licenseRecordSize(r)
	if !exists && len(s.records) >= s.entries || size > s.limit-s.used+previous || s.generation >= maxFileLicenseGeneration {
		return ErrLicenseStoreLimit
	}
	candidate := make(map[[32]byte]LicenseRecord, len(s.records)+1)
	for k, v := range s.records {
		candidate[k] = v
	}
	owned := r.Clone()
	candidate[key] = owned
	if e := s.commit(ctx, candidate, s.generation+1); e != nil {
		owned.Clear()
		return e
	}
	s.records = candidate
	s.used += size - previous
	s.generation++
	old.Clear()
	return nil
}
func (s *FileLicenseStore) Close() error {
	if s == nil || s.gate == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		close(s.done)
		s.gate <- struct{}{}
		clearLicenseRecords(s.records)
		s.records = nil
		clear(s.id[:])
		s.aead = nil
		s.used = 0
		if s.lock != nil {
			if s.lockHeld {
				if e := unlockFileLicense(s.lock); e != nil {
					s.closeErr = ErrLicenseStoreIO
				}
			}
			if e := s.lock.Close(); e != nil {
				s.closeErr = ErrLicenseStoreIO
			}
			s.lock = nil
		}
		if s.root != nil {
			if e := s.root.Close(); e != nil {
				s.closeErr = ErrLicenseStoreIO
			}
			s.root = nil
		}
		<-s.gate
	})
	return s.closeErr
}

// Disk interfaces keep real file operations in one place and permit fault tests
// at actual Write/Sync/Rename boundaries without weakening public APIs.
type licenseDiskFile interface {
	Write([]byte) (int, error)
	Sync() error
	Close() error
}
type licenseDiskRoot interface {
	OpenTemp(string) (licenseDiskFile, error)
	Rename(string, string) error
	Remove(string) error
	Sync() error
	Close() error
}
type realLicenseRoot struct{ *os.Root }

func (r realLicenseRoot) OpenTemp(name string) (licenseDiskFile, error) {
	return r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}
func (r realLicenseRoot) Sync() error { return syncFileLicenseDirectory(r.Root) }

func (s *FileLicenseStore) commit(ctx context.Context, records map[[32]byte]LicenseRecord, generation uint64) error {
	plain, e := encodeFileLicenses(ctx, s.id, generation, records)
	if e != nil {
		return e
	}
	defer clear(plain)
	if len(plain) > s.limit+fileLicensePlainHeader {
		return ErrLicenseStoreLimit
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	sealed := s.aead.Seal(nil, nil, plain, []byte(fileLicenseMagic))
	defer clear(sealed)
	wire := append([]byte(fileLicenseMagic), sealed...)
	defer clear(wire)
	var nonce [16]byte
	if _, e = rand.Read(nonce[:]); e != nil {
		return ErrLicenseStoreIO
	}
	name := "pending-" + hex.EncodeToString(nonce[:]) + ".bin"
	f, e := s.root.OpenTemp(name)
	if e != nil {
		return ErrLicenseStoreIO
	}
	closed := false
	defer func() {
		if !closed {
			f.Close()
		}
		s.root.Remove(name)
	}()
	for off := 0; off < len(wire); {
		if e = ctx.Err(); e != nil {
			return e
		}
		chunk := wire[off:min(len(wire), off+65536)]
		n, err := f.Write(chunk)
		if err != nil || n <= 0 || n > len(chunk) {
			return ErrLicenseStoreIO
		}
		off += n
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return ErrLicenseStoreIO
	}
	e = f.Close()
	closed = true
	if e != nil {
		return ErrLicenseStoreIO
	}
	if e = ctx.Err(); e != nil {
		return e
	}
	if e = s.root.Rename(name, licenseSnapshotName); e != nil {
		s.poisoned = true
		return ErrLicenseStoreCommit
	}
	if e = s.root.Sync(); e != nil {
		s.poisoned = true
		return ErrLicenseStoreCommit
	}
	return nil
}
