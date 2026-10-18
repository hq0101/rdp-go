package rdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"sort"

	"github.com/hq0101/rdp-go/internal/licensing"
)

const fileLicenseMagic = "ORCAL01\x00"
const fileLicensePlainHeader = 28 // installation identity, generation, record count
const maxFileLicenseGeneration = 1<<32 - 1

func clearLicenseRecords(records map[[32]byte]LicenseRecord) {
	for key, record := range records {
		record.Clear()
		delete(records, key)
	}
}

func encodeFileLicenses(ctx context.Context, id [16]byte, generation uint64, records map[[32]byte]LicenseRecord) ([]byte, error) {
	keys := make([][32]byte, 0, len(records))
	for key := range records {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return bytes.Compare(keys[i][:], keys[j][:]) < 0 })
	b := append([]byte(nil), id[:]...)
	b = binary.LittleEndian.AppendUint64(b, generation)
	b = binary.LittleEndian.AppendUint32(b, uint32(len(records)))
	for _, key := range keys {
		if e := ctx.Err(); e != nil {
			clear(b)
			return nil, e
		}
		r := records[key]
		b = append(b, r.Namespace[:]...)
		b = append(b, r.HardwareID[:]...)
		b = binary.LittleEndian.AppendUint32(b, r.Product.Version)
		for _, v := range [][]byte{[]byte(r.Product.Company), []byte(r.Product.ID), r.Scope, r.Data} {
			b = binary.LittleEndian.AppendUint32(b, uint32(len(v)))
			b = append(b, v...)
		}
	}
	return b, nil
}

// decodeFileLicenses runs only after AEAD authentication. It remains bounded and
// validates every field: a correct key does not authorize malformed storage.
func decodeFileLicenses(ctx context.Context, b []byte, entries, limit int) (id [16]byte, generation uint64, records map[[32]byte]LicenseRecord, used int, err error) {
	fail := func(e error) ([16]byte, uint64, map[[32]byte]LicenseRecord, int, error) {
		clearLicenseRecords(records)
		return [16]byte{}, 0, nil, 0, e
	}
	if len(b) < fileLicensePlainHeader {
		return fail(ErrLicenseStoreCorrupt)
	}
	if len(b) > limit+fileLicensePlainHeader {
		return fail(ErrLicenseStoreLimit)
	}
	copy(id[:], b[:16])
	generation = binary.LittleEndian.Uint64(b[16:])
	count := binary.LittleEndian.Uint32(b[24:])
	b = b[28:]
	if id == ([16]byte{}) || generation == 0 || generation > maxFileLicenseGeneration {
		return fail(ErrLicenseStoreCorrupt)
	}
	if count > uint32(entries) {
		return fail(ErrLicenseStoreLimit)
	}
	// Every record contains 72 fixed bytes and at least one CAL byte.
	if uint64(count)*73 > uint64(len(b)) {
		return fail(ErrLicenseStoreCorrupt)
	}
	records = make(map[[32]byte]LicenseRecord, int(count))
	var previous [32]byte
	for i := uint32(0); i < count; i++ {
		if e := ctx.Err(); e != nil {
			return fail(e)
		}
		if len(b) < 56 {
			return fail(ErrLicenseStoreCorrupt)
		}
		var r LicenseRecord
		copy(r.Namespace[:], b[:32])
		copy(r.HardwareID[:], b[32:52])
		r.Product.Version = binary.LittleEndian.Uint32(b[52:])
		b = b[56:]
		var fields [4][]byte
		for j := range fields {
			if len(b) < 4 {
				return fail(ErrLicenseStoreCorrupt)
			}
			n := binary.LittleEndian.Uint32(b)
			b = b[4:]
			maxField := []int{licensing.MaxText * 2, licensing.MaxText * 2, licensing.MaxText - 1, licensing.MaxLicense}[j]
			if uint64(n) > uint64(len(b)) || uint64(n) > uint64(maxField) {
				return fail(ErrLicenseStoreCorrupt)
			}
			fields[j] = b[:int(n)]
			b = b[int(n):]
		}
		r.Product.Company, r.Product.ID = string(fields[0]), string(fields[1])
		r.Scope, r.Data = fields[2], fields[3]
		if !validLicenseRecord(r) || !bytes.Equal(r.HardwareID[4:], id[:]) {
			return fail(ErrLicenseStoreCorrupt)
		}
		key := licenseRecordKey(r.Namespace, r.HardwareID, r.Product, r.Scope)
		if i != 0 && bytes.Compare(previous[:], key[:]) >= 0 {
			return fail(ErrLicenseStoreCorrupt)
		}
		size := licenseRecordSize(r)
		if size > limit-used {
			return fail(ErrLicenseStoreLimit)
		}
		used += size
		records[key] = r.Clone()
		previous = key
	}
	if len(b) != 0 {
		return fail(ErrLicenseStoreCorrupt)
	}
	if e := ctx.Err(); e != nil {
		return fail(e)
	}
	return id, generation, records, used, nil
}
