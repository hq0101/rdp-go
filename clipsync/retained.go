package clipsync

import (
	"errors"

	"github.com/hq0101/rdp-go/cliphost"
	"github.com/hq0101/rdp-go/clipole"
	"github.com/hq0101/rdp-go/cliprdr"
)

func (st *state) retainFiles(r *remoteItem) {
	if st.retained == nil {
		st.retained = make(map[*epoch]*remoteItem)
	}
	st.retained[r.epoch] = r
}

func (st *state) fileRemote(e *epoch) *remoteItem {
	if st.remote != nil && st.remote.epoch == e {
		return st.remote
	}
	return st.retained[e]
}

func (st *state) fileBudget() (uint64, int) {
	bytes, files := st.s.o.RemoteFiles.MaxTotalSize, cliprdr.MaxFiles
	for _, r := range st.retained {
		if r == st.remote {
			continue
		}
		f := r.files
		if f.bytes > bytes || len(f.descriptors) > files {
			return 0, 0
		}
		bytes -= f.bytes
		files -= len(f.descriptors)
	}
	return bytes, files
}

func (st *state) failFiles(r *remoteItem, err error) error {
	if r == st.remote {
		return st.rejectRemote(err)
	}
	st.s.report(err)
	r.epoch.cancel()
	if r.files.lease != nil {
		r.files.lease.Close()
	}
	return st.releaseFiles(r) // only this failed old group, not the current copy
}

func leaseError(lease cliphost.FileLease) error {
	err := lease.Err()
	if errors.Is(err, cliphost.ErrChanged) || errors.Is(err, clipole.ErrChanged) {
		return nil
	}
	return err
}

func (st *state) collectFileLeases() error {
	if r := st.remote; r != nil && r.files != nil && r.files.lease != nil {
		select {
		case <-r.files.lease.Done():
			if err := st.endRemote(false); err != nil {
				return err
			}
		default:
		}
	}
	for e, r := range st.retained {
		select {
		case <-r.files.lease.Done():
			r.epoch.cancel()
			if err := st.releaseFiles(r); err != nil {
				return err
			}
			delete(st.retained, e)
			if err := leaseError(r.files.lease); err != nil {
				return err
			}
		default:
		}
	}
	return nil
}

// Called after cancellation and Host.Close. No protocol work remains, but Done
// still waits for every native consumer/callback to actually finish teardown.
func (st *state) closeFileLeases() error {
	if r := st.remote; r != nil && r.files != nil && r.files.lease != nil {
		st.retainFiles(r)
	}
	for _, r := range st.retained {
		r.files.lease.Close()
	}
	var err error
	for _, r := range st.retained {
		<-r.files.lease.Done()
		err = errors.Join(err, leaseError(r.files.lease))
	}
	return err
}
