package ime

import "github.com/hq0101/rdp-go/rail"

func (d *WindowsDocument) commitRevision(revision uint64) error {
	s := d.store
	if d.closed || s.closed.Load() {
		return ErrUnavailable
	}
	if s.pending != 0 {
		return rail.ErrBusy
	}
	if s.state.revision != revision {
		return ErrChanged
	}
	return nil
}

// Caller holds the adapter's busy guard, outside native locks/callbacks.
// Native view Release may run code after Snapshot's last revision check.
func (d *WindowsDocument) pendingCommit() error {
	s, err := d.snapshot()
	if err != nil {
		return err
	}
	if err = d.commitRevision(s.Revision); err != nil {
		return err
	}
	n, err := committedPrefix(s)
	if err != nil {
		return err
	}
	if n != 0 {
		return ErrPendingCommit
	}
	return nil
}

// Only WindowsInput can remove the sampled committed prefix while a native
// composition survives. General SetText still refuses active compositions.
func (d *WindowsDocument) trimCommitted(snapshot TextSnapshot, n int) error {
	if err := d.commitRevision(snapshot.Revision); err != nil {
		return err
	}
	limit, err := committedPrefix(snapshot)
	if err != nil {
		return err
	}
	if n <= 0 || n != limit {
		return rail.ErrInvalid
	}
	if !d.store.state.trimPrefix(n) {
		return rail.ErrBusy
	}
	change := nativeChange{oldEnd: int32(n)}
	return d.store.notify(&change, true, true)
}
