package clipsync

import (
	"github.com/hq0101/rdp-go/clipole"
)

// FileOperation reports one native Shell copy outcome for a remote file group.
// Retained is true when a newer clipboard copy had already replaced the group.
// Outcomes are informational: success, failure and cancellation never terminate
// the connection or release a remote lock early; lease lifetimes still govern
// source retention. The public queue holds eight outcomes, dropping the oldest
// when full, and closes at Done.
type FileOperation struct {
	clipole.Operation
	Retained bool
}

// FileOperations is optionally implemented by a retained file lease whose
// native provider observes Shell copy outcomes (clipole.Offer does). Sync
// forwards those outcomes to FileOperations while the lease is alive.
type FileOperations interface {
	Operations() <-chan clipole.Operation
}

type fileOpEvent struct {
	epoch *epoch
	op    clipole.Operation
}

func (s *Sync) forwardFileOperations(e *epoch, ops <-chan clipole.Operation) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case op, ok := <-ops:
			if !ok {
				return
			}
			select {
			case s.fileOps <- fileOpEvent{epoch: e, op: op}:
			case <-s.ctx.Done():
				return
			}
		}
	}
}

func (s *Sync) deliverFileOperation(ev fileOpEvent, retained bool) {
	op := FileOperation{Operation: ev.op, Retained: retained}
	select {
	case s.fileOperations <- op:
		return
	default:
	}
	select {
	case <-s.fileOperations:
	default:
	}
	select {
	case s.fileOperations <- op:
	default:
	}
}

// FileOperations reports native Shell copy outcomes for remote file groups.
// It is nil unless RemoteFiles is enabled. See FileOperation for semantics.
func (s *Sync) FileOperations() <-chan FileOperation { return s.fileOperations }
