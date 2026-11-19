package clipole

import "github.com/hq0101/rdp-go/cliprdr"

// DropTargetOptions bounds an OLE drag-and-drop receiving endpoint.
type DropTargetOptions struct {
	// AllowedEffects is the mask of DROPEFFECT values this target accepts
	// (DropEffectCopy/Move/Link). Zero defaults to Copy. Bits outside that mask
	// are rejected. The negotiated effect also intersects the source's allowed
	// effects and the modifier keys (Ctrl=Copy, Shift=Move, Ctrl+Shift=Link).
	AllowedEffects uint32
	// MaxTotalSize bounds the acquired dropped files; zero permits only empty
	// files/directories. MaxFiles defaults to cliprdr.MaxFiles.
	MaxTotalSize uint64
	MaxFiles     int
}

// Drop reports one completed OLE drop. Effect is the negotiated DROPEFFECT.
// Source owns the acquired virtual files and their dedicated apartment; call
// Source.Release exactly once when no longer needed. Observing move intent never
// moves or deletes the drag source.
type Drop struct {
	Effect uint32
	Source cliprdr.FileSourceOffer
}
