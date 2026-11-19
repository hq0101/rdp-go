package clipole

import (
	"context"
	"math"

	"github.com/hq0101/rdp-go/cliprdr"
)

// SourceOptions bounds an explicitly acquired virtual-file clipboard item.
// Zero MaxTotalSize permits empty files/directories only; MaxFiles defaults to
// cliprdr.MaxFiles. Sizes must fit io.ReaderAt's signed offset space.
type SourceOptions struct {
	MaxTotalSize uint64
	MaxFiles     int
}

// AcquireIfCurrent obtains an OLE virtual-file source observed by Observe.
// It reads FileGroupDescriptorW metadata and acquires each regular file's
// IStream or HGLOBAL medium. Streams are read only on ReaderAt requests;
// HGLOBAL providers may render their whole file when acquiring the medium.
// Descriptor paths are never opened and no temporary files are created.
// Only Unicode descriptors are supported; ANSI descriptors are not. Contents
// may be HGLOBAL, seekable or forward-only IStream (forward-only is buffered
// once within MaxTotalSize), or IStorage opened via its "CONTENTS" stream.
// The source's Preferred DropEffect, when present, is observed into
// FileSourceOffer.PreferredDropEffect; a malformed value fails acquisition.
// Observing move intent never moves or deletes anything.
//
// The returned offer owns a dedicated COM apartment and all acquired media.
// Call Release (or transfer the offer to FileSources) exactly once ownership is
// no longer needed. Release is idempotent and waits for reads and native cleanup.
// The source's data object/media remain referenced across clipboard changes;
// a provider can nevertheless revoke or mutate its own data. Detected size
// changes and short reads fail; this is not an atomic snapshot of foreign data.
//
// ctx limits acquisition only. Cancellation is checked between native calls;
// it cannot interrupt a foreign COM call, and this function joins acquisition
// before returning. Call outside UI callbacks, keep its desktop/window station
// alive until Release completes, and keep the application's message pump active.
// Windows amd64/arm64 are implemented; other targets return ErrUnsupported.
func AcquireIfCurrent(ctx context.Context, expected Snapshot, o SourceOptions) (cliprdr.FileSourceOffer, error) {
	if ctx == nil || !expected.valid {
		return cliprdr.FileSourceOffer{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return cliprdr.FileSourceOffer{}, err
	}
	if o.MaxFiles == 0 {
		o.MaxFiles = cliprdr.MaxFiles
	}
	if o.MaxFiles < 1 || o.MaxFiles > cliprdr.MaxFiles || o.MaxTotalSize > math.MaxInt64 {
		return cliprdr.FileSourceOffer{}, ErrInvalid
	}
	return acquireSource(ctx, expected, o)
}
