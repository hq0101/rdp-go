//go:build !windows || (!amd64 && !arm64)

package clipole

import (
	"context"

	"github.com/hq0101/rdp-go/cliprdr"
)

func acquireSource(context.Context, Snapshot, SourceOptions) (cliprdr.FileSourceOffer, error) {
	return cliprdr.FileSourceOffer{}, ErrUnsupported
}
