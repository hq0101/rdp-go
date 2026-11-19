//go:build !windows

package cliphost

import (
	"context"

	"github.com/hq0101/rdp-go/cliprdr"
)

func (*Host) acquireFileSource(context.Context, Token, FileSelectionOptions) (cliprdr.FileSourceOffer, error) {
	return cliprdr.FileSourceOffer{}, ErrUnsupported
}

func (*Host) AcquireFiles(context.Context, Token, FileSelectionOptions) (*FileSelection, error) {
	return nil, ErrUnsupported
}
