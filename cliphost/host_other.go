//go:build !windows

package cliphost

import (
	"context"
	"github.com/hq0101/rdp-go/clipole"
	"github.com/hq0101/rdp-go/cliprdr"
)

type Host struct{}

func Open(ctx context.Context, o Options) (*Host, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if _, err := options(o); err != nil {
		return nil, err
	}
	return nil, ErrUnsupported
}
func (*Host) Current() (Snapshot, error)                                  { return Snapshot{}, ErrUnsupported }
func (*Host) Changes() <-chan struct{}                                    { return nil }
func (*Host) Errors() <-chan error                                        { return nil }
func (*Host) Read(context.Context, Token, cliprdr.Format) ([]byte, error) { return nil, ErrUnsupported }
func (*Host) Offer(context.Context, []cliprdr.Format, Provider) (Token, error) {
	return Token{}, ErrUnsupported
}
func (*Host) OfferIfCurrent(context.Context, Token, []cliprdr.Format, Provider) (Token, error) {
	return Token{}, ErrUnsupported
}
func (*Host) OfferFilesIfCurrent(context.Context, Token, []cliprdr.FileDescriptor, clipole.ReadFunc, clipole.Options) (Token, error) {
	return Token{}, ErrUnsupported
}
func (*Host) OfferRetainedFilesIfCurrent(context.Context, Token, []cliprdr.FileDescriptor, clipole.ReadFunc, clipole.Options) (Token, FileLease, error) {
	return Token{}, nil, ErrUnsupported
}
func (*Host) Clear(context.Context, Token) error { return ErrUnsupported }
func (*Host) Close()                             {}
func (*Host) Done() <-chan struct{}              { c := make(chan struct{}); close(c); return c }
func (*Host) Err() error                         { return ErrUnsupported }
