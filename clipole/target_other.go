//go:build !windows || (!amd64 && !arm64)

package clipole

import "context"

type DropTarget struct{}

func NewDropTarget(context.Context, DropTargetOptions) (*DropTarget, error) {
	return nil, ErrUnsupported
}
func (*DropTarget) Register(uintptr) error { return ErrUnsupported }
func (*DropTarget) Revoke() error          { return ErrUnsupported }
func (*DropTarget) Close()                 {}
func (*DropTarget) Done() <-chan struct{}  { return nil }
func (*DropTarget) Err() error             { return ErrUnsupported }
func (*DropTarget) Errors() <-chan error   { return nil }
func (*DropTarget) Drops() <-chan Drop     { return nil }
