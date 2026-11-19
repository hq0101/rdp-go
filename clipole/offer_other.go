//go:build !windows || (!amd64 && !arm64)

package clipole

func (s *Offer) start() error      { return ErrUnsupported }
func Observe() (Snapshot, error)   { return Snapshot{}, ErrUnsupported }
func (s *Offer) OwnsCurrent() bool { return false }
