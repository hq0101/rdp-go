package rdpdr

import "errors"

var errDirectoryAppendState = errors.New("rdpdr: cannot restore append descriptor flags")

// The caller exclusively owns the descriptor and serializes all of its I/O.
// Even a failed F_SETFL attempt is followed by restoration: a host error does
// not prove that none of the descriptor flags changed. Preserve both errors.
// Keep this transaction independent of the OS so failure paths can be tested
// without changing process-wide flags or requiring a failing filesystem.
func directoryAppendFlags(appendFlag uintptr, get func() (uintptr, error), set func(uintptr) error, write func() (int, error)) (n int, err error) {
	flags, err := get()
	if err != nil {
		return 0, err
	}
	if flags&appendFlag != 0 {
		return write()
	}
	defer func() {
		if restore := set(flags); restore != nil {
			err = errors.Join(errDirectoryAppendState, err, restore)
		}
	}()
	if err := set(flags | appendFlag); err != nil {
		return 0, err
	}
	// One write decides EOF in the kernel. A partial write is returned to the
	// protocol caller, never retried here as another append of the whole payload.
	return write()
}
