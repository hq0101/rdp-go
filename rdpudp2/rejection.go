package rdpudp2

import "errors"

// RejectionReason returns a bounded diagnostic category for a rejected Receive
// datagram. It never includes packet bytes, sequence values or application data.
// errors.Is continues to identify the original ErrInvalid/ErrLimit cause.
// Errors from other operations or terminal failures return "other".
func RejectionReason(err error) string {
	var rejected *rejection
	if errors.As(err, &rejected) {
		return rejected.reason
	}
	return "other"
}

type rejection struct {
	reason string
	cause  error
}

func (r *rejection) Error() string            { return "rdpudp2: rejected " + r.reason + ": " + r.cause.Error() }
func (r *rejection) Unwrap() error            { return r.cause }
func reject(reason string, cause error) error { return &rejection{reason, cause} }
