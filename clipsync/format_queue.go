package clipsync

import (
	"bytes"

	"github.com/hq0101/rdp-go/cliprdr"
)

const maxDeferredFormats = 64
const maxDeferredFormatBytes = 8 << 20

// File lists require an untagged metadata response before native publication.
// Processing a newer notification immediately would invalidate that response,
// send an artificial FAIL, and cause Windows to reject subsequent data reads.
// Keep each notification distinct and preserve ACK order. Content responses
// continue flowing, and the existing metadata/native deadlines bound waiting.
func (st *state) deferFormatList(message []byte) error {
	if err := st.client.ValidateFormatList(message); err != nil {
		return err
	}
	if len(st.deferredFormats) >= maxDeferredFormats || len(message) > maxDeferredFormatBytes-st.deferredFormatBytes {
		return cliprdr.ErrProtocol
	}
	st.deferredFormats = append(st.deferredFormats, bytes.Clone(message))
	st.deferredFormatBytes += len(message)
	return nil
}

// A new external copy supersedes every already received remote offer, including
// ones not yet applied to Client. They have been validated and each needs its
// ordered failure response; none may overwrite the user's newer clipboard.
func (st *state) rejectDeferredFormats() error {
	for range st.deferredFormats {
		if err := st.send([]byte{3, 0, 2, 0, 0, 0, 0, 0}); err != nil {
			return err
		}
	}
	st.deferredFormats = nil
	st.deferredFormatBytes = 0
	return nil
}
