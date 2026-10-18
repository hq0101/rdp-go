package rdp

import (
	"context"
	"errors"

	"github.com/hq0101/rdp-go/display"
)

// SetGraphicsOutputSize applies the dimensions of a successfully decoded
// RDPGFX RESET to Session.Info and input/display-update bounds. Call it only
// when rdpgfx.Client.Handle succeeds with Result.Resized, using that result's
// Width/Height, before processing the next ReadEvent. A graphics RESET need
// not be accompanied by Deactivate All / Demand Active.
//
// This sends no resize request and does not confirm requested monitor or DPI
// settings. Read the actual graphics topology from rdpgfx.Client.Monitors.
// Calls are serialized against input. A later Demand Active replaces these
// dimensions. The graphics pipeline must be offered and the session active.
func (s *Session) SetGraphicsOutputSize(ctx context.Context, width, height int) error {
	if width < 1 || height < 1 || width > display.MaxDimension || height > display.MaxDimension || width*height > display.MaxPixels {
		return errors.New("rdp: invalid graphics output dimensions")
	}
	if err := s.connection.Transport.acquire(ctx, s.inputGate); err != nil {
		return err
	}
	defer func() { <-s.inputGate }()
	if !s.active.Load() {
		return ErrDeactivated
	}
	s.infoMu.Lock()
	defer s.infoMu.Unlock()
	if !s.info.GraphicsPipeline {
		return ErrUnsupportedOperation
	}
	s.info.Width, s.info.Height = uint16(width), uint16(height)
	return nil
}
