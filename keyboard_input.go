package rdp

import (
	"context"
	"github.com/hq0101/rdp-go/keyboard"
)

// SendKeys sends a validated batch of at most keyboard.MaxEvents scancodes in
// one slow-path PDU. The batch is serialized with SendText, other input and
// reactivation. It can be bound directly to keyboard.NewRouter. A failed write
// can have partially reached the peer; do not replay an uncertain batch.
func (s *Session) SendKeys(ctx context.Context, events []keyboard.Event) error {
	payload, err := keyboard.MarshalEvents(events)
	if err != nil {
		return err
	}
	return s.writeActive(ctx, 28, payload)
}

// SendPause sends the complete E1 CTRL / NUMLOCK press/release sequence as one
// indivisible input batch. It does not press the user's ordinary CTRL key.
func (s *Session) SendPause(ctx context.Context) error {
	events := keyboard.PauseEvents()
	return s.SendKeys(ctx, events[:])
}
