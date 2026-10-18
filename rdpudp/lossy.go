package rdpudp

import "time"

// expireLossy releases congestion credit without retransmitting. Source
// records stay until selective/cumulative ACKs establish received/lost status;
// timer expiry alone must not move the peer's advertised receive window.
func (e *Endpoint) expireLossy(now time.Time) {
	if !e.p.Lossy {
		return
	}
	for i := range e.tx {
		s := &e.tx[i]
		if s.acked || s.lost || s.expired || now.Before(s.due) {
			continue
		}
		s.expired, s.payload = true, nil
		e.stats.SendExpired++
		e.congestion(now, true)
	}
	if !e.reorderDue.IsZero() && !now.Before(e.reorderDue) {
		e.skipLoss(now)
	}
}

func (e *Endpoint) updateReorder(now time.Time) {
	if !e.p.Lossy {
		return
	}
	if e.rxCum == e.rxHigh {
		e.reorderDue = time.Time{}
	} else if e.reorderDue.IsZero() {
		e.reorderDue = now.Add(e.c.ReorderTimeout)
	}
}

// skipLoss makes the currently buffered ordered subsequence readable. The ACK
// vector no longer represents the abandoned prefix; its absent packets must
// not subsequently be delivered behind newer data. Existing received history
// remains available to bounded FEC equations for later, unskipped sources.
func (e *Endpoint) skipLoss(now time.Time) {
	if !e.p.Lossy || e.rxCum == e.rxHigh {
		return
	}
	for seq := e.rxCum + 1; seq != e.rxHigh+1; seq++ {
		if e.rx[seq] == nil {
			e.stats.ReceiveSkipped++
		}
	}
	e.rxSkipTo, e.rxCum = e.rxHigh, e.rxHigh
	e.reorderDue = time.Time{}
	e.skipLeadingLoss()
	for k := range e.fec {
		if serialLE(k.first+uint32(k.count), e.rxRead) {
			delete(e.fec, k)
		}
	}
	e.scheduleACK(now)
}

func (e *Endpoint) skipLeadingLoss() {
	if !e.p.Lossy {
		return
	}
	for e.rxRead != e.rxCum && e.rx[e.rxRead+1] == nil {
		e.rxRead++
		delete(e.rx, e.rxRead-MaxFECSources)
	}
}
