package cliphost

import (
	"context"
	"errors"
	"time"

	"github.com/hq0101/rdp-go/clipole"
)

func (w *worker) retainFile(file *clipole.Offer, cancel context.CancelFunc) {
	if w.retained == nil {
		w.retained = make(map[*clipole.Offer]context.CancelFunc)
	}
	w.retained[file] = cancel
}

// Called only after another native item replaced this file publication.
func (w *worker) replaceFile() error {
	if w.file == nil || !w.fileRetain {
		return w.closeFile()
	}
	w.retainFile(w.file, w.fileCancel)
	w.h.mu.Lock()
	if w.h.file == w.file {
		w.h.file = nil
	}
	w.h.mu.Unlock()
	w.file, w.fileCancel, w.fileRetain = nil, nil, false
	return nil
}

func (w *worker) collectRetained() {
	for file, cancel := range w.retained {
		select {
		case err, ok := <-file.Errors():
			if ok {
				w.h.report(err)
			}
		default:
		}
		select {
		case <-file.Done():
			err := fileError(file.Err())
			if err != nil && !errors.Is(err, ErrChanged) {
				w.retainedErr = errors.Join(w.retainedErr, err)
				w.h.report(err)
			}
			if cancel != nil {
				cancel()
			}
			delete(w.retained, file)
			w.h.mu.Lock()
			delete(w.h.files, file)
			w.h.mu.Unlock()
		default:
		}
	}
}

func (w *worker) closeRetained() error {
	for file := range w.retained {
		file.Close()
	}
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for len(w.retained) != 0 {
		w.pump()
		w.collectRetained()
		if len(w.retained) != 0 {
			<-ticker.C
		}
	}
	return w.retainedErr
}
