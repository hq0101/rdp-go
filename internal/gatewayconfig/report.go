package gatewayconfig

import (
	"context"
	"encoding/json"
	"io"
	"sync"

	"github.com/hq0101/rdp-go/rdgateway"
)

// Reporter serializes JSON lines. Peer text is escaped, never a format string,
// terminal control sequence or HTML. Opaque service bytes use JSON base64.
// Writers must finish promptly; io.Writer has no cancellable operation.
type Reporter struct {
	mu     sync.Mutex
	writer io.Writer
}

func NewReporter(w io.Writer) *Reporter { return &Reporter{writer: w} }

type reportEvent struct {
	Kind     string          `json:"event"`
	Address  string          `json:"gateway_address,omitempty"`
	Text     string          `json:"text,omitempty"`
	SHA256   string          `json:"sha256,omitempty"`
	Accepted bool            `json:"accepted,omitempty"`
	Info     *rdgateway.Info `json:"gateway_info,omitempty"`
	Data     []byte          `json:"data_base64,omitempty"`
}

func (r *Reporter) write(e reportEvent) error {
	if r == nil || r.writer == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return json.NewEncoder(r.writer).Encode(e)
}

type serviceSource interface {
	GatewayInfo() (rdgateway.Info, bool)
	ReadGatewayService(context.Context) ([]byte, error)
	Close() error
}

// WatchServices drains one connection's bounded queue until stop/cancellation or
// transport closure. Start again for EVERY successor; stop joins the reader.
// Reporting failure closes the connection instead of silently losing notices.
func WatchServices(ctx context.Context, source any, report *Reporter) func() error {
	r, ok := source.(serviceSource)
	if !ok {
		return func() error { return nil }
	}
	info, via := r.GatewayInfo()
	if !via {
		return func() error { return nil }
	}
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	var result error
	go func() {
		defer close(done)
		for {
			data, err := r.ReadGatewayService(ctx)
			if err != nil {
				return
			}
			if err = report.write(reportEvent{Kind: "gateway_service", Info: &info, Data: data}); err != nil {
				result = err
				r.Close()
				return
			}
		}
	}()
	return func() error { cancel(); <-done; return result }
}
func Info(source any) *rdgateway.Info {
	if r, ok := source.(interface{ GatewayInfo() (rdgateway.Info, bool) }); ok {
		if i, via := r.GatewayInfo(); via {
			return &i
		}
	}
	return nil
}
