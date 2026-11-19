package nativeview

import (
	"context"
	"sync"

	rdp "github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/cliphost"
	"github.com/hq0101/rdp-go/clipsync"
)

type clipboardChannel interface {
	ChannelID(string) (uint16, bool)
	WriteChannel(context.Context, uint16, []byte) error
}

// Preserve the existing Remote interface for clients that leave clipboard off.
// Validation must happen before ownedRemote hides the optional channel methods.
func clipboardTransport(remote Remote, o Options) (clipboardChannel, uint16, error) {
	if o.ClipboardMode == clipsync.Off {
		return nil, 0, nil
	}
	c, ok := remote.(clipboardChannel)
	if !ok {
		return nil, 0, ErrUnsupported
	}
	id, ok := c.ChannelID("cliprdr")
	if !ok || id == 0 {
		return nil, 0, ErrUnsupported
	}
	return c, id, nil
}

type clipboardRemote struct {
	Remote
	clipboard *clipsync.Sync
	channel   uint16
	once      sync.Once
	err       error
	monitor   chan struct{}
}

func openClipboardRemote(ctx context.Context, remote Remote, c clipboardChannel, id uint16, o Options) (*clipboardRemote, error) {
	h := o.ClipboardHost
	if h == nil {
		var err error
		h, err = cliphost.Open(ctx, cliphost.Options{})
		if err != nil {
			return nil, err
		}
	}
	s, err := clipsync.New(context.Background(), h, func(ctx context.Context, p []byte) error { return c.WriteChannel(ctx, id, p) }, clipsync.Options{Mode: o.ClipboardMode, RemoteFiles: o.ClipboardFiles, LocalFiles: o.ClipboardUpload})
	if err != nil {
		h.Close()
		<-h.Done()
		return nil, err
	}
	r := &clipboardRemote{Remote: remote, clipboard: s, channel: id, monitor: make(chan struct{})}
	go func() { <-s.Stopping(); r.Close(); close(r.monitor) }()
	return r, nil
}

func (r *clipboardRemote) ReadEvent(ctx context.Context) (rdp.Event, error) {
	e, err := r.Remote.ReadEvent(ctx)
	if err == nil && e.Kind == rdp.EventData && e.Channel == r.channel && e.DataType == 0 {
		if err = r.clipboard.Feed(ctx, e.Payload); err != nil {
			r.Close()
			return rdp.Event{}, err
		}
	}
	return e, err
}
func (r *clipboardRemote) Close() error {
	r.clipboard.Close()
	r.once.Do(func() { r.err = r.Remote.Close() })
	return r.err
}
func (r *clipboardRemote) wait() error { <-r.clipboard.Done(); <-r.monitor; return r.clipboard.Err() }
