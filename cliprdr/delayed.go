package cliprdr

import "errors"

// Format data responses have no request ID. Bound pending reads, and keep even
// automatic failures in receive order rather than letting them overtake a read.
const MaxDataRequests = 16

var ErrDataLimit = errors.New("cliprdr: too many pending format data requests")

// DataRequestToken is an opaque, single-use handle bound to one Client and one
// received request. Reset/revocation invalidates it even if format IDs repeat.
type DataRequestToken struct{ request *dataRequest }

type DataRequest struct {
	Token  DataRequestToken
	Format Format
}

type dataRequest struct {
	owner  *dataOwner
	format Format
	reject bool
}

// Nonzero-sized identity; old tokens retain no Client, clipboard bytes or OS
// resources, including after the Client pointer is reused for a new connection.
type dataOwner struct{ marker byte }

// PublishDelayed advertises formats without reading or retaining their data.
// Handle emits DataNeeded only when the peer asks for a supported format. Keep
// servicing Handle while reading the data outside the Client's lock, then call
// CompleteDataRequest under that lock and send all returned PDUs in order.
//
// Bind the offer to an immutable local clipboard ownership/sequence snapshot.
// On any local change, call RevokeLocal before another operation and discard
// late reads. This method neither accesses the OS clipboard nor starts workers.
// File streams still require PublishFiles and their separate FileSet lifecycle.
// Await OfferResult before reporting acceptance. A send failure is terminal.
func (c *Client) PublishDelayed(formats []Format) ([]byte, error) {
	if !c.ready {
		return nil, ErrNotReady
	}
	if c.offerPending || c.readPending || len(c.serving) != 0 {
		return nil, ErrBusy
	}
	body, err := encodeFormats(formats, c.longNames)
	if err != nil {
		return nil, err
	}
	return c.beginOffer(body, nil, append([]Format(nil), formats...)), nil
}

func (c *Client) beginOffer(body []byte, owned []Data, delayed []Format) []byte {
	c.clearLocal()
	c.local, c.delayed = owned, delayed
	if len(delayed) != 0 {
		c.dataOwner = new(dataOwner)
	}
	c.localOwned, c.localAccepted = true, false
	c.offerPending, c.offerLocal = true, true
	c.remoteText, c.remoteFormats = false, nil
	c.remoteVersion++
	return packet(2, 0, body)
}

func (c *Client) requestDelayedData(id uint32) ([][]byte, Event, error) {
	if len(c.serving) == MaxDataRequests {
		// Cannot insert an immediate FAIL: it would answer the wrong request.
		// As with other Handle errors, the caller must terminate the channel.
		return nil, Event{}, ErrDataLimit
	}
	r := &dataRequest{owner: c.dataOwner, reject: true}
	if c.localOwned {
		for _, f := range c.delayed {
			if f.ID == id {
				r.format, r.reject = f, false
				break
			}
		}
	}
	c.serving = append(c.serving, r)
	if r.reject {
		return c.drainDataFailures(), Event{}, nil
	}
	return nil, Event{Kind: DataNeeded, DataRequest: &DataRequest{DataRequestToken{r}, r.format}, Format: r.format}, nil
}

// CompleteDataRequest answers the oldest pending DataNeeded. Because responses
// are untagged, completing a newer valid token first returns ErrBusy without
// consuming it. A read error generates FAIL without data. Oversized local data
// returns ErrFormat and leaves the token pending so it can be explicitly failed.
//
// Stale, duplicate, foreign and revoked tokens return ErrChanged with no PDU.
// Send every returned PDU in order before the next Client operation; an error
// while sending is terminal, and the completion must never be replayed. Bytes
// are copied into the response; the Client does not retain the rendered data.
func (c *Client) CompleteDataRequest(token DataRequestToken, data []byte, readErr error) ([][]byte, error) {
	r := token.request
	if r == nil || r.owner != c.dataOwner || r.reject {
		return nil, ErrChanged
	}
	index := -1
	for i, pending := range c.serving {
		if pending == r {
			index = i
			break
		}
	}
	if index < 0 {
		return nil, ErrChanged
	}
	if index != 0 {
		return nil, ErrBusy
	}
	if readErr == nil && len(data) > MaxDataBytes {
		return nil, ErrFormat
	}
	flags := uint16(1)
	if readErr != nil {
		flags, data = 2, nil
	}
	response := packet(5, flags, data)
	c.popDataRequest()
	return append([][]byte{response}, c.drainDataFailures()...), nil
}

func (c *Client) popDataRequest() {
	c.serving[0] = nil
	c.serving = c.serving[1:]
	if len(c.serving) == 0 {
		c.serving = nil
	}
}

func (c *Client) drainDataFailures() (replies [][]byte) {
	for len(c.serving) != 0 && c.serving[0].reject {
		c.popDataRequest()
		replies = append(replies, packet(5, 2, nil))
	}
	return replies
}

// RevokeLocal invalidates the current local offer and all pending DataNeeded
// tokens, emitting one ordered FAIL per outstanding format request. Call when
// the OS clipboard changes or a provider is retired; send these replies before
// publishing a new offer. This does not advertise an empty clipboard or cancel
// an untagged outbound read/offer acknowledgement: keep draining those normally.
// PublishDelayed/Publish may still return ErrBusy until the old ACK arrives.
//
// Handle performs this automatically on remote ownership change or rejection.
// On connection shutdown use Reset instead, which emits no network traffic.
// File streaming retains explicitly locked sources under its existing rules;
// callers using FileSources must Reconcile after this method as after Publish.
func (c *Client) RevokeLocal() (replies [][]byte) {
	for len(c.serving) != 0 {
		c.popDataRequest()
		replies = append(replies, packet(5, 2, nil))
	}
	c.localOwned, c.localAccepted = false, false
	c.clearLocal()
	return replies
}
