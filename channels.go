package rdp

import (
	"context"
	"errors"
	"fmt"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/mcs"
	"github.com/hq0101/rdp-go/rdgateway"
	"github.com/hq0101/rdp-go/tpkt"
	"github.com/hq0101/rdp-go/x224"
)

// ChannelConnection is a transport with GCC settings exchanged and MCS channels
// joined. Use DialSession to also perform Client Info, licensing and activation.
type ChannelConnection struct {
	Transport *Transport
	UserID    uint16
	Server    gcc.ServerSettings
	// MaxPDUSize is the server's negotiated domain bound. Send Data also obeys
	// mcs.MaxDataPDUSize and the transport's local packet-size limit.
	MaxPDUSize uint32
	resources  SessionResources // immutable effective offer; no credentials
}

// DialChannels runs X.224, TLS, NLA, GCC and MCS channel setup under one timeout.
// The returned connection is NOT an active desktop session.
func DialChannels(ctx context.Context, address string, c Credentials, opts Options, settings gcc.ClientSettings) (*ChannelConnection, error) {
	return dialChannels(ctx, address, c, opts, settings, nil)
}

func dialChannels(ctx context.Context, address string, c Credentials, opts Options, settings gcc.ClientSettings, redirected *rdstlsAuthentication) (*ChannelConnection, error) {
	return dialChannelsPrepared(ctx, address, c, &opts, &settings, redirected)
}

// The caller retains its requested settings separately. Only these per-attempt
// owned values are adjusted before the target is created, then consumed by GCC
// and the Session's channel maps, Client Info and DVC router.
func dialChannelsPrepared(ctx context.Context, address string, c Credentials, opts *Options, settings *gcc.ClientSettings, redirected *rdstlsAuthentication) (*ChannelConnection, error) {
	*opts = cloneResourceOptions(*opts)
	*settings = cloneRedirectSettings(*settings)
	settings.NetworkAutoDetect = settings.NetworkAutoDetect || opts.NetworkAutoDetect || settings.GraphicsPipeline
	settings.Heartbeat = settings.Heartbeat || opts.Heartbeat
	// Validate settings before transmitting any credentials.
	// Permit extended blocks for local preflight; actual negotiated support is
	// checked again by OpenChannels before any GCC request is sent.
	data, err := gcc.CreateRequestWithFlags(*settings, x224.ProtocolHybrid, x224.ExtendedClientDataSupported)
	if err != nil {
		return nil, err
	}
	initial, err := mcs.ConnectInitial(data)
	if err != nil {
		return nil, err
	}
	if opts.MaxPacketSize != 0 && opts.MaxPacketSize < len(initial)+7 {
		return nil, fmt.Errorf("%w: MCS Connect Initial exceeds packet limit", ErrInvalidFrame)
	}
	if opts.Gateway != nil {
		if settings.MultitransportFlags != 0 {
			return nil, ErrGatewayRoute
		}
		adjust := opts.Gateway.AdjustResources
		opts.gatewayPreflight = func(i rdgateway.Info) error {
			o, s, err := applyGatewayResources(i, *opts, *settings, adjust)
			if err == nil {
				*opts, *settings = o, s
			}
			return err
		}
		defer func() { opts.gatewayPreflight = nil }()
	}
	ctx, cancel, err := handshakeContext(ctx, opts.HandshakeTimeout)
	if err != nil {
		return nil, err
	}
	defer cancel()
	var tr *Transport
	if redirected == nil {
		tr, err = DialNLA(ctx, address, c, *opts)
	} else {
		tr, err = dialSecurityAuth(ctx, address, *opts, x224.ProtocolRDSTLS, nil, redirected)
	}
	if err != nil {
		return nil, err
	}
	tr.gatewayDynamic = cloneDynamicOptions(opts.DynamicChannels)
	result, err := tr.OpenChannels(ctx, *settings)
	if err != nil {
		tr.Close()
		return nil, err
	}
	result.resources = resourceSettings(*opts, *settings)
	return result, nil
}

// OpenChannels performs GCC/MCS setup exactly once on this transport. It takes
// both I/O gates; do not run other transport operations until it returns.
// A failed on-wire handshake closes the transport. Invalid local settings do not.
func (t *Transport) OpenChannels(ctx context.Context, s gcc.ClientSettings) (*ChannelConnection, error) {
	if i, ok := t.GatewayInfo(); ok {
		if err := checkGatewaySettings(i, Options{DynamicChannels: t.gatewayDynamic}, s); err != nil {
			return nil, err
		}
	}
	data, err := gcc.CreateRequestWithFlags(s, t.negotiation.SelectedProtocol, t.negotiation.Flags)
	if err != nil {
		return nil, err
	}
	initial, err := mcs.ConnectInitial(data)
	if err != nil {
		return nil, err
	}
	if len(initial)+7 > t.maxSize {
		return nil, fmt.Errorf("%w: MCS Connect Initial exceeds packet limit", ErrInvalidFrame)
	}
	if err := t.acquire(ctx, t.readGate); err != nil {
		return nil, err
	}
	defer func() { <-t.readGate }()
	if err := t.acquire(ctx, t.writeGate); err != nil {
		return nil, err
	}
	defer func() { <-t.writeGate }()
	if t.channelsStarted {
		return nil, errors.New("rdp: channel setup has already been started")
	}
	t.channelsStarted = true
	result := &ChannelConnection{Transport: t, resources: resourceSettings(Options{DynamicChannels: t.gatewayDynamic}, s)}
	err = runIO(ctx, t.conn.SetDeadline, func() error {
		write := func(p []byte) error {
			if len(p)+7 > t.maxSize {
				return ErrInvalidFrame
			}
			b, err := x224.MarshalData(p)
			if err != nil {
				return err
			}
			return tpkt.Write(t.conn, b)
		}
		read := func() ([]byte, error) {
			f, err := readFrame(t.conn, t.maxSize)
			if err != nil {
				return nil, err
			}
			if f.Kind != FrameMCS {
				return nil, errors.New("rdp: unexpected fast-path PDU during MCS setup")
			}
			return f.Data, nil
		}
		if err := write(initial); err != nil {
			return err
		}
		b, err := read()
		if err != nil {
			return err
		}
		response, err := mcs.ParseConnectResponse(b)
		if err != nil {
			return err
		}
		result.MaxPDUSize = response.MaxPDUSize
		result.Server, err = gcc.ParseResponse(response.UserData, t.requested, len(s.Channels))
		if err != nil {
			return err
		}
		if result.Server.HasMessageChannel && !(s.NetworkAutoDetect || s.GraphicsPipeline || s.Heartbeat || s.MultitransportFlags != 0) {
			return errors.New("rdp: unsolicited message channel")
		}
		if err := write(mcs.ErectDomainRequest()); err != nil {
			return err
		}
		if err := write(mcs.AttachUserRequest()); err != nil {
			return err
		}
		b, err = read()
		if err != nil {
			return err
		}
		result.UserID, err = mcs.ParseAttachUserConfirm(b)
		if err != nil {
			return err
		}
		ids := append([]uint16{result.UserID, result.Server.IOChannel}, result.Server.ChannelIDs...)
		if result.Server.MessageChannel != 0 {
			ids = append(ids, result.Server.MessageChannel)
		}
		seen := map[uint16]bool{}
		for _, id := range ids {
			if seen[id] {
				return errors.New("rdp: duplicate MCS channel ID")
			}
			seen[id] = true
			p, err := mcs.ChannelJoinRequest(result.UserID, id)
			if err != nil {
				return err
			}
			if err := write(p); err != nil {
				return err
			}
			b, err := read()
			if err != nil {
				return err
			}
			if err := mcs.ParseChannelJoinConfirm(b, result.UserID, id); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("rdp channel setup: %w", err)
	}
	if int(result.MaxPDUSize) < t.mcsLimit {
		t.mcsLimit = int(result.MaxPDUSize)
	}
	return result, nil
}
