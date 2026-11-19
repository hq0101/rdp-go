package rdp

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hq0101/rdp-go/autodetect"
	"github.com/hq0101/rdp-go/bulk"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/mcs"
	"github.com/hq0101/rdp-go/pdu"
	"github.com/hq0101/rdp-go/vchan"
	"github.com/hq0101/rdp-go/x224"
)

// ErrDeactivated means input is temporarily suspended. Continue calling ReadEvent
// to complete the server's capability re-exchange on the existing connection.
var ErrDeactivated = errors.New("rdp: session temporarily deactivated")

type EventKind uint8

const (
	EventData EventKind = iota
	EventDeactivated
	EventActivated
	EventSurfaceCommands
	EventLargePointer
	EventLogonInfo
	EventDynamic
	// EventRedirectionInfo is an informational LB_NOREDIRECT notification.
	// It has metadata only and does not end the session or initiate a dial.
	EventRedirectionInfo
)

// SessionInfo describes the activated protocol session, not a rendered desktop
// or proof that the user's shell has finished logging on.
type SessionInfo struct {
	ShareID                uint32
	UserChannel, IOChannel uint16
	// Width/Height are the effective output dimensions: Demand Active, or a
	// subsequent validated graphics RESET applied with SetGraphicsOutputSize.
	Width, Height, BitsPerPixel  uint16
	LicenseAccepted              bool
	AutoReconnect                bool // negotiated cookie-based reconnection
	AudioPlayback                bool // requested; inspect rdpsnd negotiation for actual formats
	AudioCapture                 bool // requested; audin negotiation/open is separate
	NetworkAutoDetect, Heartbeat bool // offered and usable message channel assigned
	MessageChannel               uint16
	Active                       bool
	RefreshRect, SuppressOutput  bool
	UnicodeInput                 bool
	ChannelChunkSize             uint32
	// BulkCompression is the offered receive profile; inspect CompressionStats
	// for actual use. ChannelCompression enables outgoing 8K channel compression.
	BulkCompression, ChannelCompression bool
	// BulkCompressionType is the offered inclusive maximum wire type (0..3),
	// meaningful only when BulkCompression is true. It is not the selected type.
	BulkCompressionType byte
	DrawingOrders       bool
	BitmapCacheV2       bool
	BitmapCacheV3       bool
	SurfaceCommands     bool
	// GraphicsPipeline reports the GCC offer, not a confirmed graphics channel.
	GraphicsPipeline           bool
	FrameAcknowledge           bool
	NSCodec                    bool
	BrushCache, OffscreenCache bool
	ExtendedOrders             bool
	GlyphCache, GlyphCacheV2   bool
	ShapeOrders                bool
	NewPointer                 bool
	LargePointerFlags          uint16
	RemoteApp                  RemoteAppInfo
	RemoteAppEnhancedRequested bool // Actual mode is reported by the caller-owned rail.Client.
}

// Event is an owned raw payload. DataType uses MS-RDPBCGR PDUTYPE2 values.
// For a static virtual channel DataType is zero and Payload includes its channel
// header with bulk compression flags removed. Fast-path updates are normalized to slow-path payloads; bitmap updates
// and pointers can be decoded with package graphics. Lifecycle events have Kind
// EventDeactivated or EventActivated and an Info snapshot, with no wire payload.
// EventLogonInfo carries a validated Save Session Info notification in Logon,
// with no raw Payload or reconnect secret. DataType remains pdu.SaveSessionInfo.
// EventSurfaceCommands carries fast-path surface commands in Payload with
// DataType zero. It is a graphics event, not a lifecycle notification.
// EventLargePointer carries the fast-path large pointer body starting at xorBpp,
// also with DataType zero; pass it to graphics.PointerDecoder.ApplyLarge.
type Event struct {
	Kind     EventKind
	Info     SessionInfo
	Channel  uint16
	DataType byte
	Payload  []byte
	Logon    LogonInfo
	// Dynamic is an owned managed DVC event, only for EventDynamic. Session
	// already sent protocol replies; handle application data and replies here.
	Dynamic     dynvc.Event
	Redirection pdu.RedirectionInfo
}

// Session owns its transport and protocol read state. ReadEvent callers are
// serialized with context cancellation; Close can run concurrently.
type Session struct {
	connection         *ChannelConnection
	info               SessionInfo
	licensingInfo      LicensingState // initialized before Session publication; read under infoMu
	infoMu             sync.RWMutex
	monitors           []pdu.Monitor // last server topology; protected by infoMu
	logonInfo          LogonInfo     // latest notification; protected by infoMu
	hasLogonInfo       bool
	reconnect          *reconnectState
	networkMu          sync.Mutex
	networkDetector    autodetect.Client
	networkInfo        NetworkInfo
	networkEstablished bool // readGate; remains true across reactivation
	active             atomic.Bool
	disconnectSent     atomic.Bool
	readGate           chan struct{}
	inputGate          chan struct{}
	textNext           time.Time // inputGate; pacing also spans consecutive SendText calls
	channelGate        chan struct{}
	channelIDs         map[string]uint16
	channelOptions     map[uint16]uint32
	channelLimits      map[uint16]int
	channelSuspended   atomic.Bool
	layout             uint32
	reactivateTimeout  time.Duration
	shares             []pdu.Share
	pending            []Event
	fastPath           pdu.FastPathDecoder
	fastEvents         []pdu.FastPathEvent
	fastEnabled        bool
	graphicsOptions    pdu.GraphicsOptions
	remoteAppOptions   *RemoteAppOptions
	bulkDecoder        bulk.Decoder
	bulkEncoder        bulk.Encoder
	compressionStats   compressionCounters
	decompressor       pdu.Decompressor
	maximumCompression byte
	dynamic            *dynamicState
	expectedTSVURL     [sha256.Size]byte
	hasExpectedTSVURL  bool
	redirect           *redirectState // immutable configuration/history; no credentials
	redirectMu         sync.Mutex
	redirectClosed     bool
	redirectUsed       bool
	redirectPending    atomic.Bool // terminal wire request; set before closing transport
	redirectCancel     context.CancelFunc
}

func (s *Session) Info() SessionInfo {
	s.infoMu.RLock()
	v := s.info
	v.Active = s.active.Load()
	s.infoMu.RUnlock()
	select {
	case <-s.connection.Transport.closed:
		v.Active = false
	default:
	}
	return v
}

// MonitorLayout returns an owned copy of the last basic server Monitor Layout
// PDU, or nil until received. A Deactivate All invalidates this topology. It is
// never inferred from requested settings, and carries no DPI confirmation. In
// graphics-pipeline mode use rdpgfx.Client.Monitors after a graphics RESET.
func (s *Session) MonitorLayout() []pdu.Monitor {
	s.infoMu.RLock()
	defer s.infoMu.RUnlock()
	return append([]pdu.Monitor(nil), s.monitors...)
}
func (s *Session) Close() error {
	s.redirectMu.Lock()
	s.redirectClosed = true
	if s.redirectCancel != nil {
		s.redirectCancel()
	}
	s.redirectMu.Unlock()
	err := s.closeNow()
	if s.dynamic != nil {
		<-s.dynamic.workersDone
	}
	return err
}

// Protocol callbacks use closeNow so they cannot wait for their own worker.
func (s *Session) closeNow() error {
	s.discardReconnect()
	s.active.Store(false)
	if s.dynamic != nil {
		s.dynamic.stop(net.ErrClosed)
	}
	// MS-RDPBCGR 1.3.1.4.1: an immediate client disconnect announces itself
	// with a user-requested ultimatum before the socket goes away. A failed
	// write must not mask the close or reclassify an already dead transport.
	// A transport without TLS never carried an MCS domain to leave.
	if t := s.connection.Transport; t.conn != nil && s.disconnectSent.CompareAndSwap(false, true) {
		if pdu, err := mcs.EncodeDisconnectProviderUltimatum(mcs.DisconnectUserRequested); err == nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			_ = t.WriteMCS(ctx, pdu)
			cancel()
		}
	}
	return s.connection.Transport.Close()
}
func (s *Session) TLSState() tls.ConnectionState { return s.connection.Transport.TLSState() }
func (s *Session) NLAState() NLAState            { return s.connection.Transport.NLAState() }
func (s *Session) Negotiation() x224.Confirm     { return s.connection.Transport.Negotiation() }
func (s *Session) CertificatePinned() bool       { return s.connection.Transport.CertificatePinned() }

// DialSession performs NLA, channel setup, Client Info, valid-client licensing,
// capability exchange and connection finalization within one total timeout.
// It waits for server Synchronize, Cooperate, Granted Control and Font Map.
// Full MS-RDPELE license issuance is not implemented. ReadEvent handles subsequent
// server-initiated reactivation, bounded by HandshakeTimeout for each exchange.
func DialSession(ctx context.Context, address string, c Credentials, opts Options, settings gcc.ClientSettings) (*Session, error) {
	return dialSession(ctx, address, c, opts, settings, nil)
}

func dialSession(ctx context.Context, address string, c Credentials, opts Options, settings gcc.ClientSettings, reconnectPacket []byte) (*Session, error) {
	return dialSessionBound(ctx, address, c, opts, settings, reconnectPacket, nil)
}

// expectedBinding preserves the caller's TSV assertion through redirected
// connections without retaining the original routing URL in session policy.
func dialSessionBound(ctx context.Context, address string, c Credentials, opts Options, settings gcc.ClientSettings, reconnectPacket []byte, expectedBinding *[sha256.Size]byte) (*Session, error) {
	return dialSessionLogin(ctx, address, c, opts, settings, sessionLogin{reconnectPacket: reconnectPacket}, expectedBinding)
}

// Login material is borrowed only while dialing. It is never placed in Options,
// Session, or reconnectState. Recovery uses its own newly derived ARC packet.
type sessionLogin struct {
	reconnectPacket, redirectionCookie []byte
	rdstls                             *rdstlsAuthentication
}

func (l sessionLogin) clientInfo(c Credentials, address string, settings gcc.ClientSettings, opts Options, maximum byte) ([]byte, error) {
	if (l.reconnectPacket != nil || l.rdstls != nil) && l.redirectionCookie != nil {
		return nil, ErrRedirectionCredentials
	}
	if l.redirectionCookie != nil {
		return pdu.ClientInfoWithRedirectionCookie(c.Username, c.Domain, address, settings.KeyboardLayout, opts.BulkCompression, maximum, l.redirectionCookie)
	}
	if l.reconnectPacket != nil {
		return pdu.ClientInfoWithReconnect(c.Username, c.Domain, address, settings.KeyboardLayout, opts.BulkCompression, maximum, l.reconnectPacket)
	}
	if l.rdstls != nil {
		return pdu.ClientInfoAfterRDSTLS(c.Username, c.Domain, address, settings.KeyboardLayout, opts.BulkCompression, maximum)
	}
	return pdu.ClientInfoWithCompressionType(c.Username, c.Domain, c.Password, address, settings.KeyboardLayout, opts.BulkCompression, maximum)
}

func dialSessionLogin(ctx context.Context, address string, c Credentials, opts Options, settings gcc.ClientSettings, login sessionLogin, expectedBinding *[sha256.Size]byte) (*Session, error) {
	licenseOptions, licenseErr := prepareLicensing(opts.Licensing)
	if licenseErr != nil {
		return nil, licenseErr
	}
	defer clearLicensingOptions(licenseOptions)
	opts.Licensing = licenseOptions
	if opts.ExpectedTSVURL != nil && (len(opts.RoutingToken) == 0 || len(opts.ExpectedTSVURL) > 65535) {
		return nil, errors.New("rdp: expected TSV URL requires a routing token and at most 65535 bytes")
	}
	// Only a digest is needed after the connection is established. The caller
	// owns the supplied URL; it must not be changed while DialSession is running.
	expectedTSVURL := sha256.Sum256(opts.ExpectedTSVURL)
	if opts.AudioCapture {
		found := false
		if opts.DynamicChannels != nil {
			found = opts.DynamicChannels.Listeners["AUDIO_INPUT"] > 0
		} else {
			for _, ch := range settings.Channels {
				if ch.Name == "drdynvc" {
					found = true
				}
			}
		}
		if !found {
			return nil, errors.New("rdp: AudioCapture requires an AUDIO_INPUT listener or caller-managed drdynvc")
		}
	}
	if opts.AudioPlayback {
		found := false
		for _, ch := range settings.Channels {
			if ch.Name == "rdpsnd" {
				found = true
				break
			}
		}
		if !found {
			return nil, errors.New("rdp: AudioPlayback requires an rdpsnd static channel and audio consumer")
		}
	}
	var err error
	opts, err = prepareRemoteApp(opts, settings)
	if err != nil {
		return nil, err
	}
	opts, settings, err = prepareDynamic(opts, settings)
	if err != nil {
		return nil, err
	}
	opts.StaticChannelLimits, err = validateStaticChannelLimits(opts.StaticChannelLimits, settings.Channels)
	if err != nil {
		return nil, err
	}
	settings.GraphicsPipeline = settings.GraphicsPipeline || opts.GraphicsPipeline
	settings.NetworkAutoDetect = settings.NetworkAutoDetect || opts.NetworkAutoDetect || settings.GraphicsPipeline
	settings.Heartbeat = settings.Heartbeat || opts.Heartbeat
	maximum, err := opts.BulkCompressionLevel.WireType()
	if err != nil {
		return nil, err
	}
	// Validate Info bounds before sending credentials to a server.
	check, err := login.clientInfo(c, "127.0.0.1", settings, opts, maximum)
	clear(check)
	if err != nil {
		return nil, err
	}
	ctx, cancel, err := handshakeContext(ctx, opts.HandshakeTimeout)
	if err != nil {
		return nil, err
	}
	defer cancel()
	// Work on a copy: callers can reuse their settings without mutation.
	settings.Channels = append([]gcc.Channel(nil), settings.Channels...)
	for i := range settings.Channels {
		if opts.BulkCompression {
			settings.Channels[i].Options |= gcc.ChannelCompressRDP
		} else if settings.Channels[i].Options&(gcc.ChannelCompress|gcc.ChannelCompressRDP) != 0 {
			return nil, errors.New("rdp: channel compression requires BulkCompression")
		}
	}
	// Preserve the original resource request for ARC. Each connection receives
	// a new policy and must derive its effective settings again before dialing.
	requestedOptions, requestedSettings := opts, settings
	connection, err := dialChannelsPrepared(ctx, address, c, &opts, &settings, login.rdstls)
	if err != nil {
		return nil, err
	}
	s := &Session{connection: connection, readGate: make(chan struct{}, 1), inputGate: make(chan struct{}, 1), layout: settings.KeyboardLayout, reactivateTimeout: opts.HandshakeTimeout}
	s.expectedTSVURL, s.hasExpectedTSVURL = expectedTSVURL, opts.ExpectedTSVURL != nil
	if expectedBinding != nil {
		s.expectedTSVURL, s.hasExpectedTSVURL = *expectedBinding, true
	}
	if opts.AutoReconnect {
		s.reconnect = newReconnectState(address, c, requestedOptions, requestedSettings)
		s.reconnect.rdstls = connection.Transport.RDSTLSState().Authenticated
		certs := connection.Transport.TLSState().PeerCertificates
		if len(certs) == 0 {
			s.Close()
			return nil, errors.New("rdp: missing TLS peer certificate")
		}
		s.reconnect.certificate = sha256.Sum256(certs[0].Raw)
	}
	s.graphicsOptions = pdu.GraphicsOptions{AutoReconnect: opts.AutoReconnect, BulkCompression: opts.BulkCompression, NewPointer: opts.NewPointer, LargePointer: opts.LargePointer, DrawingOrders: opts.DrawingOrders, BitmapCacheV2: opts.BitmapCacheV2, BitmapCacheV3: opts.BitmapCacheV3, SurfaceCommands: opts.SurfaceCommands, NSCodec: opts.NSCodec, BrushCache: opts.BrushCache, OffscreenCache: opts.OffscreenCache, ExtendedOrders: opts.ExtendedOrders, ShapeOrders: opts.ShapeOrders, GlyphCache: opts.GlyphCache, GlyphCacheV2: opts.GlyphCacheV2}
	s.remoteAppOptions = opts.RemoteApp
	s.info.RemoteAppEnhancedRequested = opts.RemoteApp != nil && opts.RemoteApp.Enhanced
	s.info.BulkCompression = opts.BulkCompression
	s.info.AudioPlayback = opts.AudioPlayback
	s.info.AudioCapture = opts.AudioCapture
	s.info.GraphicsPipeline = settings.GraphicsPipeline
	s.maximumCompression = maximum
	if opts.BulkCompression {
		s.info.BulkCompressionType = maximum
		s.decompressor = s.decompress
	}
	s.fastPath.Decompress = s.decompressor
	s.channelGate = make(chan struct{}, 1)
	s.channelIDs = make(map[string]uint16, len(settings.Channels))
	s.channelOptions = make(map[uint16]uint32, len(settings.Channels))
	s.channelLimits = make(map[uint16]int, len(settings.Channels))
	for i, ch := range settings.Channels {
		s.channelIDs[ch.Name] = connection.Server.ChannelIDs[i]
		s.channelOptions[connection.Server.ChannelIDs[i]] = ch.Options
		if n := opts.StaticChannelLimits[ch.Name]; n != 0 {
			s.channelLimits[connection.Server.ChannelIDs[i]] = n
		}
	}
	s.info.UserChannel, s.info.IOChannel = connection.UserID, connection.Server.IOChannel
	s.info.MessageChannel = connection.Server.MessageChannel
	s.info.NetworkAutoDetect = settings.NetworkAutoDetect && s.info.MessageChannel != 0
	s.info.Heartbeat = settings.Heartbeat && s.info.MessageChannel != 0
	s.networkInfo.Enabled, s.networkInfo.HeartbeatEnabled = s.info.NetworkAutoDetect, s.info.Heartbeat
	s.networkInfo.MessageChannel = s.info.MessageChannel
	s.info.ChannelChunkSize = vchan.ChunkSize
	if err := s.initDynamic(opts.DynamicChannels); err != nil {
		s.Close()
		return nil, err
	}
	localIP, err := clientIP(connection.Transport.raw)
	if err != nil {
		s.Close()
		return nil, err
	}
	info, err := login.clientInfo(c, localIP, settings, opts, maximum)
	defer clear(info)
	if err == nil {
		err = pdu.SetAudioPlayback(info, opts.AudioPlayback)
	}
	if err == nil {
		err = pdu.SetAudioCapture(info, opts.AudioCapture)
	}
	if err == nil {
		err = pdu.SetRemoteAppMode(info, opts.RemoteApp != nil, s.info.RemoteAppEnhancedRequested)
	}
	if err == nil {
		var activation *licenseActivation
		activation, err = s.licenseActivation(address, c, opts.Licensing)
		if err == nil {
			err = s.activate(ctx, info, activation)
		}
	}
	if err != nil {
		s.Close()
		var request *RedirectionError
		if errors.As(err, &request) && request.source == s {
			return nil, &activationRedirection{request: request, cause: err}
		}
		return nil, fmt.Errorf("rdp activation: %w", err)
	}
	s.active.Store(true)
	s.networkEstablished = true
	return s, nil
}

func (s *Session) send(ctx context.Context, payload []byte) error {
	b, err := mcs.SendDataRequest(s.info.UserChannel, s.info.IOChannel, payload)
	if err != nil {
		return err
	}
	return s.connection.Transport.WriteMCS(ctx, b)
}
func (s *Session) sendData(ctx context.Context, typ byte, payload []byte) error {
	info := s.Info()
	b, err := pdu.MarshalData(info.UserChannel, info.ShareID, typ, payload)
	if err != nil {
		return err
	}
	return s.send(ctx, b)
}
func (s *Session) packet(ctx context.Context) (mcs.DataIndication, *Event, error) {
packetLoop:
	for {
		if len(s.fastEvents) > 0 {
			e := s.fastEvents[0]
			s.fastEvents[0] = pdu.FastPathEvent{}
			s.fastEvents = s.fastEvents[1:]
			kind := EventData
			if e.SurfaceCommands {
				kind = EventSurfaceCommands
			}
			if e.LargePointer {
				kind = EventLargePointer
			}
			return mcs.DataIndication{}, &Event{Kind: kind, Channel: s.info.IOChannel, DataType: e.DataType, Payload: e.Payload}, nil
		}
		var f Frame
		var err error
		if s.dynamic != nil && s.dynamic.info.NegotiatedUDP {
			var event *Event
			f, event, err = s.dynamic.read(ctx)
			if event != nil || err != nil {
				return mcs.DataIndication{}, event, err
			}
		} else {
			f, err = s.connection.Transport.ReadFrame(ctx)
		}
		if err != nil {
			return mcs.DataIndication{}, nil, err
		}
		if f.Kind != FrameMCS {
			if err := s.observeNetworkData(len(f.Data) + f.fastPathHeaderSize); err != nil {
				return mcs.DataIndication{}, nil, err
			}
			if !s.fastEnabled {
				return mcs.DataIndication{}, nil, errors.New("rdp: fast-path output before capability exchange")
			}
			s.fastEvents, err = s.fastPath.Feed(f.Data)
			if err != nil {
				return mcs.DataIndication{}, nil, fmt.Errorf("rdp fast-path: %w", err)
			}
			continue
		}
		if reason, err := mcs.ParseDisconnectProviderUltimatum(f.Data); err == nil {
			return mcs.DataIndication{}, nil, fmt.Errorf("rdp: server disconnected (MCS Disconnect Provider Ultimatum: %s)", reason)
		}
		d, err := mcs.ParseDataIndication(f.Data)
		if err != nil {
			return d, nil, err
		}
		if d.Initiator != 1002 {
			return d, nil, errors.New("rdp: unexpected server MCS initiator")
		}
		if s.info.MessageChannel != 0 && d.Channel == s.info.MessageChannel {
			if err := s.handleNetworkMessage(ctx, d.Payload); err != nil {
				return d, nil, err
			}
			continue
		}
		if err := s.observeNetworkData(len(d.Payload)); err != nil {
			return d, nil, err
		}
		if d.Channel == s.info.IOChannel {
			return d, nil, nil
		}
		for _, id := range s.connection.Server.ChannelIDs {
			if d.Channel == id {
				d.Payload, err = vchan.DecompressChunkWithLimit(d.Payload, s.decompressor, s.channelLimit(id))
				if err != nil {
					return d, nil, fmt.Errorf("rdp channel: %w", err)
				}
				if len(d.Payload) >= 8 {
					flags := binary.LittleEndian.Uint32(d.Payload[4:])
					if flags&0x20 != 0 {
						s.channelSuspended.Store(true)
					}
					if flags&0x40 != 0 {
						s.channelSuspended.Store(false)
					}
				}
				if s.dynamic != nil && id == s.dynamic.id {
					e, err := s.dynamic.handleTCP(ctx, d.Payload)
					if err != nil || e != nil {
						return d, e, err
					}
					continue packetLoop
				}
				return d, nil, nil
			}
		}
		return d, nil, errors.New("rdp: data for an unjoined channel")
	}
}

func (s *Session) next(ctx context.Context) (pdu.Share, *Event, error) {
	if len(s.shares) == 0 {
		d, event, err := s.packet(ctx)
		if err != nil {
			return pdu.Share{}, nil, err
		}
		if event != nil {
			return pdu.Share{}, event, nil
		}
		if d.Channel != s.info.IOChannel {
			return pdu.Share{}, &Event{Channel: d.Channel, Payload: d.Payload}, nil
		}
		var errParse error
		s.shares, errParse = pdu.ParseShares(d.Payload)
		if errParse != nil {
			return pdu.Share{}, nil, errParse
		}
	}
	v := s.shares[0]
	s.shares[0] = pdu.Share{}
	s.shares = s.shares[1:]
	// Monitor Layout, ARC Status and Set Error Info use pduSource=0.
	arcStatus := v.Type == pdu.DataPDU && len(v.Body) >= 12 && v.Body[8] == pdu.AutoReconnectStatus
	zeroSource := v.Source == 0 && v.Type == pdu.DataPDU && len(v.Body) >= 12 && (v.Body[8] == pdu.MonitorLayout || v.Body[8] == pdu.SetErrorInfo || arcStatus)
	if (arcStatus && v.Source != 0) || (v.Source != 1002 && !zeroSource) {
		dataType := byte(0)
		if v.Type == pdu.DataPDU && len(v.Body) >= 12 {
			dataType = v.Body[8]
		}
		return pdu.Share{}, nil, fmt.Errorf("rdp: unexpected Share Control source=%d type=%d dataType=%d", v.Source, v.Type, dataType)
	}
	if v.Type == pdu.RedirectionPDU {
		event, err := s.handleRedirection(v)
		return pdu.Share{}, event, err
	}
	return v, nil, nil
}
func (s *Session) decode(v pdu.Share) (Event, error) {
	if v.Type == pdu.DeactivateAll {
		return Event{}, ErrDeactivated
	}
	d, err := pdu.ParseDataCompressed(v, s.decompressor)
	if err != nil {
		return Event{}, err
	}
	if d.Type == pdu.AutoReconnectStatus {
		if v.Source != 0 || len(d.Payload) != 4 || binary.LittleEndian.Uint32(d.Payload) != 0 {
			return Event{}, pdu.ErrInvalid
		}
		return Event{}, ErrReconnectRejected
	}
	// Errors can arrive before Demand Active establishes a Share ID.
	if d.Type == pdu.SetErrorInfo {
		if len(d.Payload) != 4 {
			return Event{}, pdu.ErrInvalid
		}
		if code := binary.LittleEndian.Uint32(d.Payload); code != 0 {
			return Event{}, &pdu.ServerError{Code: code}
		}
		return Event{Channel: s.info.IOChannel, DataType: d.Type, Payload: d.Payload}, nil
	}
	if d.ShareID != s.info.ShareID {
		return Event{}, errors.New("rdp: Share ID mismatch")
	}
	if d.Type == pdu.SaveSessionInfo {
		info, err := s.decodeLogon(d.Payload)
		if err != nil {
			return Event{}, err
		}
		return Event{Kind: EventLogonInfo, Channel: s.info.IOChannel, DataType: d.Type, Logon: info}, nil
	}
	if d.Type == pdu.Update && len(d.Payload) >= 2 && binary.LittleEndian.Uint16(d.Payload) == 0 && !s.info.DrawingOrders {
		return Event{}, errors.New("rdp: drawing orders not negotiated")
	}
	if d.Type == pdu.Pointer && len(d.Payload) >= 2 && binary.LittleEndian.Uint16(d.Payload) == 8 && !s.info.NewPointer {
		return Event{}, errors.New("rdp: new pointers not negotiated")
	}
	if d.Type == pdu.MonitorLayout {
		monitors, err := pdu.ParseMonitorLayout(d.Payload)
		if err != nil {
			return Event{}, err
		}
		s.infoMu.Lock()
		s.monitors = monitors
		s.infoMu.Unlock()
	}
	return Event{Channel: s.info.IOChannel, DataType: d.Type, Payload: d.Payload}, nil
}
func (s *Session) activate(ctx context.Context, info []byte, license *licenseActivation) error {
	if err := s.send(ctx, info); err != nil {
		return fmt.Errorf("send Client Info: %w", err)
	}
	if err := s.receiveLicense(ctx, license); err != nil {
		return err
	}
	s.info.LicenseAccepted = true
	for n := 0; n < 16; n++ {
		v, other, err := s.next(ctx)
		if err != nil {
			return err
		}
		if other != nil {
			if other.Kind == EventRedirectionInfo {
				if len(s.pending) >= 16 {
					return errors.New("rdp: too many notices before activation")
				}
				s.pending = append(s.pending, *other)
				continue
			}
			return errors.New("rdp: expected Demand Active")
		}
		if v.Type == pdu.DataPDU && len(v.Body) >= 12 && (v.Body[8] == pdu.AutoReconnectStatus || v.Body[8] == pdu.SetErrorInfo) {
			if _, err := s.decode(v); err != nil {
				return err
			}
			continue
		}
		return s.finalize(ctx, v)
	}
	return errors.New("rdp: too many status messages before Demand Active")
}

func (s *Session) finalize(ctx context.Context, v pdu.Share) error {
	demand, err := pdu.ParseDemand(v)
	if err != nil {
		return fmt.Errorf("Demand Active: %w", err)
	}
	g := s.graphicsOptions.Effective(demand)
	var remote RemoteAppInfo
	var confirm []byte
	if s.remoteAppOptions != nil {
		remote, err = s.remoteAppOptions.Negotiate(demand)
		if err != nil {
			return err
		}
		confirm, err = pdu.ConfirmRemoteApp(s.info.UserChannel, demand, s.layout, g, *s.remoteAppOptions)
	} else {
		confirm, err = pdu.ConfirmGraphics(s.info.UserChannel, demand, s.layout, g)
	}
	if err != nil {
		return err
	}
	s.infoMu.Lock()
	s.info.RemoteApp = remote
	s.info.ShareID, s.info.Width, s.info.Height, s.info.BitsPerPixel = demand.ShareID, demand.Width, demand.Height, demand.BitsPerPixel
	s.info.RefreshRect, s.info.SuppressOutput = demand.RefreshRect, demand.SuppressOutput
	s.info.UnicodeInput, s.info.ChannelChunkSize = demand.UnicodeInput, demand.ChannelChunkSize
	s.info.ChannelCompression = s.info.BulkCompression && demand.ChannelCompression
	s.info.DrawingOrders, s.info.BitmapCacheV2, s.info.SurfaceCommands = g.DrawingOrders, g.BitmapCacheV2, g.SurfaceCommands
	s.info.FrameAcknowledge = g.SurfaceCommands && demand.FrameAcknowledge
	s.info.NSCodec = g.NSCodec
	s.info.AutoReconnect = g.AutoReconnect
	s.info.BitmapCacheV3 = g.BitmapCacheV3
	s.info.BrushCache, s.info.OffscreenCache = g.BrushCache, g.OffscreenCache
	s.info.ExtendedOrders = g.ExtendedOrders
	s.info.ShapeOrders = g.ShapeOrders
	s.info.GlyphCache, s.info.GlyphCacheV2 = g.GlyphCache, g.GlyphCacheV2
	s.info.NewPointer, s.info.LargePointerFlags = g.NewPointer, g.LargePointerFlags
	s.infoMu.Unlock()
	if !g.AutoReconnect && s.reconnect != nil {
		s.reconnect.mu.Lock()
		s.reconnect.discardLocked()
		s.reconnect.mu.Unlock()
	}
	if err := s.send(ctx, confirm); err != nil {
		return err
	}
	s.fastEnabled = true
	s.fastPath.AllowOrders = s.info.DrawingOrders
	s.fastPath.AllowSurfaceCommands = s.info.SurfaceCommands
	s.fastPath.AllowNewPointer, s.fastPath.AllowLargePointer = g.NewPointer, g.LargePointerFlags&2 != 0
	for _, msg := range []struct {
		typ  byte
		data []byte
	}{
		{pdu.Synchronize, []byte{1, 0, 0xea, 3}},
		{pdu.Control, []byte{4, 0, 0, 0, 0, 0, 0, 0}},
		{pdu.Control, []byte{1, 0, 0, 0, 0, 0, 0, 0}},
		{pdu.FontList, []byte{0, 0, 0, 0, 3, 0, 0x32, 0}},
	} {
		if err := s.sendData(ctx, msg.typ, msg.data); err != nil {
			return err
		}
	}
	state := 0
	for messages := 0; messages < 128; messages++ {
		v, other, err := s.next(ctx)
		if err != nil {
			return err
		}
		var e Event
		if other != nil {
			e = *other
		} else {
			e, err = s.decode(v)
			if err != nil {
				return err
			}
		}
		switch e.DataType {
		case pdu.Synchronize:
			if state != 0 || len(e.Payload) != 4 || binary.LittleEndian.Uint16(e.Payload) != 1 {
				return errors.New("rdp: invalid server Synchronize")
			}
			// MS-RDPBCGR 3.2.5.3.19: targetUser MUST be ignored.
			state = 1
		case pdu.Control:
			if len(e.Payload) != 8 {
				return pdu.ErrInvalid
			}
			action := binary.LittleEndian.Uint16(e.Payload)
			if state == 1 && action == 4 {
				state = 2
			} else if state == 2 && action == 2 {
				// MS-RDPBCGR 3.2.5.3.21: grantId/controlId MUST be ignored.
				state = 3
			} else {
				return errors.New("rdp: invalid server Control sequence")
			}
		case pdu.FontMap:
			// MS-RDPBCGR 3.2.5.3.22: all Font Map payload values are ignored.
			if state != 3 || len(e.Payload) != 8 {
				return errors.New("rdp: incomplete Font Map finalization")
			}
			return nil
		default:
			if len(s.pending) >= 64 {
				return errors.New("rdp: too many events before activation")
			}
			s.pending = append(s.pending, e)
		}
	}
	return errors.New("rdp: activation message limit exceeded")
}

// ReadEvent reads a normalized update or lifecycle notification. After
// EventDeactivated, keep reading: EventActivated precedes all updates belonging
// to the new desktop. Protocol errors and I/O cancellation close the session.
// Negotiated managed reliable UDP uses bounded background wire readers, but
// application delivery and main-connection replies still require ReadEvent.
// No automatic TCP reconnection is started.
func (s *Session) ReadEvent(ctx context.Context) (Event, error) {
	if err := s.acquireRead(ctx); err != nil {
		return Event{}, err
	}
	defer func() { <-s.readGate }()
	if !s.active.Load() {
		if err := s.reactivate(ctx); err != nil {
			s.failSession(err)
			return Event{}, fmt.Errorf("rdp reactivation: %w", err)
		}
		s.active.Store(true)
		return Event{Kind: EventActivated, Info: s.Info()}, nil
	}
	if len(s.pending) > 0 {
		e := s.pending[0]
		s.pending[0] = Event{}
		s.pending = s.pending[1:]
		return e, nil
	}
	v, other, err := s.next(ctx)
	if err == nil && other != nil {
		return *other, nil
	}
	var e Event
	if err == nil && v.Type == pdu.DeactivateAll {
		if err := s.checkDeactivate(v); err != nil {
			s.failSession(err)
			return Event{}, err
		}
		// Stop accepting new input immediately, then drain any in-flight write.
		s.active.Store(false)
		s.infoMu.Lock()
		s.monitors = nil
		s.infoMu.Unlock()
		if err := s.connection.Transport.acquire(ctx, s.inputGate); err != nil {
			s.failSession(err)
			return Event{}, err
		}
		<-s.inputGate
		s.fastPath = pdu.FastPathDecoder{Decompress: s.decompressor}
		s.fastEvents = nil
		return Event{Kind: EventDeactivated, Info: s.Info()}, nil
	}
	if err == nil {
		e, err = s.decode(v)
	}
	if err != nil {
		s.failSession(err)
		return Event{}, err
	}
	return e, nil
}

func (s *Session) acquireRead(ctx context.Context) error {
	if s.dynamic == nil || !s.dynamic.info.NegotiatedUDP {
		return s.connection.Transport.acquire(ctx, s.readGate)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.readGate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	case <-s.dynamic.life.Done():
		return s.dynamic.err()
	}
	if err := ctx.Err(); err != nil {
		<-s.readGate
		return err
	}
	return nil
}

func (s *Session) reactivate(ctx context.Context) error {
	ctx, cancel, err := handshakeContext(ctx, s.reactivateTimeout)
	if err != nil {
		return err
	}
	defer cancel()
	// Old graphics/input handlers remain disabled until Demand Active. Static
	// channel notifications may interleave; retain them with bounded storage.
	for n := 0; n < 128; n++ {
		v, other, err := s.next(ctx)
		if err != nil {
			return err
		}
		if other == nil && v.Type == pdu.DemandActive {
			return s.finalize(ctx, v)
		}
		if other == nil && v.Type == pdu.DeactivateAll {
			if err := s.checkDeactivate(v); err != nil {
				return err
			}
			s.infoMu.Lock()
			s.monitors = nil
			s.infoMu.Unlock()
			continue
		}
		var e Event
		if other != nil {
			e = *other
		} else {
			e, err = s.decode(v)
			if err != nil {
				return err
			}
		}
		if e.DataType == pdu.Update || e.DataType == pdu.Pointer || e.Kind == EventSurfaceCommands || e.Kind == EventLargePointer {
			continue
		}
		if len(s.pending) >= 64 {
			return errors.New("rdp: too many events during reactivation")
		}
		s.pending = append(s.pending, e)
	}
	return errors.New("rdp: reactivation message limit exceeded")
}

func (s *Session) checkDeactivate(v pdu.Share) error {
	if len(v.Body) < 6 || int(binary.LittleEndian.Uint16(v.Body[4:])) != len(v.Body)-6 || binary.LittleEndian.Uint32(v.Body) != s.info.ShareID {
		return pdu.ErrInvalid
	}
	return nil
}
