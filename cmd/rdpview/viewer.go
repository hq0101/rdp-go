package main

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/cliprdr"
	"github.com/hq0101/rdp-go/disp"
	"github.com/hq0101/rdp-go/dynvc"
	"github.com/hq0101/rdp-go/graphics"
	"github.com/hq0101/rdp-go/internal/gatewayconfig"
	"github.com/hq0101/rdp-go/pdu"
	"github.com/hq0101/rdp-go/rail"
	"github.com/hq0101/rdp-go/rdgateway"
	"github.com/hq0101/rdp-go/rdpdr"
	"github.com/hq0101/rdp-go/rdpgfx"
	"github.com/hq0101/rdp-go/vchan"
)

//go:embed web/*
var assets embed.FS

type remote interface {
	ReadEvent(context.Context) (rdp.Event, error)
	SendKey(context.Context, uint8, bool, bool) error
	SendText(context.Context, string) error
	MovePointer(context.Context, uint16, uint16) error
	SendMouseButton(context.Context, rdp.MouseButton, bool, uint16, uint16) error
	Scroll(context.Context, int16) error
	Close() error
}

type viewer struct {
	app                    *viewerRemoteApp // frameMu; connectionMu guards replacement
	remote                 remote
	emptyDevices           *viewerEmptyDevices  // sole receive loop, connectionMu guards replacement
	gatewayPolicy          rdgateway.Policy     // connectionMu guards replacement
	gatewayAccess          *viewerGatewayAccess // immutable connection-chain policy gate
	gatewayReporter        *gatewayconfig.Reporter
	stopServices           func() error // connectionMu; joined outside the lock
	connectionMu           sync.RWMutex
	stopping               atomic.Bool
	recover                recoveryFunc
	follow                 redirectionFunc
	recoveryDelay          time.Duration
	reconnection           reconnectStatus // frameMu
	gfxProfile             rdpgfx.Profile
	displayAllowed         bool
	width, height          int
	host, token            string
	stop                   context.CancelFunc
	stopOnce               sync.Once
	lastSeen               atomic.Int64
	pageOpened             atomic.Bool
	frameMu                sync.Mutex
	frame                  *graphics.Framebuffer
	dirty                  bool
	active                 bool // frameMu also protects dimensions, lifecycle and pointer
	generation             uint64
	renderEpoch            uint64
	pointer                graphics.PointerDecoder
	pointerVersion         uint64
	positionVersion        uint64
	unicodeInput           bool
	frameAcknowledge       bool
	captureMu              sync.Mutex
	capture                *viewerCapture
	captureEpoch           uint64
	driveConfig            *viewerDriveConfig // immutable; application owns anchor
	drive                  *viewerDrive       // connectionMu guards replacement
	audioMu                sync.Mutex
	audio                  *viewerAudio // audioMu; connectionMu guards replacement
	audioEpoch             uint64       // independent of desktop size/generation
	clipMu                 sync.Mutex
	clip                   *cliprdr.Client
	clipChannel            uint16
	clipDecoder            vchan.Decoder
	clipWait               chan clipResult
	clipHTTPGate           chan struct{}
	clipServed             uint64
	fileClipboardRequested bool              // original local request, retained across policy changes
	fileClipboardEnabled   bool              // configured before receiving channel packets
	fileJob                *fileJob          // clipMu; worker owns resources until done
	sources                *clipboardSources // clipMu; connection-bound disk workers
	uploadJob              *uploadJob        // clipMu; explicit browser preparation
	displayMu              sync.Mutex
	dynamicManaged         bool // displayMu; Session owns DVC parsing and routing
	dynamicReady           bool // received the managed Ready event
	dynamic                *dynvc.Client
	dynamicChannel         uint16
	dynamicDecoder         vchan.Decoder
	gfx                    *rdpgfx.Client // displayMu protects protocol state
	display                disp.Client
	displayID              uint32
	displayOpen            bool
	displayEnabled         bool
	resize                 resizeStatus // protected by frameMu
	resizeDeadline         time.Time
	imageMu                sync.RWMutex
	png                    []byte
	version                uint64
	inputMu                sync.Mutex
	keys                   map[uint16]bool
	buttons                map[rdp.MouseButton]bool
	x, y                   uint16
}

func newViewer(r remote, info rdp.SessionInfo, host, token string, stop context.CancelFunc) (*viewer, error) {
	var policy rdgateway.Policy
	if i := gatewayconfig.Info(r); i != nil {
		var err error
		policy, err = rdgateway.NewPolicy(*i)
		if err != nil {
			return nil, err
		}
	}
	if policy.AllDisabled() {
		info.AudioPlayback, info.AudioCapture = false, false
	}
	f, err := graphics.NewFramebuffer(int(info.Width), int(info.Height))
	if err != nil {
		return nil, err
	}
	v := &viewer{remote: r, gatewayPolicy: policy, width: int(info.Width), height: int(info.Height), host: host, token: token, stop: stop, frame: f, active: true, generation: 1, keys: map[uint16]bool{}, buttons: map[rdp.MouseButton]bool{}}
	v.clipHTTPGate = make(chan struct{}, 1)
	v.recoveryDelay = time.Second
	v.audioEpoch = 1
	v.captureEpoch = 1
	v.reconnection.Phase = "connected"
	v.displayAllowed = true
	v.unicodeInput = info.UnicodeInput
	v.frameAcknowledge = info.FrameAcknowledge
	v.frame.AllowNSCodec = info.NSCodec
	v.frame.AllowBitmapCacheV3 = info.BitmapCacheV3
	v.frame.AllowBrushCache, v.frame.AllowOffscreen, v.frame.OffscreenDepth = info.BrushCache, info.OffscreenCache, info.BitsPerPixel
	v.frame.AllowExtendedOrders = info.ExtendedOrders
	v.frame.AllowShapeOrders = info.ShapeOrders
	v.frame.AllowGlyphCache, v.frame.AllowGlyphCacheV2 = info.GlyphCache, info.GlyphCacheV2
	v.pointer.AllowNewPointer, v.pointer.LargePointerFlags = info.NewPointer, info.LargePointerFlags
	if _, ok := r.(channelRemote); info.AudioPlayback && !ok {
		return nil, errors.New("audio requires static virtual channels")
	}
	if channels, ok := r.(channelRemote); ok {
		if info.AudioPlayback {
			v.audio, err = newViewerAudio(channels)
			if err != nil {
				return nil, err
			}
		}
		if id, ok := channels.ChannelID(rdpdr.ChannelName); ok && v.audio == nil {
			v.emptyDevices = &viewerEmptyDevices{channel: id, decoder: vchan.Decoder{Limit: rdpdr.MaxDeviceMessage}}
		}
		if id, ok := channels.ChannelID("cliprdr"); ok && policy.ClipboardAllowed() {
			v.clip = &cliprdr.Client{}
			v.clipChannel = id
			v.clipDecoder.Limit = cliprdr.MaxMessage
		}
		if id, ok := channels.ChannelID("drdynvc"); ok {
			limits := map[string]int{disp.ChannelName: dynvc.MaxMessage}
			budget := dynvc.MaxBuffered
			if info.GraphicsPipeline {
				limits[rdpgfx.ChannelName] = rdpgfx.MaxWireMessage
				budget = dynvc.HardLimit
				v.gfx = &rdpgfx.Client{}
			}
			if managed, ok := r.(managedDynamicRemote); ok && managed.DynamicInfo().Managed {
				v.dynamicManaged = true
			} else {
				v.dynamic, err = dynvc.NewWithLimits(limits, budget)
				if err != nil {
					return nil, err
				}
			}
			v.dynamicChannel = id
			v.displayEnabled = true
		}
	}
	if info.AudioCapture {
		if !v.dynamicManaged {
			return nil, errors.New("microphone requires managed dynamic channels")
		}
		if _, ok := r.(interface {
			CloseDynamic(context.Context, uint32) error
		}); !ok {
			return nil, errors.New("microphone requires dynamic close")
		}
		v.capture = &viewerCapture{}
	}
	if err := v.initRemoteApp(info); err != nil {
		return nil, err
	}
	v.lastSeen.Store(time.Now().UnixNano())
	return v, nil
}

func (v *viewer) receive(ctx context.Context) {
	defer v.closeRemote()
	for {
		r := v.currentRemote()
		e, err := r.ReadEvent(ctx)
		if err == nil {
			err = v.applyEvent(ctx, e)
			var writeErr *protocolWriteError
			if err != nil && !errors.As(err, &writeErr) {
				v.stopWithReason("remote update failed: " + err.Error())
				return
			}
		}
		if err == nil {
			continue
		}
		var redirect *rdp.RedirectionError
		if errors.As(err, &redirect) {
			if v.follow == nil || ctx.Err() != nil {
				if redirect.Request != nil {
					redirect.Request.Clear()
				}
				v.stopWithReason("server redirection is not enabled")
				return
			}
			if err := v.redirectConnection(ctx, r, redirect); err != nil {
				v.stopWithReason("session redirection failed: " + err.Error())
				return
			}
			continue
		}
		v.connectionMu.RLock()
		recoverable := v.canRecover()
		v.connectionMu.RUnlock()
		if ctx.Err() != nil || !recoverable {
			v.stopWithReason("remote session ended: " + err.Error())
			return
		}
		if err := v.recoverConnection(ctx, r); err != nil {
			var writeErr *protocolWriteError
			v.connectionMu.RLock()
			recoverable := v.canRecover()
			v.connectionMu.RUnlock()
			if errors.As(err, &writeErr) && recoverable {
				continue
			}
			v.stopWithReason("session recovery failed: " + err.Error())
			return
		}
	}
}

func (v *viewer) applyEvent(ctx context.Context, e rdp.Event) (result error) {
	v.connectionMu.RLock()
	defer v.connectionMu.RUnlock()
	defer func() {
		if result == nil {
			result = v.reconcileAppInput(ctx)
			if result == nil {
				result = v.syncAppParameters(ctx)
			}
		}
	}()
	if v.app != nil && e.Kind == rdp.EventData && e.DataType == 0 && e.Channel == v.app.channel {
		return v.receiveRemoteApp(ctx, e.Payload)
	}
	if e.Kind == rdp.EventData && e.DataType == 0 && v.drive != nil && e.Channel == v.drive.channel {
		return v.drive.enqueue(e.Payload)
	}
	if e.Kind == rdp.EventData && e.DataType == 0 && v.audio != nil && (e.Channel == v.audio.channel || e.Channel == v.audio.deviceChannel) {
		return v.receiveAudio(ctx, e.Channel, e.Payload)
	}
	if e.Kind == rdp.EventLargePointer {
		v.frameMu.Lock()
		defer v.frameMu.Unlock()
		if !v.active {
			return nil
		}
		if err := v.pointer.ApplyLarge(e.Payload); err != nil {
			return err
		}
		v.pointerVersion++
		return nil
	}
	if e.Kind == rdp.EventData && e.DataType == 0 && v.emptyDevices != nil && e.Channel == v.emptyDevices.channel {
		return v.receiveEmptyDevices(ctx, e.Payload)
	}
	if e.Kind == rdp.EventSurfaceCommands {
		v.frameMu.Lock()
		if !v.active {
			v.frameMu.Unlock()
			return nil
		}
		result, err := v.frame.ApplySurfaceCommands(e.Payload)
		v.dirty = v.dirty || len(result.Dirty) > 0
		acknowledge := v.frameAcknowledge
		v.frameMu.Unlock()
		if err != nil {
			return err
		}
		if acknowledge && len(result.CompletedFrames) > 0 {
			r, ok := v.remote.(interface {
				AcknowledgeFrame(context.Context, uint32) error
			})
			if !ok {
				return errors.New("frame acknowledgement unavailable")
			}
			ackCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			for _, id := range result.CompletedFrames {
				if err := r.AcknowledgeFrame(ackCtx, id); err != nil {
					return writeFailure(err)
				}
			}
		}
		return nil
	}
	if e.Kind == rdp.EventDynamic {
		return v.receiveDynamic(ctx, e.Dynamic)
	}
	if e.Kind == rdp.EventData && e.Channel == v.dynamicChannel && e.DataType == 0 {
		if v.dynamicManaged {
			return dynvc.ErrProtocol // managed sessions must not also expose raw DVC bytes
		}
		if v.dynamic != nil {
			return v.receiveDisplay(ctx, e.Payload)
		}
	}
	if e.Kind == rdp.EventData && e.Channel == v.clipChannel && v.clip != nil && e.DataType == 0 {
		return v.receiveClipboard(ctx, e.Payload)
	}
	if e.Kind == rdp.EventLogonInfo {
		return nil // A login notification does not deactivate or resize output.
	}
	if e.Kind != rdp.EventData {
		v.inputMu.Lock()
		defer v.inputMu.Unlock()
		v.frameMu.Lock()
		defer v.frameMu.Unlock()
		v.active = false
		if v.app != nil && v.app.moves.Invalidate() {
			v.app.moveDeadline = time.Now().Add(5 * time.Second)
			v.app.moveTarget = rail.WindowIdentity{}
		}
		v.dirty = false
		v.imageMu.Lock()
		v.png = nil // Invalidate old geometry, including an in-flight PNG encode.
		v.imageMu.Unlock()
		if e.Kind == rdp.EventActivated {
			err := v.frame.Resize(int(e.Info.Width), int(e.Info.Height))
			if err != nil {
				return err
			}
			v.width, v.height = int(e.Info.Width), int(e.Info.Height)
			v.unicodeInput = e.Info.UnicodeInput
			v.frameAcknowledge = e.Info.FrameAcknowledge
			v.frame.AllowNSCodec = e.Info.NSCodec
			v.frame.AllowBitmapCacheV3 = e.Info.BitmapCacheV3
			v.frame.AllowBrushCache, v.frame.AllowOffscreen, v.frame.OffscreenDepth = e.Info.BrushCache, e.Info.OffscreenCache, e.Info.BitsPerPixel
			v.frame.AllowExtendedOrders = e.Info.ExtendedOrders
			v.frame.AllowShapeOrders = e.Info.ShapeOrders
			v.frame.AllowGlyphCache, v.frame.AllowGlyphCacheV2 = e.Info.GlyphCache, e.Info.GlyphCacheV2
			v.pointer.AllowNewPointer, v.pointer.LargePointerFlags = e.Info.NewPointer, e.Info.LargePointerFlags
			v.generation++
			v.finishResizeLocked(int(e.Info.Width), int(e.Info.Height))
			v.x, v.y = min(v.x, e.Info.Width-1), min(v.y, e.Info.Height-1)
			// Release only input that this viewer successfully pressed before the
			// transition. Do not change the user's keyboard toggle state.
			releaseCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			err = writeFailure(v.send(releaseCtx, input{Kind: "release"}))
			cancel()
			if err != nil {
				return err
			}
			if err := v.reconfigureAppLocked(e.Info); err != nil {
				return err
			}
			v.active = true
		}
		return nil
	}
	v.frameMu.Lock()
	defer v.frameMu.Unlock()
	if !v.active {
		return nil
	}
	switch e.DataType {
	case pdu.MonitorLayout:
		if v.app != nil && !v.app.client.Status().Enhanced {
			return v.appBasicMonitorsLocked(e.Payload)
		}
	case pdu.Update:
		dirty, err := v.frame.Apply(e.Payload)
		if err == nil && len(e.Payload) >= 2 && binary.LittleEndian.Uint16(e.Payload) == 2 {
			err = v.pointer.ApplyPalette(e.Payload)
		}
		v.dirty = v.dirty || len(dirty) > 0
		if err == nil {
			err = v.syncAppSceneLocked()
		}
		return err
	case pdu.Pointer:
		if err := v.pointer.Apply(e.Payload); err != nil {
			return err
		}
		v.pointerVersion++
		if binary.LittleEndian.Uint16(e.Payload) == 3 {
			v.positionVersion++
		}
	}
	return nil
}

func (v *viewer) publish(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	encoder := png.Encoder{CompressionLevel: png.BestSpeed}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		v.frameMu.Lock()
		if v.expireAppMoveLocked(time.Now()) {
			v.frameMu.Unlock()
			return
		}
		if !v.dirty {
			v.frameMu.Unlock()
			continue
		}
		var img *image.RGBA
		var appFrame *appRender
		if v.app != nil {
			img, appFrame = v.renderAppLocked()
		} else {
			img = v.frame.Snapshot()
		}
		generation := v.generation
		epoch := v.renderEpoch
		v.dirty = false
		v.frameMu.Unlock()
		var b bytes.Buffer
		if err := encoder.Encode(&b, img); err != nil {
			v.stopWithReason("PNG encoding failed: " + err.Error())
			return
		}
		v.frameMu.Lock()
		if !v.active || generation != v.generation || epoch != v.renderEpoch || appFrame != nil && (v.app == nil || appFrame.token != v.appTokenLocked()) {
			v.frameMu.Unlock()
			continue
		}
		v.imageMu.Lock()
		v.png = b.Bytes()
		if appFrame != nil {
			v.app.presented = appFrame.views
			v.app.presentedToken = appFrame.token
			v.app.pending = appFrame.pending
		}
		v.version++
		if v.reconnection.Phase == "restoring" {
			v.reconnection.Phase = "connected"
		}
		v.imageMu.Unlock()
		v.frameMu.Unlock()
	}
}

func (v *viewer) stopWithReason(reason string) {
	v.stopOnce.Do(func() {
		v.stopping.Store(true)
		log.Printf("viewer stopping: %s", reason)
		v.stop()
	})
}

func (v *viewer) pageExpired(now time.Time) bool {
	// Starting the viewer and opening its page are separate user actions. Allow
	// time for handoff before applying the shorter abandoned-page timeout.
	limit := 30 * time.Minute
	if v.pageOpened.Load() {
		limit = 3 * time.Minute
	}
	return now.Sub(time.Unix(0, v.lastSeen.Load())) > limit
}

func (v *viewer) watch(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if v.pageExpired(time.Now()) {
			v.stopWithReason("page access timeout")
			return
		}
	}
}

func (v *viewer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' blob:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
	if r.Host != v.host {
		http.Error(w, "invalid host", http.StatusForbidden)
		return
	}
	// Public assets contain no credentials or session data. In particular, a
	// top-level navigation from a chat link may legitimately be cross-site.
	if r.URL.Path == "/" || r.URL.Path == "/app.js" || r.URL.Path == "/remoteapp.js" || r.URL.Path == "/notifications.js" || r.URL.Path == "/audio.js" || r.URL.Path == "/capture.js" || r.URL.Path == "/clipboard.js" || r.URL.Path == "/files.js" || r.URL.Path == "/upload.js" || r.URL.Path == "/capture-pcm.js" || r.URL.Path == "/capture-worklet.js" || r.URL.Path == "/style.css" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		path := r.URL.Path
		if path == "/" {
			path = "/index.html"
		}
		b, err := assets.ReadFile("web" + path)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		content := "text/html; charset=utf-8"
		if strings.HasSuffix(path, ".js") {
			content = "text/javascript; charset=utf-8"
		}
		if strings.HasSuffix(path, ".css") {
			content = "text/css; charset=utf-8"
		}
		w.Header().Set("Content-Type", content)
		w.Write(b)
		return
	}
	origin := r.Header.Get("Origin")
	if (origin != "" && origin != "http://"+v.host) || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		http.Error(w, "invalid origin", http.StatusForbidden)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-RdpGo-Token")), []byte(v.token)) != 1 {
		http.Error(w, "authentication required", http.StatusForbidden)
		return
	}
	// Startup diagnostics must not shorten the first-page handoff window.
	if r.URL.Path == "/frame" || r.URL.Path == "/input" || r.URL.Path == "/resize" || r.URL.Path == "/remoteapp" {
		v.lastSeen.Store(time.Now().UnixNano())
		v.pageOpened.Store(true)
	}
	// Clipboard releases the connection lock while waiting for a server reply.
	if !uploadPath(r.URL.Path) && r.URL.Path != "/clipboard" && r.URL.Path != "/clipboard/image" && r.URL.Path != "/clipboard/files" && r.URL.Path != "/clipboard/files/archive" && r.URL.Path != "/audio" && r.URL.Path != "/capture" {
		v.connectionMu.RLock()
		defer v.connectionMu.RUnlock()
	}
	switch r.URL.Path {
	case "/status":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		clipStatus := v.clipboardStatus()
		displayStatus := v.displayStatus()
		gfxStatus := v.graphicsStatus()
		soundStatus := v.audioStatus()
		microphoneStatus := v.captureStatus()
		directoryStatus := v.driveStatus()
		if soundStatus.Enabled && directoryStatus.Enabled {
			soundStatus.DeviceReady = directoryStatus.Phase == "ready" || directoryStatus.Phase == "rejected"
		}
		v.frameMu.Lock()
		defer v.frameMu.Unlock()
		v.expireResizeLocked(time.Now())
		v.imageMu.RLock()
		frameReady := len(v.png) > 0
		v.imageMu.RUnlock()
		w.Header().Set("Content-Type", "application/json")
		// Large shapes need not be encoded, copied or sent on every status poll.
		var pointer graphics.PointerState
		if r.URL.Query().Get("pointer_version") != strconv.FormatUint(v.pointerVersion, 10) {
			pointer = v.pointer.Snapshot()
		}
		var compression rdp.CompressionStats
		if source, ok := v.remote.(interface {
			CompressionStats() rdp.CompressionStats
		}); ok {
			compression = source.CompressionStats()
		}
		json.NewEncoder(w).Encode(struct {
			RemoteApp       appStatus               `json:"remoteapp"`
			Gateway         *rdgateway.Info         `json:"gateway,omitempty"`
			Licensing       *rdp.LicensingState     `json:"licensing,omitempty"`
			Drive           driveStatus             `json:"drive"`
			Microphone      captureStatus           `json:"microphone"`
			Audio           audioStatus             `json:"audio"`
			Multitransport  *rdp.DynamicChannelInfo `json:"multitransport,omitempty"`
			Network         *rdp.NetworkInfo        `json:"network,omitempty"`
			Reconnect       reconnectStatus         `json:"reconnect"`
			Graphics        graphicsStatusType      `json:"graphics_pipeline"`
			Compression     rdp.CompressionStats    `json:"compression"`
			Width           int                     `json:"width"`
			Height          int                     `json:"height"`
			FrameReady      bool                    `json:"frame_ready"`
			Active          bool                    `json:"active"`
			Generation      uint64                  `json:"generation"`
			Pointer         graphics.PointerState   `json:"pointer"`
			PointerVersion  uint64                  `json:"pointer_version"`
			PositionVersion uint64                  `json:"position_version"`
			UnicodeInput    bool                    `json:"unicode_input"`
			Clipboard       clipboardStatus         `json:"clipboard"`
			Display         displayStatusType       `json:"display"`
			Resize          resizeStatus            `json:"resize"`
			Orders          graphics.OrderStats     `json:"orders"`
			Surface         graphics.SurfaceStats   `json:"surface"`
			Pointers        graphics.PointerStats   `json:"pointers"`
		}{v.appStatusLocked(), gatewayconfig.Info(v.remote), v.licensingStatus(), directoryStatus, microphoneStatus, soundStatus, v.dynamicStatus(), v.networkStatus(), v.reconnectStatus(), gfxStatus, compression, v.width, v.height, frameReady, v.active, v.generation, pointer, v.pointerVersion, v.positionVersion, v.unicodeInput, clipStatus, displayStatus, v.resize, v.frame.OrderStats(), v.frame.SurfaceStats(), v.pointer.Stats()})
	case "/frame":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		v.frameMu.Lock()
		w.Header().Set("X-RdpGo-Generation", strconv.FormatUint(v.generation, 10))
		if v.app != nil {
			w.Header().Set("X-RdpGo-App-Revision", v.app.presentedToken)
		}
		v.imageMu.RLock()
		data, version := v.png, v.version
		v.imageMu.RUnlock()
		v.frameMu.Unlock()
		if len(data) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		etag := strconv.Quote(strconv.FormatUint(version, 10))
		w.Header().Set("ETag", etag)
		if r.Header.Get("If-None-Match") == etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		w.Write(data)
	case "/input":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192))
		decoder.DisallowUnknownFields()
		var events []input
		if err := decoder.Decode(&events); err != nil || len(events) == 0 || len(events) > 64 {
			http.Error(w, "invalid input batch", http.StatusBadRequest)
			return
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			http.Error(w, "trailing input", http.StatusBadRequest)
			return
		}
		v.inputMu.Lock()
		defer v.inputMu.Unlock()
		v.frameMu.Lock()
		v.expireResizeLocked(time.Now())
		if !v.active || v.reconnection.Phase != "connected" || v.resize.Pending || r.Header.Get("X-RdpGo-Generation") != strconv.FormatUint(v.generation, 10) {
			v.frameMu.Unlock()
			http.Error(w, "session changed; refresh state", http.StatusConflict)
			return
		}
		if v.app != nil {
			defer v.frameMu.Unlock()
			v.serveAppInputLocked(w, r, events)
			return
		}
		for _, e := range events {
			if err := v.validate(e); err != nil {
				v.frameMu.Unlock()
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		}
		v.frameMu.Unlock()
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		for _, e := range events {
			if err := v.send(ctx, e); err != nil {
				// Pacing/queued input can be canceled without a transport failure.
				// Preserve a demonstrably healthy session, but never replay a prefix.
				if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
					if state, ok := v.remote.(interface{ Info() rdp.SessionInfo }); ok && state.Info().Active {
						w.Header().Set("X-RdpGo-Input-Partial", "1")
						http.Error(w, "input canceled; a prefix may already have been entered", http.StatusConflict)
						return
					}
				}
				if errors.Is(err, rdp.ErrUnsupportedOperation) {
					http.Error(w, "Unicode input is not supported by this server", http.StatusUnprocessableEntity)
					return
				}
				if errors.Is(err, rdp.ErrDeactivated) {
					http.Error(w, "session reactivating", http.StatusConflict)
					return
				}
				if v.writeInterrupted("remote input failed: " + err.Error()) {
					http.Error(w, "connection interrupted; action was not replayed", http.StatusConflict)
					return
				}
				http.Error(w, "remote input failed", http.StatusBadGateway)
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case "/clipboard", "/clipboard/image":
		v.serveClipboard(w, r)
	case "/clipboard/upload", "/clipboard/upload/data":
		v.serveClipboardUpload(w, r)
	case "/clipboard/files", "/clipboard/files/archive":
		v.serveClipboardFiles(w, r)
	case "/capture":
		v.serveCapture(w, r)
	case "/audio":
		v.serveAudio(w, r)
	case "/remoteapp/notifications", "/remoteapp/notify":
		v.serveAppNotifications(w, r)
	case "/remoteapp":
		v.serveRemoteApp(w, r)
	case "/resize":
		v.serveResize(w, r)
	case "/disconnect":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		v.stopWithReason("Disconnect requested")
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

type input struct {
	Kind     string `json:"kind"`
	Code     int    `json:"code,omitempty"`
	Extended bool   `json:"extended,omitempty"`
	Down     bool   `json:"down,omitempty"`
	X        int    `json:"x,omitempty"`
	Y        int    `json:"y,omitempty"`
	Button   int    `json:"button,omitempty"`
	Units    int    `json:"units,omitempty"`
	Text     string `json:"text,omitempty"`
	AppMove  string `json:"app_move,omitempty"`
	AppFocus string `json:"app_focus,omitempty"`
}

func (v *viewer) validate(e input) error {
	if len(e.AppMove) > 20 || len(e.AppFocus) > 96 {
		return errors.New("invalid move operation")
	}
	switch e.Kind {
	case "text":
		return rdp.ValidateTextInput(e.Text)
	case "key":
		if e.Code < 1 || e.Code > 127 {
			return errors.New("invalid scancode")
		}
	case "move", "button":
		if e.X < 0 || e.Y < 0 || e.X >= v.width || e.Y >= v.height {
			return errors.New("pointer outside desktop")
		}
		if e.Kind == "button" && (e.Button < 1 || e.Button > 3) {
			return errors.New("invalid mouse button")
		}
	case "wheel":
		if e.Units == 0 || e.Units < -256 || e.Units > 255 {
			return errors.New("invalid wheel units")
		}
	case "release", "blur":
	default:
		return errors.New("unknown input type")
	}
	return nil
}

func (v *viewer) send(ctx context.Context, e input) error {
	switch e.Kind {
	case "text":
		if err := v.send(ctx, input{Kind: "release"}); err != nil {
			return err
		}
		return v.remote.SendText(ctx, e.Text)
	case "key":
		if err := v.remote.SendKey(ctx, uint8(e.Code), e.Down, e.Extended); err != nil {
			return err
		}
		key := uint16(e.Code)
		if e.Extended {
			key |= 0x100
		}
		if e.Down {
			v.keys[key] = true
		} else {
			delete(v.keys, key)
		}
	case "move":
		v.x, v.y = uint16(e.X), uint16(e.Y)
		return v.remote.MovePointer(ctx, v.x, v.y)
	case "button":
		v.x, v.y = uint16(e.X), uint16(e.Y)
		button := rdp.MouseButton(e.Button)
		if err := v.remote.SendMouseButton(ctx, button, e.Down, v.x, v.y); err != nil {
			return err
		}
		if e.Down {
			v.buttons[button] = true
		} else {
			delete(v.buttons, button)
		}
	case "wheel":
		return v.remote.Scroll(ctx, int16(e.Units))
	case "release", "blur":
		for key := range v.keys {
			if err := v.remote.SendKey(ctx, uint8(key&127), false, key&0x100 != 0); err != nil {
				return err
			}
			delete(v.keys, key)
		}
		for button := range v.buttons {
			if err := v.remote.SendMouseButton(ctx, button, false, v.x, v.y); err != nil {
				return err
			}
			delete(v.buttons, button)
		}
	default:
		return fmt.Errorf("unknown input")
	}
	return nil
}

// Caller holds connectionMu while selecting the current connection.
func (v *viewer) licensingStatus() *rdp.LicensingState {
	if r, ok := v.remote.(interface{ LicensingState() rdp.LicensingState }); ok {
		state := r.LicensingState()
		return &state
	}
	return nil
}

// Caller holds connectionMu while selecting the current connection.
func (v *viewer) networkStatus() *rdp.NetworkInfo {
	if r, ok := v.remote.(interface{ NetworkInfo() rdp.NetworkInfo }); ok {
		info := r.NetworkInfo()
		return &info
	}
	return nil
}
