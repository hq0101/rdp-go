// Package rdp implements a Windows RDP client's transport, NLA authentication
// and session activation using only the Go standard library.
//
// Probe reports a server's unauthenticated security selection and disconnects.
// DialTLS establishes a TLS-only transport. DialNLA performs CredSSP 5/6 with
// NTLMv2 and delegates credentials after checking the server's TLS key binding.
// DialChannels additionally exchanges GCC settings and joins MCS channels.
// DialSession additionally sends Client Info, checks valid-client licensing,
// exchanges capabilities and waits for connection finalization. ReadEvent exposes
// normalized slow/fast-path and static-channel payloads, without a background
// reader. ReadEvent also reports deactivation and completes capability re-exchange
// on the existing connection. Package graphics decodes baseline and 32-bit
// Planar bitmaps into an opaque RGBA framebuffer; DecodePlanar separately returns
// straight-alpha NRGBA. It decodes/caches color pointers with AND/XOR composition.
// Options.NewPointer enables arbitrary-depth and alpha pointers; LargePointer
// enables negotiated 96/384-pixel shapes. Configure PointerDecoder.AllowNewPointer
// and LargePointerFlags from SessionInfo after each activation. Feed indexed
// pointers' palettes to ApplyPalette. EventLargePointer contains a reassembled
// wide-length pointer body for ApplyLarge, not a lifecycle notification.
// PointerShape.Alpha is optional; nonempty Alpha uses straight RGB composition.
// Decoder snapshots own their data. Same-connection reactivation retains caches.
// Options.DrawingOrders opts into six basic GDI orders and volatile Revision 1
// bitmap caching at 24/32 bpp. Framebuffer.Apply handles both output paths;
// Framebuffer.Resize resets the desktop/history while preserving cached bitmaps
// on reactivation. New connections require a new framebuffer.
// Options.BitmapCacheV2 enables compact volatile caches when the server supports
// them. Options.SurfaceCommands enables raw 32-bit Set/Stream Surface Bits and
// marked-frame presentation through EventSurfaceCommands. ApplySurfaceCommands
// stages marked frames until END; AcknowledgeFrame reports completed frame IDs
// when SessionInfo.FrameAcknowledge is true. Options.NSCodec enables NSCodec for
// Surface bitmaps; Options.BitmapCacheV3 enables codec-aware volatile caches.
// Set Framebuffer.AllowNSCodec and AllowBitmapCacheV3 from the effective session
// info after every activation. DecodeNSCodec separately returns straight-alpha
// NRGBA and supports raw/RLE planes, color loss, alpha and chroma subsampling.
// Options.BrushCache adds 8x8 cached mono/color patterns. Options.OffscreenCache
// adds bounded writable surfaces, selected by alternate secondary orders and
// copied with MemBlt/Mem3Blt. Set Framebuffer.AllowBrushCache, AllowOffscreen and
// OffscreenDepth from the effective session capabilities/depth. Cache-only drawing
// does not publish desktop damage; failed batches do not mutate writable caches.
// Options.ExtendedOrders adds MultiDst/Pat/ScrBlt, MultiOpaqueRect, LineTo and
// Polyline, including delta lists, ROP2 and single-pixel cosmetic line rendering.
// Set Framebuffer.AllowExtendedOrders after each activation. Returned dirty
// regions are conservative bounds, not proof that every pixel was written.
// Options.GlyphCache enables Rev1 glyph caches, text fragments and GlyphIndex,
// FastIndex and FastGlyph. GlyphCacheV2 requests compact Rev2 cache encoding.
// Match Framebuffer.AllowGlyphCache/AllowGlyphCacheV2 after each activation;
// same-connection Resize preserves glyphs/fragments and resets text history.
// Text uses server-provided monochrome glyph pixels; no local font dependency.
// Options.ShapeOrders adds PolygonSC/CB and EllipseSC/CB, ROP2, alternate/winding
// fill and solid/pattern brushes. Match Framebuffer.AllowShapeOrders after each
// activation. Spans and curve traversal share the drawing batch's work limits;
// clipped bounds can contain untouched pixels. Production rendering is pure Go.
// Options.BulkCompression enables MPPC 8K/64K and RDP 6/6.1 for graphics and static
// channels. ReadEvent decompresses before reassembly using one receive history,
// preserved on reactivation. WriteChannel uses MPPC 8K if the server permits it;
// encoding without a size reduction falls back to raw data with a history flush.
// CompressionStats reports actual compressed receive/send counts and sizes.
// BulkCompressionLevel limits the offered maximum (zero offers RDP6.1).
// CompressionStats.ByType distinguishes actual algorithm use from negotiation.
// Session methods send scancode, Unicode, mouse and display-control events.
// WriteChannel fragments bounded static-channel messages; package vchan handles
// reassembly. Package cliprdr provides an opt-in text clipboard state machine,
// without accessing the operating system clipboard or starting a reader.
// Package dynvc implements uncompressed version 1 dynamic-channel multiplexing;
// package disp validates display capabilities and encodes single-monitor resize
// requests. Applications keep reading until EventActivated confirms the actual
// desktop dimensions; see examples/resize and cmd/rdpview.
// Options.GraphicsPipeline offers Version 8 RDPGFX over an explicitly
// configured drdynvc static channel at 32 bpp. Packages zgfx and rdpgfx provide:
// bounded RDP8 decompression, message parsing and Raw/Planar/ClearCodec/Alpha/RemoteFX/Progressive
// surface/cache/frame handling. ClearCodec caches and sequencing participate in
// message rollback and survive graphics resizing. Feed registered Graphics DVC
// events to rdpgfx.Client and send its replies through dynvc.Client.Send and
// Session.WriteChannel. Large GFX messages require dynvc.NewWithLimits. Publish
// snapshots only for completed frames; see cmd/rdpview and cmd/rdpshot. Windows 10
// RemoteFX/Raw and Progressive/ClearCodec with 1080p resize interoperability have
// been exercised. Configure rdpgfx.Client.Profile before opening the channel;
// its zero value selects ThinClient, while ProfileProgressive offers SMALL_CACHE
// with per-surface coefficient references, frame coverage, context lifecycle and
// aggregate resource limits. graphics.ProgressiveDecoder also exposes the codec
// independently. Real SIMPLE and original-layout Progressive remain unverified.
// ProfileAVC420 explicitly offers Version 8.1 AVC420 with Version 8 Progressive
// fallback. Per-surface H.264 histories, region masks, full-range BT.709 and
// aggregate reference limits have local/independent-peer coverage; Windows AVC
// interoperability remains unverified. AVCDecoder separately implements
// AVC420/444/444v2 with one shared H.264 history, region-owned main-view samples,
// both auxiliary layouts, explicit resource limits and transactional updates.
// ProfileAVC444 connects that decoder to Version 10.7/10.6/10.5/10.4/10.3/10.2/10.0
// negotiation and AVC420/Progressive fallback, with aggregate main-view limits.
// Newer negotiated versions support bilinear scaled surface-to-output mapping.
// These paths have local and independent TLS peer coverage, not Windows AVC
// interoperability evidence. RemoteApp window mapping has local coverage.
// Package h264 adds bounded Annex B/SPS/PPS parsing and experimental progressive
// YUV420 I/P/B decoding (CAVLC/CABAC), with intra/inter
// prediction, spatial/temporal Direct, inverse transforms, reference lists/MMCO,
// explicit/implicit weighting and deblocking. Picture order types 0/1/2 are
// implemented; OutputDecoder provides bounded display order for standalone use.
// RDP instead applies each decoded bitmap to its own GFX command in wire order.
// No API claims general H.264 conformance or complete mstsc interoperability.
// Cookie-based reconnection and explicit SPNEGO/Kerberos are implemented.
// Kerberos uses an explicit realm/KDC and fresh password-based ticket acquisition
// on Windows, macOS and Linux; real AD/Windows Kerberos validation is pending.
// Enhanced-security server redirection is parsed during licensing, activation
// and active/reactivating sessions. A terminal RedirectionError closes the old
// connection and owns a Request that callers must Clear. Informational notices
// use EventRedirectionInfo and continue the session. Explicit RoutingToken,
// ExpectedTSVURL and GCC cluster/session settings support caller-managed routing;
// DialSessionWithRedirection and Session.FollowRedirection explicitly apply a
// caller policy for cross-server dialing, independent authentication/trust,
// cumulative hop/cycle bounds and cancellation. Return values are new Sessions;
// consumers must rebuild their graphics/channel/device state. PasswordMode
// explicitly selects fresh credentials, a strict UTF-16 server password, or an
// opaque legacy cookie in Client Info with separately supplied NLA credentials.
// RedirectionPasswordRDSTLS selects version-one RDSTLS for PK-encrypted server
// credentials, with explicit target trust plus broker certificate binding. Its
// ARC recovery authenticates with the retained server cookie instead of NLA.
// Version-six cluster advertising is explicit. Real RDS validation is pending.
// Package rail provides the separate RemoteApp static-channel state machine,
// explicit remote launch/result correlation and baseline window controls. The
// root Options.RemoteApp requests Client Info/RAIL/Window List negotiation;
// an explicit rail channel and DrawingOrders are required. Applications handle
// channel initialization and decide when to call Execute. rail.WindowState parses and
// tracks window/notification/desktop drawing orders with bounded icon storage;
// Framebuffer.WindowState explicitly commits them with mixed drawing batches.
// rail.Icon.Decode produces immutable DIB pixels with transparent-image export
// and opaque-background AND/XOR or alpha composition. Its Windows GDI layout
// has native comparison coverage; real RAIL icon interoperability is pending.
// SessionInfo.RemoteApp reports each activation's effective profile. Reconfigure
// the existing WindowState on reactivation; use fresh consumers on a new connection.
// rdpgfx.WindowMapping explicitly accepts normal/scaled window mappings and
// publishes completed window surfaces with alpha. WindowSnapshot exposes owned
// source pixels and mapping geometry; Image applies the documented scale/crop.
// RemoteAppOptions.Enhanced requests GFX delivery with an explicit DVC consumer;
// SessionInfo.RemoteAppEnhancedRequested records the request, while rail.Status
// reports the server's actual mode. Package remoteapp.Scene joins completed GFX
// frames to observed RAIL window lifetimes, gates presentation on Enhanced, and
// rejects stale associations after ID reuse. It creates no local windows.
// remoteapp.View extracts shaped/visible base window pixels or Enhanced alpha
// frames, checks current geometry before desktop-origin pointer conversion and
// includes declared resize margins in move/snap bounds. WindowState.Window
// returns one owned window for target validation. No GUI/input loop is created.
// Applications must not advertise RemoteApp based solely on rail support.
// Actual RDS license issuance remains unverified; RemoteApp is incomplete.
// Activation does not prove that a
// user's shell has logged on or that bitmap output will arrive. Local mock peers
// cover failure cases; opt-in Windows interoperability tests cover live hosts.
package rdp
