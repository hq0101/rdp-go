# rdp-go

[中文文档](README.zh-CN.md)

A client-side RDP protocol library written in pure Go, for connecting to Windows RDP servers (Windows 10/11 and Windows Server) from Windows, macOS and Linux clients.

## Features

- **Connection**: TLS with optional certificate pinning, NLA/CredSSP (NTLMv2, Kerberos), RD Gateway, KDCProxy, server redirection, automatic reconnect, UDP sideband.
- **Graphics**: drawing orders, bitmap caches, surface commands; NSCodec, RemoteFX, Progressive, planar/RLE; pure-Go H.264 decoding; fast-path output and MPPC compression.
- **Input & clipboard**: scancode/Unicode/text input; cliprdr text, HTML, image and file transfer; Windows OLE drag-and-drop, delayed rendering and virtual files.
- **Devices & audio**: rdpdr drive, printer and smartcard protocol slices (backends supplied by your application); rdpsnd PCM/ADPCM playback and audin PCM capture.
- **RemoteApp & display**: RAIL window orders, monitor layout and dynamic resize, managed dynamic channels.
- **Bundled clients**: `rdpnative` (native Windows window with IME/TSF) and `rdpview` (browser client). The library decodes events; rendering is yours or the bundled clients'.

## Install

```sh
go get github.com/hq0101/rdp-go@v0.2.0
```

## Quick start

```go
package main

import (
	"context"
	"log"
	"os"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/gcc"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	s, err := rdp.DialSession(ctx, os.Getenv("RDPGO_ADDR"), rdp.Credentials{
		Username: os.Getenv("RDPGO_USER"),
		Domain:   os.Getenv("RDPGO_DOMAIN"),
		Password: os.Getenv("RDPGO_PASSWORD"),
	}, rdp.Options{
		CertificateSHA256: os.Getenv("RDPGO_CERT_SHA256"), // optional verified pin
	}, gcc.ClientSettings{Width: 1280, Height: 720})
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close() // sends MCS Disconnect Provider Ultimatum, then closes

	for {
		e, err := s.ReadEvent(ctx)
		if err != nil {
			log.Fatal(err)
		}
		switch e.Kind {
		case rdp.EventLogonInfo:
			log.Println("logon:", e.Logon.Logon)
		case rdp.EventData:
			// channel payload in e.Payload
		case rdp.EventSurfaceCommands, rdp.EventLargePointer:
			// graphics updates for your renderer
		}
	}
}
```

Lower-level entry points: `DialTLS`, `DialNLA`, then `OpenChannels` for manual MCS/PDU handling. `Session.Reconnect` recovers after network failures once the server confirms the original session ID.

## Commands and examples

| Command | Purpose |
| --- | --- |
| `cmd/rdpcheck` | connection/NLA/session diagnostics |
| `cmd/rdpshot` | desktop screenshot |
| `cmd/rdpview` | browser client |
| `cmd/rdpnative` | native Windows viewer |
| `cmd/rdpaudiocheck` / `cmd/rdpincheck` | audio output / input checks |
| `cmd/rdpudpcheck` | UDP sideband check |

```sh
RDPGO_PASSWORD='...' go run ./cmd/rdpview -addr server.example:3389 -user alice -password-env RDPGO_PASSWORD
```

`examples/` contains runnable samples (`session`, `tls`, `nla`, `reconnect`, `resize`, `monitors`). Credential-using samples read environment variables named in their headers; `tls` is transport-only and needs none.

## Security and limitations

- Credentials are never persisted; prefer certificate pinning or a private CA pool. Gateway redirection policy is enforced by your application before tunnel creation; local resources are shared only through backends you configure.
- Printer spooler/XPS and smartcard winscard/NDR backends are application responsibilities; the library implements the protocol slices.
- Native system integration is deepest on Windows; macOS/Linux native host integration is partial. Real-server evidence is mainly Windows 10; Windows 11/arm64 and some RDS/AD/Gateway deployments remain to be validated.

## Contributing

Issues and pull requests are welcome! Bug reports, protocol coverage improvements, performance work and documentation fixes all help make rdp-go better.

## License

Apache-2.0 — see [LICENSE](LICENSE).