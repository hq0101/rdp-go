// rdpudpcheck performs an opt-in sideband transport/TLS/DTLS diagnostic. It does not
// activate a desktop. -bind-tunnel also verifies the session's cookie/ID binding.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/autodetect"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/mcs"
	"github.com/hq0101/rdp-go/pdu"
	"github.com/hq0101/rdp-go/rdpemt"
	"github.com/hq0101/rdp-go/rdpudp"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	address := flag.String("addr", "", "authorized RDP server host:port")
	user := flag.String("user", "", "username; password comes from RDPGO_PASSWORD")
	domain := flag.String("domain", "", "logon domain")
	pin := flag.String("cert-sha256", "", "approved server leaf fingerprint; empty uses system trust")
	bind := flag.Bool("bind-tunnel", false, "also create the authenticated tunnel, then close without desktop activation")
	lossy := flag.Bool("lossy", false, "offer UDP-L and bind a DTLS tunnel (requires -bind-tunnel)")
	legacyDTLS := flag.Bool("dtls-legacy-master-secret", false, "explicitly permit DTLS without EMS (requires -lossy)")
	probeFor := flag.Duration("probe-for", 0, "read and answer tunnel network probes for up to 10s (requires -bind-tunnel; no desktop activation)")
	flag.Parse()
	password := os.Getenv("RDPGO_PASSWORD")
	_ = os.Unsetenv("RDPGO_PASSWORD")
	if *address == "" || *user == "" || password == "" {
		return errors.New("addr, user and RDPGO_PASSWORD are required")
	}
	if *probeFor < 0 || *probeFor > 10*time.Second || (*probeFor != 0 && !*bind) {
		return errors.New("probe-for must be between 0 and 10s and requires bind-tunnel")
	}
	if *lossy && (!*bind || *probeFor != 0) || *legacyDTLS && !*lossy {
		return errors.New("lossy requires bind-tunnel and does not yet support probe-for; dtls-legacy-master-secret requires lossy")
	}
	transportFlags := uint32(1)
	requiredMode := uint32(1)
	if *lossy {
		transportFlags = 5 // advertise both carriers, like a full client
		requiredMode = 4
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	c, err := rdp.DialChannels(ctx, *address, rdp.Credentials{Username: *user, Domain: *domain, Password: password}, rdp.Options{CertificateSHA256: *pin}, gcc.ClientSettings{MultitransportFlags: transportFlags, NetworkAutoDetect: true, Channels: []gcc.Channel{{Name: "drdynvc"}}})
	if err != nil {
		return err
	}
	defer c.Transport.Close()
	identity, err := rdpemt.IdentityFromTLS(c.Transport.TLSState(), c.Transport.CertificatePinned())
	if err != nil {
		return err
	}
	fmt.Printf("main TLS/NLA verified; hasMessageChannel=%t messageChannel=%d transportFlags=%#x\n", c.Server.HasMessageChannel, c.Server.MessageChannel, c.Server.MultitransportFlags)
	if c.Server.MessageChannel == 0 || c.Server.MultitransportFlags&requiredMode == 0 {
		return errors.New("server did not negotiate the requested multitransport mode")
	}
	info, err := pdu.ClientInfo(*user, *domain, password, c.Transport.LocalAddr().(*net.TCPAddr).IP.String(), 0)
	password = ""
	if err != nil {
		return err
	}
	defer clear(info)
	request, err := mcs.SendDataRequest(c.UserID, c.Server.IOChannel, info)
	if err != nil {
		return err
	}
	err = c.Transport.WriteMCS(ctx, request)
	clear(request)
	clear(info)
	if err != nil {
		return err
	}
	licensed := false
	var companion *rdpemt.Tunnel
	defer func() {
		if companion != nil {
			companion.Close()
		}
	}()
	var detector autodetect.Client
	for i := 0; i < 128; i++ {
		f, err := c.Transport.ReadFrame(ctx)
		if err != nil {
			return err
		}
		if f.Kind != rdp.FrameMCS {
			continue
		}
		d, err := mcs.ParseDataIndication(f.Data)
		if err != nil {
			return err
		}
		if d.Initiator != 1002 {
			return errors.New("unexpected MCS initiator")
		}
		if d.Channel == c.Server.IOChannel && len(d.Payload) >= 4 && binary.LittleEndian.Uint16(d.Payload) == 0x80 {
			if err = pdu.ParseLicense(d.Payload); err != nil {
				return err
			}
			licensed = true
			fmt.Println("license accepted")
			continue
		}
		if d.Channel != c.Server.MessageChannel {
			continue
		}
		b := d.Payload
		if len(b) >= 4 && binary.LittleEndian.Uint16(b)&^uint16(0x8000) == 0x1000 {
			reply, err := detector.Handle(b[4:], time.Now(), false)
			if err != nil {
				return err
			}
			if reply != nil {
				msg, err := mcs.SendDataRequest(c.UserID, c.Server.MessageChannel, append([]byte{0, 0x20, 0, 0}, reply...))
				if err != nil {
					return err
				}
				if err = c.Transport.WriteMCS(ctx, msg); err != nil {
					return err
				}
			}
			continue
		}
		bootstrap, err := rdpemt.ParseInitiateRequest(b)
		if err != nil {
			return err
		}
		defer clear(bootstrap.Cookie[:])
		if !licensed {
			return errors.New("bootstrap arrived before license acceptance")
		}
		id, protocol := bootstrap.ID, bootstrap.Protocol
		fmt.Printf("bootstrap request id=%d protocol=%d\n", id, protocol)
		bound := false
		defer func() {
			// No Soft-Sync capability was offered. Abort only an unfinished bind.
			if bound {
				return
			}
			x, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			abort, _ := rdpemt.InitiateResponse(id, false, false)
			msg, e := mcs.SendDataRequest(c.UserID, c.Server.MessageChannel, abort)
			if e == nil {
				_ = c.Transport.WriteMCS(x, msg)
			}
		}()
		if *lossy && protocol == rdpemt.ReliableUDP {
			if companion != nil {
				return errors.New("duplicate reliable bootstrap")
			}
			clear(b[12:])
			companion, err = bindCompanionReliable(ctx, c.Transport.RemoteAddr().String(), identity, bootstrap)
			clear(bootstrap.Cookie[:])
			if err != nil {
				return err
			}
			bound = true
			fmt.Println("companion reliable tunnel bound; waiting for UDP-L bootstrap")
			continue
		}
		if *lossy && protocol != rdpemt.LossyUDP || !*lossy && protocol != rdpemt.ReliableUDP {
			return errors.New("server requested unsupported mode for this diagnostic")
		}
		clear(b[12:])
		if *lossy {
			err = checkLossyTunnel(ctx, c.Transport.RemoteAddr().String(), identity, bootstrap, *legacyDTLS)
			clear(bootstrap.Cookie[:])
			bound = err == nil
			return err
		}
		hash := rdpudp.HashCookie(bootstrap.Cookie)
		if !*bind {
			clear(bootstrap.Cookie[:])
		}
		defer clear(hash[:])
		dialCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		udp, err := rdpudp.DialContext(dialCtx, "udp", c.Transport.RemoteAddr().String(), rdpudp.DialConfig{Initialization: rdpudp.InitConfig{MaxVersion: rdpudp.Version3, CookieHash: &hash}})
		stop()
		if err != nil {
			return err
		}
		defer udp.Close()
		fmt.Printf("UDP negotiated version=%#x sendMTU=%d receiveMTU=%d\n", udp.Parameters().Version, udp.Parameters().SendMTU, udp.Parameters().ReceiveMTU)
		secure := tls.Client(udp, identity.TLSConfig())
		tlsCtx, stopTLS := context.WithTimeout(ctx, 10*time.Second)
		defer stopTLS()
		err = secure.HandshakeContext(tlsCtx)
		s := udp.Stats()
		fmt.Printf("transport sent=%d received=%d retransmits=%d rejected=%d\n", s.Endpoint.SourcesSent, s.Endpoint.SourcesReceived, s.Endpoint.Retransmitted, s.RejectedDatagrams)
		if udp.Parameters().Version == rdpudp.Version3 {
			fmt.Printf("UDP2 datagrams sent=%d received=%d dummy=%d\n", s.UDP2.Sent, s.UDP2.Received, s.UDP2.Dummy)
		}
		if err != nil {
			return fmt.Errorf("sideband TLS: %w", err)
		}
		fmt.Printf("sideband %s complete; identity matches main connection\n", tls.VersionName(secure.ConnectionState().Version))
		if *bind {
			tunnel, err := rdpemt.BindReliable(ctx, secure, identity, bootstrap, rdpemt.TunnelOptions{HandleNetworkProbes: *probeFor > 0})
			clear(bootstrap.Cookie[:])
			if err != nil {
				return fmt.Errorf("tunnel binding: %w", err)
			}
			defer tunnel.Close()
			bound = true
			fmt.Println("Tunnel Create accepted; request ID/cookie bound to main session; no desktop activated")
			if *probeFor > 0 {
				probeCtx, endProbe := context.WithTimeout(ctx, *probeFor)
				defer endProbe()
				var applicationMessages, applicationBytes uint64
				for {
					m, readErr := tunnel.ReadMessage(probeCtx)
					if readErr != nil {
						n := tunnel.NetworkInfo()
						fmt.Printf("tunnel probes: messages=%d payloadBytes=%d requests=%d measurements=%d responsesSent=%d results=%d measuring=%t lastBytes=%d lastMilliseconds=%d applicationMessages=%d applicationBytes=%d\n", n.Messages, n.PayloadBytes, n.Stats.Requests, n.Stats.Measurements, n.ResponsesSent, n.Stats.ResultUpdates, n.Stats.Measuring, n.Stats.LastByteCount, n.Stats.LastTimeDelta, applicationMessages, applicationBytes)
						if errors.Is(readErr, context.DeadlineExceeded) && ctx.Err() == nil {
							fmt.Println("bounded tunnel observation completed; test connection closed")
							break
						}
						return readErr
					}
					applicationMessages++
					applicationBytes += uint64(len(m.Data))
					clear(m.Data)
				}
			}
		} else {
			fmt.Println("tunnel not created")
		}
		return nil
	}
	return errors.New("bootstrap request not received within packet limit")
}

func bindCompanionReliable(ctx context.Context, address string, identity rdpemt.ServerIdentity, bootstrap rdpemt.InitiateRequest) (*rdpemt.Tunnel, error) {
	defer clear(bootstrap.Cookie[:])
	hash := rdpudp.HashCookie(bootstrap.Cookie)
	defer clear(hash[:])
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	udp, err := rdpudp.DialContext(dialCtx, "udp", address, rdpudp.DialConfig{Initialization: rdpudp.InitConfig{MaxVersion: rdpudp.Version3, CookieHash: &hash}})
	cancel()
	if err != nil {
		return nil, err
	}
	return rdpemt.BindReliable(ctx, tls.Client(udp, identity.TLSConfig()), identity, bootstrap, rdpemt.TunnelOptions{})
}

func checkLossyTunnel(ctx context.Context, address string, identity rdpemt.ServerIdentity, bootstrap rdpemt.InitiateRequest, legacy bool) error {
	defer clear(bootstrap.Cookie[:])
	dialCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	udp, err := rdpudp.DialDatagramContext(dialCtx, "udp", address, rdpudp.DialConfig{Initialization: rdpudp.InitConfig{MaxVersion: rdpudp.Version2}})
	cancel()
	if err != nil {
		return err
	}
	defer udp.Close()
	fmt.Printf("UDP-L negotiated version=%#x sendMTU=%d receiveMTU=%d\n", udp.Parameters().Version, udp.Parameters().SendMTU, udp.Parameters().ReceiveMTU)
	tunnel, err := rdpemt.BindLossy(ctx, udp, identity, bootstrap, rdpemt.LossyTunnelOptions{AllowLegacyMasterSecret: legacy})
	s := udp.Stats()
	fmt.Printf("lossy transport sent=%d received=%d skipped=%d rejected=%d\n", s.Endpoint.SourcesSent, s.Endpoint.SourcesReceived, s.Endpoint.ReceiveSkipped, s.RejectedDatagrams)
	if err != nil {
		return fmt.Errorf("DTLS/tunnel binding: %w", err)
	}
	defer tunnel.Close()
	fmt.Printf("DTLS 1.2 identity matches main connection; Tunnel Create accepted; payloadLimit=%d; no desktop activated\n", tunnel.PayloadLimit())
	return nil
}
