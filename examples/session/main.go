// Set RDPGO_ADDR, RDPGO_USER, RDPGO_PASSWORD locally. Optional:
// RDPGO_DOMAIN, RDPGO_CERT_SHA256 (independently verified certificate pin).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/gcc"
)

func run(readEvent, waitLogon bool) error {
	for _, key := range []string{"RDPGO_ADDR", "RDPGO_USER", "RDPGO_PASSWORD"} {
		if _, ok := os.LookupEnv(key); !ok || (key != "RDPGO_PASSWORD" && os.Getenv(key) == "") {
			return fmt.Errorf("missing environment variable %s", key)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := rdp.DialSession(ctx, os.Getenv("RDPGO_ADDR"), rdp.Credentials{
		Username: os.Getenv("RDPGO_USER"), Domain: os.Getenv("RDPGO_DOMAIN"), Password: os.Getenv("RDPGO_PASSWORD"),
	}, rdp.Options{CertificateSHA256: os.Getenv("RDPGO_CERT_SHA256")}, gcc.ClientSettings{Width: 1280, Height: 720})
	if err != nil {
		return err
	}
	defer s.Close()
	fmt.Printf("Protocol session activated: %+v. Desktop is not rendered.\n", s.Info())
	if waitLogon {
		for {
			e, err := s.ReadEvent(ctx)
			if err != nil {
				return err
			}
			if e.Kind == rdp.EventLogonInfo && e.Logon.Logon {
				fmt.Printf("Server logon notification: type=%d session_id_known=%t session_id=%d identity_known=%t\n", e.Logon.Type, e.Logon.SessionIDKnown, e.Logon.SessionID, e.Logon.IdentityKnown)
				return nil
			}
		}
	}
	if readEvent {
		e, err := s.ReadEvent(ctx)
		if err != nil {
			return err
		}
		// Log metadata only; channel/application payloads can still be private.
		fmt.Printf("Event: kind=%d channel=%d type=%d bytes=%d\n", e.Kind, e.Channel, e.DataType, len(e.Payload))
	}
	return nil
}
func main() {
	readEvent := flag.Bool("read-event", false, "wait for one raw event within 30 seconds; may time out")
	waitLogon := flag.Bool("wait-logon", false, "wait for an explicit server logon notification within 30 seconds; does not render the desktop")
	flag.Parse()
	if err := run(*readEvent, *waitLogon); err != nil {
		log.Fatal(err)
	}
}
