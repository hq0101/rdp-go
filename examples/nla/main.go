// Example: set RDPGO_PASSWORD locally, then run with -addr and -user.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/gcc"
	"log"
	"os"
	"time"
)

func main() {
	address := flag.String("addr", "", "server:3389")
	user := flag.String("user", "", "account name")
	domain := flag.String("domain", "", "domain or computer name")
	ca := flag.String("ca", "", "optional trusted CA PEM")
	pin := flag.String("cert-sha256", "", "optional trusted leaf SHA-256 fingerprint")
	serverName := flag.String("server-name", "", "certificate DNS name")
	spnego := flag.Bool("spnego", false, "use SPNEGO with NTLMv2 and mechanism-list MICs; does not enable Kerberos")
	krbRealm := flag.String("kerberos-realm", "", "explicit Kerberos realm; requires -kerberos-kdc; no NTLM fallback")
	krbKDC := flag.String("kerberos-kdc", "", "Kerberos KDC host:port, normally port 88")
	krbSPN := flag.String("kerberos-spn", "", "optional TERMSRV/host override; requires realm and KDC")
	flag.Parse()
	var kerberosOptions *rdp.KerberosOptions
	if *krbRealm != "" || *krbKDC != "" || *krbSPN != "" {
		if *krbRealm == "" || *krbKDC == "" {
			log.Fatal("Kerberos requires -kerberos-realm and -kerberos-kdc")
		}
		kerberosOptions = &rdp.KerberosOptions{Realm: *krbRealm, KDC: *krbKDC, ServicePrincipal: *krbSPN}
	}

	if *ca != "" && *pin != "" {
		log.Fatal("choose either -ca or -cert-sha256")
	}
	password, ok := os.LookupEnv("RDPGO_PASSWORD")
	if *address == "" || *user == "" || !ok {
		log.Fatal("provide -addr, -user and local RDPGO_PASSWORD environment variable")
	}
	config := &tls.Config{ServerName: *serverName}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			log.Fatal(err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			log.Fatal("CA PEM contains no certificates")
		}
		config.RootCAs = pool
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	connection, err := rdp.DialChannels(ctx, *address, rdp.Credentials{Username: *user, Domain: *domain, Password: password}, rdp.Options{Kerberos: kerberosOptions, SPNEGO: *spnego, TLSConfig: config, CertificateSHA256: *pin, HandshakeTimeout: 30 * time.Second}, gcc.ClientSettings{Width: 1280, Height: 720})
	if err != nil {
		log.Fatal(err)
	}
	defer connection.Transport.Close()
	fmt.Printf("NLA completed; MCS user=%d I/O=%d. Desktop is not active.\n", connection.UserID, connection.Server.IOChannel)
}
