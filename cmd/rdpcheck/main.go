// rdpcheck diagnoses RDP negotiation, TLS, NLA, channels and session activation.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/gcc"
	"github.com/hq0101/rdp-go/internal/gatewayconfig"
	"github.com/hq0101/rdp-go/internal/kdcproxyconfig"
	"github.com/hq0101/rdp-go/internal/redirectconfig"
	"github.com/hq0101/rdp-go/x224"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, out, errOut io.Writer) (runErr error) {
	fs := flag.NewFlagSet("rdpcheck", flag.ContinueOnError)
	fs.SetOutput(errOut)
	addr := fs.String("addr", "", "RDP endpoint, e.g. server.example:3389 or [::1]:3389")
	mode := fs.String("mode", "probe", "probe (negotiation only), tls, nla, channels, or session (activates a Windows session)")
	timeout := fs.Duration("timeout", 10*time.Second, "total connection/handshake timeout")
	ca := fs.String("ca", "", "PEM trust bundle for tls/nla/channels/session mode")
	pin := fs.String("cert-sha256", "", "trusted leaf certificate SHA-256 fingerprint (64 hex characters); replaces CA/name checks")
	name := fs.String("server-name", "", "certificate DNS name; defaults to endpoint host")
	user := fs.String("user", "", "username for nla/channels/session mode")
	domain := fs.String("domain", "", "domain or server name, separate from username")
	passwordEnv := fs.String("password-env", "", "name of environment variable containing the password; never the password itself")
	spnego := fs.Bool("spnego", false, "use SPNEGO with NTLMv2 and mechanism-list MICs; does not enable Kerberos")
	krbRealm := fs.String("kerberos-realm", "", "explicit Kerberos realm; requires a direct KDC or HTTPS proxy; no NTLM fallback")
	krbKDC := fs.String("kerberos-kdc", "", "Kerberos KDC host:port, normally port 88")
	krbSPN := fs.String("kerberos-spn", "", "optional TERMSRV/host override; requires realm and KDC/proxy")
	var proxyFlags kdcproxyconfig.Flags
	proxyFlags.Register(fs, "kerberos-proxy-")
	var gatewayFlags gatewayconfig.Flags
	gatewayFlags.Register(fs)
	var licensing licenseFlags
	licensing.register(fs)
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	proxyOptions, proxyErr := proxyFlags.Options(fs)
	if proxyErr != nil {
		return proxyErr
	}
	if *addr == "" || fs.NArg() != 0 {
		return fmt.Errorf("provide -addr host:port; use -h for help")
	}
	if *timeout <= 0 {
		return fmt.Errorf("-timeout must be positive")
	}
	if *ca != "" && *pin != "" {
		return fmt.Errorf("choose either -ca or -cert-sha256")
	}
	if err := licensing.validate(fs, *mode, *user); err != nil {
		return err
	}
	if *mode != "nla" && *mode != "channels" && *mode != "session" && (*user != "" || *domain != "" || *passwordEnv != "" || *spnego || *krbRealm != "" || *krbKDC != "" || *krbSPN != "" || proxyOptions != nil) {
		return fmt.Errorf("credential options require -mode nla, channels or session")
	}
	var kerberosOptions *rdp.KerberosOptions
	if *krbRealm != "" || *krbKDC != "" || *krbSPN != "" || proxyOptions != nil {
		if *krbRealm == "" || ((*krbKDC != "") == (proxyOptions != nil)) {
			return fmt.Errorf("Kerberos requires -kerberos-realm and -kerberos-kdc, or -kerberos-proxy-url instead of -kerberos-kdc (exactly one transport)")
		}
		kerberosOptions = &rdp.KerberosOptions{Realm: *krbRealm, KDC: *krbKDC, ServicePrincipal: *krbSPN, Proxy: proxyOptions}
	}
	switch *mode {
	case "probe", "tls", "nla", "channels", "session":
	default:
		return fmt.Errorf("unsupported -mode %q", *mode)
	}
	if *mode == "probe" && (*ca != "" || *name != "" || *pin != "") {
		return fmt.Errorf("certificate options require -mode tls, nla, channels or session")
	}
	var credentials rdp.Credentials
	if *mode == "nla" || *mode == "channels" || *mode == "session" {
		if *user == "" || *passwordEnv == "" {
			return fmt.Errorf("nla/channels/session requires -user and -password-env VARIABLE_NAME")
		}
		password, ok := os.LookupEnv(*passwordEnv)
		if !ok {
			return fmt.Errorf("password environment variable is not set")
		}
		credentials = rdp.Credentials{Username: *user, Domain: *domain, Password: password}
		if err := credentials.Validate(); err != nil {
			return err
		}
	}
	config := &tls.Config{ServerName: *name}
	if *ca != "" {
		pem, err := os.ReadFile(*ca)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return fmt.Errorf("no certificates found in -ca PEM file")
		}
		config.RootCAs = pool
	}

	gatewayConfig, err := gatewayFlags.Config(fs)
	if err != nil {
		return err
	}
	reporter := gatewayconfig.NewReporter(errOut)
	connections, err := redirectconfig.LoadConnections(ctx, "", *addr, false, licensing.config, *passwordEnv, redirectconfig.GatewaySetup{Config: gatewayConfig, Reporter: reporter, ApplyPolicy: gatewayconfig.NoLocalResources})
	if err != nil {
		return err
	}
	defer connections.Close()
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	switch *mode {
	case "probe":
		if *ca != "" || *name != "" || *pin != "" {
			return fmt.Errorf("certificate options require -mode tls, nla, channels or session")
		}
		c, err := rdp.Probe(ctx, *addr, rdp.ProbeOptions{Timeout: *timeout, Gateway: connections.Gateway})
		if err != nil {
			return err
		}
		return enc.Encode(struct {
			GatewayRoute  bool   `json:"gateway_route"`
			Stage         string `json:"stage"`
			Protocol      string `json:"selected_protocol"`
			Flags         byte   `json:"flags"`
			Authenticated bool   `json:"authenticated"`
			Notice        string `json:"notice"`
		}{connections.Gateway != nil, "negotiation", c.SelectedProtocol.String(), c.Flags, false, "Unauthenticated negotiation result only; no TLS verification, login, or desktop session."})
	case "tls", "nla", "channels", "session":
		opts := rdp.Options{Gateway: connections.Gateway, Kerberos: kerberosOptions, SPNEGO: *spnego, TLSConfig: config, CertificateSHA256: *pin, HandshakeTimeout: *timeout}
		if *mode == "session" {
			opts.Licensing = connections.Licensing
			session, err := rdp.DialSession(ctx, *addr, credentials, opts, gcc.ClientSettings{})
			if err != nil {
				return err
			}
			defer session.Close()
			stopServices := gatewayconfig.WatchServices(ctx, session, reporter)
			defer func() {
				if e := stopServices(); runErr == nil {
					runErr = e
				}
			}()
			info := session.Info()
			verification := "certificate_authority"
			if session.CertificatePinned() {
				verification = "sha256_pin"
			}
			return enc.Encode(map[string]any{
				"gateway": gatewayconfig.Info(session), "resources": session.Resources(), "stage": "session", "selected_protocol": session.Negotiation().SelectedProtocol.String(),
				"tls_version": tls.VersionName(session.TLSState().Version), "server_certificate_verified": true,
				"certificate_verification": verification, "credentials_delegated": session.NLAState().CredentialsDelegated,
				"early_authorization_confirmed": session.NLAState().EarlyAuthorizationConfirmed,
				"spnego":                        session.NLAState().SPNEGO,
				"kerberos":                      session.NLAState().Kerberos,
				"session_active":                info.Active, "license_accepted": info.LicenseAccepted,
				"licensing": session.LicensingState(),
				"share_id":  info.ShareID, "user_channel": info.UserChannel, "io_channel": info.IOChannel,
				"width": info.Width, "height": info.Height, "bits_per_pixel": info.BitsPerPixel,
				"desktop_rendered": false, "notice": "Protocol session activated. This diagnostic closes after activation; use rdpview for desktop interaction or rdpshot for screenshots.",
			})
		}
		var tr *rdp.Transport
		var channels *rdp.ChannelConnection
		var err error
		switch *mode {
		case "tls":
			tr, err = rdp.DialTLS(ctx, *addr, opts)
		case "nla":
			tr, err = rdp.DialNLA(ctx, *addr, credentials, opts)
		case "channels":
			channels, err = rdp.DialChannels(ctx, *addr, credentials, opts, gcc.ClientSettings{})
			if err == nil {
				tr = channels.Transport
			}
		}
		if err != nil {
			return err
		}
		defer tr.Close()
		stopServices := gatewayconfig.WatchServices(ctx, tr, reporter)
		defer func() {
			if e := stopServices(); runErr == nil {
				runErr = e
			}
		}()
		s := tr.TLSState()
		verified := len(s.VerifiedChains) > 0 || tr.CertificatePinned()
		verification := "certificate_authority"
		if tr.CertificatePinned() {
			verification = "sha256_pin"
		}
		if *mode != "tls" {
			result := map[string]any{
				"gateway": gatewayconfig.Info(tr), "stage": *mode, "selected_protocol": tr.Negotiation().SelectedProtocol.String(),
				"server_certificate_verified": verified, "certificate_verification": verification, "tls_version": tls.VersionName(s.Version),
				"credentials_delegated":         tr.NLAState().CredentialsDelegated,
				"early_authorization_confirmed": tr.NLAState().EarlyAuthorizationConfirmed,
				"spnego":                        tr.NLAState().SPNEGO,
				"kerberos":                      tr.NLAState().Kerberos,
				"desktop_active":                false, "notice": "This mode stops before session activation; use session mode for activation or rdpview for desktop interaction.",
			}
			if channels != nil {
				result["resources"] = channels.Resources()
				result["user_channel"] = channels.UserID
				result["io_channel"] = channels.Server.IOChannel
				result["max_mcs_pdu_size"] = channels.MaxPDUSize
			}
			return enc.Encode(result)
		}
		return enc.Encode(struct {
			Gateway        any    `json:"gateway"`
			Stage          string `json:"stage"`
			Protocol       string `json:"selected_protocol"`
			TLSVersion     string `json:"tls_version"`
			CipherSuite    string `json:"cipher_suite"`
			ServerVerified bool   `json:"server_certificate_verified"`
			Verification   string `json:"certificate_verification"`
			Authenticated  bool   `json:"user_authenticated"`
			Notice         string `json:"notice"`
		}{gatewayconfig.Info(tr), "tls_transport", x224.ProtocolTLS.String(), tls.VersionName(s.Version), tls.CipherSuiteName(s.CipherSuite), verified, verification, false, "TLS transport only; this mode does not authenticate or create a desktop session."})
	default:
		return fmt.Errorf("unsupported -mode %q (use probe, tls, nla, channels or session)", *mode)
	}
}
