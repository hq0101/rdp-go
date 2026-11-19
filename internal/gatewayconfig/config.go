// Package gatewayconfig owns explicit gateway configuration for the example
// clients. Gateway secrets and certificate trust never come from the RDP target.
package gatewayconfig

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/internal/kdcproxyconfig"
	"github.com/hq0101/rdp-go/internal/licenseconfig"
	"github.com/hq0101/rdp-go/internal/ntlm"
	"github.com/hq0101/rdp-go/rdgateway"
)

var ErrConfig = errors.New("invalid gateway client configuration")
var ErrClosed = errors.New("gateway credentials have been cleared")
var ErrConsent = errors.New("gateway consent requires the SHA-256 of the reviewed prompt")

// Config contains local references, never password values. CA paths are relative
// to the process working directory. ConsentSHA256 hashes the exact UTF-8 prompt.
type Config struct {
	Address           string                 `json:"address"`
	Username          string                 `json:"username"`
	Domain            string                 `json:"domain"`
	PasswordEnv       string                 `json:"password_env"`
	CA                string                 `json:"ca"`
	CertificateSHA256 string                 `json:"cert_sha256"`
	ServerName        string                 `json:"server_name"`
	Authentication    string                 `json:"authentication"`
	ConsentSHA256     string                 `json:"consent_sha256"`
	KerberosRealm     string                 `json:"kerberos_realm"`
	KerberosKDC       string                 `json:"kerberos_kdc"`
	KerberosSPN       string                 `json:"kerberos_spn"`
	KerberosProxy     *kdcproxyconfig.Config `json:"kerberos_proxy,omitempty"`
}

func (Config) Format(f fmt.State, _ rune) { io.WriteString(f, "[redacted gateway config]") }

func (c Config) Validate() (*Config, error) {
	h, p, e := net.SplitHostPort(c.Address)
	n, pe := strconv.Atoi(p)
	if e != nil || pe != nil || n < 1 || n > 65535 || strconv.Itoa(n) != p || h == "" || len(h) > 253 || strings.ContainsAny(h, "\x00\r\n\t /\\") ||
		c.PasswordEnv == "" || len(c.PasswordEnv) > 32767 || strings.ContainsAny(c.PasswordEnv, "\x00=") || len(c.CA) > 4096 || strings.ContainsRune(c.CA, 0) || len(c.ServerName) > 253 || strings.ContainsAny(c.ServerName, "\x00\r\n\t /\\") {
		return nil, ErrConfig
	}
	if (ntlm.Credentials{Username: c.Username, Domain: c.Domain}).Validate() != nil {
		return nil, ErrConfig
	}
	if c.Authentication == "" {
		c.Authentication = "ntlm"
	}
	switch c.Authentication {
	case "ntlm", "negotiate-ntlm", "negotiate-raw-ntlm", "negotiate-kerberos":
	default:
		return nil, ErrConfig
	}
	if c.Authentication == "negotiate-kerberos" {
		name := c.ServerName
		if name == "" {
			name = h
		}
		k, err := c.kerberosOptions()
		if err != nil || k.Validate("HTTP/"+name, rdgateway.Credentials{Username: c.Username, Domain: c.Domain}) != nil {
			return nil, ErrConfig
		}
	} else if c.KerberosRealm != "" || c.KerberosKDC != "" || c.KerberosSPN != "" || c.KerberosProxy != nil {
		return nil, ErrConfig
	}
	if c.CA != "" && c.CertificateSHA256 != "" {
		return nil, ErrConfig
	}
	for _, v := range []string{c.CertificateSHA256, c.ConsentSHA256} {
		if v != "" {
			b, e := hex.DecodeString(v)
			if e != nil || len(b) != 32 {
				return nil, ErrConfig
			}
		}
	}
	if c.KerberosProxy != nil {
		v := *c.KerberosProxy
		c.KerberosProxy = &v
	}
	return &c, nil
}

func (c Config) kerberosOptions() (*rdgateway.KerberosOptions, error) {
	if c.Authentication != "negotiate-kerberos" {
		return nil, nil
	}
	o := &rdgateway.KerberosOptions{Realm: c.KerberosRealm, KDC: c.KerberosKDC, ServicePrincipal: c.KerberosSPN}
	if c.KerberosProxy != nil {
		var err error
		o.Proxy, err = c.KerberosProxy.Options()
		if err != nil {
			return nil, err
		}
	}
	return o, nil
}

type Flags struct {
	config Config
	proxy  kdcproxyconfig.Flags
}

func (f *Flags) Register(fs *flag.FlagSet) {
	f.proxy.Register(fs, "gateway-kerberos-proxy-")
	c := &f.config
	fs.StringVar(&c.Address, "gateway-addr", "", "independent HTTPS RD Gateway host:port; no direct fallback")
	fs.StringVar(&c.Username, "gateway-user", "", "explicit gateway account, independent of the target")
	fs.StringVar(&c.Domain, "gateway-domain", "", "gateway account domain")
	fs.StringVar(&c.PasswordEnv, "gateway-password-env", "", "gateway password environment variable; must differ from target/key variables")
	fs.StringVar(&c.CA, "gateway-ca", "", "gateway PEM CA bundle, independent of target trust")
	fs.StringVar(&c.CertificateSHA256, "gateway-cert-sha256", "", "independently verified gateway leaf SHA-256")
	fs.StringVar(&c.ServerName, "gateway-server-name", "", "gateway certificate name; defaults to gateway address host")
	fs.StringVar(&c.Authentication, "gateway-auth", "ntlm", "ntlm, negotiate-ntlm, negotiate-raw-ntlm, or negotiate-kerberos; no fallback")
	fs.StringVar(&c.KerberosRealm, "gateway-kerberos-realm", "", "explicit independent gateway realm; requires negotiate-kerberos")
	fs.StringVar(&c.KerberosKDC, "gateway-kerberos-kdc", "", "gateway KDC host:port; excludes explicit KDC Proxy")
	fs.StringVar(&c.KerberosSPN, "gateway-kerberos-spn", "", "optional HTTP/host service override; target TERMSRV options are independent")
	fs.StringVar(&c.ConsentSHA256, "gateway-consent-sha256", "", "SHA-256 of exact reviewed UTF-8 gateway consent prompt; unset rejects prompts")
}
func (f *Flags) Config(fs *flag.FlagSet) (*Config, error) {
	used := false
	fs.Visit(func(v *flag.Flag) {
		if strings.HasPrefix(v.Name, "gateway-") {
			used = true
		}
	})
	if !used {
		return nil, nil
	}
	c := f.config
	var err error
	c.KerberosProxy, err = f.proxy.Config(fs)
	if err != nil {
		return nil, err
	}
	return c.Validate()
}

type entry struct {
	config      Config
	credentials rdgateway.Credentials
	kerberos    *rdgateway.KerberosOptions
	tls         *tls.Config
}

// Manager retains independent gateway passwords for fresh authentication on
// reconnect. Close after every session and hop is stopped. Clearing Go string
// references cannot guarantee erasure of runtime/cryptographic copies.
type Manager struct {
	mu      sync.Mutex
	entries []*entry
	report  *Reporter
	apply   func(context.Context, rdgateway.Info) error
	closed  bool
}

func (*Manager) Format(f fmt.State, _ rune)   { io.WriteString(f, "[redacted gateway credentials]") }
func (*Manager) MarshalJSON() ([]byte, error) { return []byte(`"[redacted gateway credentials]"`), nil }

// Prepare validates ALL configuration, reads bounded CA bundles and snapshots
// credentials without consuming environment variables or opening a connection.
// reserved contains every target-password and license-key environment name.
// apply must implement this application's devices/custom resources before the
// target is created. Root-library channel adaptation remains an additional gate.
func Prepare(ctx context.Context, configs []*Config, reserved []string, report *Reporter, apply func(context.Context, rdgateway.Info) error) (*Manager, error) {
	if len(configs) > 17 {
		return nil, ErrConfig
	}
	m := &Manager{report: report, apply: apply}
	ok := false
	defer func() {
		if !ok {
			m.Close()
		}
	}()
	for _, c := range configs {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if c == nil {
			m.entries = append(m.entries, nil)
			continue
		}
		if apply == nil {
			return nil, ErrConfig
		}
		v, e := c.Validate()
		if e != nil {
			return nil, e
		}
		for _, name := range reserved {
			if name != "" && licenseconfig.SameEnvironmentName(v.PasswordEnv, name) {
				return nil, ErrConfig
			}
		}
		cfg := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: v.ServerName}
		if v.CA != "" {
			f, e := os.Open(v.CA)
			if e != nil {
				return nil, errors.New("cannot open gateway CA bundle")
			}
			b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
			f.Close()
			if e != nil || len(b) > 1<<20 {
				return nil, ErrConfig
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(b) {
				return nil, ErrConfig
			}
			cfg.RootCAs = pool
		}
		k, e := v.kerberosOptions()
		if e != nil {
			return nil, e
		}
		m.entries = append(m.entries, &entry{config: *v, tls: cfg, kerberos: k})
	}
	for _, v := range m.entries {
		if v == nil {
			continue
		}
		password, set := os.LookupEnv(v.config.PasswordEnv)
		if !set {
			return nil, errors.New("gateway password environment variable is missing")
		}
		if (ntlm.Credentials{Username: v.config.Username, Domain: v.config.Domain, Password: password}).Validate() != nil {
			return nil, ErrConfig
		}
		v.credentials = rdgateway.Credentials{Username: v.config.Username, Domain: v.config.Domain, Password: password}
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	ok = true
	return m, nil
}

// Consume removes only the already validated gateway password variables. Call
// after the rest of the local connection/plan/license setup has succeeded.
func (m *Manager) Consume() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return ErrClosed
	}
	for _, e := range m.entries {
		if e != nil {
			if err := os.Unsetenv(e.config.PasswordEnv); err != nil {
				return errors.New("cannot clear gateway password environment variable")
			}
		}
	}
	return nil
}
func (m *Manager) Close() {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.entries {
		if e != nil {
			e.credentials = rdgateway.Credentials{}
		}
	}
	m.entries = nil
	m.apply = nil
	m.report = nil
	m.closed = true
}
func (m *Manager) Options(index int) (*rdp.GatewayOptions, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	if index < 0 || index >= len(m.entries) {
		return nil, ErrConfig
	}
	e := m.entries[index]
	if e == nil {
		return nil, nil
	}
	c := e.config
	cfg := e.tls.Clone()
	if cfg.RootCAs != nil {
		cfg.RootCAs = cfg.RootCAs.Clone()
	}
	report, apply := m.report, m.apply
	var k *rdgateway.KerberosOptions
	if e.kerberos != nil {
		k = e.kerberos.Clone()
	}
	auth := rdgateway.NTLM
	if c.Authentication == "negotiate-ntlm" {
		auth = rdgateway.NegotiateNTLM
	}
	if c.Authentication == "negotiate-raw-ntlm" {
		auth = rdgateway.NegotiateRawNTLM
	}
	if c.Authentication == "negotiate-kerberos" {
		auth = rdgateway.NegotiateKerberos
	}
	return &rdp.GatewayOptions{Address: c.Address, AdjustResources: true, Credentials: func(ctx context.Context) (rdgateway.Credentials, error) {
		if err := ctx.Err(); err != nil {
			return rdgateway.Credentials{}, err
		}
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.closed {
			return rdgateway.Credentials{}, ErrClosed
		}
		return m.entries[index].credentials, nil
	}, Options: rdgateway.Options{Kerberos: k, TLSConfig: cfg, CertificateSHA256: c.CertificateSHA256, Authentication: auth, ClientName: "rdpgo",
		Consent: func(ctx context.Context, prompt string) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			sum := sha256.Sum256([]byte(prompt))
			digest := hex.EncodeToString(sum[:])
			accepted := c.ConsentSHA256 != "" && strings.EqualFold(c.ConsentSHA256, digest)
			if err := report.write(reportEvent{Kind: "gateway_consent", Address: c.Address, Text: prompt, SHA256: digest, Accepted: accepted}); err != nil {
				return err
			}
			if !accepted {
				return ErrConsent
			}
			return ctx.Err()
		}, ApplyPolicy: func(ctx context.Context, i rdgateway.Info) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if _, err := rdgateway.NewPolicy(i); err != nil {
				return err
			}
			if err := apply(ctx, i); err != nil {
				return err
			}
			if err := report.write(reportEvent{Kind: "gateway_policy", Address: c.Address, Info: &i}); err != nil {
				return err
			}
			return ctx.Err()
		}}}, nil
}

// NoLocalResources is only for diagnostic/screenshot clients with no devices,
// clipboard, audio or custom channels. It must not be used by a sharing viewer.
func NoLocalResources(ctx context.Context, i rdgateway.Info) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := rdgateway.NewPolicy(i)
	return err
}
