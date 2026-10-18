// Package redirectconfig implements the example clients' explicit local hop
// plan. It never resolves a server-provided name into a network destination.
package redirectconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/internal/gatewayconfig"
	"github.com/hq0101/rdp-go/internal/kdcproxyconfig"
	"github.com/hq0101/rdp-go/internal/licenseconfig"
	"github.com/hq0101/rdp-go/pdu"
)

const maxSize = 64 << 10

var (
	ErrConfig = errors.New("invalid redirection config")
	ErrDenied = errors.New("redirection does not match the configured hop")
	ErrClosed = errors.New("redirection credentials have been cleared")
)

type document struct {
	Version        int   `json:"version"`
	TimeoutSeconds int   `json:"timeout_seconds"`
	Hops           []hop `json:"hops"`
}

type kerberos struct {
	Realm            string                 `json:"realm"`
	KDC              string                 `json:"kdc"`
	ServicePrincipal string                 `json:"service_principal"`
	Proxy            *kdcproxyconfig.Config `json:"proxy,omitempty"`
}

type hop struct {
	From              string                `json:"from"`
	MatchField        string                `json:"match_field"`
	MatchValue        string                `json:"match_value"`
	Address           string                `json:"address"`
	Username          string                `json:"username"`
	Domain            string                `json:"domain"`
	PasswordEnv       string                `json:"password_env"`
	PasswordMode      string                `json:"password_mode"`
	CertificateSHA256 string                `json:"cert_sha256"`
	ServerName        string                `json:"server_name"`
	SPNEGO            bool                  `json:"spnego"`
	Kerberos          *kerberos             `json:"kerberos,omitempty"`
	ShareResources    bool                  `json:"share_resources"`
	Licensing         *licenseconfig.Config `json:"licensing,omitempty"`
	Gateway           *gatewayconfig.Config `json:"gateway,omitempty"`
	AllowDirect       bool                  `json:"allow_direct"`
}

type entry struct {
	from, field, value string
	target             rdp.RedirectionTarget
	licensing          *licenseconfig.Config
	gateway            *gatewayconfig.Config
}

// Plan owns environment-sourced target credentials until Close. The application
// must not print a decoded document; Plan itself always formats as redacted.
// Go strings and cryptographic copies cannot be guaranteed to be erased.
type Plan struct {
	mu            sync.Mutex
	entries       []entry
	timeout       time.Duration
	closed        bool
	ownedLicenses *licenseconfig.Manager // only the Load convenience API
	gateways      *gatewayconfig.Manager // borrowed from Connections
}

func (*Plan) Format(f fmt.State, _ rune)   { _, _ = io.WriteString(f, "[redacted redirection plan]") }
func (*Plan) MarshalJSON() ([]byte, error) { return []byte(`"[redacted redirection plan]"`), nil }

// Load validates the whole plan before consuming any password environment
// variable. On success the referenced variables are unset. Empty path disables
// redirection. resources means the client has enabled local resource sharing;
// every hop must explicitly allow carrying those configured resources forward.
func Load(path, initialAddress string, resources bool) (*Plan, error) {
	p, m, _, err := LoadWithLicensing(context.Background(), path, initialAddress, resources, nil, "")
	if err != nil {
		return nil, err
	}
	if p != nil {
		p.ownedLicenses = m
	} else {
		m.Close()
	}
	return p, nil
}

func readPlan(path, initialAddress string, resources bool) (*Plan, []string, error) {
	if path == "" {
		return nil, nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, errors.New("cannot open redirection config")
	}
	defer f.Close()
	return decode(f, initialAddress, resources, os.LookupEnv)
}

func decode(r io.Reader, initialAddress string, resources bool, lookup func(string) (string, bool)) (*Plan, []string, error) {
	b, err := io.ReadAll(io.LimitReader(r, maxSize+1))
	if err != nil || len(b) > maxSize || !utf8.Valid(b) {
		return nil, nil, ErrConfig
	}
	defer clear(b)
	// Duplicate and case-aliased members are not an acceptable authorization
	// policy. JSON null is rejected, including null booleans and array entries.
	d := json.NewDecoder(bytes.NewReader(b))
	if err := uniqueValue(d, 0); err != nil {
		return nil, nil, ErrConfig
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, nil, ErrConfig
	}
	var doc document
	d = json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&doc); err != nil {
		return nil, nil, ErrConfig
	}
	if doc.Version != 1 || len(doc.Hops) < 1 || len(doc.Hops) > 16 || !endpoint(initialAddress) {
		return nil, nil, ErrConfig
	}
	if doc.TimeoutSeconds == 0 {
		doc.TimeoutSeconds = 60
	}
	if doc.TimeoutSeconds < 1 || doc.TimeoutSeconds > 600 {
		return nil, nil, ErrConfig
	}
	p := &Plan{timeout: time.Duration(doc.TimeoutSeconds) * time.Second}
	var names []string
	previous := initialAddress
	for _, h := range doc.Hops {
		if h.From != previous || !endpoint(h.Address) || h.Username == "" || resources && !h.ShareResources || strings.ContainsAny(h.ServerName, "\x00\r\n /\\") {
			return nil, nil, ErrConfig
		}
		switch h.MatchField {
		case "address", "fqdn", "netbios":
			if h.MatchValue == "" || len(h.MatchValue) > 512 || strings.ContainsAny(h.MatchValue, "\x00\r\n") {
				return nil, nil, ErrConfig
			}
		case "route_sha256":
			if !digest(h.MatchValue) {
				return nil, nil, ErrConfig
			}
		default:
			return nil, nil, ErrConfig
		}
		if h.CertificateSHA256 != "" && !digest(h.CertificateSHA256) {
			return nil, nil, ErrConfig
		}
		if h.Gateway != nil && h.AllowDirect {
			return nil, nil, ErrConfig
		}
		var gc *gatewayconfig.Config
		if h.Gateway != nil {
			gc, err = h.Gateway.Validate()
			if err != nil {
				return nil, nil, ErrConfig
			}
		}
		t := rdp.RedirectionTarget{Address: h.Address, CertificateSHA256: h.CertificateSHA256, SPNEGO: h.SPNEGO, AllowDirect: h.AllowDirect, Credentials: rdp.Credentials{Username: h.Username, Domain: h.Domain}}
		if h.ServerName != "" {
			t.TLSConfig = &tls.Config{ServerName: h.ServerName, MinVersion: tls.VersionTLS12}
		}
		if h.Kerberos != nil {
			if h.Kerberos.Realm == "" || ((h.Kerberos.KDC != "") == (h.Kerberos.Proxy != nil)) || (h.Kerberos.KDC != "" && !endpoint(h.Kerberos.KDC)) {
				return nil, nil, ErrConfig
			}
			t.Kerberos = &rdp.KerberosOptions{Realm: h.Kerberos.Realm, KDC: h.Kerberos.KDC, ServicePrincipal: h.Kerberos.ServicePrincipal}
			if h.Kerberos.Proxy != nil {
				t.Kerberos.Proxy, err = h.Kerberos.Proxy.Options()
				if err != nil {
					return nil, nil, ErrConfig
				}
			}
		}
		switch h.PasswordMode {
		case "", "reject":
			t.PasswordMode = rdp.RedirectionPasswordReject
		case "ignore":
			t.PasswordMode = rdp.RedirectionPasswordIgnore
		case "cookie":
			t.PasswordMode = rdp.RedirectionPasswordCookie
		case "rdstls":
			t.PasswordMode = rdp.RedirectionPasswordRDSTLS
		default:
			return nil, nil, ErrConfig
		}
		if t.PasswordMode == rdp.RedirectionPasswordRDSTLS {
			if h.PasswordEnv != "" || h.SPNEGO || h.Kerberos != nil {
				return nil, nil, ErrConfig
			}
		} else {
			if h.PasswordEnv == "" || strings.ContainsAny(h.PasswordEnv, "\x00=") {
				return nil, nil, ErrConfig
			}
			var ok bool
			t.Credentials.Password, ok = lookup(h.PasswordEnv)
			if !ok {
				return nil, nil, errors.New("redirection password environment variable is missing")
			}
			names = append(names, h.PasswordEnv)
		}
		if t.Credentials.Validate() != nil {
			return nil, nil, ErrConfig
		}
		var lc *licenseconfig.Config
		if h.Licensing != nil {
			lc, err = h.Licensing.Validate(h.Username)
			if err != nil {
				return nil, nil, ErrConfig
			}
		}
		p.entries = append(p.entries, entry{from: h.From, field: h.MatchField, value: h.MatchValue, target: t, licensing: lc, gateway: gc})
		previous = h.Address
	}
	return p, names, nil
}

func endpoint(s string) bool {
	h, p, err := net.SplitHostPort(s)
	n, e := strconv.Atoi(p)
	return err == nil && e == nil && h != "" && len(h) <= 253 && n > 0 && n <= 65535 && !strings.ContainsAny(h, "\x00\r\n\t /\\")
}
func digest(s string) bool { b, err := hex.DecodeString(s); return err == nil && len(b) == sha256.Size }

func uniqueValue(d *json.Decoder, depth int) error {
	if depth > 8 {
		return ErrConfig
	}
	t, err := d.Token()
	if err != nil || t == nil {
		return ErrConfig
	}
	switch t {
	case json.Delim('{'):
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return ErrConfig
			}
			name, ok := key.(string)
			if !ok || name != strings.ToLower(name) || seen[name] {
				return ErrConfig
			}
			seen[name] = true
			if err := uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim('}') {
			return ErrConfig
		}
	case json.Delim('['):
		for d.More() {
			if err := uniqueValue(d, depth+1); err != nil {
				return err
			}
		}
		end, err := d.Token()
		if err != nil || end != json.Delim(']') {
			return ErrConfig
		}
	case json.Delim('}'), json.Delim(']'):
		return ErrConfig
	}
	return nil
}

func (p *Plan) Policy() rdp.RedirectionPolicy {
	p.mu.Lock()
	defer p.mu.Unlock()
	return rdp.RedirectionPolicy{MaxHops: len(p.entries), Timeout: p.timeout, Resolve: p.resolve}
}

func (p *Plan) UsesGateway() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, e := range p.entries {
		if e.gateway != nil {
			return true
		}
	}
	return false
}

func (p *Plan) resolve(ctx context.Context, proposal rdp.RedirectionContext) (rdp.RedirectionTarget, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return rdp.RedirectionTarget{}, err
	}
	if p.closed {
		return rdp.RedirectionTarget{}, ErrClosed
	}
	if proposal.Hop < 1 || proposal.Hop > len(p.entries) {
		return rdp.RedirectionTarget{}, ErrDenied
	}
	e := p.entries[proposal.Hop-1]
	if proposal.FromAddress != e.from || proposal.Request == nil {
		return rdp.RedirectionTarget{}, ErrDenied
	}
	info := proposal.Info
	var proposed string
	var flag pdu.RedirectionFlags
	switch e.field {
	case "address":
		proposed, flag = info.TargetAddress, pdu.RedirectTargetAddress
	case "fqdn":
		proposed, flag = info.TargetFQDN, pdu.RedirectTargetFQDN
	case "netbios":
		proposed, flag = info.TargetNetBIOS, pdu.RedirectTargetNetBIOS
	case "route_sha256":
		if info.Flags&pdu.RedirectTargetAddress != 0 {
			return rdp.RedirectionTarget{}, ErrDenied
		}
		b, err := proposal.Request.Field(pdu.RedirectLoadBalanceInfo)
		if err != nil {
			return rdp.RedirectionTarget{}, ErrDenied
		}
		sum := sha256.Sum256(b)
		clear(b)
		proposed, flag = hex.EncodeToString(sum[:]), pdu.RedirectLoadBalanceInfo
	}
	if info.Flags&flag == 0 || !strings.EqualFold(proposed, e.value) {
		return rdp.RedirectionTarget{}, ErrDenied
	}
	target := e.target
	if e.gateway != nil {
		if p.gateways == nil {
			return rdp.RedirectionTarget{}, ErrConfig
		}
		var err error
		target.Gateway, err = p.gateways.Options(proposal.Hop)
		if err != nil {
			return rdp.RedirectionTarget{}, err
		}
	} else if proposal.ViaGateway && !target.AllowDirect {
		return rdp.RedirectionTarget{}, rdp.ErrGatewayRoute
	}
	if e.licensing != nil && target.Licensing == nil {
		return rdp.RedirectionTarget{}, ErrConfig
	}
	target.Licensing = target.Licensing.Clone()
	if target.TLSConfig != nil {
		target.TLSConfig = target.TLSConfig.Clone()
	}
	if target.Kerberos != nil {
		target.Kerberos = target.Kerberos.Clone()
	}
	return target, nil
}

// Credentials returns only the configured hop's credentials for ARC. A caller
// must obtain hop from its own successful Session.RedirectionInfo, not HTTP or
// a server field. RDSTLS ARC uses its server cookie and needs no local password.
func (p *Plan) Credentials(hop int) (rdp.Credentials, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return rdp.Credentials{}, ErrClosed
	}
	if hop < 1 || hop > len(p.entries) {
		return rdp.Credentials{}, ErrDenied
	}
	return p.entries[hop-1].target.Credentials, nil
}

func (p *Plan) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for i := range p.entries {
		p.entries[i].target.Credentials = rdp.Credentials{}
		licenseconfig.ClearOptions(p.entries[i].target.Licensing)
		p.entries[i].target.Licensing = nil
		p.entries[i].licensing = nil
		p.entries[i].gateway = nil
	}
	if p.ownedLicenses != nil {
		p.ownedLicenses.Close()
		p.ownedLicenses = nil
	}
	p.closed = true
	p.gateways = nil
}
