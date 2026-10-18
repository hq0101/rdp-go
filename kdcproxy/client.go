// Package kdcproxy implements explicit MS-KKDCP over HTTPS. It transports
// Kerberos messages without owning passwords, tickets or KDC authentication.
package kdcproxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hq0101/rdp-go/internal/kkdcp"
)

const MaxMessage = kkdcp.MaxMessage

var ErrInvalid = errors.New("kdcproxy: invalid configuration or response")

// Options selects exactly one HTTPS endpoint, independent of gateway and RDP
// trust. No environment proxy, redirect, discovery, HTTP authentication,
// direct-KDC fallback or automatic replay is used. TLS client certificates may
// be supplied explicitly in TLSConfig; OS credential discovery is never used.
type Options struct {
	URL               string        // https://host[:port][/path]; omitted path defaults to /KdcProxy
	TLSConfig         *tls.Config   // cloned; verified CA/name or explicit leaf pin, TLS>=1.2
	CertificateSHA256 string        // replaces CA/name checks; still checks certificate dates
	DCLocatorHint     *uint32       // optional MS-NRPC locator flags
	Timeout           time.Duration // whole HTTP exchange; default 15s, maximum 2m
}

// Clone owns client TLS slices and trust pools. Signer keys, certificate Leaf and
// callbacks remain caller-owned immutable objects as in crypto/tls.Config.
func (o Options) Clone() *Options {
	if o.DCLocatorHint != nil {
		v := *o.DCLocatorHint
		o.DCLocatorHint = &v
	}
	if o.TLSConfig != nil {
		c := o.TLSConfig.Clone()
		o.TLSConfig = c
		if c.RootCAs != nil {
			c.RootCAs = c.RootCAs.Clone()
		}
		if c.ClientCAs != nil {
			c.ClientCAs = c.ClientCAs.Clone()
		}
		c.NextProtos = append([]string(nil), c.NextProtos...)
		c.CipherSuites = append([]uint16(nil), c.CipherSuites...)
		c.CurvePreferences = append([]tls.CurveID(nil), c.CurvePreferences...)
		c.EncryptedClientHelloConfigList = append([]byte(nil), c.EncryptedClientHelloConfigList...)
		c.Certificates = append([]tls.Certificate(nil), c.Certificates...)
		for i := range c.Certificates {
			cert := &c.Certificates[i]
			cert.Certificate = cloneBytes(cert.Certificate)
			cert.SignedCertificateTimestamps = cloneBytes(cert.SignedCertificateTimestamps)
			cert.OCSPStaple = append([]byte(nil), cert.OCSPStaple...)
			cert.SupportedSignatureAlgorithms = append([]tls.SignatureScheme(nil), cert.SupportedSignatureAlgorithms...)
		}
		// Avoid a mutable map of certificate pointers outside this snapshot. Client
		// selection uses Certificates/GetClientCertificate, not server name lookup.
		c.NameToCertificate = nil
	}
	return &o
}
func cloneBytes(in [][]byte) [][]byte {
	if in == nil {
		return nil
	}
	out := make([][]byte, len(in))
	for i, b := range in {
		out[i] = append([]byte(nil), b...)
	}
	return out
}

// StatusError exposes only the numeric status, never the proxy's response body
// or authentication challenge. 401/403 require a separately supported setup.
type StatusError struct{ Code int }

func (e *StatusError) Error() string { return fmt.Sprintf("kdcproxy: HTTP status %d", e.Code) }

// Client is an immutable configuration safe for concurrent independent calls.
// Every Exchange opens and closes its own connection and has a bounded lifetime.
type Client struct {
	endpoint string
	tls      *tls.Config
	hint     *uint32
	timeout  time.Duration
}

func (o Options) Validate() error { _, e := New(o); return e }
func New(o Options) (*Client, error) {
	o = *o.Clone()
	if len(o.URL) > 8192 || strings.ContainsAny(o.URL, "\x00\r\n\t #") {
		return nil, ErrInvalid
	}
	u, e := url.Parse(o.URL)
	if e != nil || u.Scheme != "https" || u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Host == "" || !validHost(u.Hostname()) {
		return nil, ErrInvalid
	}
	port := u.Port()
	if strings.HasSuffix(u.Host, ":") {
		return nil, ErrInvalid
	}
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return nil, ErrInvalid
		}
	}
	if len(u.Path) > 4096 || strings.ContainsAny(u.Path, "\x00\r\n\t\\") {
		return nil, ErrInvalid
	}
	if u.Path == "" {
		u.Path = "/KdcProxy"
	}
	if o.Timeout == 0 {
		o.Timeout = 15 * time.Second
	}
	if o.Timeout < 0 || o.Timeout > 2*time.Minute {
		return nil, ErrInvalid
	}
	c := o.TLSConfig
	if c == nil {
		c = &tls.Config{}
	}
	if c.InsecureSkipVerify {
		return nil, errors.New("kdcproxy: verified TLS is required")
	}
	if c.ServerName == "" {
		c.ServerName = u.Hostname()
	}
	if !validHost(c.ServerName) {
		return nil, ErrInvalid
	}
	if c.MinVersion == 0 {
		c.MinVersion = tls.VersionTLS12
	}
	if c.MinVersion < tls.VersionTLS12 || c.MaxVersion != 0 && c.MaxVersion < c.MinVersion {
		return nil, ErrInvalid
	}
	c.NextProtos = []string{"http/1.1"}
	c.ClientSessionCache = nil
	c.SessionTicketsDisabled = true
	if o.CertificateSHA256 != "" {
		pin, e := hex.DecodeString(o.CertificateSHA256)
		if e != nil || len(pin) != 32 {
			return nil, ErrInvalid
		}
		verify := c.VerifyConnection
		c.InsecureSkipVerify = true
		c.VerifyConnection = func(s tls.ConnectionState) error {
			if len(s.PeerCertificates) == 0 {
				return ErrInvalid
			}
			cert := s.PeerCertificates[0]
			sum := sha256.Sum256(cert.Raw)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return errors.New("kdcproxy: certificate pin mismatch")
			}
			now := time.Now()
			if c.Time != nil {
				now = c.Time()
			}
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("kdcproxy: certificate expired or not yet valid")
			}
			if verify != nil {
				return verify(s)
			}
			return nil
		}
	}
	return &Client{endpoint: u.String(), tls: c, hint: o.DCLocatorHint, timeout: o.Timeout}, nil
}
func validHost(s string) bool {
	if net.ParseIP(s) != nil {
		return true
	}
	if s == "" || len(s) > 253 {
		return false
	}
	for _, v := range s {
		if !(v >= 'a' && v <= 'z' || v >= 'A' && v <= 'Z' || v >= '0' && v <= '9' || v == '.' || v == '-' || v == '_') {
			return false
		}
	}
	return true
}

// An HTTP RoundTripper may close the request body after returning. Serialize
// Close/Read so cleanup on early response/cancellation cannot race the writer.
type messageBody struct {
	mu     sync.Mutex
	data   []byte
	offset int
}

func (b *messageBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.offset == len(b.data) {
		return 0, io.EOF
	}
	n := copy(p, b.data[b.offset:])
	b.offset += n
	return n, nil
}
func (b *messageBody) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	clear(b.data)
	b.data = nil
	b.offset = 0
	return nil
}

func (c *Client) Exchange(ctx context.Context, realm string, message []byte) (response []byte, err error) {
	if c == nil || c.tls == nil || c.endpoint == "" || ctx == nil {
		return nil, ErrInvalid
	}
	wire, err := kkdcp.EncodeRequest(message, realm, c.hint)
	if err != nil {
		return nil, ErrInvalid
	}
	body := &messageBody{data: wire}
	defer body.Close()
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	defer func() {
		if ctx.Err() != nil {
			clear(response)
			response = nil
			err = ctx.Err()
		}
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, body)
	if err != nil {
		return nil, ErrInvalid
	}
	req.ContentLength = int64(len(wire))
	req.GetBody = nil
	req.Header.Set("Content-Type", "application/kerberos")
	req.Header.Set("Accept", "application/kerberos")
	req.Header.Set("Cache-Control", "no-store")
	tr := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{}).DialContext, TLSClientConfig: c.tls.Clone(), DisableKeepAlives: true, DisableCompression: true, MaxConnsPerHost: 1, MaxResponseHeaderBytes: 64 << 10, TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{}}
	defer tr.CloseIdleConnections()
	client := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, &StatusError{resp.StatusCode}
	}
	encoding := resp.Header.Get("Content-Encoding")
	if resp.ContentLength > kkdcp.MaxEnvelope || encoding != "" && !strings.EqualFold(encoding, "identity") {
		return nil, ErrInvalid
	}
	encoded, err := io.ReadAll(io.LimitReader(resp.Body, kkdcp.MaxEnvelope+1))
	defer clear(encoded)
	if err != nil {
		return nil, err
	}
	response, err = kkdcp.DecodeResponse(encoded)
	if err != nil {
		return nil, ErrInvalid
	}
	return response, nil
}
