package rdghttp

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hq0101/rdp-go/internal/ntlm"
)

var (
	ErrHTTP     = errors.New("rdghttp: invalid HTTP exchange")
	ErrHTTPAuth = errors.New("rdghttp: HTTP authentication failed")
)

const (
	maxHTTPHeaders = 128 * 1024
	maxHTTPFields  = 64
	maxAuthToken   = 65536
	maxAuthBody    = 65536
	methodOut      = "RDG_OUT_DATA"
	methodIn       = "RDG_IN_DATA"
	gatewayPath    = "/remoteDesktopGateway/"
)

type HTTPOptions struct {
	// Authentication is explicit; zero preserves direct MS-NTHT NTLM.
	Authentication HTTPAuthentication
	Kerberos       *HTTPKerberosOptions // required exactly for HTTPNegotiateKerberos
	// TLSConfig is cloned. System roots and TLS1.2 are defaults. Unconditional
	// InsecureSkipVerify, session resumption and HTTP2 are not supported.
	TLSConfig         *tls.Config
	CertificateSHA256 string
	// Applies to the entire two-connection authentication, default 20 seconds.
	HandshakeTimeout time.Duration
}

// HTTPPair owns two authenticated HTTPS connections and their final HTTP
// responses. OpenStreams establishes the supported persistent IN/OUT profile.
// HTTP authentication alone does NOT indicate target authorization or an RDP
// connection. It starts no reader goroutine. The caller must Close on every exit.
type HTTPPair struct {
	out, in  *httpChannel
	id, host string
	opened   atomic.Bool
	closed   atomic.Bool
	once     sync.Once
	closeErr error
}
type httpChannel struct {
	raw      net.Conn
	conn     *tls.Conn
	reader   *bufio.Reader
	response *http.Response
	leaf     [32]byte
}

func (p *HTTPPair) Close() error {
	if p == nil {
		return nil
	}
	p.once.Do(func() {
		p.closed.Store(true)
		// Closing raw sockets interrupts blocked operations without TLS
		// close-notify writes or HTTP response-body draining.
		if p.out != nil {
			p.closeErr = p.out.raw.Close()
		}
		if p.in != nil {
			if e := p.in.raw.Close(); p.closeErr == nil {
				p.closeErr = e
			}
		}
	})
	return p.closeErr
}
func (*HTTPPair) String() string   { return "rdghttp.HTTPPair{private connections}" }
func (*HTTPPair) GoString() string { return "rdghttp.HTTPPair{private connections}" }

// DialHTTPNTLMPair explicitly selects MS-NTHT NTLM, with no fallback, SSO,
// redirects, HTTP proxy discovery or credential reuse from an RDP server.
// OUT is authenticated first, then IN with the same fresh correlation GUID,
// fixed TCP peer and exact leaf certificate. Credentials are not retained.
// Use DialHTTPPair with an explicit Authentication for Negotiate profiles.
func DialHTTPNTLMPair(ctx context.Context, address string, c ntlm.Credentials, o HTTPOptions) (*HTTPPair, error) {
	if o.Authentication != HTTPNTLM {
		return nil, ErrInvalid
	}
	return DialHTTPPair(ctx, address, c, o)
}

// DialHTTPPair authenticates two verified HTTPS connections using only the
// configured profile. HTTPNegotiateNTLM requires successful final SPNEGO/MIC
// validation before exposing the 200 body or creating the IN connection.
func DialHTTPPair(ctx context.Context, address string, c ntlm.Credentials, o HTTPOptions) (pair *HTTPPair, err error) {
	if ctx == nil || !o.Authentication.valid() {
		return nil, ErrInvalid
	}
	if err = c.Validate(); err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, ErrInvalid
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || !httpHost(host) {
		return nil, ErrInvalid
	}
	config, err := httpTLSConfig(host, o)
	if err != nil {
		return nil, err
	}
	var factory *httpKerberosFactory
	if (o.Authentication == HTTPNegotiateKerberos) != (o.Kerberos != nil) {
		return nil, ErrInvalid
	}
	if o.Kerberos != nil {
		client, service, e := o.Kerberos.prepare("HTTP/"+config.ServerName, c)
		if e != nil {
			return nil, e
		}
		factory = &httpKerberosFactory{client: client, service: service, credentials: c}
	}
	defer factory.close()
	if o.HandshakeTimeout < 0 {
		return nil, ErrInvalid
	}
	timeout := o.HandshakeTimeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	var guid [16]byte
	if _, err = rand.Read(guid[:]); err != nil {
		return nil, err
	}
	guid[6] = guid[6]&15 | 64
	guid[8] = guid[8]&63 | 128
	id := fmt.Sprintf("{%x-%x-%x-%x-%x}", guid[:4], guid[4:6], guid[6:8], guid[8:10], guid[10:])
	p := &HTTPPair{id: id, host: address}
	defer func() {
		if err != nil {
			p.Close()
		}
	}()
	p.out, err = authenticateHTTP(ctx, address, address, id, methodOut, c, config, nil, o.Authentication, factory)
	if err != nil {
		return nil, err
	}
	p.in, err = authenticateHTTP(ctx, p.out.raw.RemoteAddr().String(), address, id, methodIn, c, config, &p.out.leaf, o.Authentication, factory)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return p, nil
}

func httpHost(s string) bool {
	if s == "" || len(s) > 255 {
		return false
	}
	for _, c := range s {
		if c <= 32 || c >= 127 || strings.ContainsRune("/\\?#@[]", c) {
			return false
		}
	}
	return true
}

func httpTLSConfig(host string, o HTTPOptions) (*tls.Config, error) {
	c := &tls.Config{}
	if o.TLSConfig != nil {
		c = o.TLSConfig.Clone()
	}
	if c.InsecureSkipVerify {
		return nil, errors.New("rdghttp: verified gateway TLS is required")
	}
	if c.ServerName == "" {
		c.ServerName = host
	}
	if !httpHost(c.ServerName) {
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
				return ErrHTTPAuth
			}
			cert := s.PeerCertificates[0]
			sum := sha256.Sum256(cert.Raw)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return errors.New("rdghttp: gateway certificate pin mismatch")
			}
			now := time.Now()
			if c.Time != nil {
				now = c.Time()
			}
			if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
				return errors.New("rdghttp: gateway certificate expired or not yet valid")
			}
			if verify != nil {
				return verify(s)
			}
			return nil
		}
	}
	return c, nil
}

func authenticateHTTP(ctx context.Context, dialAddress, host, id, method string, c ntlm.Credentials, config *tls.Config, expected *[32]byte, profile HTTPAuthentication, factory *httpKerberosFactory) (channel *httpChannel, err error) {
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", dialAddress)
	if err != nil {
		return nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { raw.Close(); close(done) })
	defer func() {
		if !stop() {
			<-done
		}
		err = httpContextResult(ctx, err)
		if err != nil {
			raw.Close()
			channel = nil
		}
	}()
	if deadline, ok := ctx.Deadline(); ok {
		if err = raw.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	conn := tls.Client(raw, config)
	if err = conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 || len(state.VerifiedChains) == 0 && !config.InsecureSkipVerify {
		return nil, ErrHTTPAuth
	}
	if state.NegotiatedProtocol != "" && state.NegotiatedProtocol != "http/1.1" {
		return nil, ErrUnsupported
	}
	leaf := sha256.Sum256(state.PeerCertificates[0].Raw)
	if expected != nil && leaf != *expected {
		return nil, errors.New("rdghttp: IN and OUT gateway certificates differ")
	}
	cb, err := httpChannelBinding(state.PeerCertificates[0])
	if err != nil {
		return nil, err
	}
	defer clear(cb)
	scheme := profile.scheme()
	r := bufio.NewReaderSize(conn, maxHTTPHeaders+1)
	if err = writeHTTPRequest(conn, method, host, id, ""); err != nil {
		return nil, err
	}
	resp, err := readHTTPResponse(r, method)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 401 {
		return nil, ErrHTTPAuth
	}
	token, found, err := authChallenge(resp.Header.Values("WWW-Authenticate"), scheme)
	if err != nil || !found || len(token) != 0 {
		return nil, ErrHTTPAuth
	}
	if err = drainAuthResponse(resp); err != nil {
		return nil, err
	}
	if factory != nil {
		resp, err = authenticateKerberosHTTP(ctx, conn, r, method, host, id, factory, state.PeerCertificates[0])
	} else {
		resp, err = authenticateNTLMHTTP(conn, r, method, host, id, c, "HTTP/"+config.ServerName, cb, profile)
	}
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(strings.TrimSpace(resp.Header.Get("Persistent-Auth")), "false") {
		return nil, ErrUnsupported
	}
	if err = raw.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return &httpChannel{raw, conn, r, resp, leaf}, nil
}

func authenticateNTLMHTTP(w io.Writer, r *bufio.Reader, method, host, id string, c ntlm.Credentials, target string, cb []byte, profile HTTPAuthentication) (*http.Response, error) {
	a := &httpAuth{profile: profile}
	defer a.Close()
	scheme := profile.scheme()
	neg, err := a.start()
	if err != nil {
		return nil, err
	}
	defer clear(neg)
	if err = writeHTTPRequest(w, method, host, id, scheme+" "+base64.StdEncoding.EncodeToString(neg)); err != nil {
		return nil, err
	}
	resp, err := readHTTPResponse(r, method)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 401 {
		return nil, ErrHTTPAuth
	}
	token, found, err := authChallenge(resp.Header.Values("WWW-Authenticate"), scheme)
	if err != nil || !found || len(token) == 0 {
		return nil, ErrHTTPAuth
	}
	if err = drainAuthResponse(resp); err != nil {
		clear(token)
		return nil, err
	}
	auth, err := a.challenge(token, c, target, cb)
	clear(token)
	if err != nil {
		return nil, err
	}
	defer clear(auth)
	if err = writeHTTPRequest(w, method, host, id, scheme+" "+base64.StdEncoding.EncodeToString(auth)); err != nil {
		return nil, err
	}
	resp, err = readHTTPResponse(r, method)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, ErrHTTPAuth
	}
	token, _, err = authChallenge(resp.Header.Values("WWW-Authenticate"), scheme)
	if err != nil {
		return nil, ErrHTTPAuth
	}
	err = a.finish(token)
	clear(token)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// Socket deadlines and context timers may become observable in either order.
// The same absolute handshake deadline governs both, even if the context's
// timer callback has not run when the socket operation reports its timeout.
func httpContextResult(ctx context.Context, err error) error {
	if cause := ctx.Err(); cause != nil {
		return cause
	}
	if deadline, ok := ctx.Deadline(); ok && !time.Now().Before(deadline) {
		return context.DeadlineExceeded
	}
	return err
}

func writeHTTPRequest(w io.Writer, method, host, id, authorization string) error {
	return writeHTTPHeader(w, method, host, id, authorization, false)
}

func writeHTTPHeader(w io.Writer, method, host, id, authorization string, chunked bool) error {
	// All variable fields have already been validated or locally generated.
	var b bytes.Buffer
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: rdpgo/1.0\r\nConnection: Keep-Alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\nAccept: */*\r\nRDG-Connection-Id: %s\r\n", method, gatewayPath, host, id)
	if authorization != "" {
		fmt.Fprintf(&b, "Authorization: %s\r\n", authorization)
	}
	if chunked {
		b.WriteString("Transfer-Encoding: chunked\r\n")
	}
	b.WriteString("\r\n")
	data := b.Bytes()
	defer clear(data)
	return writeHTTPAll(w, data)
}

// A short successful write is progress, but a partial write with an error is
// terminal. Callers must never replay an HTTP request or packet after failure.
func writeHTTPAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if n < 0 || n > len(data) {
			return io.ErrShortWrite
		}
		data = data[n:]
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	return nil
}

// Validate the complete header in the same buffer before net/http parses it.
// Its body reader then retains all buffered bytes and standard chunk/trailer
// handling, including across the next response on this physical connection.
func readHTTPResponse(r *bufio.Reader, method string) (*http.Response, error) {
	scanned := 0
	var connectionHeaders []string
	for {
		n := r.Buffered()
		if n <= scanned {
			if _, e := r.Peek(n + 1); e != nil {
				return nil, e
			}
			n = r.Buffered()
		}
		b, e := r.Peek(n)
		if e != nil {
			return nil, e
		}
		i := bytes.Index(b[max(0, scanned-3):], []byte("\r\n\r\n"))
		if i >= 0 {
			end := max(0, scanned-3) + i + 4
			if end > maxHTTPHeaders {
				return nil, ErrLimit
			}
			if e = validateHTTPHeader(b[:end]); e != nil {
				return nil, e
			}
			// net/http removes Connection when it sees a close token. Preserve
			// the wire declaration so the persistent RDG stream can distinguish
			// an explicit close from Close inferred solely from an unframed body.
			for _, line := range bytes.Split(b[:end], []byte("\r\n"))[1:] {
				key, value, ok := bytes.Cut(line, []byte(":"))
				if ok && bytes.EqualFold(key, []byte("Connection")) {
					connectionHeaders = append(connectionHeaders, strings.TrimSpace(string(value)))
				}
			}
			break
		}
		if n > maxHTTPHeaders {
			return nil, ErrLimit
		}
		scanned = n
	}
	resp, e := http.ReadResponse(r, &http.Request{Method: method})
	if e != nil {
		return nil, ErrHTTP
	}
	if len(connectionHeaders) > 0 {
		resp.Header["Connection"] = connectionHeaders
	}
	if resp.ProtoMajor != 1 || resp.ProtoMinor > 1 {
		return nil, ErrUnsupported
	}
	if enc := resp.Header.Get("Content-Encoding"); enc != "" && !strings.EqualFold(enc, "identity") {
		return nil, ErrUnsupported
	}
	return resp, nil
}

func validateHTTPHeader(b []byte) error {
	lines := bytes.Split(b, []byte("\r\n"))
	if len(lines) < 3 || len(lines) > maxHTTPFields+3 {
		return ErrLimit
	}
	seenLength, seenTransfer := false, false
	seenSingle := map[string]bool{}
	for i, line := range lines[:len(lines)-2] {
		if len(line) == 0 || len(line) > 96*1024 {
			return ErrHTTP
		}
		for _, v := range line {
			if v == 127 || v < 32 && v != '\t' {
				return ErrHTTP
			}
		}
		if i == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			return ErrHTTP
		}
		key, _, ok := bytes.Cut(line, []byte(":"))
		if !ok {
			return ErrHTTP
		}
		name := strings.ToLower(string(key))
		if name == "content-encoding" || name == "persistent-auth" {
			if seenSingle[name] {
				return ErrHTTP
			}
			seenSingle[name] = true
		}
		if bytes.EqualFold(key, []byte("Content-Length")) {
			if seenLength {
				return ErrHTTP
			}
			seenLength = true
		}
		if bytes.EqualFold(key, []byte("Transfer-Encoding")) {
			if seenTransfer {
				return ErrHTTP
			}
			seenTransfer = true
		}
	}
	if seenLength && seenTransfer {
		return ErrHTTP
	}
	return nil
}

func drainAuthResponse(r *http.Response) error {
	if r.Close || r.ContentLength < 0 && len(r.TransferEncoding) == 0 {
		return ErrHTTP
	}
	if r.ContentLength > maxAuthBody {
		return ErrLimit
	}
	n, e := io.Copy(io.Discard, io.LimitReader(r.Body, maxAuthBody+1))
	if e != nil {
		return ErrHTTP
	}
	if n > maxAuthBody {
		return ErrLimit
	}
	if e = r.Body.Close(); e != nil {
		return ErrHTTP
	}
	return nil
}

// Split challenge lists without treating commas in quoted Basic/Digest realms
// as a scheme. Multiple challenges for the selected scheme are rejected.
func ntlmChallenge(values []string) ([]byte, bool, error) {
	return authChallenge(values, "NTLM")
}
func authChallenge(values []string, scheme string) ([]byte, bool, error) {
	found := false
	var token []byte
	for _, value := range values {
		quoted, escaped := false, false
		start := 0
		for i := 0; i <= len(value); i++ {
			if i < len(value) {
				ch := value[i]
				if escaped {
					escaped = false
					continue
				}
				if quoted && ch == '\\' {
					escaped = true
					continue
				}
				if ch == '"' {
					quoted = !quoted
					continue
				}
				if ch != ',' || quoted {
					continue
				}
			}
			if quoted || escaped {
				return nil, false, ErrHTTP
			}
			s := strings.TrimSpace(value[start:i])
			start = i + 1
			fields := strings.Fields(s)
			if len(fields) == 0 || !strings.EqualFold(fields[0], scheme) {
				continue
			}
			if found || len(fields) > 2 {
				return nil, false, ErrHTTP
			}
			found = true
			if len(fields) == 2 {
				if len(fields[1]) > base64.StdEncoding.EncodedLen(maxAuthToken) {
					return nil, false, ErrLimit
				}
				var e error
				token, e = base64.StdEncoding.Strict().DecodeString(fields[1])
				if e != nil || len(token) > maxAuthToken {
					return nil, false, ErrHTTP
				}
			}
		}
	}
	return token, found, nil
}

// RFC5929 tls-server-end-point application data shared by NTLM and Kerberos.
func httpTLSEndpoint(cert *x509.Certificate) ([]byte, error) {
	if cert == nil {
		return nil, ErrInvalid
	}
	var digest []byte
	switch cert.SignatureAlgorithm {
	case x509.MD5WithRSA, x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.SHA256WithRSA, x509.SHA256WithRSAPSS, x509.ECDSAWithSHA256:
		h := sha256.Sum256(cert.Raw)
		digest = h[:]
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS, x509.ECDSAWithSHA384:
		h := sha512.Sum384(cert.Raw)
		digest = h[:]
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS, x509.ECDSAWithSHA512:
		h := sha512.Sum512(cert.Raw)
		digest = h[:]
	default:
		return nil, ErrUnsupported
	}
	return append([]byte("tls-server-end-point:"), digest...), nil
}

// GSS serialization and MS-NLMP MD5 binding hash.
func httpChannelBinding(cert *x509.Certificate) ([]byte, error) {
	app, err := httpTLSEndpoint(cert)
	if err != nil {
		return nil, err
	}
	defer clear(app)
	b := make([]byte, 20)
	binary.LittleEndian.PutUint32(b[16:], uint32(len(app)))
	b = append(b, app...)
	h := md5.Sum(b)
	return h[:], nil
}
