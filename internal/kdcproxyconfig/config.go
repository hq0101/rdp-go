// Package kdcproxyconfig provides independent, bounded file and CLI settings
// for the examples' KDC proxy. It never reads gateway or target TLS settings.
package kdcproxyconfig

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"io"
	"os"
	"strings"

	"github.com/hq0101/rdp-go/kdcproxy"
)

var ErrConfig = errors.New("invalid KDC proxy configuration")

type Config struct {
	URL               string `json:"url"`
	CA                string `json:"ca"`
	CertificateSHA256 string `json:"cert_sha256"`
	ServerName        string `json:"server_name"`
	ClientCertificate string `json:"client_cert"`
	ClientKey         string `json:"client_key"`
}

func (c Config) Options() (*kdcproxy.Options, error) {
	if c.URL == "" || c.CA != "" && c.CertificateSHA256 != "" || (c.ClientCertificate == "") != (c.ClientKey == "") {
		return nil, ErrConfig
	}
	for _, p := range []string{c.CA, c.ClientCertificate, c.ClientKey} {
		if len(p) > 4096 || strings.ContainsRune(p, 0) {
			return nil, ErrConfig
		}
	}
	o := &kdcproxy.Options{URL: c.URL, CertificateSHA256: c.CertificateSHA256, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: c.ServerName}}
	if e := o.Validate(); e != nil {
		return nil, ErrConfig
	}
	if c.CA != "" {
		b, e := readFile(c.CA)
		if e != nil {
			return nil, e
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(b) {
			return nil, ErrConfig
		}
		o.TLSConfig.RootCAs = roots
	}
	if c.ClientCertificate != "" {
		cert, e := readFile(c.ClientCertificate)
		if e != nil {
			return nil, e
		}
		key, e := readFile(c.ClientKey)
		if e != nil {
			return nil, e
		}
		defer clear(key)
		pair, e := tls.X509KeyPair(cert, key)
		if e != nil {
			return nil, ErrConfig
		}
		o.TLSConfig.Certificates = []tls.Certificate{pair}
	}
	return o, nil
}
func readFile(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, ErrConfig
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() > 1<<20 {
		return nil, ErrConfig
	}
	b, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
	if e != nil || len(b) > 1<<20 {
		clear(b)
		return nil, ErrConfig
	}
	return b, nil
}

type Flags struct {
	config Config
	prefix string
}

func (f *Flags) Register(fs *flag.FlagSet, prefix string) {
	f.prefix = prefix
	c := &f.config
	fs.StringVar(&c.URL, prefix+"url", "", "explicit HTTPS KDC Proxy URL, alternative to direct KDC")
	fs.StringVar(&c.CA, prefix+"ca", "", "independent proxy CA bundle; defaults to system roots")
	fs.StringVar(&c.CertificateSHA256, prefix+"cert-sha256", "", "independently verified proxy leaf SHA-256; excludes CA")
	fs.StringVar(&c.ServerName, prefix+"server-name", "", "proxy certificate name; defaults to URL hostname")
	fs.StringVar(&c.ClientCertificate, prefix+"client-cert", "", "explicit PEM TLS client certificate for this proxy")
	fs.StringVar(&c.ClientKey, prefix+"client-key", "", "PEM private key file for the proxy client certificate")
}
func (f *Flags) Config(fs *flag.FlagSet) (*Config, error) {
	used := false
	fs.Visit(func(v *flag.Flag) {
		if strings.HasPrefix(v.Name, f.prefix) {
			used = true
		}
	})
	if !used {
		return nil, nil
	}
	c := f.config
	if c.URL == "" {
		return nil, ErrConfig
	}
	return &c, nil
}
func (f *Flags) Options(fs *flag.FlagSet) (*kdcproxy.Options, error) {
	c, e := f.Config(fs)
	if e != nil || c == nil {
		return nil, e
	}
	return c.Options()
}
