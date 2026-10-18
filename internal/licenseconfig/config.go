// Package licenseconfig owns the example clients' explicit license stores.
// It is configuration/lifecycle glue; protocol trust remains in rdp.
package licenseconfig

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/internal/licensing"
)

var ErrConfig = errors.New("invalid licensing client configuration")
var ErrClosed = errors.New("licensing client stores closed")

// Config contains references to application-owned secrets, never key values.
// Relative directories are resolved against the process working directory.
type Config struct {
	Store             string `json:"store"`
	KeyEnv            string `json:"key_env"`
	Create            bool   `json:"create"`
	Machine           string `json:"machine"`
	User              string `json:"user"`
	Platform          uint64 `json:"platform"`
	CertificateSHA256 string `json:"cert_sha256"`
}

func (Config) Format(f fmt.State, _ rune) { io.WriteString(f, "[redacted licensing config]") }
func (c Config) Validate(username string) (*Config, error) {
	if c.User == "" {
		c.User = username
	}
	ascii := func(s string) bool {
		if len(s) == 0 || len(s) >= licensing.MaxText {
			return false
		}
		for i := range s {
			if s[i] == 0 || s[i] > 127 {
				return false
			}
		}
		return true
	}
	if c.Store == "" || len(c.Store) > 4096 || strings.IndexByte(c.Store, 0) >= 0 || c.KeyEnv == "" || strings.ContainsAny(c.KeyEnv, "\x00=") || !ascii(c.User) || !ascii(c.Machine) || c.Platform > 0xffffffff {
		return nil, ErrConfig
	}
	if c.CertificateSHA256 != "" {
		b, e := hex.DecodeString(c.CertificateSHA256)
		if e != nil || len(b) != 32 || [32]byte(b) == ([32]byte{}) {
			return nil, ErrConfig
		}
	}
	return &c, nil
}

type Flags struct{ config Config }

func (f *Flags) Register(fs *flag.FlagSet) {
	c := &f.config
	fs.StringVar(&c.Store, "license-store", "", "encrypted license store directory (session mode)")
	fs.BoolVar(&c.Create, "license-create", false, "explicitly create a new license store directory; never overwrite")
	fs.StringVar(&c.KeyEnv, "license-key-env", "", "environment variable holding the independent 64-hex-digit store key")
	fs.StringVar(&c.Machine, "license-machine", "", "stable ASCII licensing client name; required with -license-store")
	fs.StringVar(&c.User, "license-user", "", "ASCII licensing user name; defaults to -user")
	fs.StringVar(&c.CertificateSHA256, "license-cert-sha256", "", "optional complete licensing SERVER_CERTIFICATE SHA-256 pin; separate from TLS pin")
	fs.Uint64Var(&c.Platform, "license-platform", 0, "explicit MS-RDPELE PlatformId (uint32); default unknown/0")
}
func (f *Flags) Config(fs *flag.FlagSet, mode, username string) (*Config, error) {
	selected := false
	fs.Visit(func(v *flag.Flag) {
		switch v.Name {
		case "license-store", "license-create", "license-key-env", "license-machine", "license-user", "license-cert-sha256", "license-platform":
			selected = true
		}
	})
	if !selected {
		return nil, nil
	}
	if mode != "session" {
		return nil, ErrConfig
	}
	return f.config.Validate(username)
}

// SameEnvironmentName accounts for Windows' case-insensitive environment names.
func SameEnvironmentName(a, b string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// Manager opens each selected local store once. Keep it alive until every
// session, reconnect and target handoff has stopped, then Close. Options returns
// independent identity/name buffers while sharing the application-owned Store.
// It does not unset key environment variables or retain their raw keys.
type Manager struct {
	mu       sync.Mutex
	stores   []*rdp.FileLicenseStore
	options  []*rdp.LicensingOptions
	closed   bool
	closeErr error
}

func (*Manager) Format(f fmt.State, _ rune)   { io.WriteString(f, "[redacted licensing stores]") }
func (*Manager) MarshalJSON() ([]byte, error) { return []byte(`"[redacted licensing stores]"`), nil }

type prepared struct {
	config    Config
	key       [32]byte
	directory string
	info      os.FileInfo
	leader    int
}

// Open checks every config/key and duplicate-store policy before writing any
// directory. Later filesystem failures close all already opened stores, but do
// not delete newly created data. A nil entry explicitly disables licensing for
// that connection. All identity and certificate choices remain per entry.
func Open(ctx context.Context, configs []*Config) (*Manager, error) {
	return open(ctx, configs, os.LookupEnv)
}
func open(ctx context.Context, configs []*Config, lookup func(string) (string, bool)) (*Manager, error) {
	if len(configs) > 17 {
		return nil, ErrConfig
	}
	pending := make([]prepared, len(configs))
	defer func() {
		for i := range pending {
			clear(pending[i].key[:])
		}
	}()
	for i, c := range configs {
		pending[i].leader = -1
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if c == nil {
			continue
		}
		normalized, e := c.Validate("")
		if e != nil {
			return nil, e
		}
		raw, ok := lookup(c.KeyEnv)
		if !ok || len(raw) != 64 {
			return nil, ErrConfig
		}
		key, e := hex.DecodeString(raw)
		if e != nil || len(key) != 32 {
			clear(key)
			return nil, ErrConfig
		}
		copy(pending[i].key[:], key)
		clear(key)
		if pending[i].key == ([32]byte{}) {
			return nil, ErrConfig
		}
		path, e := filepath.Abs(c.Store)
		if e != nil {
			return nil, ErrConfig
		}
		resolved, e := filepath.EvalSymlinks(path)
		if e == nil {
			path = resolved
		} else if !errors.Is(e, os.ErrNotExist) {
			return nil, rdp.ErrLicenseStoreIO
		}
		info, e := os.Stat(path)
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return nil, rdp.ErrLicenseStoreIO
		}
		q := &pending[i]
		q.config = *normalized
		q.directory = path
		q.info = info
		q.leader = i
		for j := 0; j < i; j++ {
			other := &pending[j]
			if other.leader < 0 {
				continue
			}
			same := path == other.directory || info != nil && other.info != nil && os.SameFile(info, other.info)
			if same {
				if q.key != other.key {
					return nil, ErrConfig
				}
				q.leader = other.leader
				pending[q.leader].config.Create = pending[q.leader].config.Create || c.Create
				break
			}
			// Distinct stores need independently generated keys. Unresolved aliases
			// fail closed here rather than guessing that a second identity is wanted.
			if q.key == other.key {
				return nil, ErrConfig
			}
		}
	}
	m := &Manager{options: make([]*rdp.LicensingOptions, len(configs))}
	opened := make(map[int]*rdp.FileLicenseStore)
	success := false
	defer func() {
		if !success {
			m.Close()
		}
	}()
	for i := range pending {
		q := &pending[i]
		if q.leader < 0 {
			continue
		}
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		store := opened[q.leader]
		if store == nil {
			leader := &pending[q.leader]
			o := rdp.FileLicenseStoreOptions{Key: leader.key}
			var e error
			if leader.config.Create {
				store, e = rdp.CreateFileLicenseStore(ctx, leader.directory, o)
			} else {
				store, e = rdp.OpenFileLicenseStore(ctx, leader.directory, o)
			}
			clear(o.Key[:])
			if e != nil {
				return nil, e
			}
			opened[q.leader] = store
			m.stores = append(m.stores, store)
		}
		id, e := store.HardwareID(ctx)
		if e != nil {
			return nil, e
		}
		c := q.config
		m.options[i] = &rdp.LicensingOptions{Store: store, CertificateSHA256: c.CertificateSHA256, Identity: rdp.LicenseIdentity{HardwareID: id, PlatformID: uint32(c.Platform), UserName: []byte(c.User), MachineName: []byte(c.Machine)}}
	}
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	success = true
	return m, nil
}
func (m *Manager) Options(index int) (*rdp.LicensingOptions, error) {
	if m == nil {
		return nil, ErrClosed
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, ErrClosed
	}
	if index < 0 || index >= len(m.options) {
		return nil, ErrConfig
	}
	return m.options[index].Clone(), nil
}
func ClearOptions(o *rdp.LicensingOptions) {
	if o != nil {
		clear(o.Identity.UserName)
		clear(o.Identity.MachineName)
		*o = rdp.LicensingOptions{}
	}
}
func (m *Manager) Close() error {
	if m == nil {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return m.closeErr
	}
	m.closed = true
	for _, o := range m.options {
		ClearOptions(o)
	}
	m.options = nil
	for _, s := range m.stores {
		m.closeErr = errors.Join(m.closeErr, s.Close())
	}
	m.stores = nil
	return m.closeErr
}
