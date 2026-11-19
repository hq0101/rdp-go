// Protocol-only reconnect example. Credentials use RDPGO_ADDR, RDPGO_USER,
// RDPGO_PASSWORD and optional RDPGO_DOMAIN / RDPGO_CERT_SHA256.
// -simulate-disconnect cuts only this example's TCP proxy connection. It does
// not change the server's network or log off its desktop session.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/gcc"
)

type proxy struct {
	listener net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	mu       sync.Mutex
	pairs    map[net.Conn]net.Conn
	wg       sync.WaitGroup
}

func newProxy(ctx context.Context, target string) (*proxy, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(ctx)
	p := &proxy{listener: l, ctx: ctx, cancel: cancel, pairs: make(map[net.Conn]net.Conn)}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			local, err := l.Accept()
			if err != nil {
				return
			}
			p.wg.Add(1)
			go func() {
				defer p.wg.Done()
				defer local.Close()
				remote, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", target)
				if err != nil {
					return
				}
				defer remote.Close()
				p.mu.Lock()
				if ctx.Err() != nil {
					p.mu.Unlock()
					return
				}
				p.pairs[local] = remote
				p.mu.Unlock()
				defer func() { p.mu.Lock(); delete(p.pairs, local); p.mu.Unlock() }()
				done := make(chan struct{})
				go func() { io.Copy(remote, local); remote.Close(); close(done) }()
				io.Copy(local, remote)
				local.Close()
				<-done
			}()
		}
	}()
	return p, nil
}
func (p *proxy) drop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for local, remote := range p.pairs {
		local.Close()
		remote.Close()
	}
}
func (p *proxy) close() { p.cancel(); p.listener.Close(); p.drop(); p.wg.Wait() }

func credentials() rdp.Credentials {
	return rdp.Credentials{Username: os.Getenv("RDPGO_USER"), Domain: os.Getenv("RDPGO_DOMAIN"), Password: os.Getenv("RDPGO_PASSWORD")}
}

func run(simulate bool, cycles int, timeout time.Duration) error {
	for _, key := range []string{"RDPGO_ADDR", "RDPGO_USER", "RDPGO_PASSWORD"} {
		if _, ok := os.LookupEnv(key); !ok || (key != "RDPGO_PASSWORD" && os.Getenv(key) == "") {
			return fmt.Errorf("missing environment variable %s", key)
		}
	}
	if cycles < 1 || cycles > 3 || timeout <= 0 || timeout > 10*time.Minute {
		return errors.New("cycles must be 1..3 and timeout in (0,10m]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	address := os.Getenv("RDPGO_ADDR")
	opts := rdp.Options{CertificateSHA256: os.Getenv("RDPGO_CERT_SHA256"), AutoReconnect: true}
	var p *proxy
	if simulate {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return err
		}
		p, err = newProxy(ctx, address)
		if err != nil {
			return err
		}
		defer p.close()
		opts.TLSConfig = &tls.Config{ServerName: host}
		address = p.listener.Addr().String()
	}
	s, err := rdp.DialSession(ctx, address, credentials(), opts, gcc.ClientSettings{Width: 1280, Height: 720})
	if err != nil {
		return err
	}
	defer func() { s.Close() }()
	enc := json.NewEncoder(os.Stdout)
	for cycle := 1; cycle <= cycles; cycle++ {
		loggedOn := false
		for !loggedOn || !s.ReconnectInfo().CookieAvailable {
			e, err := s.ReadEvent(ctx)
			if err != nil {
				return err
			}
			if e.Kind == rdp.EventLogonInfo && e.Logon.Logon {
				loggedOn = true
			}
		}
		if err := enc.Encode(struct {
			Phase string
			Cycle int
			Info  rdp.ReconnectInfo
		}{"cookie-received", cycle, s.ReconnectInfo()}); err != nil {
			return err
		}
		if simulate {
			p.drop()
		}
		for {
			_, err = s.ReadEvent(ctx)
			if err != nil {
				break
			}
		}
		if !s.ReconnectInfo().Ready {
			return fmt.Errorf("connection ended without a usable network-reconnect credential: %w", err)
		}
		old := s
		next, err := old.Reconnect(ctx, credentials(), rdp.ReconnectPolicy{})
		if err != nil {
			return err
		}
		s = next
		old.Close()
		if err := enc.Encode(struct {
			Phase           string
			Cycle, Attempts int
			Info            rdp.ReconnectInfo
		}{"session-restored", cycle, old.ReconnectInfo().Attempts, s.ReconnectInfo()}); err != nil {
			return err
		}
		if s.Info().RefreshRect {
			if err := s.Refresh(ctx); err != nil {
				return err
			}
		}
	}
	return nil
}
func main() {
	simulate := flag.Bool("simulate-disconnect", false, "cut this process's local proxy connection after receiving a cookie")
	cycles := flag.Int("cycles", 1, "number of consecutive recoveries (1..3)")
	timeout := flag.Duration("timeout", 90*time.Second, "total timeout")
	flag.Parse()
	if err := run(*simulate, *cycles, *timeout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
