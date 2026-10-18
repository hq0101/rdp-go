package redirectconfig

import (
	"context"
	"errors"
	"os"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/internal/gatewayconfig"
	"github.com/hq0101/rdp-go/internal/licenseconfig"
	"github.com/hq0101/rdp-go/rdgateway"
)

// Connections owns initial and per-hop gateway credentials and license stores.
// Close only after all sessions, candidates, readers and device workers stop.
type Connections struct {
	Plan      *Plan
	Licenses  *licenseconfig.Manager
	Licensing *rdp.LicensingOptions
	Gateways  *gatewayconfig.Manager
	Gateway   *rdp.GatewayOptions
}

func (c *Connections) Close() {
	if c == nil {
		return
	}
	if c.Plan != nil {
		c.Plan.Close()
	}
	c.Gateways.Close()
	licenseconfig.ClearOptions(c.Licensing)
	if c.Licenses != nil {
		c.Licenses.Close()
	}
	c.Gateway = nil
	c.Licensing = nil
}

// GatewaySetup selects the initial route and application policy implementation.
// ReliableUDP rejects ANY gateway route during local validation, before secrets
// are consumed or stores opened. It never falls back to a direct UDP connection.
type GatewaySetup struct {
	Config      *gatewayconfig.Config
	Reporter    *gatewayconfig.Reporter
	ApplyPolicy func(context.Context, rdgateway.Info) error
	ReliableUDP bool
}

// LoadConnections validates the whole plan, separate secret references, gateway
// trust and credentials before opening stores or consuming password variables.
// Every hop chooses its own gateway. A gateway-to-direct hop must allow_direct.
func LoadConnections(ctx context.Context, path, initialAddress string, resources bool, initial *licenseconfig.Config, initialPasswordEnv string,
	setup GatewaySetup) (*Connections, error) {
	p, names, e := readPlan(path, initialAddress, resources)
	if e != nil {
		return nil, e
	}
	c := &Connections{Plan: p}
	success := false
	defer func() {
		if !success {
			c.Close()
		}
	}()
	configs := []*licenseconfig.Config{initial}
	gateways := []*gatewayconfig.Config{setup.Config}
	if p != nil {
		via := setup.Config != nil
		for _, entry := range p.entries {
			if via && entry.gateway == nil && !entry.target.AllowDirect {
				return nil, rdp.ErrGatewayRoute
			}
			configs = append(configs, entry.licensing)
			gateways = append(gateways, entry.gateway)
			via = entry.gateway != nil
		}
	}
	if setup.ReliableUDP {
		for _, g := range gateways {
			if g != nil {
				return nil, rdp.ErrGatewayRoute
			}
		}
	}
	passwordNames := append([]string{initialPasswordEnv}, names...)
	reserved := append([]string(nil), passwordNames...)
	for _, cfg := range configs {
		if cfg == nil {
			continue
		}
		for _, name := range passwordNames {
			if name != "" && licenseconfig.SameEnvironmentName(cfg.KeyEnv, name) {
				return nil, ErrConfig
			}
		}
		reserved = append(reserved, cfg.KeyEnv)
	}
	c.Gateways, e = gatewayconfig.Prepare(ctx, gateways, reserved, setup.Reporter, setup.ApplyPolicy)
	if e != nil {
		return nil, e
	}
	c.Gateway, e = c.Gateways.Options(0)
	if e != nil {
		return nil, e
	}
	c.Licenses, e = licenseconfig.Open(ctx, configs)
	if e != nil {
		return nil, e
	}
	c.Licensing, e = c.Licenses.Options(0)
	if e != nil {
		return nil, e
	}
	if p != nil {
		p.gateways = c.Gateways
		for i := range p.entries {
			p.entries[i].target.Licensing, e = c.Licenses.Options(i + 1)
			if e != nil {
				return nil, e
			}
		}
	}
	if e = ctx.Err(); e != nil {
		return nil, e
	}
	if e = c.Gateways.Consume(); e != nil {
		return nil, e
	}
	for _, name := range names {
		if e = os.Unsetenv(name); e != nil {
			return nil, errors.New("cannot clear redirection password environment variable")
		}
	}
	success = true
	return c, nil
}
