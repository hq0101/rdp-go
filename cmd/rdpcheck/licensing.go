package main

import (
	"context"
	"flag"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/internal/licenseconfig"
)

type licenseFlags struct {
	flags  licenseconfig.Flags
	config *licenseconfig.Config
}

func (l *licenseFlags) register(fs *flag.FlagSet) { l.flags.Register(fs) }
func (l *licenseFlags) validate(fs *flag.FlagSet, mode, user string) error {
	var e error
	l.config, e = l.flags.Config(fs, mode, user)
	if e != nil {
		return e
	}
	if l.config != nil && licenseconfig.SameEnvironmentName(l.config.KeyEnv, fs.Lookup("password-env").Value.String()) {
		return licenseconfig.ErrConfig
	}
	return nil
}
func (l *licenseFlags) open(ctx context.Context) (*licenseconfig.Manager, *rdp.LicensingOptions, error) {
	if l.config == nil {
		return nil, nil, nil
	}
	m, e := licenseconfig.Open(ctx, []*licenseconfig.Config{l.config})
	if e != nil {
		return nil, nil, e
	}
	o, e := m.Options(0)
	if e != nil {
		m.Close()
		return nil, nil, e
	}
	return m, o, nil
}
