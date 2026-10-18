package redirectconfig

import (
	"context"

	"github.com/hq0101/rdp-go"
	"github.com/hq0101/rdp-go/internal/licenseconfig"
)

// LoadWithLicensing validates the complete local plan and key references, then
// opens all selected stores before any network connection. The returned Manager
// is owned by the caller, including when Plan is nil. Close sessions, then Plan,
// then Manager. No hop inherits the initial connection's licensing configuration.
// Password variables are consumed only after store setup succeeds; key variables
// are retained for the caller to manage and cannot alias any password variable.
func LoadWithLicensing(ctx context.Context, path, initialAddress string, resources bool, initial *licenseconfig.Config, initialPasswordEnv string) (*Plan, *licenseconfig.Manager, *rdp.LicensingOptions, error) {
	c, e := LoadConnections(ctx, path, initialAddress, resources, initial, initialPasswordEnv, GatewaySetup{})
	if e != nil {
		return nil, nil, nil, e
	}
	c.Gateways.Close() // no gateway config is accepted by this legacy entry point
	return c.Plan, c.Licenses, c.Licensing, nil
}
