package rdgateway

import (
	"github.com/hq0101/rdp-go/internal/ntlm"
	"github.com/hq0101/rdp-go/internal/rdghttp"
)

// KerberosOptions configures password-based gateway HTTP Negotiate/Kerberos.
// Realm and exactly one of KDC/Proxy are required. ServicePrincipal defaults to HTTP/<TLS ServerName>
// and an override must also use HTTP/host. Enctypes is AES-only (20,19,18,17 by
// default); Network defaults to tcp, Timeout to 15s, Lifetime to 8h. There is no
// OS credential cache, discovery, delegation or fallback to NTLM. This is wholly
// independent of target RDP KerberosOptions (whose service is TERMSRV/host).
type KerberosOptions rdghttp.HTTPKerberosOptions

// Clone returns an owned configuration without credentials, tickets or keys.
func (o KerberosOptions) Clone() *KerberosOptions {
	o.Enctypes = append([]int32(nil), o.Enctypes...)
	if o.Proxy != nil {
		o.Proxy = o.Proxy.Clone()
	}
	return &o
}

// Validate performs local validation only. target is HTTP/<gateway TLS name>.
func (o KerberosOptions) Validate(target string, c Credentials) error {
	return rdghttp.HTTPKerberosOptions(o).Validate(target, ntlm.Credentials{Username: c.Username, Domain: c.Domain, Password: c.Password})
}
