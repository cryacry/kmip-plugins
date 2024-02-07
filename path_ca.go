package kmipengine

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/hashicorp/vault/helper/namespace"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	caPath           = "ca"
	serialNumberPath = "serial_number"
)

// hashiCupsConfig includes the minimum configuration
// required to instantiate a new HashiCups client.
type CA struct {
	L          *sync.RWMutex
	CertPEM    string            `json:"cert_pem"`
	CertBytes  []byte            `json:"cert_bytes"`
	Cert       *x509.Certificate `json:"cert"`
	PrivateKey interface{}       `json:"private_key"`
}

// pathConfig extends the Vault API with a `/config`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. For example, password
// is marked as sensitive and will not be output
// when you read the configuration.
func pathCa(b *KmipBackend) *framework.Path {
	return &framework.Path{
		Pattern: caPath,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "kmip",
		},

		TakesArbitraryInput: true,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleCARead(),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "read",
				},
			},
		},

		ExistenceCheck: b.handleCAExistenceCheck(),

		HelpSynopsis:    strings.TrimSpace(KmipHelpSynopsis),
		HelpDescription: strings.TrimSpace(KmipHelpDescription),
	}
}

func (b *KmipBackend) handleCAExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		key := caPath

		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return false, fmt.Errorf("existence check failed: %w", err)
		}
		b.once.Do(func() { b.init(ctx, req) })
		return out != nil, nil
	}
}

func (b *KmipBackend) handleCARead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

		b.rootCA[0].L.RLock()
		rootCertPEM := b.rootCA[0].CertPEM
		b.rootCA[0].L.RUnlock()
		b.rootCA[1].L.RLock()
		childCertPEM := b.rootCA[1].CertPEM
		b.rootCA[1].L.RUnlock()
		resData := map[string]interface{}{
			"ca_pem": rootCertPEM + childCertPEM,
		}
		resp := &logical.Response{
			Secret: &logical.Secret{},
			Data:   resData,
		}
		return resp, nil
	}
}

func (b *KmipBackend) addRootCAChain(index int, certPEM string, certBytes []byte, cert *x509.Certificate, privateKey interface{}) {
	if index >= 0 {
		b.rootCA[index].L.Lock()
		b.rootCA[index].CertBytes = certBytes
		b.rootCA[index].CertPEM = certPEM
		b.rootCA[index].Cert = cert
		b.rootCA[index].PrivateKey = privateKey
		b.rootCA[index].L.Unlock()
		return
	}
	CA := CA{
		L:          new(sync.RWMutex),
		CertPEM:    certPEM,
		CertBytes:  certBytes,
		Cert:       cert,
		PrivateKey: privateKey,
	}
	b.rootCA = append(b.rootCA, &CA)
}

func (b *KmipBackend) SetCACert(role, scope, ttl string, ns *namespace.Namespace) (*big.Int, *x509.Certificate) {
	duration, _ := time.ParseDuration(ttl)
	b.SerialNumber.L.Lock()
	SerialNumber := b.SerialNumber.SN
	b.SerialNumber.SN.Add(b.SerialNumber.SN, big.NewInt(1))
	b.SerialNumber.L.Unlock()
	rootCert := &x509.Certificate{
		SerialNumber: SerialNumber,
		Subject: pkix.Name{
			CommonName:   role,                     // role
			Organization: []string{scope, ns.Path}, // scope

		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration), // 有效期
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return SerialNumber, rootCert
}

// pathConfigHelpSynopsis summarizes the help text for the configuration
const pathConfigHelpSynopsis = `Configure the HashiCups backend.`

// pathConfigHelpDescription describes the help text for the configuration
const pathConfigHelpDescription = `
The HashiCups secret backend requires credentials for managing
JWTs issued to users working with the products API.

You must sign up with a username and password and
specify the HashiCups address for the products API
before using this secrets backend.
`
