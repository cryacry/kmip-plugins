package kmipengine

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
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
	ParentCaSn string            `json:"parent_ca_sn"`
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
		return out != nil, nil
	}
}

func (b *KmipBackend) handleCARead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		sn, err := listStorage(ctx, req, caPath)
		if err != nil {
			return nil, err
		}
		// read cert pem
		pem := ""
		ca := new(CA)
		for _, k := range sn {
			ca.readStorage(ctx, req, caPath, k)
			if err != nil {
				return nil, err
			}
			pem = pem + ca.CertPEM
		}
		resData := map[string]interface{}{
			"ca_pem": pem,
		}
		resp := &logical.Response{
			Secret: &logical.Secret{},
			Data:   resData,
		}
		return resp, nil
	}

}

func (c *CA) setCA(certPEM string, certBytes []byte, cert *x509.Certificate, privateKey interface{}, sn *big.Int) {
	c.Cert = cert
	c.CertPEM = certPEM
	c.PrivateKey = privateKey
	c.CertBytes = certBytes
	if sn == nil {
		c.ParentCaSn = ""
	} else {
		c.ParentCaSn = sn.String()
	}
}

func (c *CA) readStorage(ctx context.Context, req *logical.Request, key string, sn string) error {
	path := key
	if !strings.HasSuffix(key, "/") {
		path = path + "/"
	}
	path = path + sn
	data, err := readStorage(ctx, req, path)
	if err != nil {
		return err
	}
	if err := MapToStruct(data, c); err != nil {
		return err
	}
	return nil
}

func (c *CA) writeStorage(ctx context.Context, req *logical.Request, key string) error {
	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("json encoding failed: %w", err)
	}

	if !strings.HasSuffix(key, "/") {
		key = key + "/"
	}
	// Write out a new key
	entry := &logical.StorageEntry{
		Key:   key + c.Cert.SerialNumber.String(),
		Value: buf,
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	return nil
}

func SetCACert(role, scope, ttl string, ns *namespace.Namespace, sn *SerialNumber) *x509.Certificate {
	duration, _ := time.ParseDuration(ttl)
	rootCert := &x509.Certificate{
		SerialNumber: sn.SN,
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
	return rootCert
}

func (sn *SerialNumber) readStorage(ctx context.Context, req *logical.Request) error {
	data, err := readStorage(ctx, req, serialNumberPath)
	var snOld SerialNumber
	if err != nil {
		// SerialNumber not initialized
		if err.Error() == errPathDataIsEmpty {
			snOld = SerialNumber{
				L:  new(sync.RWMutex),
				SN: big.NewInt(0),
			}
		} else {
			return err
		}
	} else {
		MapToStruct(data, &snOld)
	}
	// 将sn
	snNew := snOld
	snNew.SN.Add(snNew.SN, big.NewInt(1))
	buf, err := json.Marshal(snNew)
	if err != nil {
		return fmt.Errorf("json encoding failed: %w", err)
	}

	// Write out a new key
	entry := &logical.StorageEntry{
		Key:   serialNumberPath,
		Value: buf,
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	sn.SN = snOld.SN
	return nil
}

func (sn *SerialNumber) writeStorage(ctx context.Context, req *logical.Request) error {
	buf, err := json.Marshal(sn)
	if err != nil {
		return fmt.Errorf("json encoding failed: %w", err)
	}

	// Write out a new key
	entry := &logical.StorageEntry{
		Key:   serialNumberPath,
		Value: buf,
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	return nil
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
