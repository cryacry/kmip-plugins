package kmipengine

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/cryacry/kmip-plugins/helper/namespace"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	caPath           = "ca"
	serialNumberPath = "serial_number"
)

// RSAKey and ECDSAKey represent the private keys of RSA and ECDSA, respectively
type RSAKey struct {
	PrivateKey *rsa.PrivateKey `json:"private_key_rsa"`
}

type ECDSAKey struct {
	PrivateKey *ecdsa.PrivateKey `json:"private_key_ecdsa"`
}

// PrivateKeyType is an interface for private key types
type PrivateKeyType interface {
	isPrivateKeyType() tlsKeyType
}

func (r *RSAKey) isPrivateKeyType() tlsKeyType   { return rsaKeyType }
func (e *ECDSAKey) isPrivateKeyType() tlsKeyType { return ecKeyType }

// hashiCupsConfig includes the minimum configuration
// required to instantiate a new HashiCups client.
type CA struct {
	L          *sync.RWMutex
	ParentCaSn string            `json:"parent_ca_sn"`
	CertPEM    string            `json:"cert_pem"`
	CertBytes  []byte            `json:"cert_bytes"`
	Cert       *x509.Certificate `json:"cert"`
	//PrivateKey interface{}       `json:"private_key"`
	PrivateKey PrivateKeyType `json:"private_key"`
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

func (c *CA) setCA(certPEM string, certBytes []byte, cert *x509.Certificate, privateKey PrivateKeyType, sn *big.Int) {
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

	privateKeyData := data["private_key"].(map[string]interface{})
	delete(data, "private_key")
	if _, ok := privateKeyData["private_key_rsa"]; ok {
		key := new(RSAKey)
		if err := MapToStruct(privateKeyData, key); err != nil {
			return err
		}
		c.PrivateKey = key
	} else if _, ok := privateKeyData["private_key_ecdsa"]; ok {
		key := new(RSAKey)
		if err := MapToStruct(privateKeyData, key); err != nil {
			return err
		}
		c.PrivateKey = key
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

func (c *CA) SetCACert(role, scope, ttl string, ns *namespace.Namespace, sn *SerialNumber) {
	duration, _ := time.ParseDuration(ttl)
	cert := &x509.Certificate{
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
	c.Cert = cert
}

func (c *CA) PrivateKeyPEM() []byte {
	var keyBytes []byte
	var _type string
	switch c.PrivateKey.isPrivateKeyType() {
	case rsaKeyType:
		privateKey := c.PrivateKey.(*RSAKey)
		keyBytes = x509.MarshalPKCS1PrivateKey(privateKey.PrivateKey)
		_type = "RSA PRIVATE KEY"
	case ecKeyType:
		privateKey := c.PrivateKey.(*ECDSAKey)
		keyBytes, _ = x509.MarshalECPrivateKey(privateKey.PrivateKey)
		_type = "EC PRIVATE KEY"
	}

	// 将私钥转换为 PEM 格式
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  _type,
		Bytes: keyBytes,
	})
	return privateKeyPEM
}

func (c *CA) CaGenerate(tlsCAKeyType tlsKeyType, tlsCAKeyBits int, parentCA *CA) error {

	// Set certificate information
	var CertBytes []byte
	// Generate random private key
	switch tlsCAKeyType {
	case rsaKeyType:
		privateKey, err := rsa.GenerateKey(rand.Reader, tlsCAKeyBits)
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return err
		}
		// Generate certificate
		if parentCA == nil {
			CertBytes, err = x509.CreateCertificate(rand.Reader, c.Cert, c.Cert, &privateKey.PublicKey, privateKey)
			c.ParentCaSn = ""
		} else {
			rootPrivateKey := parentCA.PrivateKey.(*RSAKey)
			CertBytes, err = x509.CreateCertificate(rand.Reader, c.Cert, parentCA.Cert, &privateKey.PublicKey, rootPrivateKey.PrivateKey)
			c.ParentCaSn = parentCA.Cert.SerialNumber.String()
		}
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return err
		}
		c.CertPEM, err = CertPEM(CertBytes)
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return err
		}
		c.CertBytes = CertBytes
		c.PrivateKey = &RSAKey{PrivateKey: privateKey}
		return nil

	case ecKeyType:
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return err
		}
		if parentCA == nil {
			CertBytes, err = x509.CreateCertificate(rand.Reader, c.Cert, c.Cert, &privateKey.PublicKey, privateKey)
			c.ParentCaSn = ""
		} else {
			rootPrivateKey := parentCA.PrivateKey.(*ECDSAKey)
			CertBytes, err = x509.CreateCertificate(rand.Reader, c.Cert, parentCA.Cert, &privateKey.PublicKey, rootPrivateKey.PrivateKey)
			c.ParentCaSn = parentCA.Cert.SerialNumber.String()
		}
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return err
		}
		c.CertPEM, err = CertPEM(CertBytes)
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return err
		}
		c.CertBytes = CertBytes
		c.PrivateKey = &ECDSAKey{PrivateKey: privateKey}
		return nil
	}
	return fmt.Errorf("This type of certificate type is not supported")
}

type SerialNumber struct {
	SN *big.Int
	L  *sync.RWMutex
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
	// update SN, Write SN+1 back to Storage
	snNew := snOld
	snNew.SN.Add(snNew.SN, big.NewInt(1))
	snNew.writeStorage(ctx, req)
	// return sn
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
