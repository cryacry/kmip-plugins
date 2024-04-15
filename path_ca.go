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
	"github.com/hashicorp/vault/helper/namespace"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"math/big"
	"strings"
	"sync"
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
	lock       *sync.RWMutex     `json:"-"`
	ParentCaSn string            `json:"parent_ca_sn"`
	CertPEM    string            `json:"cert_pem"`
	CertBytes  []byte            `json:"cert_bytes"`
	Cert       *x509.Certificate `json:"cert"`
	//PrivateKey interface{}       `json:"private_key"`
	PrivateKey PrivateKeyType `json:"private_key"`
	sn         string
}

func (kb *KmipBackend) newCA(sn string) *CA {
	kb.lock.Lock()
	defer kb.lock.Unlock()
	if lock, ok := kb.certLock[sn]; ok {
		return &CA{
			lock: lock,
			sn:   sn,
		}
	} else {
		kb.certLock[sn] = new(sync.RWMutex)
		return &CA{
			lock: kb.certLock[sn],
			sn:   sn,
		}
	}
}

func (c *CA) readStorage(ctx context.Context, storage logical.Storage, key string) error {
	c.lock.RLock()
	defer c.lock.RUnlock()
	path := key
	if !strings.HasSuffix(key, "/") {
		path = path + "/"
	}
	path = path + c.sn

	data, err := readStorage(ctx, storage, path)
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
		key := new(ECDSAKey)
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

func (c *CA) writeStorage(ctx context.Context, storage logical.Storage, key string) error {
	c.lock.Lock()
	defer c.lock.Unlock()
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
	if err := storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	return nil
}

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

func (kb *KmipBackend) handleCAExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		key := caPath
		kb.tokenAccessor = req.ClientTokenAccessor
		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return false, fmt.Errorf("existence check failed: %w", err)
		}
		return out != nil, nil
	}
}

func (kb *KmipBackend) handleCARead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		sn, err := listStorage(ctx, req.Storage, caPath)
		if err != nil {
			return nil, err
		}
		// read cert pem
		resData := map[string]interface{}{}
		pem := ""

		for _, k := range sn {
			ca := kb.newCA(k)
			ca.readStorage(ctx, req.Storage, caPath)
			if err != nil {
				return nil, err
			}
			Data := map[string]interface{}{
				"ca_pem":     ca.CertPEM,
				"privateKey": ca.PrivateKeyPEM(),
			}
			resData[k] = Data
			pem = pem + ca.CertPEM
		}
		resData["pem"] = pem
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

func (c *CA) SetCACert(role, scope, ttl string, ns *namespace.Namespace, sn *SerialNumber) {
	duration, _ := time.ParseDuration(ttl)
	cert := &x509.Certificate{
		SerialNumber: sn.SN,
		Subject: pkix.Name{
			Province:      []string{ns.Path}, // namespacePath
			Locality:      []string{scope},   // scope
			StreetAddress: []string{role},    // role
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(duration), // Validity period
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	c.Cert = cert
}

func (c *CA) setToken(auth *logical.Auth) {
	c.Cert.Subject.PostalCode = []string{auth.ClientToken}
	c.Cert.Subject.CommonName = auth.Accessor
}

func (c *CA) getTokenAccessor() string {
	return c.Cert.Subject.CommonName
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

	//Convert private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  _type,
		Bytes: keyBytes,
	})
	return privateKeyPEM
}

func (c *CA) PublicKeyPEM() []byte {
	var publicKey any
	keyType := ""
	switch c.PrivateKey.isPrivateKeyType() {
	case rsaKeyType:
		privateKey := c.PrivateKey.(*RSAKey)
		publicKey = privateKey.PrivateKey.PublicKey
		keyType = "RSA PUBLIC KEY"
	case ecKeyType:
		privateKey := c.PrivateKey.(*ECDSAKey)
		publicKey = privateKey.PrivateKey.PublicKey
		keyType = "EC PUBLIC KEY"
	}
	derBytes, _ := x509.MarshalPKIXPublicKey(publicKey)
	//if err != nil {
	//	return nil, err
	//}
	//Convert private key to PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  keyType,
		Bytes: derBytes,
	})
	return privateKeyPEM
}

func (c *CA) CaGenerate(tlsCAKeyType tlsKeyType, tlsCAKeyBits int, parentCA *CA) error {

	// Set certificate information
	var CertBytes []byte
	// Generate random private key
	switch tlsCAKeyType {
	case rsaKeyType:
		var privateKey *rsa.PrivateKey
		var err error

		switch tlsCAKeyBits {
		case 2048:
			privateKey, err = rsa.GenerateKey(rand.Reader, tlsCAKeyBits)
		case 3072:
			privateKey, err = rsa.GenerateKey(rand.Reader, tlsCAKeyBits)
		case 4096:
			privateKey, err = rsa.GenerateKey(rand.Reader, tlsCAKeyBits)
		default:
			return fmt.Errorf("unsupport rsa key bits size")
		}

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
		var privateKey *ecdsa.PrivateKey
		var err error

		switch tlsCAKeyBits {
		case 256:
			privateKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		case 384:
			privateKey, err = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		case 521:
			privateKey, err = ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		default:
			return fmt.Errorf("unsupport ec key bits size")
		}

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
	SN   *big.Int
	lock *sync.Mutex
}

func (kb *KmipBackend) newSerialNumber() *SerialNumber {
	kb.lock.Lock()
	defer kb.lock.Unlock()
	return &SerialNumber{lock: kb.snLock}
}

func (sn *SerialNumber) readStorage(ctx context.Context, storage logical.Storage) error {
	sn.lock.Lock()
	data, err := readStorage(ctx, storage, serialNumberPath)
	sn.lock.Unlock()
	var snOld SerialNumber
	if err != nil {
		// SerialNumber not initialized
		if err.Error() == errPathDataIsEmpty {
			snOld = SerialNumber{
				lock: sn.lock,
				SN:   big.NewInt(0),
			}
		} else {
			return err
		}
	} else {
		MapToStruct(data, &snOld)
		snOld.lock = sn.lock
	}
	// update SN, Write SN+1 back to Storage
	snNew := snOld
	snNew.SN.Add(snNew.SN, big.NewInt(1))
	snNew.writeStorage(ctx, storage)
	// return sn
	sn.SN = snOld.SN
	return nil
}

func (sn *SerialNumber) writeStorage(ctx context.Context, storage logical.Storage) error {
	sn.lock.Lock()
	defer sn.lock.Unlock()
	buf, err := json.Marshal(sn)
	if err != nil {
		return fmt.Errorf("json encoding failed: %w", err)
	}

	// Write out a new key
	entry := &logical.StorageEntry{
		Key:   serialNumberPath,
		Value: buf,
	}
	if err := storage.Put(ctx, entry); err != nil {
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
