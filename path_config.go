package kmipengine

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configPath = "config"
)

// hashiCupsConfig includes the minimum configuration
// required to instantiate a new HashiCups client.
type Config struct {
	DefaultTLSClientKeyBits int          `json:"default_tls_client_key_bits"`
	DefaultTLSClientKeyType Tls_key_type `json:"default_tls_client_key_type"`
	DefaultTLSClientTTL     string       `json:"default_tls_client_ttl"`
	ListenAddrs             []string     `json:"listen_addrs"`
	ServerHostnames         []string     `json:"server_hostnames"`
	ServerIPs               []string     `json:"server_ips"`
	TLSCAKeyBits            int          `json:"tls_ca_key_bits"`
	TLSCAKeyType            Tls_key_type `json:"tls_ca_key_type"`
	TLSMinVersion           string       `json:"tls_min_version"`
}

// pathConfig extends the Vault API with a `/config`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. For example, password
// is marked as sensitive and will not be output
// when you read the configuration.
func pathConfig(b *KmipBackend) *framework.Path {
	return &framework.Path{
		Pattern: configPath,

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "kmip",
		},

		TakesArbitraryInput: true,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite(),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "write",
				},
				Responses: map[int][]framework.Response{
					http.StatusNoContent: {{
						Description: http.StatusText(http.StatusNoContent),
					}},
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleConfigWrite(),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "write",
				},
				Responses: map[int][]framework.Response{
					http.StatusNoContent: {{
						Description: http.StatusText(http.StatusNoContent),
					}},
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleConfigRead(),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "read",
				},
				Responses: map[int][]framework.Response{
					http.StatusOK: {{
						Description: http.StatusText(http.StatusOK),
					}},
				},
			},
		},

		ExistenceCheck: b.handleConfigExistenceCheck(),

		HelpSynopsis:    strings.TrimSpace(KmipHelpSynopsis),
		HelpDescription: strings.TrimSpace(KmipHelpDescription),
	}
}

func (b *KmipBackend) handleConfigExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		key := configPath

		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return false, fmt.Errorf("existence check failed: %w", err)
		}
		if out != nil {
			b.once.Do(func() { b.init(ctx, req) })
		}
		return out != nil, nil
	}
}

func (b *KmipBackend) handleConfigRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		rawData, err := readStorage(ctx, req, configPath)
		if err != nil {
			return nil, fmt.Errorf("json decoding failed: %w", err)
		}
		resp := &logical.Response{
			Secret: &logical.Secret{},
			Data:   rawData,
		}
		return resp, nil
	}

}

func (b *KmipBackend) handleConfigWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		key := configPath
		ns, err := namespace.FromContext(ctx)
		if err != nil {
			return nil, err
		}
		// Check that some fields are given
		if len(req.Data) == 0 {
			return logical.ErrorResponse("missing data fields"), nil
		}
		var conf map[string]interface{}
		out, err := req.Storage.Get(ctx, key)
		// Fast-path the no data case
		if out == nil {
			// load default config
			conf = DefaultConfigMap()
		} else {
			// load config from storage
			if err := jsonutil.DecodeJSON(out.Value, &conf); err != nil {
				return nil, fmt.Errorf("json decoding failed: %w", err)
			}
		}
		// Determine if it is necessary to regenerate the CA certificate
		newCA := false
		if _, ok := req.Data[CAType]; ok {
			newCA = true
		}
		if _, ok := req.Data[CABits]; ok {
			newCA = true
		}
		// update config
		for i := range conf {
			if data, ok := req.Data[i]; ok {
				conf[i] = data
			}
		}
		// update cache
		MapToStruct(conf, &b.config)

		// update caCert
		{
			out, err := req.Storage.Get(ctx, caPath)
			if err != nil && out != nil && newCA == false {
				// CA exists and does not need to be updated
				goto setConfig
			}
			// set new CA-Cert
			// 1、更新根证书链
			_, rootCert := b.SetCACert("root", "root", "1000h", ns)
			rootCertBytes, rootPrivateKey, err := CaGenerate(b.config.TLSCAKeyType, b.config.TLSCAKeyBits, rootCert)
			if err != nil {
				return nil, err
			}
			_, childCert := b.SetCACert("rootChildCA", "root", "1000h", ns)
			childCertBytes, childPrivateKey, err := ChildCaGenerate(b.config.TLSCAKeyType, b.config.TLSCAKeyBits, rootCert, childCert, rootPrivateKey)
			if err != nil {
				return nil, err
			}

			// update SerialNumber
			buf, err := json.Marshal(b.SerialNumber)
			if err != nil {
				return nil, fmt.Errorf("json encoding failed: %w", err)
			}

			// Write out a new config
			entry := &logical.StorageEntry{
				Key:   serialNumberPath,
				Value: buf,
			}
			if err := req.Storage.Put(ctx, entry); err != nil {
				return nil, fmt.Errorf("failed to write: %w", err)
			}

			rootPEM, err := CertPEM(rootCertBytes)
			if err != nil {
				return nil, err
			}
			childPEM, err := CertPEM(childCertBytes)
			if err != nil {
				return nil, err
			}
			// add in cache
			b.addRootCAChain(-1, rootPEM, rootCertBytes, rootCert, rootPrivateKey)
			b.addRootCAChain(-1, childPEM, childCertBytes, childCert, childPrivateKey)
			// update CA Chain
			buf, err = json.Marshal(b.rootCA)
			if err != nil {
				return nil, fmt.Errorf("json encoding failed: %w", err)
			}
			// Write out a new config
			entry = &logical.StorageEntry{
				Key:   caPath,
				Value: buf,
			}
			if err := req.Storage.Put(ctx, entry); err != nil {
				return nil, fmt.Errorf("failed to write: %w", err)
			}

			// 2、更新所有空间下的所有角色的证书
			for scopeName, scopes := range b.scopes {
				for roleName, roleConf := range scopes.Roles {
					key := fmt.Sprintf("scope/%s/role/%s/credential/", scopeName, roleName)
					// Generate Cert
					CertBytes, PrivateKey, err := ChildCaGenerate(roleConf.TlsClientKeyType, roleConf.TlsClientKeyBits, b.rootCA[1].Cert, roleConf.Cert, childPrivateKey)
					// PEM format
					certificate, err := CertPEM(CertBytes)
					if err != nil {
						continue
					}
					data := map[string]interface{}{
						"ca_chain":      []string{b.rootCA[0].CertPEM, b.rootCA[1].CertPEM},
						"certificate":   certificate,
						"private_key":   PrivateKeyPEM(PrivateKey, roleConf),
						"serial_number": roleConf.SerialNumber,
					}
					// write credential information
					if err := writeStorage(ctx, req, key+roleConf.SerialNumber, data); err != nil {
						return nil, fmt.Errorf("failed to write: %w", err)
					}

				}
			}
		}

	setConfig:
		if err := writeStorage(ctx, req, key, conf); err != nil {
			return nil, fmt.Errorf("failed to write: %w", err)
		}
		return nil, nil
	}
}

func DefaultConfigMap() map[string]interface{} {
	// Return default tls information
	return map[string]interface{}{
		"default_tls_client_key_bits": 2048,
		"default_tls_client_key_type": rsa_key_type,
		"default_tls_client_ttl":      (336 * time.Hour).String(),
		"listen_addrs":                []string{"0.0.0.0:5696"},
		"server_hostnames":            []string{"localhost"},
		"server_ips":                  []string{"127.0.0.1", "::1"}, // 将拆分后的IP列表赋值给server_ips
		"tls_ca_key_bits":             2048,
		"tls_ca_key_type":             rsa_key_type,
		"tls_min_version":             "tls12",
	}
}

//func (b *KmipBackend) handleDelete() framework.OperationFunc {
//	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
//		key := data.Get("path").(string)
//
//		// delete the role
//		if strings.Contains(key, "role") {
//			re := regexp.MustCompile(`scope/(?P<scope>.+)/role/(?P<role>.+)`)
//			match := re.FindStringSubmatch(key)
//			if len(match) != 3 {
//				return nil, fmt.Errorf("must specify the deleted rolename")
//			}
//
//		}
//
//		// Delete the key at the request path
//		if err := req.Storage.Delete(ctx, key); err != nil {
//			return nil, err
//		}
//
//		//kvEvent(ctx, b.Backend, "delete", key, "", true, 1)
//
//		return nil, nil
//	}
//}
//
//func (b *KmipBackend) handleList() framework.OperationFunc {
//	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
//		// Right now we only handle directories, so ensure it ends with /; however,
//		// some physical backends may not handle the "/" case properly, so only add
//		// it if we're not listing the root
//		path := data.Get("path").(string)
//		if path != "" && !strings.HasSuffix(path, "/") {
//			path = path + "/"
//		}
//
//		// List the keys at the prefix given by the request
//		keys, err := req.Storage.List(ctx, path)
//		var d []string
//		for _, k := range keys {
//			if !strings.ContainsAny(k, "/") {
//				d = append(d, k)
//			}
//		}
//		if err != nil {
//			return nil, err
//		}
//
//		// Generate the response
//		return logical.ListResponse(d), nil
//	}
//}
