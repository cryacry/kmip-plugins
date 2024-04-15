package kmipengine

import (
	"context"
	"encoding/json"
	"fmt"

	"net/http"
	"strings"
	"time"

	"github.com/cryacry/kmip-plugins/helper/namespace"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	configPath = "config"
)

// hashiCupsConfig includes the minimum configuration
// required to instantiate a new HashiCups client.
type Config struct {
	DefaultTLSClientKeyBits int        `json:"default_tls_client_key_bits"`
	DefaultTLSClientKeyType tlsKeyType `json:"default_tls_client_key_type"`
	DefaultTLSClientTTL     string     `json:"default_tls_client_ttl"`
	ListenAddrs             []string   `json:"listen_addrs"`
	ServerHostnames         []string   `json:"server_hostnames"`
	ServerIPs               []string   `json:"server_ips"`
	TLSCAKeyBits            int        `json:"tls_ca_key_bits"`
	TLSCAKeyType            tlsKeyType `json:"tls_ca_key_type"`
	TLSMinVersion           string     `json:"tls_min_version"`
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
				Callback: b.handleConfigCreate(),
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

func (b *KmipBackend) handleConfigCreate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		//ns, err := namespace.FromContext(ctx)
		ns := namespace.RootNamespace
		//if err != nil {
		//	return nil, err
		//}
		// Check that some fields are given
		if len(req.Data) == 0 {
			return logical.ErrorResponse("missing data fields"), nil
		}

		// load default config
		conf := DefaultConfigMap()
		// update config
		for i := range conf {
			if data, ok := req.Data[i]; ok {
				conf[i] = data
			}
		}
		var config Config
		MapToStruct(conf, &config)

		// create root ca chain
		rootCA := new(CA)
		childCA := new(CA)
		// set new CA-Cert
		s := new(SerialNumber)
		s.readStorage(ctx, req)
		rootCA.SetCACert("root", "root", "1000h", ns, s)
		s.readStorage(ctx, req)
		childCA.SetCACert("root", "root", "1000h", ns, s)

		// 1、Update root certificate chain
		// rootCA
		if err := rootCA.CaGenerate(config.TLSCAKeyType, config.TLSCAKeyBits, nil); err != nil {
			return nil, err
		}
		if err := rootCA.writeStorage(ctx, req, caPath); err != nil {
			return nil, err
		}
		// childCA
		if err := childCA.CaGenerate(config.TLSCAKeyType, config.TLSCAKeyBits, rootCA); err != nil {
			return nil, err
		}
		if err := childCA.writeStorage(ctx, req, caPath); err != nil {
			return nil, err
		}
		if err := config.writeStorage(ctx, req); err != nil {
			return nil, fmt.Errorf("failed to write: %w", err)
		}
		return nil, nil
	}
}

func (b *KmipBackend) handleConfigWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// Check that some fields are given
		if len(req.Data) == 0 {
			return logical.ErrorResponse("missing data fields"), nil
		}

		// load config
		var config Config
		if err := config.readStorage(ctx, req); err != nil {
			return nil, err
		}
		conf, err := structToMapWithJsonTags(config)
		if err != nil {
			return nil, err
		}
		// update config
		for i := range conf {
			if data, ok := req.Data[i]; ok {
				conf[i] = data
			}
		}
		MapToStruct(conf, &config)

		// Determine if it is necessary to regenerate the CA certificate
		newCA := false
		if _, ok := req.Data[CAType]; ok {
			newCA = true
		}
		if _, ok := req.Data[CABits]; ok {
			newCA = true
		}

		// update caCert
		if newCA {
			out, err := listStorage(ctx, req, caPath)
			if err != nil {
				return nil, err
			}
			rootCA := new(CA)
			if err := rootCA.readStorage(ctx, req, caPath, out[0]); err != nil {
				return nil, err
			}
			if err := rootCA.CaGenerate(config.TLSCAKeyType, config.TLSCAKeyBits, nil); err != nil {
				return nil, err
			}
			if err := rootCA.writeStorage(ctx, req, caPath); err != nil {
				return nil, err
			}
			childCA := new(CA)
			// If there are more than two CA certificates in the CA chain
			for _, sn := range out[1:] {
				childCA.readStorage(ctx, req, caPath, sn)
				if err := childCA.CaGenerate(config.TLSCAKeyType, config.TLSCAKeyBits, rootCA); err != nil {
					return nil, err
				}
				if err := childCA.writeStorage(ctx, req, caPath); err != nil {
					return nil, err
				}
				*rootCA = *childCA
			}

			// 2、Update certificates for all roles in all spaces
			scopes, err := listStorage(ctx, req, "scope")
			if err != nil {
				return nil, err
			}
			ca := new(CA)
			role := new(Role)
			for _, scopeName := range scopes {
				roles, err := listStorage(ctx, req, "scope/"+scopeName)
				if err != nil {
					return nil, err
				}
				for _, roleName := range roles {
					role.readStorage(ctx, req, scopeName, roleName)
					key := fmt.Sprintf("scope/%s/role/%s/credential/", scopeName, roleName)
					sn, err := listStorage(ctx, req, key)
					if err != nil {
						return nil, err
					}
					for _, s := range sn {
						// read ca information
						if err := ca.readStorage(ctx, req, key, s); err != nil {
							return nil, err
						}
						// Regenerate certificate
						if err := ca.CaGenerate(role.TlsClientKeyType, role.TlsClientKeyBits, childCA); err != nil {
							return nil, err
						}
						// storage ca
						if err := ca.writeStorage(ctx, req, key); err != nil {
							return nil, err
						}
						data := map[string]interface{}{
							"ca_chain":      []string{rootCA.CertPEM, childCA.CertPEM},
							"certificate":   ca.CertPEM,
							"private_key":   ca.PrivateKeyPEM(),
							"serial_number": s,
						}
						// write credential information
						if err := writeStorage(ctx, req, key+s+"_resData", data); err != nil {
							return nil, fmt.Errorf("failed to write: %w", err)
						}
					}
				}
			}
		}
		if err := config.writeStorage(ctx, req); err != nil {
			return nil, fmt.Errorf("failed to write: %w", err)
		}
		return nil, nil
	}
}

func (c *Config) readStorage(ctx context.Context, req *logical.Request) error {
	data, err := readStorage(ctx, req, configPath)
	if err != nil {
		return err
	}
	if err := MapToStruct(data, c); err != nil {
		return err
	}
	return nil
}

func (c *Config) writeStorage(ctx context.Context, req *logical.Request) error {
	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("json encoding failed: %w", err)
	}

	// Write out a new key
	entry := &logical.StorageEntry{
		Key:   configPath,
		Value: buf,
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	return nil
}

func DefaultConfigMap() map[string]interface{} {
	// Return default tls information
	return map[string]interface{}{
		"default_tls_client_key_bits": 2048,
		"default_tls_client_key_type": rsaKeyType,
		"default_tls_client_ttl":      (336 * time.Hour).String(),
		"listen_addrs":                []string{"0.0.0.0:5696"},
		"server_hostnames":            []string{"localhost"},
		"server_ips":                  []string{"127.0.0.1", "::1"}, // 将拆分后的IP列表赋值给server_ips
		"tls_ca_key_bits":             2048,
		"tls_ca_key_type":             rsaKeyType,
		"tls_min_version":             "tls12",
	}
}
