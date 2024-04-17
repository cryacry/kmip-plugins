package kmipengine

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

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
	lock                    *sync.RWMutex `json:"-"`
	DefaultTLSClientKeyBits int           `json:"default_tls_client_key_bits"`
	DefaultTLSClientKeyType tlsKeyType    `json:"default_tls_client_key_type"`
	DefaultTLSClientTTL     string        `json:"default_tls_client_ttl"`
	ListenAddrs             []string      `json:"listen_addrs"`
	ServerHostnames         []string      `json:"server_hostnames"`
	ServerIPs               []string      `json:"server_ips"`
	TLSCAKeyBits            int           `json:"tls_ca_key_bits"`
	TLSCAKeyType            tlsKeyType    `json:"tls_ca_key_type"`
	TLSMinVersion           string        `json:"tls_min_version"`
}

func (kb *KmipBackend) newConfig() Config {
	kb.lock.Lock()
	defer kb.lock.Unlock()
	if kb.configLock == nil {

		kb.configLock = new(sync.RWMutex)
	}
	return Config{
		lock: kb.configLock,
	}
}

func (c *Config) readStorage(ctx context.Context, storage logical.Storage) error {
	c.lock.RLock()
	defer c.lock.RUnlock()
	data, err := readStorage(ctx, storage, configPath)
	if err != nil {
		return err
	}
	if err := MapToStruct(data, c); err != nil {
		return err
	}
	return nil
}

func (c *Config) writeStorage(ctx context.Context, storage logical.Storage) error {
	c.lock.Lock()
	defer c.lock.Unlock()
	buf, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("json encoding failed: %w", err)
	}

	// Write out a new key
	entry := &logical.StorageEntry{
		Key:   configPath,
		Value: buf,
	}
	if err := storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	return nil
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

		Fields: map[string]*framework.FieldSchema{
			"listen_addrs": {
				Type:        framework.TypeStringSlice,
				Description: "The action of the api-lock\n\n",
				Default:     nil,
			},
			"server_hostnames": {
				Type:        framework.TypeStringSlice,
				Description: "The namespace of the operation\n\n",
				Default:     nil,
			},
			"server_ips": {
				Type:        framework.TypeStringSlice,
				Description: "The key of unlock\n\n",
				Default:     nil,
			},
		},

		TakesArbitraryInput: true,

		Operations: map[logical.Operation]framework.OperationHandler{
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

func (kb *KmipBackend) handleConfigExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		key := configPath
		kb.tokenAccessor = req.ClientTokenAccessor
		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return false, fmt.Errorf("existence check failed: %w", err)
		}
		return out != nil, nil
	}
}

func (kb *KmipBackend) handleConfigRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		rawData, err := readStorage(ctx, req.Storage, configPath)
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

func (kb *KmipBackend) handleConfigWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// Check that some fields are given
		if len(req.Data) == 0 {
			return logical.ErrorResponse("missing data fields"), nil
		}

		// load config
		config := kb.newConfig()
		if err := config.readStorage(ctx, req.Storage); err != nil {
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

		if raw := data.Get("listen_addrs").([]string); len(raw) > 0 {
			// restart Listener
			config.ListenAddrs = kb.setupListener(raw)
		}
		if raw := data.Get("server_hostnames").([]string); len(raw) > 0 {
			config.ServerHostnames = raw
		}
		if raw := data.Get("server_ips").([]string); len(raw) > 0 {
			config.ServerIPs = raw
		}

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
			out, err := listStorage(ctx, req.Storage, caPath)
			if err != nil {
				return nil, err
			}
			rootCA := kb.newCA(out[0])
			if err := rootCA.readStorage(ctx, req.Storage, caPath); err != nil {
				return nil, err
			}
			if err := rootCA.CaGenerate(config.TLSCAKeyType, config.TLSCAKeyBits, nil); err != nil {
				return nil, err
			}
			if err := rootCA.writeStorage(ctx, req.Storage, caPath); err != nil {
				return nil, err
			}
			// If there are more than two CA certificates in the CA chain
			for _, sn := range out[1:] {
				childCA := kb.newCA(sn)
				childCA.readStorage(ctx, req.Storage, caPath)
				if err := childCA.CaGenerate(config.TLSCAKeyType, config.TLSCAKeyBits, rootCA); err != nil {
					return nil, err
				}
				if err := childCA.writeStorage(ctx, req.Storage, caPath); err != nil {
					return nil, err
				}
				*rootCA = *childCA
			}

			// 2、Update certificates for all roles in all spaces
			scopes, err := listStorage(ctx, req.Storage, "scope")
			if err != nil {
				return nil, err
			}

			for _, scopeName := range scopes {
				roles, err := listStorage(ctx, req.Storage, "scope/"+scopeName)
				if err != nil {
					return nil, err
				}
				for _, roleName := range roles {
					role, err := kb.newRole(scopeName, roleName)
					if err != nil {
						return nil, err
					}
					role.readStorage(ctx, req.Storage, scopeName, roleName)
					key := fmt.Sprintf("scope/%s/role/%s/credential/", scopeName, roleName)
					sn, err := listStorage(ctx, req.Storage, key)
					if err != nil {
						return nil, err
					}
					for _, s := range sn {
						ca := kb.newCA(s)
						// read ca information
						if err := ca.readStorage(ctx, req.Storage, key); err != nil {
							return nil, err
						}
						// Regenerate certificate
						if err := ca.CaGenerate(role.TlsClientKeyType, role.TlsClientKeyBits, rootCA); err != nil {
							return nil, err
						}
						// storage ca
						if err := ca.writeStorage(ctx, req.Storage, key); err != nil {
							return nil, err
						}
						data := map[string]interface{}{
							"ca_chain":      []string{rootCA.CertPEM, rootCA.CertPEM},
							"certificate":   ca.CertPEM,
							"public_key":    ca.PublicKeyPEM(),
							"private_key":   ca.PrivateKeyPEM(),
							"serial_number": s,
						}
						// write credential information
						if err := writeStorage(ctx, req.Storage, key+s+"_resData", data); err != nil {
							return nil, fmt.Errorf("failed to write: %w", err)
						}
					}
				}
			}
		}
		if err := config.writeStorage(ctx, req.Storage); err != nil {
			return nil, fmt.Errorf("failed to write: %w", err)
		}
		return nil, nil
	}
}

func DefaultConfigMap() map[string]interface{} {
	// Return default tls information
	return map[string]interface{}{
		"default_tls_client_key_bits": 2048,
		"default_tls_client_key_type": rsaKeyType,
		"default_tls_client_ttl":      (336 * time.Hour).String(),
		"listen_addrs":                []string{"0.0.0.0:5696"},
		"server_hostnames":            []string{"localhost"},
		"server_ips":                  []string{"127.0.0.1", "::1"}, //Assign the split IP list to server_ips
		"tls_ca_key_bits":             2048,
		"tls_ca_key_type":             rsaKeyType,
		"tls_min_version":             "tls12",
	}
}
