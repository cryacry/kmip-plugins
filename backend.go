package kmipengine

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"math/big"
	"strings"
	"sync"
)

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type kmip struct {
	// CA number
	SerialNumber CASerialNumber
	// kmip config information
	config Config
	// root ca chain
	rootCA []*CA
	// scope and role information
	scopes map[string]*Scope
}

// KmipBackend is used storing secrets directly into the physical
// backend.
type KmipBackend struct {
	*framework.Backend
	once sync.Once
	*kmip
}

func backend() *KmipBackend {
	b := &KmipBackend{
		kmip: &kmip{
			SerialNumber: CASerialNumber{
				L:  new(sync.RWMutex),
				SN: big.NewInt(0),
			},
			config: Config{},
			rootCA: []*CA{},
			scopes: make(map[string]*Scope),
		},
	}
	backend := &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(KmipHelp),

		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathCa(b),
			},
			pathScope(b),
			pathRole(b),
			pathCredentials(b),
		),
		Secrets: []*framework.Secret{},
	}

	b.Backend = backend

	return b
}

// read data from path
func (b *KmipBackend) init(ctx context.Context, req *logical.Request) {
	var data map[string]interface{}
	var err error
	data, err = readStorage(ctx, req, configPath)
	if err == nil {
		MapToStruct(data, &b.config)
	}
	data, err = readStorage(ctx, req, caPath)
	if err == nil {
		MapToStruct(data, &b.rootCA)
	}

	scopes, err := listStorage(ctx, req, "scope/")
	if err == nil {
		for _, k := range scopes {
			b.scopes[k] = new(Scope)
			roles, err := listStorage(ctx, req, fmt.Sprintf("scope/%s/role/", k))
			if err != nil {
				continue
			}
			for _, m := range roles {
				role, err := readStorage(ctx, req, fmt.Sprintf("scope/%s/role/%s", k, m))
				if err != nil {
					continue
				}
				r := new(Role)
				MapToStruct(role, r)
				b.scopes[k].Roles[m] = r
			}
		}
	}
	data, err = readStorage(ctx, req, serialNumberPath)
	if err == nil {
		MapToStruct(data, &b.SerialNumber)
	}

}

func readStorage(ctx context.Context, req *logical.Request, key string) (map[string]interface{}, error) {
	out, err := req.Storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	// Fast-path the no data case
	var data map[string]interface{}
	// load config from storage
	if err := jsonutil.DecodeJSON(out.Value, &data); err != nil {
		return nil, fmt.Errorf("json decoding failed: %w", err)
	}
	return data, nil
}

func listStorage(ctx context.Context, req *logical.Request, key string) ([]string, error) {
	if key != "" && !strings.HasSuffix(key, "/") {
		key = key + "/"
	}
	keys, err := req.Storage.List(ctx, key)
	if err != nil {
		return nil, err
	}
	//var d []string
	//for _, k := range keys {
	//	if !strings.ContainsAny(k, "/") {
	//		d = append(d, k)
	//	}
	//}
	return keys, nil
}

func writeStorage(ctx context.Context, req *logical.Request, key string, data map[string]interface{}) error {
	buf, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("json encoding failed: %w", err)
	}

	// Write out a new key
	entry := &logical.StorageEntry{
		Key:   key,
		Value: buf,
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	return nil
}

func deleteStorage(ctx context.Context, req *logical.Request, key string) error {
	//Delete the key at the request path
	if err := req.Storage.Delete(ctx, key); err != nil {
		return err
	}
	return nil
}

const KmipHelp = `
KMIP backend manages certificates and writes them to the backend.
`

const KmipHelpSynopsis = `
KMIP backend management certificate chain
`

const KmipHelpDescription = `
KMIP backend, managing the creation, update, and destruction of certificate chains
`
