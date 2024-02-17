package kmipengine

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
)

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// KmipBackend is used storing secrets directly into the physical
// backend.
type KmipBackend struct {
	*framework.Backend
}

func backend() *KmipBackend {
	b := &KmipBackend{}
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

func readStorage(ctx context.Context, req *logical.Request, key string) (map[string]interface{}, error) {
	out, err := req.Storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf(errPathDataIsEmpty)
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
	var d []string
	for _, k := range keys {
		if !strings.ContainsAny(k, "/") {
			d = append(d, k)
		}
	}
	return d, nil
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
