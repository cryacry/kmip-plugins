package kmipengine

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"sync"
	"time"
)

type Scope struct {
	L     *sync.RWMutex
	Roles map[string]*Role
}

func pathScope(b *KmipBackend) *framework.Path {
	return &framework.Path{
		Pattern: "scope/(?P<scope>[^/]+)$",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: "kmip",
		},

		TakesArbitraryInput: true,
		Fields: map[string]*framework.FieldSchema{
			"scope": {
				Type:        framework.TypeString,
				Description: "The action of the scope\n\n",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.handleScopeCreate(),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "write",
				},
			},
			logical.ListOperation: &framework.PathOperation{
				Callback: b.handleScopeList(),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "read",
				},
			},
		},

		ExistenceCheck: b.handleScopeExistenceCheck(),

		HelpSynopsis:    strings.TrimSpace(KmipHelpSynopsis),
		HelpDescription: strings.TrimSpace(KmipHelpDescription),
	}
}

func (b *KmipBackend) handleScopeExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		key := data.Get("scope").(string)
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

func (b *KmipBackend) handleScopeList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// Right now we only handle directories, so ensure it ends with /; however,
		// some physical backends may not handle the "/" case properly, so only add
		// it if we're not listing the root
		path := data.Get("scope").(string)
		if path != "" && !strings.HasSuffix(path, "/") {
			path = path + "/"
		}

		// List the keys at the prefix given by the request
		keys, err := req.Storage.List(ctx, path)
		var d []string
		for _, k := range keys {
			if !strings.ContainsAny(k, "/") {
				d = append(d, k)
			}
		}
		if err != nil {
			return nil, err
		}

		// Generate the response
		return logical.ListResponse(d), nil
	}
}

func (b *KmipBackend) handleScopeCreate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scope := data.Get("scope").(string)
		key := "scope/" + scope
		if key == "" {
			return logical.ErrorResponse("missing path"), nil
		}

		out, _ := req.Storage.Get(ctx, key)
		if out != nil {
			return nil, fmt.Errorf("existence check failed: the path existed")
		}

		// JSON encode the data
		d := map[string]interface{}{
			"create_time": time.Now().String(),
		}
		buf, err := json.Marshal(d)
		if err != nil {
			return nil, fmt.Errorf("json encoding failed: %w", err)
		}

		// Write out a new key
		entry := &logical.StorageEntry{
			Key:   key,
			Value: buf,
		}
		if err := req.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("failed to write: %w", err)
		}
		//kvEvent(ctx, b.Backend, "write", key, key, true, 1)
		b.scopes[scope] = &Scope{
			L:     new(sync.RWMutex),
			Roles: make(map[string]*Role),
		}
		return nil, nil
	}
}
