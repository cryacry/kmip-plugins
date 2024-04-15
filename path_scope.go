package kmipengine

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"sync"
	"time"
)

func pathScope(b *KmipBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "scope/?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "kmip",
			},

			TakesArbitraryInput: true,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleScopeList(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "read",
					},
				},
			},

			ExistenceCheck: b.handleListScopeExistenceCheck(),

			HelpSynopsis:    strings.TrimSpace(KmipHelpSynopsis),
			HelpDescription: strings.TrimSpace(KmipHelpDescription),
		},
		{
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
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleScopeDelete(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "write",
					},
				},
			},

			ExistenceCheck: b.handleScopeExistenceCheck(),

			HelpSynopsis:    strings.TrimSpace(KmipHelpSynopsis),
			HelpDescription: strings.TrimSpace(KmipHelpDescription),
		},
	}
}

func (kb *KmipBackend) handleListScopeExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		return true, nil
	}
}

func (kb *KmipBackend) handleScopeExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		key := data.Get("scope").(string)
		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return false, fmt.Errorf("existence check failed: %w", err)
		}
		return out != nil, nil
	}
}

func (kb *KmipBackend) handleScopeList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// List the keys at the prefix given by the request
		keys, err := listStorage(ctx, req.Storage, "scope")
		if err != nil {
			return nil, err
		}
		// Generate the response
		return logical.ListResponse(keys), nil
	}
}

func (kb *KmipBackend) handleScopeCreate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scope := data.Get("scope").(string)
		kb.scopeLock[scope] = new(sync.RWMutex)
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
		if err := writeStorage(ctx, req.Storage, key, d); err != nil {
			return nil, fmt.Errorf("failed to write: %w", err)
		}
		return nil, nil
	}
}

func (kb *KmipBackend) handleScopeDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scopeName := data.Get("scope").(string)
		scopePath := "scope/" + scopeName
		flag := true // Allow deletion
		roles, err := listStorage(ctx, req.Storage, scopePath+"/role")
		if err != nil {
			return nil, err
		}
		if len(roles) > 0 {
			flag = false
			// judge force parameter
			if d, ok := req.Data["force"]; ok {
				if d == "true" {
					flag = true
				}
			}
		}
		if !flag {
			return nil, fmt.Errorf(errNeedForceParam)
		}
		for _, roleName := range roles {
			if err := kb.deleteRole(ctx, req, scopeName, roleName); err != nil {
				return nil, err
			}
		}
		// Delete the key at the request path
		if err := req.Storage.Delete(ctx, scopePath); err != nil {
			return nil, err
		}
		delete(kb.scopeLock, scopeName)
		return nil, nil
	}
}
