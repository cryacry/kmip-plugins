package kmipengine

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
)

type Role struct {
	//L                *sync.RWMutex     `json:"-"`
	Operations       []operation       `json:"operations"`
	TlsClientKeyBits int               `json:"tls_client_key_bits"`
	TlsClientKeyTTL  string            `json:"tls_client_key_ttl"`
	TlsClientKeyType Tls_key_type      `json:"tls_client_key_type"`
	Cert             *x509.Certificate `json:"cert"`
}

func pathRole(b *KmipBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "scope/(?P<scope>[^/]+)/role/?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "kmip",
			},

			TakesArbitraryInput: true,
			Fields: map[string]*framework.FieldSchema{
				"scope": {
					Type:        framework.TypeString,
					Description: "The action of the scope\n\n",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleRoleList(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "list",
					},
				},
			},

			ExistenceCheck: b.handleRoleListExistenceCheck(),

			HelpSynopsis:    strings.TrimSpace(KmipHelpSynopsis),
			HelpDescription: strings.TrimSpace(KmipHelpDescription),
		},
		{
			Pattern: "scope/(?P<scope>[^/]+)/role/(?P<role>[^/]+)?$",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "kmip",
			},

			TakesArbitraryInput: true,
			Fields: map[string]*framework.FieldSchema{
				"scope": {
					Type:        framework.TypeString,
					Description: "The action of the scope\n\n",
				},
				"role": {
					Type:        framework.TypeString,
					Description: "The action of the role\n\n",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.handleRoleCreate(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "create",
					},
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.handleRoleWrite(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "write",
					},
				},
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.handleRoleRead(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "read",
					},
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.handleRoleDelete(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "delete",
					},
				},
			},

			ExistenceCheck: b.handleRoleExistenceCheck(),

			HelpSynopsis:    strings.TrimSpace(KmipHelpSynopsis),
			HelpDescription: strings.TrimSpace(KmipHelpDescription),
		},
	}
}

func (b *KmipBackend) handleRoleListExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		return true, nil
	}
}

func (b *KmipBackend) handleRoleExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		// Determine if the scope exists
		scope := data.Get("scope").(string)
		role := data.Get("role").(string)
		scopePath := fmt.Sprintf("scope/%s", scope)
		out, err := req.Storage.Get(ctx, scopePath)
		if out == nil {
			return false, fmt.Errorf("scope not exsist: %s", scope)
		}

		rolePath := fmt.Sprintf("scope/%s/role/%s", scope, role)
		out, err = req.Storage.Get(ctx, rolePath)
		if err != nil {
			return false, fmt.Errorf("role existence check err: %s : %s -- %w", scope, role, err)
		}
		return out != nil, nil
	}
}

func (b *KmipBackend) handleRoleCreate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scopeName := data.Get("scope").(string)
		roleName := data.Get("role").(string)
		//Check that some fields are given
		if len(req.Data) == 0 {
			return logical.ErrorResponse("missing data fields"), nil
		}

		// new role
		role := new(Role)
		// load default config
		config := new(Config)
		if err := config.readStorage(ctx, req); err != nil {
			return nil, err
		}
		role.TlsClientKeyBits = config.DefaultTLSClientKeyBits
		role.TlsClientKeyType = config.DefaultTLSClientKeyType
		role.TlsClientKeyTTL = config.DefaultTLSClientTTL
		// set req config
		if _, ok := req.Data["tls_client_key_bits"]; ok {
			role.TlsClientKeyBits = req.Data["tls_client_key_bits"].(int)
		}
		if _, ok := req.Data["tls_client_key_type"]; ok {
			role.TlsClientKeyType = req.Data["tls_client_key_type"].(Tls_key_type)
		}
		if _, ok := req.Data["tls_client_key_ttl"]; ok {
			role.TlsClientKeyTTL = req.Data["tls_client_key_ttl"].(string)
		}

		for i, k := range Operations {
			if _, ok := req.Data[k]; ok {
				role.Operations = append(role.Operations, i)
			}
		}

		if err := role.writeStorage(ctx, req, scopeName, roleName); err != nil {
			return nil, err
		}
		return nil, nil
	}
}

func (b *KmipBackend) handleRoleWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scopeName := data.Get("scope").(string)
		roleName := data.Get("role").(string)
		//Check that some fields are given
		if len(req.Data) == 0 {
			return logical.ErrorResponse("missing data fields"), nil
		}

		role := new(Role)
		// read role config
		role.readStorage(ctx, req, scopeName, roleName)
		// set req config
		if _, ok := req.Data["tls_client_key_bits"]; ok {
			role.TlsClientKeyBits = req.Data["tls_client_key_bits"].(int)
		}
		if _, ok := req.Data["tls_client_key_type"]; ok {
			role.TlsClientKeyType = req.Data["tls_client_key_type"].(Tls_key_type)
		}
		if _, ok := req.Data["tls_client_key_ttl"]; ok {
			role.TlsClientKeyTTL = req.Data["tls_client_key_ttl"].(string)
		}

		for i, k := range Operations {
			if _, ok := req.Data[k]; ok {
				role.Operations = append(role.Operations, i)
			}
		}

		if err := role.writeStorage(ctx, req, scopeName, roleName); err != nil {
			return nil, err
		}

		return nil, nil
	}
}

func (b *KmipBackend) handleRoleRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scopeName := data.Get("scope").(string)
		roleName := data.Get("role").(string)

		role := new(Role)

		if err := role.readStorage(ctx, req, scopeName, roleName); err != nil {
			return nil, err
		}
		rawData, err := role.responseFormat()
		if err != nil {
			return nil, fmt.Errorf("json encoding failed: %w", err)
		}
		resp := &logical.Response{
			Secret: &logical.Secret{},
			Data:   rawData,
		}
		return resp, nil
	}
}

func (b *KmipBackend) handleRoleList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// Right now we only handle directories, so ensure it ends with /; however,
		// some physical backends may not handle the "/" case properly, so only add
		// it if we're not listing the root
		scope := data.Get("scope").(string)
		path := "scope/" + scope + "/role/"

		d, err := listStorage(ctx, req, path)
		if err != nil {
			return nil, err
		}
		// Generate the response
		return logical.ListResponse(d), nil
	}
}

func (b *KmipBackend) handleRoleDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scopeName := data.Get("scope").(string)
		roleName := data.Get("role").(string)
		if err := deleteRole(ctx, req, scopeName, roleName); err != nil {
			return nil, err
		}
		return nil, nil
	}
}

func (r *Role) readStorage(ctx context.Context, req *logical.Request, scope, role string) error {
	path := "scope/" + scope + "/role/" + role
	data, err := readStorage(ctx, req, path)
	if err != nil {
		return err
	}
	if err := MapToStruct(data, r); err != nil {
		return err
	}
	return nil
}

func (r *Role) writeStorage(ctx context.Context, req *logical.Request, scope, role string) error {
	path := "scope/" + scope + "/role/" + role
	buf, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("json encoding failed: %w", err)
	}
	// Write out a new key
	entry := &logical.StorageEntry{
		Key:   path,
		Value: buf,
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	return nil
}

func (r *Role) responseFormat() (map[string]interface{}, error) {
	rawData, err := structToMapWithJsonTags(*r)
	if err != nil {
		return nil, fmt.Errorf("json encoding failed: %w", err)
	}
	delete(rawData, "cert")
	delete(rawData, "operations")
	for _, k := range r.Operations {
		rawData[Operations[k]] = true
	}
	return rawData, nil
}

func deleteRole(ctx context.Context, req *logical.Request, scope, role string) error {
	rolePath := fmt.Sprintf("scope/%s/role/%s", scope, role)
	credentialPath := rolePath + "/credential/"
	sn, err := listStorage(ctx, req, credentialPath)
	if err != nil {
		return err
	}
	// delete role ca
	for _, k := range sn {
		key := fmt.Sprintf("scope/%s/role/%s/credential/%s", scope, role, k)
		// Delete the key at the request path
		if err := req.Storage.Delete(ctx, key); err != nil {
			return err
		}
		// Delete the key at the request path
		if err := req.Storage.Delete(ctx, key+"_resData"); err != nil {
			return err
		}
	}
	// Delete the key at the request path
	if err := req.Storage.Delete(ctx, rolePath); err != nil {
		return err
	}
	return nil
}
