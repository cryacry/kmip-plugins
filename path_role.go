package kmipengine

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
	"sync"
)

type Role struct {
	roleLock         *sync.RWMutex `json:"-"`
	scopeLock        *sync.RWMutex
	Operations       map[operation]struct{} `json:"operations"`
	TlsClientKeyBits int                    `json:"tls_client_key_bits"`
	TlsClientKeyTTL  string                 `json:"tls_client_key_ttl"`
	TlsClientKeyType tlsKeyType             `json:"tls_client_key_type"`
	Cert             *x509.Certificate      `json:"cert"`
}

func (kb *KmipBackend) newRole(scopeName, roleName string) (role *Role, err error) {
	kb.lock.Lock()
	defer kb.lock.Unlock()
	role = &Role{}
	if lock, ok := kb.scopeLock[scopeName]; ok {
		role.scopeLock = lock
	} else {
		err = fmt.Errorf("scope not exsist")
	}
	if lock, ok := kb.roleLock[scopeName+"-"+roleName]; ok {
		role.roleLock = lock
	} else {
		kb.roleLock[scopeName+"-"+roleName] = new(sync.RWMutex)
		role.roleLock = kb.roleLock[scopeName+"-"+roleName]
	}
	return
}

func (r *Role) readStorage(ctx context.Context, storage logical.Storage, scope, role string) error {
	r.scopeLock.RLock()
	defer r.scopeLock.RUnlock()
	r.roleLock.RLock()
	defer r.roleLock.RUnlock()
	path := "scope/" + scope + "/role/" + role
	data, err := readStorage(ctx, storage, path)
	if err != nil {
		return err
	}
	if data == nil {
		return fmt.Errorf("role not exsist")
	}
	if err := MapToStruct(data, r); err != nil {
		return err
	}
	return nil
}

func (r *Role) writeStorage(ctx context.Context, storage logical.Storage, scope, role string) error {
	r.scopeLock.RLock()
	defer r.scopeLock.RUnlock()
	r.roleLock.Lock()
	defer r.roleLock.Unlock()
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
	if err := storage.Put(ctx, entry); err != nil {
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
	for k := range r.Operations {
		rawData[Operations[k]] = true
	}
	return rawData, nil
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

func (kb *KmipBackend) handleRoleListExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		return true, nil
	}
}

func (kb *KmipBackend) handleRoleExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		kb.tokenAccessor = req.ClientTokenAccessor
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

func (kb *KmipBackend) handleRoleCreate() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scopeName := data.Get("scope").(string)
		roleName := data.Get("role").(string)
		kb.roleLock[scopeName+"-"+roleName] = new(sync.RWMutex)
		//Check that some fields are given
		if len(req.Data) == 0 {
			return logical.ErrorResponse("missing data fields"), nil
		}

		// new role
		role, err := kb.newRole(scopeName, roleName)
		if err != nil {
			return nil, err
		}
		// load default config
		config := kb.newConfig()
		if err := config.readStorage(ctx, req.Storage); err != nil {
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
			role.TlsClientKeyType = req.Data["tls_client_key_type"].(tlsKeyType)
		}
		if _, ok := req.Data["tls_client_key_ttl"]; ok {
			role.TlsClientKeyTTL = req.Data["tls_client_key_ttl"].(string)
		}

		role.Operations = make(map[operation]struct{})
		for i, k := range Operations {
			if _, ok := req.Data[k]; ok {
				role.Operations[i] = struct{}{}
			}
		}

		// create policy
		if err := kb.policyCreate(ctx, scopeName, roleName); err != nil {
			return nil, err
		}
		// mount transit
		if err := kb.mountTransit(ctx, scopeName, roleName); err != nil {
			return nil, err
		}
		// persist role
		if err := role.writeStorage(ctx, req.Storage, scopeName, roleName); err != nil {
			return nil, err
		}

		return nil, nil
	}
}

func (kb *KmipBackend) handleRoleWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scopeName := data.Get("scope").(string)
		roleName := data.Get("role").(string)
		//Check that some fields are given
		if len(req.Data) == 0 {
			return logical.ErrorResponse("missing data fields"), nil
		}

		role, err := kb.newRole(scopeName, roleName)
		if err != nil {
			return nil, err
		}
		// read role config
		role.readStorage(ctx, req.Storage, scopeName, roleName)
		// set req config
		if _, ok := req.Data["tls_client_key_bits"]; ok {
			role.TlsClientKeyBits = req.Data["tls_client_key_bits"].(int)
		}
		if _, ok := req.Data["tls_client_key_type"]; ok {
			role.TlsClientKeyType = req.Data["tls_client_key_type"].(tlsKeyType)
		}
		if _, ok := req.Data["tls_client_key_ttl"]; ok {
			role.TlsClientKeyTTL = req.Data["tls_client_key_ttl"].(string)
		}

		role.Operations = make(map[operation]struct{})
		for i, k := range Operations {
			if _, ok := req.Data[k]; ok {
				role.Operations[i] = struct{}{}
			}
		}

		if err := role.writeStorage(ctx, req.Storage, scopeName, roleName); err != nil {
			return nil, err
		}

		return nil, nil
	}
}

func (kb *KmipBackend) handleRoleRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scopeName := data.Get("scope").(string)
		roleName := data.Get("role").(string)

		role, err := kb.newRole(scopeName, roleName)
		if err != nil {
			return nil, err
		}

		if err := role.readStorage(ctx, req.Storage, scopeName, roleName); err != nil {
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

func (kb *KmipBackend) handleRoleList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scope := data.Get("scope").(string)
		path := "scope/" + scope + "/role/"

		d, err := listStorage(ctx, req.Storage, path)
		if err != nil {
			return nil, err
		}
		// Generate the response
		return logical.ListResponse(d), nil
	}
}

func (kb *KmipBackend) handleRoleDelete() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scopeName := data.Get("scope").(string)
		roleName := data.Get("role").(string)
		// delete role
		if err := kb.deleteRole(ctx, req, scopeName, roleName); err != nil {
			return nil, err
		}
		// delete policy
		if err := kb.policyDelete(ctx, scopeName, roleName); err != nil {
			return nil, err
		}
		// unmount transit
		if err := kb.unmountTransit(ctx, scopeName, roleName); err != nil {
			return nil, err
		}
		return nil, nil
	}
}

func (kb *KmipBackend) deleteRole(ctx context.Context, req *logical.Request, scope, role string) error {
	rolePath := fmt.Sprintf("scope/%s/role/%s", scope, role)
	credentialPath := rolePath + "/credential/"
	sn, err := listStorage(ctx, req.Storage, credentialPath)
	if err != nil {
		return err
	}

	// delete role ca
	for _, k := range sn {
		ca := kb.newCA(k)
		// revoke token
		if err := ca.readStorage(ctx, req.Storage, credentialPath); err != nil {
			return err
		}
		tokenAccessor := ca.getTokenAccessor()
		if err := kb.tokenRevoke(ctx, tokenAccessor); err != nil {
			return err
		}
		key := credentialPath + k
		// delete the key at the request path
		if err := req.Storage.Delete(ctx, key); err != nil {
			return err
		}
		// delete the key at the request path
		if err := req.Storage.Delete(ctx, key+"_resData"); err != nil {
			return err
		}
		delete(kb.certLock, k)
		// revoke token

	}
	// Delete the key at the request path
	if err := req.Storage.Delete(ctx, rolePath); err != nil {
		return err
	}
	delete(kb.roleLock, scope+"-"+role)
	return nil
}
