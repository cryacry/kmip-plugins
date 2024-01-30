package kmipengine

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"net/http"
	"strings"
	"sync"
)

type Role struct {
	L *sync.RWMutex
	//Operation        map[operation]bool
	TlsClientKeyBits int               `json:"tls_client_key_bits"`
	TlsClientKeyTTL  string            `json:"tls_client_key_ttl"`
	TlsClientKeyType Tls_key_type      `json:"tls_client_key_type"`
	Cert             *x509.Certificate `json:"cert"`
	SerialNumber     string            `json:"serial_number "`
}

func pathRole(b *KmipBackend) *framework.Path {
	return &framework.Path{
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
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleRoleWrite(),
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
				Callback: b.handleRoleRead(),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "write",
				},
				Responses: map[int][]framework.Response{
					http.StatusNoContent: {{
						Description: http.StatusText(http.StatusNoContent),
					}},
				},
			},
		},

		ExistenceCheck: b.handleRoleExistenceCheck(),

		HelpSynopsis:    strings.TrimSpace(KmipHelpSynopsis),
		HelpDescription: strings.TrimSpace(KmipHelpDescription),
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

		return true, nil
	}
}

func (b *KmipBackend) handleRoleWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scopeName := data.Get("scope").(string)
		roleName := data.Get("role").(string)
		key := "scope/" + scopeName + "/role/" + roleName
		newRole := false
		//Check that some fields are given
		if len(req.Data) == 0 {
			return logical.ErrorResponse("missing data fields"), nil
		}

		scope, ok := b.scopes[scopeName]
		if !ok {
			return nil, fmt.Errorf("no scope")
		}
		role, ok := scope.Roles[roleName]
		if !ok {
			// new role
			newRole = true
			role = new(Role)
			role.L = new(sync.RWMutex)
			scope.Roles[roleName] = role
		}
		role.L.Lock()
		if newRole {
			role.TlsClientKeyBits = b.config.DefaultTLSClientKeyBits
			role.TlsClientKeyType = b.config.DefaultTLSClientKeyType
			role.TlsClientKeyTTL = b.config.DefaultTLSClientTTL
		}
		// update tls config
		if _, ok := req.Data["tls_client_key_bits"]; !ok {
			req.Data["tls_client_key_bits"] = role.TlsClientKeyBits
		} else {
			role.TlsClientKeyBits = req.Data["tls_client_key_bits"].(int)
		}
		if _, ok := req.Data["tls_client_key_type"]; !ok {
			req.Data["tls_client_key_type"] = role.TlsClientKeyType
		} else {
			role.TlsClientKeyType = req.Data["tls_client_key_type"].(Tls_key_type)
		}
		if _, ok := req.Data["tls_client_ttl"]; !ok {
			req.Data["tls_client_ttl"] = role.TlsClientKeyTTL
		} else {
			role.TlsClientKeyTTL = req.Data["tls_client_ttl"].(string)
		}
		role.L.Unlock()
		// JSON encode the data
		buf, err := json.Marshal(req.Data)
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

		return nil, nil
	}
}

func (b *KmipBackend) handleRoleRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scope := data.Get("scope").(string)
		role := data.Get("role").(string)
		key := "scope/" + scope + "/role/" + role

		// Read the path
		out, err := req.Storage.Get(ctx, key)
		if err != nil {
			return nil, fmt.Errorf("read failed: %w", err)
		}

		// Fast-path the no data case
		if out == nil {
			return nil, nil
		}

		// Decode the data
		var rawData map[string]interface{}

		if err := jsonutil.DecodeJSON(out.Value, &rawData); err != nil {
			return nil, fmt.Errorf("json decoding failed: %w", err)
		}

		resp := &logical.Response{
			Secret: &logical.Secret{},
			Data:   rawData,
		}
		return resp, nil
	}
}
