package kmipengine

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
)

func pathCredentials(b *KmipBackend) *framework.Path {
	return &framework.Path{
		Pattern: "scope/(?P<scope>[^/]+)/role/(?P<role>[^/]+)/credential/(?P<action>[^/]+)$",

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
				Description: "The action of the scope\n\n",
			},
			"action": {
				Type:        framework.TypeString,
				Description: "The action of the scope\n\n",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.handleCredentialWrite(),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "write",
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.handleCredentialRead(),
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "read",
				},
			},
		},

		ExistenceCheck: b.handleCredentialExistenceCheck(),

		HelpSynopsis:    strings.TrimSpace(KmipHelpSynopsis),
		HelpDescription: strings.TrimSpace(KmipHelpDescription),
	}
}

func (b *KmipBackend) handleCredentialExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		return true, nil
	}
}

func (b *KmipBackend) handleCredentialWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scope := data.Get("scope").(string)
		role := data.Get("role").(string)
		action := data.Get("action").(string)
		key := fmt.Sprintf("scope/%s/role/%s/credential/", scope, role)
		switch action {
		case "generate":
			ns, _ := namespace.FromContext(ctx)
			// generate certificate
			// root ca chain
			childCert := b.rootCA[1].Cert
			childPrivateKey := b.rootCA[1].PrivateKey
			// role config
			roleConf := b.scopes[scope].Roles[role]
			roleConf.L.RLock()
			// set Cert information
			serialNumber, cert := b.SetCACert(role, scope, roleConf.TlsClientKeyTTL, ns)
			// Generate Cert
			CertBytes, PrivateKey, err := ChildCaGenerate(roleConf.TlsClientKeyType, roleConf.TlsClientKeyBits, childCert, cert, childPrivateKey)
			roleConf.L.RUnlock()
			roleConf.L.Lock()
			roleConf.Cert = cert
			roleConf.L.Unlock()
			// root ca chain
			certificate, err := CertPEM(CertBytes)
			if err != nil {
				return nil, err
			}
			roleConf.L.RLock()
			data := map[string]interface{}{
				"ca_chain":      []string{b.rootCA[0].CertPEM, b.rootCA[1].CertPEM},
				"certificate":   certificate,
				"private_key":   PrivateKeyPEM(PrivateKey, roleConf),
				"serial_number": serialNumber.String(),
			}
			roleConf.L.RUnlock()
			buf, err := json.Marshal(data)
			if err != nil {
				return nil, fmt.Errorf("json encoding failed: %w", err)
			}

			// Write out a new key
			entry := &logical.StorageEntry{
				Key:   key + serialNumber.String(),
				Value: buf,
			}
			if err := req.Storage.Put(ctx, entry); err != nil {
				return nil, fmt.Errorf("failed to write: %w", err)
			}
			resp := &logical.Response{
				Data: data,
			}
			return resp, nil
		case "revoke":
			// revoke certificate
			serialNumber := req.Data["serial_number"].(string)
			if err := req.Storage.Delete(ctx, key+serialNumber); err != nil {
				return nil, fmt.Errorf("failed to write: %w", err)
			}
		}
		return nil, nil
	}

}

func (b *KmipBackend) handleCredentialRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scope := data.Get("scope").(string)
		role := data.Get("role").(string)
		action := data.Get("action").(string)
		if action != "lookup" {
			return nil, fmt.Errorf("credential action error")
		}
		serialNumber := req.Data["serial_number"].(string)
		path := fmt.Sprintf("scope/%s/role/%s/credential/%s", scope, role, serialNumber)
		// Read the path
		out, err := req.Storage.Get(ctx, path)
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
			Data: rawData,
		}
		return resp, nil
	}
}
