package kmipengine

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredentials(b *KmipBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "scope/(?P<scope>[^/]+)/role/(?P<role>[^/]+)/credential/?$",

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
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.handleCredentialList(),
					DisplayAttrs: &framework.DisplayAttributes{
						OperationVerb: "read",
					},
				},
			},

			ExistenceCheck: b.handleCredentialExistenceCheck(),

			HelpSynopsis:    strings.TrimSpace(KmipHelpSynopsis),
			HelpDescription: strings.TrimSpace(KmipHelpDescription),
		},
		{
			Pattern: "scope/(?P<scope>[^/]+)/role/(?P<role>[^/]+)/credential/(?P<action>[^/]+)$",

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
				"role": {
					Type:        framework.TypeString,
					Description: "The action of the scope\n\n",
					Required:    true,
				},
				"action": {
					Type:        framework.TypeString,
					Description: "The action of the scope\n\n",
					Required:    true,
				},
				"serial_number": {
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
		},
	}
}

func (kb *KmipBackend) handleCredentialExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		return true, nil
	}
}

func (kb *KmipBackend) handleCredentialWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		kb.tokenAccessor = req.ClientTokenAccessor
		scopeName := data.Get("scope").(string)
		roleName := data.Get("role").(string)
		action := data.Get("action").(string)
		key := fmt.Sprintf("scope/%s/role/%s/credential/", scopeName, roleName)
		switch action {
		case "generate":
			ns, _ := namespace.FromContext(ctx)
			// generate certificate
			// root ca chain
			rootSN, err := listStorage(ctx, req.Storage, caPath)
			if err != nil {
				return nil, err
			}
			// Sort the root certificate serial number to obtain the end of the certificate chain
			//i1 := new(big.Int)
			//j1 := new(big.Int)
			//sort.Slice(rootSN, func(i, j int) bool {
			//	i1.SetString(rootSN[i], 10)
			//	j1.SetString(rootSN[j], 10)
			//	return i1.Cmp(j1) > 0
			//})

			// ca chain

			var caChain []string
			for _, k := range rootSN {
				ca := kb.newCA(k)
				if err := ca.readStorage(ctx, req.Storage, caPath); err != nil {
					return nil, err
				}
				caChain = append(caChain, ca.CertPEM)
			}
			// last ca
			rootCA := kb.newCA(rootSN[0])
			rootCA.readStorage(ctx, req.Storage, caPath)

			// roleName config
			role, err := kb.newRole(scopeName, roleName)
			if err != nil {
				return nil, err
			}
			if err := role.readStorage(ctx, req.Storage, scopeName, roleName); err != nil {
				return nil, err
			}

			// read sn
			sn := kb.newSerialNumber()
			if err := sn.readStorage(ctx, req.Storage); err != nil {
				return nil, err
			}

			// create token
			//auth, err := kb.TokenCreate(ctx, req, scopeName, roleName, role)
			//if err != nil {
			//	return nil, err
			//}

			// set Cert information
			childCA := kb.newCA(sn.SN.String())
			childCA.SetCACert(roleName, scopeName, role.TlsClientKeyTTL, ns, sn)
			//childCA.setToken(auth)

			// generate ca
			childCA.CaGenerate(role.TlsClientKeyType, role.TlsClientKeyBits, rootCA)
			childCA.writeStorage(ctx, req.Storage, key)
			//role.L.RLock()
			certSN := childCA.Cert.SerialNumber.String()
			data := map[string]interface{}{
				"ca_chain":      caChain,
				"certificate":   childCA.CertPEM,
				"public_key":    childCA.PublicKeyPEM(),
				"private_key":   childCA.PrivateKeyPEM(),
				"serial_number": certSN,
			}
			err = writeStorage(ctx, req.Storage, key+certSN+"_resData", data)
			if err != nil {
				return nil, err
			}
			resp := &logical.Response{
				Data: data,
			}
			return resp, nil
		case "revoke":
			// revoke certificate
			if _, ok := req.Data["serial_number"]; !ok {
				return nil, fmt.Errorf("serial_number is required")
			}
			serialNumber := req.Data["serial_number"].(string)
			// revoke token
			ca := kb.newCA(serialNumber)
			ca.readStorage(ctx, req.Storage, key)
			//tokenAccessor := ca.Cert.Subject.CommonName
			//if err := kb.TokenRevoke(ctx, tokenAccessor); err != nil {
			//	return nil, err
			//}

			if err := req.Storage.Delete(ctx, key+serialNumber); err != nil {
				return nil, fmt.Errorf("failed to write: %w", err)
			}
			if err := req.Storage.Delete(ctx, key+serialNumber+"_resData"); err != nil {
				return nil, fmt.Errorf("failed to write: %w", err)
			}
			delete(kb.certLock, serialNumber)
		}
		return nil, nil
	}

}

func (kb *KmipBackend) handleCredentialRead() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scope := data.Get("scope").(string)
		role := data.Get("role").(string)
		action := data.Get("action").(string)
		if action != "lookup" {
			return nil, fmt.Errorf("credential action error")
		}
		if _, ok := req.Data["serial_number"]; !ok {
			return nil, fmt.Errorf("serial_number is required")
		}
		serialNumber := req.Data["serial_number"].(string)
		path := fmt.Sprintf("scope/%s/role/%s/credential/%s_resData", scope, role, serialNumber)

		rawData, err := readStorage(ctx, req.Storage, path)
		if err != nil {
			return nil, err
		}

		resp := &logical.Response{
			Data: rawData,
		}
		return resp, nil
	}
}

func (kb *KmipBackend) handleCredentialList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scope := data.Get("scope").(string)
		role := data.Get("role").(string)
		path := fmt.Sprintf("scope/%s/role/%s/credential", scope, role)

		rawData, err := listStorage(ctx, req.Storage, path)
		if err != nil {
			return nil, err
		}

		var resData []string
		for _, k := range rawData {
			if !strings.Contains(k, "_") {
				resData = append(resData, k)
			}
		}

		// Generate the response
		return logical.ListResponse(resData), nil
	}
}
