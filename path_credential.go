package kmipengine

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/helper/namespace"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
)

func pathCredentials(b *KmipBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "scope/(?P<scope>[^/]+)/role/(?P<role>[^/]+)/credential",

			DisplayAttrs: &framework.DisplayAttributes{
				OperationPrefix: "kmip",
			},

			TakesArbitraryInput: true,
			Fields:              map[string]*framework.FieldSchema{},
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
		},
	}
}

func (b *KmipBackend) handleCredentialExistenceCheck() framework.ExistenceFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
		return true, nil
	}
}

func (b *KmipBackend) handleCredentialWrite() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		scopeName := data.Get("scopeName").(string)
		roleName := data.Get("roleName").(string)
		action := data.Get("action").(string)
		key := fmt.Sprintf("scopeName/%s/roleName/%s/credential/", scopeName, roleName)
		switch action {
		case "generate":
			ns, _ := namespace.FromContext(ctx)
			// generate certificate
			// root ca chain
			rootSN, err := listStorage(ctx, req, caPath)
			if err != nil {
				return nil, err
			}
			//i1 := new(big.Int)
			//j1 := new(big.Int)
			//sort.Slice(rootSN, func(i, j int) bool {
			//	i1.SetString(rootSN[i], 10)
			//	j1.SetString(rootSN[j], 10)
			//	return i1.Cmp(j1) > 0
			//})
			ca := new(CA)
			var caChain []string
			for _, k := range rootSN {
				if err := ca.readStorage(ctx, req, key, k); err != nil {
					return nil, err
				}
				caChain = append(caChain, ca.CertPEM)
			}

			rootCA := new(CA)
			rootCA.readStorage(ctx, req, caPath, rootSN[len(rootSN)-1])

			// roleName config
			role := new(Role)
			if err := role.readStorage(ctx, req, scopeName, roleName); err != nil {
				return nil, err
			}

			// read sn
			sn := new(SerialNumber)
			if err := sn.readStorage(ctx, req); err != nil {
				return nil, err
			}

			// set Cert information
			cert := SetCACert(roleName, scopeName, role.TlsClientKeyTTL, ns, sn)
			CertBytes, PrivateKey, err := ChildCaGenerate(role.TlsClientKeyType, role.TlsClientKeyBits, rootCA.Cert, cert, rootCA.PrivateKey)
			if err != nil {
				return nil, err
			}
			certificate, err := CertPEM(CertBytes)
			if err != nil {
				return nil, err
			}

			role.Cert = cert
			childCA := new(CA)
			childCA.setCA(certificate, CertBytes, cert, PrivateKey, rootCA.Cert.SerialNumber)
			childCA.writeStorage(ctx, req, key)
			//role.L.RLock()

			data := map[string]interface{}{
				"ca_chain":      caChain,
				"certificate":   certificate,
				"private_key":   PrivateKeyPEM(PrivateKey, role),
				"serial_number": sn.SN.String(),
			}
			err = writeStorage(ctx, req, key+sn.SN.String()+"_resData", data)
			if err != nil {
				return nil, err
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
			if err := req.Storage.Delete(ctx, key+serialNumber+"_resData"); err != nil {
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
		path := fmt.Sprintf("scope/%s/role/%s/credential/%s_resData", scope, role, serialNumber)

		rawData, err := readStorage(ctx, req, path)
		if err != nil {
			return nil, err
		}

		resp := &logical.Response{
			Data: rawData,
		}
		return resp, nil
	}
}

func (b *KmipBackend) handleCredentialList() framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		// Right now we only handle directories, so ensure it ends with /; however,
		// some physical backends may not handle the "/" case properly, so only add
		// it if we're not listing the root
		scope := data.Get("scope").(string)
		role := data.Get("role").(string)
		path := fmt.Sprintf("scope/%s/role/%s/credential", scope, role)

		rawData, err := listStorage(ctx, req, path)
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
