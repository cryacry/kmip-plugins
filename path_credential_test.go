package kmipengine

import (
	"fmt"
	"github.com/hashicorp/vault/helper/namespace"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

// TestConfig mocks the creation, read, update, and delete
// of the backend configuration for HashiCups.
func TestCredential(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	scopes := []string{"aaa"}

	roles := []string{"qq"}

	d := map[string]interface{}{
		"operation_add_attribute": true,
		"operation_create":        true,
	}

	d1 := map[string]interface{}{
		"tls_client_key_ttl":      (336 * time.Hour).String(),
		"tls_client_key_bits":     2048,
		"tls_client_key_type":     rsaKeyType,
		"operation_add_attribute": true,
		"operation_create":        true,
	}

	t.Run("Test Configuration", func(t *testing.T) {
		var err error

		err = testConfigCreate(t, b, reqStorage, map[string]interface{}{
			"listen_addrs": []string{"0.0.0.0:5696"},
		})

		assert.NoError(t, err)

		err = testScopeCreate(t, b, reqStorage, scopes)

		assert.NoError(t, err)

		err = testRoleCreate(t, b, reqStorage, scopes, roles, d)

		assert.NoError(t, err)

		err = testRoleRead(t, b, reqStorage, scopes, roles, d1)

		assert.NoError(t, err)

		err = testCredentialGenerate(t, b, reqStorage, scopes[0:1], roles[0:1])

		assert.NoError(t, err)

		err = testCredentialRead(t, b, reqStorage, scopes[0], roles[0])

		assert.NoError(t, err)

		err = testCredentialList(t, b, reqStorage, scopes[0], roles[0])

		assert.NoError(t, err)
	})
}

//func testConfigDelete(t *testing.T, b logical.Backend, s logical.Storage) error {
//	resp, err := b.HandleRequest(context.Background(), &logical.Request{
//		Operation: logical.DeleteOperation,
//		Path:      configStoragePath,
//		Storage:   s,
//	})
//
//	if err != nil {
//		return err
//	}
//
//	if resp != nil && resp.IsError() {
//		return resp.Error()
//	}
//	return nil
//}

func testCredentialCreate(t *testing.T, b logical.Backend, s logical.Storage, scopes, roles []string, d map[string]interface{}) error {
	ctx := namespace.RootContext(nil)
	for _, scope := range scopes {
		for _, role := range roles {
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.CreateOperation,
				Path:      "scope/" + scope + "/role/" + role,
				Data:      d,
				Storage:   s,
			})
			if err != nil {
				return err
			}
			if resp != nil && resp.IsError() {
				return resp.Error()
			}
		}
	}
	return nil
}

func testCredentialGenerate(t *testing.T, b logical.Backend, s logical.Storage, scopes, roles []string) error {
	ctx := namespace.RootContext(nil)
	for _, scope := range scopes {
		for _, role := range roles {
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "scope/" + scope + "/role/" + role + "/credential/generate",
				Storage:   s,
			})
			if err != nil {
				return err
			}
			if resp != nil && resp.IsError() {
				return resp.Error()
			}
		}
	}
	return nil
}

func testCredentialRead(t *testing.T, b logical.Backend, s logical.Storage, scope, role string) error {
	ctx := namespace.RootContext(nil)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "scope/" + scope + "/role/" + role + "/credential",
		Storage:   s,
	})
	sn, ok := resp.Data["keys"].([]string)
	if !ok {
		return fmt.Errorf("list error")
	}
	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "scope/" + scope + "/role/" + role + "/credential/lookup",
		Data: map[string]interface{}{
			"serial_number": sn[0],
		},
		Storage: s,
	})
	if err != nil {
		return err
	}

	if resp == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	//return fmt.Errorf("read data mismatch (got %v)", resp.Data)

	if len(resp.Data) <= 0 {
		return fmt.Errorf("read data mismatch ( got %v)", resp.Data)
	}

	if _, ok := resp.Data["ca_chain"]; !ok {
		return fmt.Errorf("read data mismatch ( got %v)", resp.Data)
	}

	return nil
}

func testCredentialList(t *testing.T, b logical.Backend, s logical.Storage, scope, role string) error {
	ctx := namespace.RootContext(nil)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "scope/" + scope + "/role/" + role + "/credential",
		Storage:   s,
	})
	if err != nil {
		return err
	}

	if resp == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	if len(resp.Data) <= 0 {
		return fmt.Errorf("read data mismatch ( got %v)", resp.Data)
	}
	return nil
}
