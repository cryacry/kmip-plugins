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
func TestConfig(t *testing.T) {
	b, reqStorage := getTestBackend(t)
	var err error

	d := map[string]interface{}{
		"default_tls_client_ttl": (112 * time.Hour).String(),
		"server_hostnames":       []string{"localhost", "kmipserver"},
		"tls_ca_key_bits":        1025,
	}

	d1 := map[string]interface{}{
		"default_tls_client_key_bits": 2048,
		"default_tls_client_key_type": rsaKeyType,
		"default_tls_client_ttl":      (112 * time.Hour).String(),
		"listen_addrs":                []string{"0.0.0.0:5696"},
		"server_hostnames":            []string{"localhost", "kmipserver"},
		"server_ips":                  []string{"127.0.0.1", "::1"}, // 将拆分后的IP列表赋值给server_ips
		"tls_ca_key_bits":             1024,
		"tls_ca_key_type":             rsaKeyType,
		"tls_min_version":             "tls12",
	}

	scopes := []string{"aaa", "bbb", "ccc"}

	roles := []string{"qq", "ww", "ee"}

	roleConf := map[string]interface{}{
		"operation_add_attribute": true,
		"operation_create":        true,
	}

	t.Run("Test Configuration", func(t *testing.T) {
		err = testConfigCreate(t, b, reqStorage, map[string]interface{}{
			"listen_addrs": []string{"0.0.0.0:5696"},
		})

		assert.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, DefaultConfigMap())

		assert.NoError(t, err)

		err = testCARead(t, b, reqStorage, map[string]interface{}{})

		assert.NoError(t, err)

		// create scope role credential
		err = testScopeCreate(t, b, reqStorage, scopes)

		assert.NoError(t, err)

		err = testRoleCreate(t, b, reqStorage, scopes, roles, roleConf)

		assert.NoError(t, err)

		err = testCredentialGenerate(t, b, reqStorage, scopes, roles)

		assert.NoError(t, err)

		// update config
		err = testConfigUpdate(t, b, reqStorage, d)

		assert.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, d1)

		assert.NoError(t, err)
	})
}

func testConfigCreate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	ctx := namespace.RootContext(nil)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.CreateOperation,
		Path:      configPath,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
	ctx := namespace.RootContext(nil)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configPath,
		Data:      d,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func testConfigRead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) error {
	ctx := namespace.RootContext(nil)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configPath,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	//return fmt.Errorf("read data mismatch (expected %v values, got %v)", expected, resp.Data)

	if len(expected) != len(resp.Data) {
		return fmt.Errorf("read data mismatch (expected %v values, got %v)", expected, resp.Data)
	}

	//for k, expectedV := range expected {
	//	actualV, ok := resp.Data[k]
	//
	//	if !ok {
	//		return fmt.Errorf(`expected data["%s"] = %v but was not included in read output"`, k, expectedV)
	//	} else if expectedV != actualV {
	//		return fmt.Errorf(`expected data["%s"] = %v, instead got %v"`, k, expectedV, actualV)
	//	}
	//}

	return nil
}

func testCARead(t *testing.T, b logical.Backend, s logical.Storage, expected map[string]interface{}) error {
	ctx := namespace.RootContext(nil)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      caPath,
		Storage:   s,
	})

	if err != nil {
		return err
	}

	if resp == nil && expected == nil {
		return nil
	}

	if resp.IsError() {
		return resp.Error()
	}

	//return fmt.Errorf("read data mismatch (expected %v values, got %v)", expected, resp.Data)

	if data := resp.Data["ca_pem"].(string); len(data) <= 0 {
		return fmt.Errorf("read data mismatch (expected %v values, got %v)", expected, resp.Data)
	}

	return nil
}
