package kmipengine

import (
	"fmt"
	"github.com/hashicorp/vault/helper/namespace"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

// TestConfig mocks the creation, read, update, and delete
// of the backend configuration for HashiCups.
func TestConfig(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	t.Run("Test Configuration", func(t *testing.T) {
		err := testConfigCreate(t, b, reqStorage, map[string]interface{}{
			"listen_addrs": []string{"0.0.0.0:5696"},
		})

		assert.NoError(t, err)

		err = testConfigRead(t, b, reqStorage, DefaultConfigMap())

		assert.NoError(t, err)

		err = testCARead(t, b, reqStorage, map[string]interface{}{})

		assert.NoError(t, err)

		//err = testConfigDelete(t, b, reqStorage)
		//
		//assert.NoError(t, err)
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

//func testConfigUpdate(t *testing.T, b logical.Backend, s logical.Storage, d map[string]interface{}) error {
//	resp, err := b.HandleRequest(context.Background(), &logical.Request{
//		Operation: logical.UpdateOperation,
//		Path:      configStoragePath,
//		Data:      d,
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

	if len(expected) != len(resp.Data) {
		return fmt.Errorf("read data mismatch (expected %s values, got %s)", expected, resp.Data)
	}

	//if len(expected) != len(resp.Data) {
	//	return fmt.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
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

	if data := resp.Data["ca_pem"].(string); len(data) <= 0 {
		return fmt.Errorf("read data mismatch (expected %s values, got %s)", expected, resp.Data)
	}

	return nil
}
