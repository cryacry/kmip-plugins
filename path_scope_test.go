package kmipengine

import (
	"fmt"
	"testing"

	"github.com/cryacry/kmip-plugins/helper/namespace"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

// TestConfig mocks the creation, read, update, and delete
// of the backend configuration for HashiCups.
func TestScope(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	scopes := []string{"aaa", "bbb", "ccc"}

	roles := []string{"qq", "ww", "ee"}

	d := map[string]interface{}{
		"operation_add_attribute": true,
		"operation_create":        true,
	}

	t.Run("Test Configuration", func(t *testing.T) {
		err := testScopeCreate(t, b, reqStorage, scopes)

		assert.NoError(t, err)

		err = testScopeList(t, b, reqStorage, scopes)

		assert.NoError(t, err)

		// create Role
		err = testRoleWrite(t, b, reqStorage, scopes[0:2], roles, d)

		assert.NoError(t, err)

		err = testScopeDelete(t, b, reqStorage, scopes[0], map[string]interface{}{})

		assert.NoError(t, err)

		err = testScopeList(t, b, reqStorage, scopes)

		assert.NoError(t, err)

		err = testScopeDelete(t, b, reqStorage, scopes[0], map[string]interface{}{
			"force": "true",
		})

		assert.NoError(t, err)

		err = testScopeList(t, b, reqStorage, scopes[1:])

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

func testScopeCreate(t *testing.T, b logical.Backend, s logical.Storage, scopes []string) error {
	ctx := namespace.RootContext(nil)
	for _, scope := range scopes {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "scope/" + scope,
			Storage:   s,
		})
		if err != nil {
			return err
		}
		if resp != nil && resp.IsError() {
			return resp.Error()
		}
	}
	return nil
}

func testScopeList(t *testing.T, b logical.Backend, s logical.Storage, expected []string) error {
	ctx := namespace.RootContext(nil)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "scope",
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

	var resData []string
	if res, ok := resp.Data["keys"]; !ok {
		return fmt.Errorf("res data miss keys")
	} else if resData, ok = res.([]string); !ok {
		return fmt.Errorf("res data miss keys")
	}

	if len(expected) != len(resData) {
		return fmt.Errorf("read data mismatch (expected %s values, got %s)", expected, resp.Data)
	}

	for i := range expected {
		if expected[i] != resData[i] {
			return fmt.Errorf(`expected data["%d"] = %v, instead got %v"`, i, expected[i], resData[i])
		}
	}
	return nil
}

func testScopeDelete(t *testing.T, b logical.Backend, s logical.Storage, scope string, d map[string]interface{}) error {
	ctx := namespace.RootContext(nil)
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "scope/" + scope,
		Data:      d,
		Storage:   s,
	})
	if err != nil && err.Error() != errNeedForceParam {
		return err
	}
	if resp != nil && resp.IsError() {
		return resp.Error()
	}
	return nil
}

func compareStringSlices(slice1, slice2 []string) bool {

	for i := range slice1 {
		if slice1[i] != slice2[i] {
			return false
		}
	}

	return true
}
