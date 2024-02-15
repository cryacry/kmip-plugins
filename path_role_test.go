package kmipengine

import (
	"fmt"
	"github.com/hashicorp/vault/helper/namespace"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

// TestConfig mocks the creation, read, update, and delete
// of the backend configuration for HashiCups.
func TestRole(t *testing.T) {
	b, reqStorage := getTestBackend(t)

	scopes := []string{"aaa"}

	roles := []string{"qq", "ww", "ee"}

	d := map[string]interface{}{
		"operation_add_attribute": true,
		"operation_create":        true,
	}

	d1 := map[string]interface{}{
		"tls_client_key_ttl":      (336 * time.Hour).String(),
		"tls_client_key_bits":     2048,
		"tls_client_key_type":     rsa_key_type,
		"operation_add_attribute": true,
		"operation_create":        true,
	}

	d2 := map[string]interface{}{
		"tls_client_key_ttl":      (112 * time.Hour).String(),
		"tls_client_key_bits":     1024,
		"tls_client_key_type":     rsa_key_type,
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

		err = testRoleWrite(t, b, reqStorage, scopes, roles, d2)

		assert.NoError(t, err)

		err = testRoleRead(t, b, reqStorage, scopes, roles, d2)

		assert.NoError(t, err)

		err = testRoleList(t, b, reqStorage, scopes, roles)

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

func testRoleCreate(t *testing.T, b logical.Backend, s logical.Storage, scopes, roles []string, d map[string]interface{}) error {
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

func testRoleWrite(t *testing.T, b logical.Backend, s logical.Storage, scopes, roles []string, d map[string]interface{}) error {
	ctx := namespace.RootContext(nil)
	for _, scope := range scopes {
		for _, role := range roles {
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
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

func testRoleRead(t *testing.T, b logical.Backend, s logical.Storage, scopes, roles []string, expected map[string]interface{}) error {
	ctx := namespace.RootContext(nil)
	for _, scope := range scopes {
		for _, role := range roles {
			resp, err := b.HandleRequest(ctx, &logical.Request{
				Operation: logical.ReadOperation,
				Path:      "scope/" + scope + "/role/" + role,
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

			//return fmt.Errorf("read data mismatch (expected %d values, got %v)", len(expected), resp.Data)

			if len(expected) != len(resp.Data) {
				return fmt.Errorf("read data mismatch (expected %d values, got %d)", len(expected), len(resp.Data))
			}

			for k, expectedV := range expected {
				actualV, ok := resp.Data[k]

				if !ok {
					return fmt.Errorf(`expected data["%s"] = %v but was not included in read output"`, k, expectedV)
				} else if expectedV != actualV {
					return fmt.Errorf(`expected data["%s"] = %v, instead got %v"`, k, expectedV, actualV)
				}
			}

		}
	}

	return nil
}

func testRoleList(t *testing.T, b logical.Backend, s logical.Storage, scopes, expected []string) error {
	ctx := namespace.RootContext(nil)
	for _, scope := range scopes {
		resp, err := b.HandleRequest(ctx, &logical.Request{
			Operation: logical.ListOperation,
			Path:      "scope/" + scope + "/role",
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
		//
		if ok := areArraysEqual(expected, resData); !ok {
			return fmt.Errorf(`expected %v, instead %v"`, expected, resData)
		}

	}

	return nil
}

func areArraysEqual(arr1, arr2 []string) bool {
	// 克隆数组以避免修改原始数据
	sortedArr1 := make([]string, len(arr1))
	copy(sortedArr1, arr1)

	sortedArr2 := make([]string, len(arr2))
	copy(sortedArr2, arr2)

	// 对数组进行排序
	sort.Strings(sortedArr1)
	sort.Strings(sortedArr2)

	// 比较排序后的数组
	return reflect.DeepEqual(sortedArr1, sortedArr2)
}
