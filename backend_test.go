package kmipengine

import (
	"testing"

	"github.com/cryacry/kmip-plugins/helper/namespace"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

// getTestBackend will help you construct a test backend object.
// Update this function with your target backend.
func getTestBackend(tb testing.TB) (*KmipBackend, logical.Storage) {
	tb.Helper()

	config := logical.TestBackendConfig()
	config.StorageView = new(logical.InmemStorage)
	config.Logger = hclog.NewNullLogger()
	config.System = logical.TestSystemView()
	ctx := namespace.RootContext(nil)
	b, err := Factory(ctx, config)
	if err != nil {
		tb.Fatal(err)
	}

	return b.(*KmipBackend), config.StorageView
}
