package kmipengine

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"math/big"
	"strings"
	"sync"
)

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// KmipBackend is used storing secrets directly into the physical
// backend.
type KmipBackend struct {
	*framework.Backend
	// CA number
	SerialNumber CASerialNumber
	// kmip config information
	config Config
	// root ca chain
	rootCA []*CA
	// scope and role information
	scopes map[string]*Scope
}

func backend() *KmipBackend {
	b := &KmipBackend{
		SerialNumber: CASerialNumber{
			L:  new(sync.RWMutex),
			SN: big.NewInt(0),
		},
		config: Config{},
		rootCA: []*CA{},
		scopes: make(map[string]*Scope),
	}
	backend := &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(KmipHelp),

		Paths: []*framework.Path{
			pathConfig(b),
			pathCa(b),
			pathScope(b),
			pathRole(b),
			pathCredentials(b),
		},
		Secrets: []*framework.Secret{},
	}

	b.Backend = backend

	return b
}

const KmipHelp = `
KMIP backend manages certificates and writes them to the backend.
`

const KmipHelpSynopsis = `
KMIP backend management certificate chain
`

const KmipHelpDescription = `
KMIP backend, managing the creation, update, and destruction of certificate chains
`
