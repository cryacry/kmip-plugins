package kmipengine

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/cryacry/kmip-plugins/helper/namespace"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
	"strings"
	"sync"
)

// Factory returns a new backend as logical.Backend
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := NewKmipBackend(ctx, conf)
	return b, nil
}

type locks struct {
	scopeLock  map[string]*sync.RWMutex
	roleLock   map[string]*sync.RWMutex
	configLock *sync.RWMutex
	certLock   map[string]*sync.RWMutex
	snLock     *sync.Mutex
}

// KmipBackend is used storing secrets directly into the physical
// backend.
type KmipBackend struct {
	*framework.Backend
	locks
	tokenAccessor string
	// listening service management
	server *kmip.Server
	// logger is the server logger copied over from core
	logger  log.Logger
	storage logical.Storage
	lock    *sync.Mutex
}

func NewKmipBackend(ctx context.Context, config *logical.BackendConfig) *KmipBackend {
	b := &KmipBackend{
		logger: config.Logger,
		locks: locks{
			scopeLock:  make(map[string]*sync.RWMutex),
			roleLock:   make(map[string]*sync.RWMutex),
			certLock:   make(map[string]*sync.RWMutex),
			configLock: new(sync.RWMutex),
			snLock:     new(sync.Mutex),
		},
		lock:   new(sync.Mutex),
		server: &kmip.Server{},
	}
	backend := &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(KmipHelp),

		Paths: framework.PathAppend(
			[]*framework.Path{
				pathConfig(b),
				pathCa(b),
			},
			pathScope(b),
			pathRole(b),
			pathCredentials(b),
		),
		Secrets:        []*framework.Secret{},
		InitializeFunc: b.initialize,
		Clean:          b.cleanup,
	}
	backend.Setup(ctx, config)
	b.Backend = backend
	return b
}

// write default config
func (kb *KmipBackend) initialize(ctx context.Context, l *logical.InitializationRequest) error {
	kb.serverInit()
	kb.storage = l.Storage
	out, err := kb.storage.Get(ctx, configPath)
	if err != nil {
		return err
	}
	if out != nil {
		// exist config information
		var data map[string]interface{}
		// load config from storage
		if err := jsonutil.DecodeJSON(out.Value, &data); err != nil {
			return fmt.Errorf("json decoding failed: %w", err)
		}
		// open listener
		raw := data["listen_addrs"].([]interface{})
		var addrs []string
		for _, k := range raw {
			addrs = append(addrs, k.(string))
		}
		kb.setupListener(addrs)
		if err := kb.initLocks(ctx); err != nil {
			return err
		}
		return nil
	}
	// init default config
	conf := DefaultConfigMap()
	config := kb.newConfig()
	MapToStruct(conf, &config)

	// open listener

	// set listened addr
	config.ListenAddrs = kb.setupListener(config.ListenAddrs)

	// create root ca chain
	ns, err := namespace.FromContext(ctx)

	// set new CA-Cert
	s := kb.newSerialNumber()
	s.readStorage(ctx, kb.storage)
	rootCA := kb.newCA(s.SN.String())
	rootCA.SetCACert("root", "root", "1000h", ns, s)
	s.readStorage(ctx, kb.storage)
	childCA := kb.newCA(s.SN.String())
	childCA.SetCACert("root", "root", "1000h", ns, s)

	// 1、Update root certificate chain
	// rootCA
	if err := rootCA.CaGenerate(config.TLSCAKeyType, config.TLSCAKeyBits, nil); err != nil {
		return err
	}
	if err := rootCA.writeStorage(ctx, kb.storage, caPath); err != nil {
		return err
	}
	// childCA
	if err := childCA.CaGenerate(config.TLSCAKeyType, config.TLSCAKeyBits, rootCA); err != nil {
		return err
	}
	if err := childCA.writeStorage(ctx, kb.storage, caPath); err != nil {
		return err
	}
	if err := config.writeStorage(ctx, kb.storage); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	if kb.logger.IsInfo() {
		kb.logger.Info("init default config")
	}
	return nil
}

func (kb *KmipBackend) initLocks(ctx context.Context) error {
	scopePath := "scope/"
	scopes, err := listStorage(ctx, kb.storage, scopePath)
	if err != nil {
		return err
	}
	for _, scopeName := range scopes {
		kb.scopeLock[scopeName] = new(sync.RWMutex)
		rolePath := fmt.Sprintf("scope/%s/role/", scopeName)
		roles, err := listStorage(ctx, kb.storage, rolePath)
		if err != nil {
			return err
		}
		for _, roleName := range roles {
			kb.roleLock[scopeName+"-"+roleName] = new(sync.RWMutex)
		}
	}
	return nil
}

// stop kmip listener
func (kb *KmipBackend) cleanup(ctx context.Context) {
	kb.stopListen()
	if kb.logger.IsInfo() {
		kb.logger.Info("Server is shutting down")
	}
}

func readStorage(ctx context.Context, storage logical.Storage, key string) (map[string]interface{}, error) {
	out, err := storage.Get(ctx, key)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf(errPathDataIsEmpty)
	}
	// Fast-path the no data case
	var data map[string]interface{}
	// load config from storage
	if err := jsonutil.DecodeJSON(out.Value, &data); err != nil {
		return nil, fmt.Errorf("json decoding failed: %w", err)
	}
	return data, nil
}

func listStorage(ctx context.Context, storage logical.Storage, key string) ([]string, error) {
	if key != "" && !strings.HasSuffix(key, "/") {
		key = key + "/"
	}
	keys, err := storage.List(ctx, key)
	if err != nil {
		return nil, err
	}
	var d []string
	for _, k := range keys {
		if !strings.ContainsAny(k, "/") {
			d = append(d, k)
		}
	}
	return d, nil
}

func writeStorage(ctx context.Context, storage logical.Storage, key string, data map[string]interface{}) error {
	buf, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("json encoding failed: %w", err)
	}

	// Write out a new key
	entry := &logical.StorageEntry{
		Key:   key,
		Value: buf,
	}
	if err := storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("failed to write: %w", err)
	}
	return nil
}

func deleteStorage(ctx context.Context, req *logical.Request, key string) error {
	//Delete the key at the request path
	if err := req.Storage.Delete(ctx, key); err != nil {
		return err
	}
	return nil
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
