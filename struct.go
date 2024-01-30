package kmipengine

import (
	"math/big"
	"sync"
)

type (
	Tls_key_type string
)

const (
	CABits       = "tls_ca_key_bits"
	CAType       = "tls_ca_key_type"
	CAClientType = "tls_client_key_type"
	CAClientBits = "tls_client_key_bits"
	CAClientTTL  = "tls_client_key_ttl"
)

const (
	ec_key_type  Tls_key_type = "ec"
	rsa_key_type Tls_key_type = "rsa"
)

type operation uint8

const (
	OperationAddAttribute operation = iota
	OperationCreate
	OperationCreateKeypair
	OperationDecrypt
	OperationDeleteAttribute
	OperationDestroy
	OperationDiscoverVersions
	OperationEncrypt
	OperationGet
	OperationGetAttributeList
	OperationGetAttributes
	OperationImport
	OperationLocate
	OperationMac
	OperationMacVerify
	OperationModifyAttribute
	OperationQuery
	OperationRegister
	OperationRekey
	OperationRekeyKeypair
	OperationRevoke
	OperationSign
	OperationSignatureVerify
	OperationRngSeed
	OperationRngRetrieve
)

var Operation = map[operation]string{
	OperationAddAttribute:     "operation_add_attribute",
	OperationCreate:           "operation_create",
	OperationCreateKeypair:    "operation_create_keypair",
	OperationDecrypt:          "operation_decrypt",
	OperationDeleteAttribute:  "operation_delete_attribute",
	OperationDestroy:          "operation_destroy",
	OperationDiscoverVersions: "operation_discover_versions",
	OperationEncrypt:          "operation_encrypt",
	OperationGet:              "operation_get",
	OperationGetAttributeList: "operation_get_attribute_list",
	OperationGetAttributes:    "operation_get_attributes",
	OperationImport:           "operation_import",
	OperationLocate:           "operation_locate",
	OperationMac:              "operation_mac",
	OperationMacVerify:        "operation_mac_verify",
	OperationModifyAttribute:  "operation_modify_attribute",
	OperationQuery:            "operation_query",
	OperationRegister:         "operation_register",
	OperationRekey:            "operation_rekey",
	OperationRekeyKeypair:     "operation_rekey_keypair",
	OperationRevoke:           "operation_revoke",
	OperationSign:             "operation_sign",
	OperationSignatureVerify:  "operation_signature_verify",
	OperationRngSeed:          "operation_rng_seed",
	OperationRngRetrieve:      "operation_rng_retrieve",
}

type RoleCAConfig struct {
	TlsClientKeyBits int          `json:"tls_client_key_bits"`
	TlsClientKeyTTL  string       `json:"tls_client_key_ttl"`
	TlsClientKeyType Tls_key_type `json:"tls_client_key_type"`
}

type CASerialNumber struct {
	SN *big.Int
	L  *sync.RWMutex
}

//type Config map[string]interface{}

//func DefaultConfig() map[string]interface{} {
//	// 创建一个TLSConfig结构体的实例
//	return map[string]interface{}{
//		"default_tls_client_key_bits": 2048,
//		"default_tls_client_key_type": rsa_key_type,
//		"default_tls_client_ttl":      (336 * time.Hour).String(),
//		"listen_addrs":                []string{"0.0.0.0:5696"},
//		"server_hostnames":            []string{"localhost"},
//		"server_ips":                  []string{"127.0.0.1", "::1"}, // 将拆分后的IP列表赋值给server_ips
//		"tls_ca_key_bits":             2048,
//		"tls_ca_key_type":             rsa_key_type,
//		"tls_min_version":             "tls12",
//	}
//}

//func DefaultConfig() Config {
//	return Config{
//		DefaultTLSClientKeyBits: 2048,
//		DefaultTLSClientKeyType: rsa_key_type,
//		DefaultTLSClientTTL:     (336 * time.Hour).String(),
//		ListenAddrs:             []string{"0.0.0.0:5696"},
//		ServerHostnames:         []string{"localhost"},
//		ServerIPs:               []string{"127.0.0.1", "::1"},
//		TLSCAKeyBits:            2048,
//		TLSCAKeyType:            rsa_key_type,
//		TLSMinVersion:           "tls12",
//	}
//}
