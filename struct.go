package kmipengine

type (
	tlsKeyType = string
)

const (
	CABits       = "tls_ca_key_bits"
	CAType       = "tls_ca_key_type"
	CAClientType = "tls_client_key_type"
	CAClientBits = "tls_client_key_bits"
	CAClientTTL  = "tls_client_key_ttl"
)

const (
	ecKeyType  tlsKeyType = "ec"
	rsaKeyType tlsKeyType = "rsa"
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
	OperationAll
)

const (
	errPathDataIsEmpty = "path data is empty"
	errNeedForceParam  = "scope not empty, need force parameter"
)

var Operations = map[operation]string{
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
	OperationAll:              "operation_all",
}

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
