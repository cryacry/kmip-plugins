package kmipengine

import (
	"bytes"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"reflect"
)

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

// CertPEM Convert certificate content to PEM format
func CertPEM(certBytes []byte) (string, error) {
	var pemBuffer bytes.Buffer
	err := pem.Encode(&pemBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	if err != nil {
		fmt.Println("Failed to encode to PEM:", err)
		return "", err
	}

	// Save PEM format content to variable pemCert
	pemCert := pemBuffer.Bytes()
	return string(pemCert), nil
}

// Auxiliary function to convert map [string] interface {} into a structure
func MapToStruct(data map[string]interface{}, result interface{}) error {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return err
	}
	err = json.Unmarshal(jsonData, &result)
	if err != nil {
		return err
	}
	return nil
}

func structToMapWithJsonTags(input interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})

	val := reflect.ValueOf(input)
	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("input is not a struct")
	}

	typ := val.Type()
	for i := 0; i < val.NumField(); i++ {
		field := val.Field(i)
		fieldName := typ.Field(i).Name

		// Using JSON tags as keys in the map
		jsonTag := typ.Field(i).Tag.Get("json")
		if jsonTag != "" && jsonTag != "-" {
			result[jsonTag] = field.Interface()
		} else {
			// If there is no JSON tag, use the field name as the key
			result[fieldName] = field.Interface()
		}
	}

	return result, nil
}
