package kmipengine

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
)

func CaGenerate(tlsCAKeyType Tls_key_type, tlsCAKeyBits int, ca *x509.Certificate) ([]byte, interface{}, error) {

	// Set certificate information
	var caBytes []byte
	// Generate random private key
	switch tlsCAKeyType {
	case rsa_key_type:
		priv, err := rsa.GenerateKey(rand.Reader, tlsCAKeyBits)
		// Generate certificate
		caBytes, err = x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return nil, nil, err
		}
		return caBytes, priv, nil

	case ec_key_type:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caBytes, err = x509.CreateCertificate(rand.Reader, ca, ca, &priv.PublicKey, priv)
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return nil, nil, err
		}
		return caBytes, priv, nil
	}
	return nil, nil, fmt.Errorf("This type of certificate type is not supported")
	//pem.Encode(privFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	//
	//fmt.Println("CA certificate and private key generated successfully.")
}

func ChildCaGenerate(tlsCAKeyType Tls_key_type, tlsCAKeyBits int, rootCert *x509.Certificate, ca *x509.Certificate, rootPri interface{}) ([]byte, interface{}, error) {
	// Set certificate information

	var caBytes []byte
	// Generate random private key
	switch tlsCAKeyType {
	case rsa_key_type:
		priv, err := rsa.GenerateKey(rand.Reader, tlsCAKeyBits)
		// Generate certificate
		caBytes, err = x509.CreateCertificate(rand.Reader, ca, rootCert, &priv.PublicKey, rootPri)
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return nil, nil, err
		}
		return caBytes, priv, nil

	case ec_key_type:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		caBytes, err = x509.CreateCertificate(rand.Reader, ca, rootCert, &priv.PublicKey, rootPri)
		if err != nil {
			fmt.Println("Failed to create certificate:", err)
			return nil, nil, err
		}
		return caBytes, priv, nil
	}
	return nil, nil, fmt.Errorf("This type of certificate type is not supported")
	//pem.Encode(privFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	//
	//fmt.Println("CA certificate and private key generated successfully.")
}

//func SetCACert(role, scope, ttl string, ns *namespace.Namespace) (*big.Int, *x509.Certificate) {
//	duration, _ := time.ParseDuration(ttl)
//	SerialNumber := big.NewInt(1234)
//	rootCert := &x509.Certificate{
//		SerialNumber: SerialNumber,
//		Subject: pkix.Name{
//			CommonName:   role,                     // role
//			Organization: []string{scope, ns.Path}, // scope
//
//		},
//		NotBefore:             time.Now(),
//		NotAfter:              time.Now().Add(duration), // 有效期
//		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
//		BasicConstraintsValid: true,
//		IsCA:                  true,
//	}
//	return SerialNumber, rootCert
//}

// CertsPEM Convert certificate content to PEM format
func CertsPEM(certs [][]byte) (string, error) {
	var pemBuffer bytes.Buffer
	caPem := ""
	for _, certBytes := range certs {
		err := pem.Encode(&pemBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		if err != nil {
			fmt.Println("Failed to encode to PEM:", err)
			return "", err
		}

		// Save PEM format content to variable pemCert
		pemCert := pemBuffer.Bytes()
		caPem = caPem + string(pemCert)
		pemBuffer.Reset()
	}
	return caPem, nil
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

// PrivateKeyPEM Convert PrivateKey content to PEM format
func PrivateKeyPEM(privateKey interface{}, roleConf *Role) []byte {
	var keyBytes []byte
	var _type string
	switch roleConf.TlsClientKeyType {
	case rsa_key_type:
		keyBytes = x509.MarshalPKCS1PrivateKey(privateKey.(*rsa.PrivateKey))
		_type = "RSA PRIVATE KEY"
	case ec_key_type:
		keyBytes, _ = x509.MarshalECPrivateKey(privateKey.(*ecdsa.PrivateKey))
		_type = "EC PRIVATE KEY"
	}

	// 将私钥转换为 PEM 格式
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  _type,
		Bytes: keyBytes,
	})
	return privateKeyPEM
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
