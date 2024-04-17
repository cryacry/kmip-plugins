package kmipengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/cryacry/kmip-plugins/kmip"
	"github.com/cryacry/kmip-plugins/kmip/kmip14"
	"github.com/cryacry/kmip-plugins/kmip/ttlv"
	"github.com/hashicorp/vault/helper/namespace"
	"net"
	"strconv"
	"strings"
)

const externalProcAddr = "127.0.0.1:4444"

func (kb *KmipBackend) serverInit() {
	kmip.DefaultProtocolHandler.LogTraffic = true

	kmip.DefaultOperationMux.Handle(kmip14.OperationDiscoverVersions, &kmip.DiscoverVersionsHandler{
		SupportedVersions: []kmip.ProtocolVersion{
			{
				ProtocolVersionMajor: 1,
				ProtocolVersionMinor: 4,
			},
			{
				ProtocolVersionMajor: 1,
				ProtocolVersionMinor: 3,
			},
			{
				ProtocolVersionMajor: 1,
				ProtocolVersionMinor: 2,
			},
		},
	})
	kmip.DefaultOperationMux.Handle(kmip14.OperationCreate, &kmip.CreateHandler{
		Create: kb.createFunc(),
	})
	kmip.DefaultOperationMux.Handle(kmip14.OperationCreateKeyPair, &kmip.CreateKeyPairHandler{
		CreateKeyPair: kb.creatKeyPair(),
	})
	kmip.DefaultOperationMux.Handle(kmip14.OperationDestroy, &kmip.DestroyHandler{
		Destroy: kb.destroyFunc(),
	})
	kmip.DefaultOperationMux.Handle(kmip14.OperationGet, &kmip.GetHandler{
		Get: kb.getFunc(),
	})
	//kmip.DefaultOperationMux.Handle(kmip14.OperationRegister, &kmip.RegisterHandler{})
	kmip.DefaultOperationMux.Handle(kmip14.OperationEncrypt, &kmip.EncryptHandler{
		Encrypt: kb.encryptFunc(),
	})
	kmip.DefaultOperationMux.Handle(kmip14.OperationDecrypt, &kmip.DecryptHandler{
		Decrypt: kb.decryptFunc(),
	})
	kmip.DefaultOperationMux.Handle(kmip14.OperationSign, &kmip.SignHandler{
		Sign: kb.signFunc(),
	})
	kmip.DefaultOperationMux.Handle(kmip14.OperationSignatureVerify, &kmip.SignatureVerifyHandler{
		SignatureVerify: kb.signatureVerifyFunc(),
	})
	kmip.DefaultOperationMux.Handle(kmip14.OperationReKey, &kmip.RekeyHandler{
		Rekey: kb.rekeyFunc(),
	})
}

func (kb *KmipBackend) setupListener(addrs []string) []string {
	openAddr, closeAddr := kb.addrTidyUp(addrs)
	kb.closeWithAddrs(closeAddr) // need close addr
	kb.openWithAddrs(openAddr)   // need open addr
	return kb.server.ListenerList()
}

func (kb *KmipBackend) addrTidyUp(newIP []string) (add, del []string) {
	nowIP := kb.server.ListenerList()
	// judge ip
	for _, ip := range nowIP {
		flag := true
		for i, k := range newIP {
			if ip == k {
				// ip is listened
				flag = false
				newIP[i] = newIP[len(newIP)-1]
				newIP = newIP[:len(newIP)-1]
				break
			}
		}
		if flag {
			// ip needn't listen
			del = append(del, ip)
		}
	}
	add = newIP
	return
}

func (kb *KmipBackend) openWithAddrs(addrs []string) {
	for _, addr := range addrs {
		// this is a test, and we will read the server ca information in the config later to use it
		testCert := "/home/go_file/vault-1.15.6/debug/kmip/kmip_server-master/certificates/server_certificate.pem"
		testKey := "/home/go_file/vault-1.15.6/debug/kmip/kmip_server-master/certificates/server_key.pem"
		cert1, err := tls.LoadX509KeyPair(testCert, testKey)
		if err != nil {
			fmt.Println(err)
		}
		tlsConfig := &tls.Config{
			Certificates: []tls.Certificate{cert1},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS10,
			MaxVersion:   tls.VersionTLS13,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
		}

		listener, err := tls.Listen("tcp", addr, tlsConfig)
		if err != nil {
			kb.logger.Error("error listening:", "err", err.Error())
			continue
		}
		go func() {
			err := kb.server.Serve(listener)
			if err != nil {
				kb.logger.Error("error listened:", "addr", addr, "err", err.Error())
			}
		}()
		if kb.logger.IsInfo() {
			kb.logger.Info("Server is listening", "addr", addr)
		}
	}
}

func (kb *KmipBackend) closeWithAddrs(addrs []string) (err error) {
	for _, addr := range addrs {
		if err := kb.server.CloseListenersLockedWithAddr(addr); err != nil {
		} else {
			kb.logger.Info("Service stopped listening", "addr", addr)
		}
	}
	return
}

// stop all listening
func (kb *KmipBackend) stopListen() {
	ctx, _ := context.WithCancel(context.Background())
	kb.server.Shutdown(ctx)
}

// auth the cert information and create a one-time token and return it
func (kb *KmipBackend) sessionAuthHandler(state tls.ConnectionState, op operation) (*externalRequest, error) {
	//nsPath := state.PeerCertificates[0].Subject.Province[0]
	//scopeName := state.PeerCertificates[0].Subject.Locality[0]
	//roleName := state.PeerCertificates[0].Subject.StreetAddress[0]
	nsPath := ""
	scopeName := "fin"
	roleName := "acc"
	ns, err := kb.NamespaceByPath(nsPath)
	if err != nil {
		return nil, kmip.WithResultReason(err, kmip14.ResultReasonApplicationNamespaceNotSupported)
	}
	ctx := namespace.ContextWithNamespace(context.Background(), ns)
	role, err := kb.newRole(scopeName, roleName)
	if err != nil {
		return nil, kmip.WithResultReason(err, kmip14.ResultReasonPermissionDenied)
	}

	if err := role.readStorage(ctx, kb.storage, scopeName, roleName); err != nil {
		return nil, kmip.WithResultReason(err, kmip14.ResultReasonPermissionDenied)
	}
	// Determine permissions
	if _, ok := role.Operations[OperationAll]; !ok {
		if _, ok := role.Operations[op]; !ok {
			var err error
			return nil, kmip.WithResultReason(err, kmip14.ResultReasonPermissionDenied)
		}
	}

	auth, err := kb.tokenCreate(ctx, scopeName, roleName)
	if err != nil {
		return nil, kmip.WithResultReason(err, kmip14.ResultReasonPermissionDenied)
	}
	return &externalRequest{
		Namespace: nsPath,
		Scope:     scopeName,
		Role:      roleName,
		Token:     auth.ClientToken,
		accessor:  auth.Accessor,
		Operation: Operations[op],
	}, nil
}

type externalRequest struct {
	accessor         string
	Operation        string `json:"operation"`
	KeyID            string `json:"key_id"`
	EncryptAlgorithm string `json:"encrypt_algorithm"`
	KenLen           int32  `json:"key_len"`
	EncryptMode      string `json:"encrypt_mode"`
	Namespace        string `json:"namespace"`
	Scope            string `json:"scope"`
	Role             string `json:"role"`
	Token            string `json:"token"`
	Content          []byte `json:"content"`
	Signature        []byte `json:"signature"`
	HashingAlgorithm string `json:"hashing_algorithm"`
}

func (e *externalRequest) setAttribute(attribute []kmip.Attribute) {
	for _, k := range attribute {
		switch k.AttributeName {
		case "Cryptographic Algorithm":
			value, _ := k.AttributeValue.(ttlv.EnumValue)
			e.EncryptAlgorithm = ttlv.FormatEnum(uint32(value), &kmip14.CryptographicAlgorithmEnum)
		case "Cryptographic Length":
			e.KenLen = k.AttributeValue.(int32)
			//case "Cryptographic Usage Mask":
			//value, _ := k.AttributeValue.(ttlv.EnumValue)
			//info[k.AttributeName] = ttlv.FormatEnum(uint32(value), &kmip14.CryptographicUsageMaskEnum)

			//case "Name":
			//value, _ := k.AttributeValue.(ttlv.TTLV)
			//info[k.AttributeName] = value.ValueTextString()
		}
	}
}

func externalProc(serverAddr string, info *externalRequest) (map[string]interface{}, error) {
	message, err := json.Marshal(*info)
	exit := []byte("/exit")
	message = append(message, exit...)
	conn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		return nil, kmip.WithResultReason(err, kmip14.ResultReasonGeneralFailure)
	}
	defer conn.Close()

	fmt.Println("Connected to server:", serverAddr)

	_, err = conn.Write(message)
	if err != nil {
		return nil, kmip.WithResultReason(err, kmip14.ResultReasonGeneralFailure)
	}

	//fmt.Println("Sent message to server:", message)

	buffer := make([]byte, 65535)
	_, err = conn.Read(buffer)
	if err != nil {
		return nil, kmip.WithResultReason(err, kmip14.ResultReasonGeneralFailure)
	}
	var dataMap map[string]interface{}
	data := bytes.Split(buffer, []byte("/exit"))[0]

	err = json.Unmarshal(data, &dataMap)
	if err != nil {
		fmt.Println("Error decoding JSON:", err)
		return nil, kmip.WithResultReason(err, kmip14.ResultReasonGeneralFailure)
	}
	if err := respondsState(dataMap); err != nil {
		return nil, err
	}
	return dataMap, nil
}

func (kb *KmipBackend) createFunc() func(ctx context.Context, payload *kmip.CreateRequestPayload) (*kmip.CreateResponsePayload, error) {
	return func(ctx context.Context, payload *kmip.CreateRequestPayload) (*kmip.CreateResponsePayload, error) {
		t := ctx.Value(kmip.TLS).(tls.ConnectionState)
		info, err := kb.sessionAuthHandler(t, OperationCreate)
		if err != nil {
			return nil, err
		}
		defer kb.tokenRevoke(ctx, info.accessor)
		info.setAttribute(payload.TemplateAttribute.Attribute)
		res, err := externalProc(externalProcAddr, info)
		if err != nil {
			return nil, err
		}
		data := res["data"].(map[string]interface{})
		resp := &kmip.CreateResponsePayload{
			ObjectType:        payload.ObjectType,
			UniqueIdentifier:  data["name"].(string),
			TemplateAttribute: &kmip.TemplateAttribute{},
			//TemplateAttribute: &kmip.TemplateAttribute{
			//	Name: nil,
			//	Attribute: []kmip.Attribute{
			//		{
			//			AttributeName:  kmip14.TagUniqueIdentifier.String(),
			//			AttributeIndex: 0,
			//			AttributeValue: data["name"].(string),
			//		},
			//	},
			//},
		}
		return resp, nil
	}
}

func (kb *KmipBackend) destroyFunc() func(ctx context.Context, payload *kmip.DestroyRequestPayload) (*kmip.DestroyResponsePayload, error) {
	return func(ctx context.Context, payload *kmip.DestroyRequestPayload) (*kmip.DestroyResponsePayload, error) {
		state := ctx.Value(kmip.TLS).(tls.ConnectionState)
		info, err := kb.sessionAuthHandler(state, OperationDestroy)
		if err != nil {
			return nil, err
		}
		defer kb.tokenRevoke(ctx, info.accessor)
		info.KeyID = keyIDRemoveSuffix(payload.UniqueIdentifier)
		_, err = externalProc(externalProcAddr, info)
		if err != nil {
			return nil, err
		}

		return &kmip.DestroyResponsePayload{UniqueIdentifier: payload.UniqueIdentifier}, nil
	}
}

func (kb *KmipBackend) getFunc() func(ctx context.Context, payload *kmip.GetRequestPayload) (*kmip.GetResponsePayload, error) {
	return func(ctx context.Context, payload *kmip.GetRequestPayload) (*kmip.GetResponsePayload, error) {
		state := ctx.Value(kmip.TLS).(tls.ConnectionState)
		info, err := kb.sessionAuthHandler(state, OperationGet)
		if err != nil {
			return nil, err
		}
		defer kb.tokenRevoke(ctx, info.accessor)
		resp := &kmip.GetResponsePayload{
			UniqueIdentifier: payload.UniqueIdentifier,
		}
		if strings.Contains(payload.UniqueIdentifier, "_") {
			// asymmetric key
			info.KeyID = keyIDRemoveSuffix(payload.UniqueIdentifier)
			res, err := externalProc(externalProcAddr, info)
			if err != nil {
				return nil, err
			}
			data := res["data"].(map[string]interface{})
			latestVersion := data["latest_version"].(float64)
			latestVersionS := strconv.Itoa(int(latestVersion))
			keys := data["keys"].(map[string]interface{})
			keys = keys[latestVersionS].(map[string]interface{})
			cryptoType, cryptoLen, err := cryptoAndLen(data["type"].(string))
			if err != nil {
				return nil, err
			}
			if strings.Contains(payload.UniqueIdentifier, "public") {
				resp.ObjectType = kmip14.ObjectTypePublicKey
				publicKey, _ := json.Marshal(keys["public_key"].(string))
				resp.PublicKey = &kmip.PublicKey{KeyBlock: kmip.KeyBlock{
					KeyFormatType: kmip14.KeyFormatTypeX_509,
					KeyValue: &kmip.KeyValue{
						KeyMaterial: publicKey,
						//Attribute: []kmip.Attribute{
						//	{
						//		AttributeName:  kmip14.TagOriginalCreationDate.String(),
						//		AttributeValue: keys["creation_time"].(string),
						//	},
						//},
					},
					CryptographicAlgorithm: cryptoType,
					CryptographicLength:    cryptoLen,
					KeyWrappingData:        nil,
				}}
			} else if strings.Contains(payload.UniqueIdentifier, "private") {
				resp.ObjectType = kmip14.ObjectTypePrivateKey
				privateKey, _ := json.Marshal(keys["private_key"].(string))
				resp.PrivateKey = &kmip.PrivateKey{KeyBlock: kmip.KeyBlock{
					KeyFormatType: kmip14.KeyFormatTypeRaw,
					KeyValue: &kmip.KeyValue{
						KeyMaterial: privateKey,
						//Attribute: []kmip.Attribute{
						//	{
						//		AttributeName:  kmip14.TagOriginalCreationDate.String(),
						//		AttributeValue: keys["creation_time"],
						//	},
						//},
					},
					CryptographicAlgorithm: cryptoType,
					CryptographicLength:    cryptoLen,
					KeyWrappingData:        nil,
				}}
			}

		} else {
			// SymmetricKey
			info.KeyID = payload.UniqueIdentifier
			res, err := externalProc(externalProcAddr, info)
			if err != nil {
				return nil, err
			}
			data := res["data"].(map[string]interface{})
			latestVersion := data["latest_version"].(float64)
			latestVersionS := strconv.Itoa(int(latestVersion))
			keys := data["keys"].(map[string]interface{})
			keys = keys[latestVersionS].(map[string]interface{})
			cryptoType, cryptoLen, err := cryptoAndLen(data["type"].(string))
			if err != nil {
				return nil, err
			}
			resp.ObjectType = kmip14.ObjectTypeSymmetricKey
			key, _ := base64.StdEncoding.DecodeString(keys["key"].(string))
			resp.SymmetricKey = &kmip.SymmetricKey{KeyBlock: kmip.KeyBlock{
				KeyFormatType: kmip14.KeyFormatTypeRaw,
				KeyValue: &kmip.KeyValue{
					KeyMaterial: key,
				},
				CryptographicAlgorithm: cryptoType,
				CryptographicLength:    cryptoLen,
			}}
		}

		return resp, nil
	}
}

func (kb *KmipBackend) creatKeyPair() func(ctx context.Context, payload *kmip.CreateKeyPairRequestPayload) (*kmip.CreateKeyPairResponsePayload, error) {
	return func(ctx context.Context, payload *kmip.CreateKeyPairRequestPayload) (*kmip.CreateKeyPairResponsePayload, error) {
		t := ctx.Value(kmip.TLS).(tls.ConnectionState)
		info, err := kb.sessionAuthHandler(t, OperationCreateKeypair)
		if err != nil {
			return nil, err
		}
		defer kb.tokenRevoke(ctx, info.accessor)
		info.setAttribute(payload.CommonTemplateAttribute.Attribute)
		//for _, k := range payload.PublicKeyTemplateAttribute.Attribute {
		//	info[publicKeyAddSuffix(k.AttributeName)] = k.AttributeValue.(string)
		//}
		//for _, k := range payload.PrivateKeyTemplateAttribute.Attribute {
		//	info[privateKeyAddSuffix(k.AttributeName)] = k.AttributeValue.(string)
		//}
		res, err := externalProc(externalProcAddr, info)
		if err != nil {
			return nil, err
		}
		data := res["data"].(map[string]interface{})
		latestVersion := data["latest_version"].(float64)
		latestVersionS := strconv.Itoa(int(latestVersion))
		keys := data["keys"].(map[string]interface{})
		keys = keys[latestVersionS].(map[string]interface{})
		//private, _ := json.Marshal(keys["private_key"].(string))
		//public, _ := json.Marshal(keys["public_key"].(string))
		//privateKeyAttribute := []kmip.Attribute{
		//	{
		//		AttributeName:  kmip14.TagPrivateKeyUniqueIdentifier.String(),
		//		AttributeIndex: 0,
		//		AttributeValue: privateKeyAddSuffix(data["name"].(string)),
		//	}, {
		//		AttributeName:  kmip14.TagPrivateKey.String(),
		//		AttributeIndex: 0,
		//		AttributeValue: private,
		//	}, {
		//		AttributeName:  kmip14.TagOriginalCreationDate.String(),
		//		AttributeIndex: 0,
		//		AttributeValue: keys["creation_time"].(string),
		//	},
		//}
		//publicKeyAttribute := []kmip.Attribute{
		//	{
		//		AttributeName:  kmip14.TagPublicKeyUniqueIdentifier.String(),
		//		AttributeIndex: 0,
		//		AttributeValue: publicKeyAddSuffix(data["name"].(string)),
		//	}, {
		//		AttributeName:  kmip14.TagPublicKey.String(),
		//		AttributeIndex: 0,
		//		AttributeValue: public,
		//	}, {
		//		AttributeName:  kmip14.TagOriginalCreationDate.String(),
		//		AttributeIndex: 0,
		//		AttributeValue: keys["creation_time"].(string),
		//	},
		//}
		resp := &kmip.CreateKeyPairResponsePayload{
			PrivateKeyUniqueIdentifier: privateKeyAddSuffix(data["name"].(string)),
			PublicKeyUniqueIdentifier:  publicKeyAddSuffix(data["name"].(string)),
			//PrivateKey: kmip.PrivateKey{KeyBlock: kmip.KeyBlock{
			//	KeyFormatType:          kmip14.KeyFormatTypeX_509,
			//	KeyCompressionType:     0,
			//	KeyValue:               private,
			//	CryptographicAlgorithm: 0,
			//	CryptographicLength:    0,
			//	KeyWrappingData:        nil,
			//}},
			//PrivateKeyTemplateAttribute: &kmip.TemplateAttribute{
			//	Name:      nil,
			//	Attribute: privateKeyAttribute,
			//},
			//PublicKeyTemplateAttribute: &kmip.TemplateAttribute{
			//	Name:      nil,
			//	Attribute: publicKeyAttribute,
			//},
		}
		return resp, nil
	}
}

func privateKeyAddSuffix(uid string) string {
	return uid + "_privateKey"
}

func publicKeyAddSuffix(uid string) string {
	return uid + "_publicKey"
}

func keyIDRemoveSuffix(uid string) string {
	if strings.Contains(uid, "_") {
		return strings.Split(uid, "_")[0]
	}
	return uid
}

func respondsState(res map[string]interface{}) (err error) {
	state := res["status"].(float64)
	if _, ok := res["data"]; !ok {
		err = fmt.Errorf("no data return")
	} else {
		switch state {
		case 0:
			err = nil
		default:
			err = fmt.Errorf("status:%f,msg:%v", state, res["msg"])

		}
	}
	return
}

func cryptoAndLen(t string) (crypto kmip14.CryptographicAlgorithm, len int, err error) {
	err = nil
	switch t {
	case "aes128-gcm96":
		crypto = kmip14.CryptographicAlgorithmAES
		len = 128
	case "aes256-gcm96":
		crypto = kmip14.CryptographicAlgorithmAES
		len = 256
	case "chacha20-poly1305":
		crypto = kmip14.CryptographicAlgorithmChaCha20Poly1305
	//case "ed25519":
	case "ecdsa-p256":
		crypto = kmip14.CryptographicAlgorithmECDSA
		len = 256
	case "ecdsa-p384":
		crypto = kmip14.CryptographicAlgorithmECDSA
		len = 384
	case "ecdsa-p521":
		crypto = kmip14.CryptographicAlgorithmECDSA
		len = 521
	case "rsa-2048":
		crypto = kmip14.CryptographicAlgorithmRSA
		len = 2048
	case "rsa-3072":
		crypto = kmip14.CryptographicAlgorithmRSA
		len = 3072
	case "rsa-4096":
		crypto = kmip14.CryptographicAlgorithmRSA
		len = 4096
	default:
		var errs error
		err = kmip.WithResultReason(errs, kmip14.ResultReasonCryptographicFailure)
	}
	return
}

func (kb *KmipBackend) encryptFunc() func(ctx context.Context, payload *kmip.EncryptRequestPayload) (*kmip.EncryptResponsePayload, error) {
	return func(ctx context.Context, payload *kmip.EncryptRequestPayload) (*kmip.EncryptResponsePayload, error) {
		state := ctx.Value(kmip.TLS).(tls.ConnectionState)
		info, err := kb.sessionAuthHandler(state, OperationEncrypt)
		if err != nil {
			return nil, err
		}
		defer kb.tokenRevoke(ctx, info.accessor)
		info.KeyID = keyIDRemoveSuffix(payload.UniqueIdentifier)
		info.Content = payload.Data
		//info["cryptographic_parameters"], err = json.Marshal(payload.CryptographicParameters)
		if err != nil {
			return nil, kmip.WithResultReason(err, kmip14.ResultReasonGeneralFailure)
		}
		res, err := externalProc(externalProcAddr, info)
		if err != nil {
			return nil, err
		}
		data := res["data"].(map[string]interface{})
		//data := data.(map[string]string)
		cip, _ := json.Marshal(data["ciphertext"].(string))
		return &kmip.EncryptResponsePayload{
			UniqueIdentifier: payload.UniqueIdentifier,
			Data:             cip[1 : len(cip)-1],
		}, nil
	}
}

func (kb *KmipBackend) decryptFunc() func(ctx context.Context, payload *kmip.DecryptRequestPayload) (*kmip.DecryptResponsePayload, error) {
	return func(ctx context.Context, payload *kmip.DecryptRequestPayload) (*kmip.DecryptResponsePayload, error) {
		state := ctx.Value(kmip.TLS).(tls.ConnectionState)
		info, err := kb.sessionAuthHandler(state, OperationDecrypt)
		if err != nil {
			return nil, err
		}
		defer kb.tokenRevoke(ctx, info.accessor)
		info.KeyID = keyIDRemoveSuffix(payload.UniqueIdentifier)
		info.Content = payload.Data
		//info["cryptographic_parameters"], err = json.Marshal(payload.CryptographicParameters)
		if err != nil {
			return nil, kmip.WithResultReason(err, kmip14.ResultReasonGeneralFailure)
		}
		res, err := externalProc(externalProcAddr, info)
		if err != nil {
			return nil, err
		}

		data := res["data"].(map[string]interface{})
		decodedBytes, err := base64.StdEncoding.DecodeString(data["plaintext"].(string))
		return &kmip.DecryptResponsePayload{
			UniqueIdentifier: payload.UniqueIdentifier,
			Data:             decodedBytes,
		}, nil
	}
}

func (kb *KmipBackend) signFunc() func(ctx context.Context, payload *kmip.SignRequestPayload) (*kmip.SignResponsePayload, error) {
	return func(ctx context.Context, payload *kmip.SignRequestPayload) (*kmip.SignResponsePayload, error) {
		state := ctx.Value(kmip.TLS).(tls.ConnectionState)
		info, err := kb.sessionAuthHandler(state, OperationSign)
		if err != nil {
			return nil, err
		}
		defer kb.tokenRevoke(ctx, info.accessor)
		info.KeyID = keyIDRemoveSuffix(payload.UniqueIdentifier)
		info.Content = payload.Data
		info.HashingAlgorithm = payload.CryptographicParameters.HashingAlgorithm.String()
		if err != nil {
			return nil, kmip.WithResultReason(err, kmip14.ResultReasonGeneralFailure)
		}
		res, err := externalProc(externalProcAddr, info)
		if err != nil {
			return nil, err
		}

		data := res["data"].(map[string]interface{})
		signature, _ := json.Marshal(data["signature"].(string))
		signature = signature[1 : len(signature)-1]
		return &kmip.SignResponsePayload{
			UniqueIdentifier: payload.UniqueIdentifier,
			SignatureData:    signature,
		}, nil
	}
}

func (kb *KmipBackend) signatureVerifyFunc() func(ctx context.Context, payload *kmip.SignatureVerifyRequestPayload) (*kmip.SignatureVerifyResponsePayload, error) {
	return func(ctx context.Context, payload *kmip.SignatureVerifyRequestPayload) (*kmip.SignatureVerifyResponsePayload, error) {
		state := ctx.Value(kmip.TLS).(tls.ConnectionState)
		info, err := kb.sessionAuthHandler(state, OperationSignatureVerify)
		if err != nil {
			return nil, err
		}
		defer kb.tokenRevoke(ctx, info.accessor)
		info.KeyID = keyIDRemoveSuffix(payload.UniqueIdentifier)
		info.Signature = payload.SignatureData
		info.Content = payload.Data
		info.HashingAlgorithm = payload.CryptographicParameters.HashingAlgorithm.String()
		if err != nil {
			return nil, kmip.WithResultReason(err, kmip14.ResultReasonGeneralFailure)
		}
		res, err := externalProc(externalProcAddr, info)
		if err != nil {
			return nil, err
		}

		data := res["data"].(map[string]interface{})
		var valid kmip14.ValidityIndicator
		if data["valid"].(bool) {
			valid = kmip14.ValidityIndicatorValid
		} else {
			valid = kmip14.ValidityIndicatorInvalid
		}
		return &kmip.SignatureVerifyResponsePayload{
			UniqueIdentifier:  payload.UniqueIdentifier,
			ValidityIndicator: valid,
		}, nil
	}
}

func (kb *KmipBackend) rekeyFunc() func(ctx context.Context, payload *kmip.RekeyRequestPayload) (*kmip.RekeyResponsePayload, error) {
	return func(ctx context.Context, payload *kmip.RekeyRequestPayload) (*kmip.RekeyResponsePayload, error) {
		state := ctx.Value(kmip.TLS).(tls.ConnectionState)
		info, err := kb.sessionAuthHandler(state, OperationRekey)
		if err != nil {
			return nil, err
		}
		defer kb.tokenRevoke(ctx, info.accessor)
		info.KeyID = keyIDRemoveSuffix(payload.UniqueIdentifier)
		if err != nil {
			return nil, kmip.WithResultReason(err, kmip14.ResultReasonGeneralFailure)
		}
		_, err = externalProc(externalProcAddr, info)
		if err != nil {
			return nil, err
		}
		return &kmip.RekeyResponsePayload{
			UniqueIdentifier: payload.UniqueIdentifier,
		}, nil
	}
}
