package kmip

import (
	"context"
	"github.com/hashicorp/vault/vault/kmip/kmip14"
)

type SignatureVerifyRequestPayload struct {
	UniqueIdentifier        string
	SignatureData           []byte
	Data                    []byte
	CryptographicParameters CryptographicParameters
}

type SignatureVerifyResponsePayload struct {
	UniqueIdentifier  string
	ValidityIndicator kmip14.ValidityIndicator
}

type SignatureVerifyHandler struct {
	SignatureVerify func(ctx context.Context, payload *SignatureVerifyRequestPayload) (*SignatureVerifyResponsePayload, error)
}

func (h *SignatureVerifyHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload SignatureVerifyRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.SignatureVerify(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
