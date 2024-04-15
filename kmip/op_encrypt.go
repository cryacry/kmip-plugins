package kmip

import (
	"context"
)

type EncryptRequestPayload struct {
	UniqueIdentifier string
	Data             []byte
	CryptographicParameters
	IVCounterNonce []byte
}

type EncryptResponsePayload struct {
	UniqueIdentifier string
	Data             []byte
}

type EncryptHandler struct {
	Encrypt func(ctx context.Context, payload *EncryptRequestPayload) (*EncryptResponsePayload, error)
}

func (h *EncryptHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload EncryptRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Encrypt(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
