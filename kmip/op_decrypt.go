package kmip

import (
	"context"
)

type DecryptRequestPayload struct {
	UniqueIdentifier string
	Data             []byte
	CryptographicParameters
	IVCounterNonce []byte
}

type DecryptResponsePayload struct {
	UniqueIdentifier string
	Data             []byte
}

type DecryptHandler struct {
	Decrypt func(ctx context.Context, payload *DecryptRequestPayload) (*DecryptResponsePayload, error)
}

func (h *DecryptHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload DecryptRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Decrypt(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
