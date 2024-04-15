package kmip

import (
	"context"
)

type SignRequestPayload struct {
	UniqueIdentifier        string
	Data                    []byte
	CryptographicParameters CryptographicParameters
}

type SignResponsePayload struct {
	UniqueIdentifier string
	SignatureData    []byte
}

type SignHandler struct {
	Sign func(ctx context.Context, payload *SignRequestPayload) (*SignResponsePayload, error)
}

func (h *SignHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload SignRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Sign(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
