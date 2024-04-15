package kmip

import "context"

// GetRequestPayload ////////////////////////////////////////
type RekeyRequestPayload struct {
	UniqueIdentifier string
	Offset           int
}

type RekeyResponsePayload struct {
	UniqueIdentifier string
}

type RekeyHandler struct {
	Rekey func(ctx context.Context, payload *RekeyRequestPayload) (*RekeyResponsePayload, error)
}

func (h *RekeyHandler) HandleItem(ctx context.Context, req *Request) (*ResponseBatchItem, error) {
	var payload RekeyRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Rekey(ctx, &payload)
	if err != nil {
		return nil, err
	}

	// req.Key = respPayload.Key

	return &ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
