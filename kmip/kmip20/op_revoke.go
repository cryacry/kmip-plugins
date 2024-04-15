package kmip20

import (
	"context"
	"time"

	"github.com/cryacry/kmip-plugins/kmip"
	"github.com/cryacry/kmip-plugins/kmip/kmip14"
)

// 6.1.40 Revoke

// Table 269

type RevocationReason struct {
	RevocationReasonCode kmip14.RevocationReasonCode
}

type RevokeRequestPayload struct {
	UniqueIdentifier         *UniqueIdentifierValue
	RevocationReason         RevocationReason
	CompromiseOccurrenceDate *time.Time
}

// Table 270

type RevokeResponsePayload struct {
	UniqueIdentifier string
}

type RevokeHandler struct {
	Revoke func(ctx context.Context, payload *RevokeRequestPayload) (*RevokeResponsePayload, error)
}

func (h *RevokeHandler) HandleItem(ctx context.Context, req *kmip.Request) (*kmip.ResponseBatchItem, error) {
	var payload RevokeRequestPayload

	err := req.DecodePayload(&payload)
	if err != nil {
		return nil, err
	}

	respPayload, err := h.Revoke(ctx, &payload)
	if err != nil {
		return nil, err
	}

	return &kmip.ResponseBatchItem{
		ResponsePayload: respPayload,
	}, nil
}
