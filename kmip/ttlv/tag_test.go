package ttlv_test

import (
	"testing"

	"github.com/cryacry/kmip-plugins/kmip/kmip14"
	"github.com/stretchr/testify/assert"
)

func TestTag_CanonicalName(t *testing.T) {
	assert.Equal(t, "Cryptographic Algorithm", kmip14.TagCryptographicAlgorithm.CanonicalName())
}
