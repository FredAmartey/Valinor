package proxy_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valinor-ai/valinor/internal/proxy"
)

func TestEncodeFrame(t *testing.T) {
	f := proxy.Frame{
		Type:    proxy.TypeMessage,
		ID:      "req-1",
		Payload: json.RawMessage(`{"role":"user","content":"hello"}`),
	}

	data, err := proxy.EncodeFrame(f)
	require.NoError(t, err)

	// First 4 bytes = big-endian uint32 payload length
	payloadLen := uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
	assert.Equal(t, uint32(len(data)-4), payloadLen)

	// Remaining bytes are valid JSON matching the frame
	var decoded proxy.Frame
	err = json.Unmarshal(data[4:], &decoded)
	require.NoError(t, err)
	assert.Equal(t, proxy.TypeMessage, decoded.Type)
	assert.Equal(t, "req-1", decoded.ID)
}

func TestDecodeFrame(t *testing.T) {
	original := proxy.Frame{
		Type:    proxy.TypeChunk,
		ID:      "req-2",
		Payload: json.RawMessage(`{"content":"hi","done":false}`),
	}

	data, err := proxy.EncodeFrame(original)
	require.NoError(t, err)

	decoded, n, err := proxy.DecodeFrame(data)
	require.NoError(t, err)
	assert.Equal(t, len(data), n)
	assert.Equal(t, original.Type, decoded.Type)
	assert.Equal(t, original.ID, decoded.ID)
}

func TestDecodeFrame_InsufficientData(t *testing.T) {
	// Less than 4 bytes header
	_, _, err := proxy.DecodeFrame([]byte{0, 0})
	assert.Error(t, err)
}

func TestDecodeFrame_TruncatedPayload(t *testing.T) {
	// Header says 100 bytes but only 5 available
	data := []byte{0, 0, 0, 100, '{', '}'}
	_, _, err := proxy.DecodeFrame(data)
	assert.Error(t, err)
}

func TestFrameTypeConstants(t *testing.T) {
	// Verify all type constants are defined
	types := []string{
		proxy.TypeConfigUpdate,
		proxy.TypeMessage,
		proxy.TypePing,
		proxy.TypeHeartbeat,
		proxy.TypeChunk,
		proxy.TypeConfigAck,
		proxy.TypeToolBlocked,
		proxy.TypePong,
		proxy.TypeError,
	}
	for _, typ := range types {
		assert.NotEmpty(t, typ)
	}
}
