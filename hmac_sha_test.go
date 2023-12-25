package crypto

import (
	"encoding/hex"
	"testing"
)

func TestHmacShaKey_Sign(t *testing.T) {
	key := HmacShaKey[string]{
		algorithm: HmacSha256,
	}

	sigByte, _ := key.Sign("hello world")
	t.Log(hex.EncodeToString(sigByte))
}
