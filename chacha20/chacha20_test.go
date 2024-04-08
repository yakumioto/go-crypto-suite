package chacha20

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/yakumioto/go-crypto-suite/types"
)

func TestAlgorithm(t *testing.T) {
	ki := new(KeyImportImpl[string])

	key, err := ki.KeyImport("123456", types.Chacha20)
	assert.NoErrorf(t, err, "KeyImport failed: %s", err)

	assert.Equal(t, types.Chacha20, key.Algorithm(), "Algorithm failed")
}

func TestExport(t *testing.T) {
	ki := new(KeyImportImpl[string])

	key, err := ki.KeyImport("123456", types.Chacha20)
	assert.NoErrorf(t, err, "KeyImport failed: %s", err)

	password, err := key.Export()
	assert.NoErrorf(t, err, "Export failed: %s", err)
	assert.Equal(t, "123456", password, "Export failed")
}

func TestSKI(t *testing.T) {
	ki := new(KeyImportImpl[string])

	key, err := ki.KeyImport("123456", types.Chacha20)
	assert.NoErrorf(t, err, "KeyImport failed: %s", err)

	assert.Equal(t, "8d969eef6ecad3c29a3a629280e686cf0c3f5d5a86aff3ca12020c923adc6c92", key.SKI(), "SKI failed")
}

func TestUnsupportedMethod(t *testing.T) {
	ki := new(KeyImportImpl[string])

	key, err := ki.KeyImport("123456", types.Chacha20)
	assert.NoErrorf(t, err, "KeyImport failed: %s", err)

	_, err = key.PublicKey()
	assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "PublicKey failed")

	err = nil
	_, err = key.Sign("hello world")
	assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Sign failed")

	err = nil
	_, err = key.Verify("hello world", "signature")
	assert.EqualError(t, err, ErrUnsupportedMethod.Error(), "Verify failed")

}
func TestEncryptAndDecrypt(t *testing.T) {
	tcs := []struct {
		algorithm types.Algorithm
	}{
		{
			algorithm: types.Chacha20,
		},
		{
			algorithm: types.XChacha20,
		},
	}

	for _, tc := range tcs {
		ki := new(KeyImportImpl[string])

		key, err := ki.KeyImport("123456", tc.algorithm)
		assert.NoErrorf(t, err, "KeyImport failed: %s", err)

		ct, err := key.Encrypt("hello world")
		assert.NoErrorf(t, err, "Encrypt failed: %s", err)

		t.Log(ct)

		plaintext, err := key.Decrypt(ct)
		assert.NoErrorf(t, err, "Decrypt failed: %s", err)
		assert.Equal(t, "hello world", plaintext, "Decrypt failed")
	}
}