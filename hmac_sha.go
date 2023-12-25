package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"
)

type HmacShaKey[T ~[]byte | ~string] struct {
	key       []byte
	algorithm Algorithm
}

func (h *HmacShaKey[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(h.algorithm)
}

func (h *HmacShaKey[T]) Bytes() ([]byte, error) {
	return h.key, nil
}

func (h *HmacShaKey[T]) SKI() []byte {
	sha := sha256.New()
	sha.Write(h.key)
	return sha.Sum(nil)
}

func (h *HmacShaKey[T]) PublicKey() (Key[T], error) {
	return nil, fmt.Errorf("cannot call this method on a hmac sha key")
}

func (h *HmacShaKey[T]) Sign(digest T) ([]byte, error) {
	var hc hash.Hash
	switch h.algorithm {
	case HmacSha256:
		hc = hmac.New(sha256.New, h.key)
	case HmacSha512:
		hc = hmac.New(sha512.New, h.key)
	default:
		return nil, fmt.Errorf("not support %v algorithm", GetTypeByAlgorithm(h.algorithm))
	}

	switch digest := any(digest).(type) {
	case string:
		hc.Write([]byte(digest))
	case []byte:
		hc.Write(digest)
	}

	return hc.Sum(nil), nil
}

func (h *HmacShaKey[T]) Verify(hash T, sig []byte) bool {
	digest, err := h.Sign(hash)
	if err != nil {
		return false
	}

	return bytes.Equal(digest, sig)
}

func (h *HmacShaKey[T]) Encrypt(src T) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

func (h *HmacShaKey[T]) Decrypt(src T) ([]byte, error) {
	//TODO implement me
	panic("implement me")
}

type HmacShaKeyImporter[T ~[]byte | ~string] struct{}

func (h *HmacShaKeyImporter[T]) KeyImport(raw interface{}, alg Algorithm) (Key[T], error) {
	var key []byte

	switch raw := raw.(type) {
	case []byte:
		key = raw
	case string:
		key = []byte(raw)
	default:
		return nil, fmt.Errorf("only supports string or []byte type of key")
	}

	switch alg {
	case HmacSha256, HmacSha512:
		return &HmacShaKey[T]{
			key:       key,
			algorithm: alg,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported aes algorithm: %v", GetTypeByAlgorithm(alg))
	}
}

func HmacShaKeyImport[T ~[]byte | ~string](raw interface{}, alg Algorithm) (Key[T], error) {
	return new(HmacShaKeyImporter[T]).KeyImport(raw, alg)
}
