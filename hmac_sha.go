package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strconv"
)

type hmacShaKeyImpl[T DataType] struct {
	key       []byte
	algorithm Algorithm
}

func (h *hmacShaKeyImpl[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(h.algorithm)
}

func (h *hmacShaKeyImpl[T]) Bytes() ([]byte, error) {
	return h.key, nil
}

func (h *hmacShaKeyImpl[T]) SKI() []byte {
	sha := sha256.New()
	sha.Write(h.key)

	return sha.Sum(nil)
}

func (h *hmacShaKeyImpl[T]) PublicKey() (Key[T], error) {
	return nil, fmt.Errorf("cannot call this method on a hmac sha key")
}

func (h *hmacShaKeyImpl[T]) Sign(msg T) (digest T, err error) {
	var hc hash.Hash
	switch h.algorithm {
	case HmacSha256:
		hc = hmac.New(sha256.New, h.key)
	case HmacSha512:
		hc = hmac.New(sha512.New, h.key)
	default:
		err = fmt.Errorf("not support %v algorithm", GetTypeByAlgorithm(h.algorithm))
		return
	}

	hc.Write(toBytes(msg))

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(int(h.algorithm)))
	data.WriteString(".")
	data.WriteString(base64.StdEncoding.EncodeToString(hc.Sum(nil)))

	return convertToT[T](T(data.Bytes())), nil
}

func (h *hmacShaKeyImpl[T]) Verify(msg, digest T) bool {
	newDigest, err := h.Sign(msg)
	if err != nil {
		return false
	}

	return bytes.Equal(toBytes(newDigest), toBytes(digest))
}

func (h *hmacShaKeyImpl[T]) Encrypt(_ T) (ciphertext T, err error) {
	err = errors.New("cannot call this method on a hmac hash")
	return
}

func (h *hmacShaKeyImpl[T]) Decrypt(_ T) (plaintext T, err error) {
	err = errors.New("cannot call this method on a hmac hash")
	return
}

type hmacShaKeyImportImpl[T DataType] struct{}

func (h *hmacShaKeyImportImpl[T]) KeyImport(raw interface{}, alg Algorithm) (Key[T], error) {
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
		return &hmacShaKeyImpl[T]{
			key:       key,
			algorithm: alg,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported aes algorithm: %v", GetTypeByAlgorithm(alg))
	}
}
