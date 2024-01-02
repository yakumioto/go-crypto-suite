package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
)

type ecdsaPrivateKey[T DataType] struct {
	privateKey *ecdsa.PrivateKey
	algorithm  Algorithm
}

func (e *ecdsaPrivateKey[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(e.algorithm)
}

func (e *ecdsaPrivateKey[T]) Bytes() ([]byte, error) {
	pkcs8Encoded, err := x509.MarshalPKCS8PrivateKey(e.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Encoded}), nil
}

func (e *ecdsaPrivateKey[T]) SKI() []byte {
	pubKey, _ := e.PublicKey()
	return pubKey.SKI()
}

func (e *ecdsaPrivateKey[T]) PublicKey() (Key[T], error) {
	return &ecdsaPublicKey[T]{publicKey: &e.privateKey.PublicKey}, nil
}

func (e *ecdsaPrivateKey[T]) Sign(msg T) (digest T, err error) {
	payload, err := e.privateKey.Sign(rand.Reader, toBytes(msg), crypto.SHA256)
	if err != nil {
		err = fmt.Errorf("sign error: %w", err)
		return
	}

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(int(e.algorithm)))
	data.WriteString(".")
	data.WriteString(base64.StdEncoding.EncodeToString(payload))

	return T(data.Bytes()), nil
}

func (e *ecdsaPrivateKey[T]) Verify(_, _ T) bool {
	return false
}

func (e *ecdsaPrivateKey[T]) Encrypt(plaintext T) (ciphertext T, err error) {
	err = ErrUnsupportedMethod
	return
}

func (e *ecdsaPrivateKey[T]) Decrypt(ciphertext T) (plaintext T, err error) {
	err = ErrUnsupportedMethod
	return
}

type ecdsaPublicKey[T DataType] struct {
	publicKey *ecdsa.PublicKey
	algorithm Algorithm
}

func (e *ecdsaPublicKey[T]) AlgorithmType() AlgorithmType {
	// TODO implement me
	panic("implement me")
}

func (e *ecdsaPublicKey[T]) Bytes() ([]byte, error) {
	pkcs8Encoded, err := x509.MarshalPKIXPublicKey(e.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkcs8Encoded}), nil
}

func (e *ecdsaPublicKey[T]) SKI() []byte {
	// TODO implement me
	panic("implement me")
}

func (e *ecdsaPublicKey[T]) PublicKey() (Key[T], error) {
	// TODO implement me
	panic("implement me")
}

func (e *ecdsaPublicKey[T]) Sign(msg T) (digest T, err error) {
	// TODO implement me
	panic("implement me")
}

func (e *ecdsaPublicKey[T]) Verify(msg, digest T) bool {
	// TODO implement me
	panic("implement me")
}

func (e *ecdsaPublicKey[T]) Encrypt(plaintext T) (ciphertext T, err error) {
	// TODO implement me
	panic("implement me")
}

func (e *ecdsaPublicKey[T]) Decrypt(ciphertext T) (plaintext T, err error) {
	// TODO implement me
	panic("implement me")
}
