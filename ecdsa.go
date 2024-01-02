package crypto

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strconv"
	"strings"
)

type ecdsaPrivateKey[T DataType] struct {
	privateKey *ecdsa.PrivateKey
	algorithm  Algorithm
}

func (e *ecdsaPrivateKey[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(e.algorithm)
}

func (e *ecdsaPrivateKey[T]) Bytes() (key T, err error) {
	pkcs8Encoded, err := x509.MarshalPKCS8PrivateKey(e.privateKey)
	if err != nil {
		err = fmt.Errorf("failed to marshal private key: %w", err)
		return
	}

	return T(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Encoded})), nil
}

func (e *ecdsaPrivateKey[T]) SKI() T {
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

func (e *ecdsaPrivateKey[T]) Encrypt(_ T) (ciphertext T, err error) {
	err = ErrUnsupportedMethod
	return
}

func (e *ecdsaPrivateKey[T]) Decrypt(_ T) (plaintext T, err error) {
	err = ErrUnsupportedMethod
	return
}

type ecdsaPublicKey[T DataType] struct {
	publicKey *ecdsa.PublicKey
	algorithm Algorithm
}

func (e *ecdsaPublicKey[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(e.algorithm)
}

func (e *ecdsaPublicKey[T]) Bytes() (key T, err error) {
	pkcs8Encoded, err := x509.MarshalPKIXPublicKey(e.publicKey)
	if err != nil {
		err = fmt.Errorf("failed to marshal public key: %v", err)
		return
	}
	return T(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pkcs8Encoded})), nil
}

func (e *ecdsaPublicKey[T]) SKI() T {
	raw := elliptic.MarshalCompressed(e.publicKey.Curve, e.publicKey.X, e.publicKey.Y)

	hash := sha256.New()
	hash.Write(raw)
	return T(hash.Sum(nil))
}

func (e *ecdsaPublicKey[T]) PublicKey() (Key[T], error) {
	return e, nil
}

func (e *ecdsaPublicKey[T]) Sign(_ T) (digest T, err error) {
	err = ErrUnsupportedMethod
	return
}

func (e *ecdsaPublicKey[T]) Verify(msg, digest T) bool {
	dataBytes := toString(msg)

	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		return false
	}

	typ, err := strconv.Atoi(parts[0])
	if err != nil {
		return false
	}

	if Algorithm(typ) != e.algorithm {
		return false
	}

	return ecdsa.VerifyASN1(e.publicKey, toBytes(msg), toBytes(digest))
}

func (e *ecdsaPublicKey[T]) Encrypt(_ T) (ciphertext T, err error) {
	err = ErrUnsupportedMethod
	return
}

func (e *ecdsaPublicKey[T]) Decrypt(_ T) (plaintext T, err error) {
	err = ErrUnsupportedMethod
	return
}
