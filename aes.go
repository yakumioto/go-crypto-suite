package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

type aesCbcKeyImpl[T DataType] struct {
	key       []byte
	algorithm Algorithm
}

func (a *aesCbcKeyImpl[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(a.algorithm)
}

func (a *aesCbcKeyImpl[T]) Bytes() (key T, err error) {
	return T(toHexString(a.key)), nil
}

func (a *aesCbcKeyImpl[T]) SKI() T {
	sha := sha256.New()
	sha.Write(a.key)

	return T(toHexString(sha.Sum(nil)))
}

func (a *aesCbcKeyImpl[T]) PublicKey() (Key[T], error) {
	return nil, ErrUnsupportedMethod
}

func (a *aesCbcKeyImpl[T]) Sign(_ T) (digest T, err error) {
	err = ErrUnsupportedMethod
	return
}

func (a *aesCbcKeyImpl[T]) Verify(_, _ T) bool {
	return false
}

func (a *aesCbcKeyImpl[T]) Encrypt(plaintext T) (ciphertext T, err error) {
	paddedText := pkcs7Padding[T](plaintext, aes.BlockSize)

	iv, err := randomSize(aes.BlockSize)
	if err != nil {
		err = fmt.Errorf("random iv error: %w", err)
		return
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		err = fmt.Errorf("new aes chipher error: %w", err)
		return
	}

	mode := cipher.NewCBCEncrypter(block, iv)
	dst := make([]byte, len(paddedText))
	mode.CryptBlocks(dst, paddedText)

	payload := bytes.NewBuffer(nil)
	payload.Write(iv)
	payload.Write(dst)

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(int(a.algorithm)))
	data.WriteString(".")
	data.WriteString(base64.StdEncoding.EncodeToString(payload.Bytes()))

	return T(data.Bytes()), nil
}

func (a *aesCbcKeyImpl[T]) Decrypt(ciphertext T) (plaintext T, err error) {
	ciphertextStr := toString(ciphertext)
	parts := strings.SplitN(ciphertextStr, ".", 2)
	if len(parts) != 2 {
		err = errors.New("invalid encrypted data")
		return
	}

	typ, err := strconv.Atoi(parts[0])
	if err != nil {
		err = errors.New("type is not a number")
		return
	}

	if Algorithm(typ) != a.algorithm {
		err = fmt.Errorf("invalid algorithm type: %s", GetTypeByAlgorithm(Algorithm(typ)))
		return
	}

	ciphertextBytes, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		err = fmt.Errorf("ciphertext decodeing base64 error: %w", err)
		return
	}

	iv := ciphertextBytes[0:aes.BlockSize]
	srcCiphertextBytes := ciphertextBytes[aes.BlockSize:]

	block, err := aes.NewCipher(a.key)
	if err != nil {
		err = fmt.Errorf("new aes chipher error: %v", err)
		return
	}

	mode := cipher.NewCBCDecrypter(block, iv)
	paddedText := make([]byte, len(srcCiphertextBytes))
	mode.CryptBlocks(paddedText, srcCiphertextBytes)

	return T(pkcs7UnPadding(paddedText)), nil
}

type aesGcmKeyImpl[T DataType] struct {
	key       []byte
	algorithm Algorithm
}

func (a *aesGcmKeyImpl[T]) AlgorithmType() AlgorithmType {
	return GetTypeByAlgorithm(a.algorithm)
}

func (a *aesGcmKeyImpl[T]) Bytes() (key T, err error) {
	return T(toHexString(a.key)), nil
}

func (a *aesGcmKeyImpl[T]) SKI() T {
	sha := sha256.New()
	sha.Write(a.key)

	return T(toHexString(sha.Sum(nil)))
}

func (a *aesGcmKeyImpl[T]) PublicKey() (Key[T], error) {
	return nil, ErrUnsupportedMethod
}

func (a *aesGcmKeyImpl[T]) Sign(_ T) (digest T, err error) {
	err = ErrUnsupportedMethod
	return
}

func (a *aesGcmKeyImpl[T]) Verify(_, _ T) bool {
	return false
}

func (a *aesGcmKeyImpl[T]) Encrypt(plaintext T) (ciphertext T, err error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		err = fmt.Errorf("new aes chipher error: %w", err)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		err = fmt.Errorf("new gcm chipher error: %w", err)
		return
	}

	nonce, err := randomSize(gcm.NonceSize())
	if err != nil {
		err = fmt.Errorf("random gcm nonce error: %w", err)
		return
	}

	payload := bytes.NewBuffer(nil)
	payload.Write(nonce)
	payload.Write(gcm.Seal(nil, nonce, toBytes(plaintext), nil))

	data := bytes.NewBuffer(nil)
	data.WriteString(strconv.Itoa(int(a.algorithm)))
	data.WriteString(".")
	data.WriteString(base64.StdEncoding.EncodeToString(payload.Bytes()))

	return T(data.Bytes()), nil
}

func (a *aesGcmKeyImpl[T]) Decrypt(ciphertext T) (plaintext T, err error) {
	dataBytes := toString(ciphertext)

	parts := strings.SplitN(dataBytes, ".", 2)
	if len(parts) != 2 {
		err = errors.New("invalid encrypted data")
		return
	}

	typ, err := strconv.Atoi(parts[0])
	if err != nil {
		err = errors.New("type is not a number")
		return
	}

	if Algorithm(typ) != a.algorithm {
		err = fmt.Errorf("invalid algorithm type: %s", GetTypeByAlgorithm(Algorithm(typ)))
		return
	}

	encryptedData, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		err = fmt.Errorf("ciphertext decodeing base64 error: %w", err)
		return
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		err = fmt.Errorf("new aes chipher error: %w", err)
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		err = fmt.Errorf("new gcm cipher error: %w", err)
		return
	}

	// Extract the nonce from the encrypted data.
	if len(encryptedData) < gcm.NonceSize() {
		err = fmt.Errorf("encrypted data too short")
		return
	}

	nonce, encryptedData := encryptedData[:gcm.NonceSize()], encryptedData[gcm.NonceSize():]

	decryptedData, err := gcm.Open(nil, nonce, encryptedData, nil)
	if err != nil {
		err = fmt.Errorf("gcm open error: %w", err)
		return
	}

	return T(decryptedData), nil
}

type aesKeyImportImpl[T DataType] struct{}

func (a *aesKeyImportImpl[T]) KeyImport(raw interface{}, alg Algorithm) (Key[T], error) {
	key, err := checkAndConvertKey(raw)
	if err != nil {
		return nil, err
	}

	keyLen := 0

	switch alg {
	case AesCbc128, AesGcm128:
		keyLen = 128 / 8
	case AesCbc192, AesGcm192:
		keyLen = 192 / 8
	case AesCbc256, AesGcm256:
		keyLen = 256 / 8
	default:
		panic("unhandled default case")
	}

	if len(key) != keyLen {
		key = pbkdf2.Key(key, key, 1000, keyLen, sha256.New)
	}

	switch alg {
	case AesCbc128, AesCbc192, AesCbc256:
		return &aesCbcKeyImpl[T]{
			algorithm: alg,
			key:       key,
		}, nil
	case AesGcm128, AesGcm192, AesGcm256:
		return &aesGcmKeyImpl[T]{
			algorithm: alg,
			key:       key,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported aes algorithm: %v", GetTypeByAlgorithm(alg))
	}
}
