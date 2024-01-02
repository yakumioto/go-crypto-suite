package crypto

import "fmt"

type DataType interface {
	~[]byte | ~string
}

type Key[T DataType] interface {
	AlgorithmType() AlgorithmType
	Bytes() (key T, err error)
	SKI() T
	PublicKey() (Key[T], error)
	Sign(msg T) (digest T, err error)
	Verify(msg, digest T) bool
	Encrypt(plaintext T) (ciphertext T, err error)
	Decrypt(ciphertext T) (plaintext T, err error)
}

type KeyGenerator[T DataType] interface {
	KeyGen(alg Algorithm) (Key[T], error)
}

type KeyImporter[T DataType] interface {
	KeyImport(raw interface{}, alg Algorithm) (Key[T], error)
}

func KeyImport[T DataType](raw interface{}, alg Algorithm) (Key[T], error) {
	switch alg {
	case HmacSha256, HmacSha512:
		return new(hmacShaKeyImportImpl[T]).KeyImport(raw, alg)
	case AesCbc128, AesCbc192, AesCbc256, AesGcm128, AesGcm192, AesGcm256:
		return new(aesKeyImportImpl[T]).KeyImport(raw, alg)
	default:
		return nil, fmt.Errorf("not found key importer: %v", alg)
	}
}
