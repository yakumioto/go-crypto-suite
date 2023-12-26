package crypto

type DataType interface {
	~[]byte | ~string
}

type Key[T DataType] interface {
	AlgorithmType() AlgorithmType
	Bytes() ([]byte, error)
	SKI() []byte
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
