package crypto

type Input interface {
	~[]byte | ~string
}

type Key[T Input] interface {
	AlgorithmType() AlgorithmType
	Bytes() ([]byte, error)
	SKI() []byte
	PublicKey() (Key[T], error)
	Sign(hash T) ([]byte, error)
	Verify(hash T, sig []byte) bool
	Encrypt(src T) ([]byte, error)
	Decrypt(src T) ([]byte, error)
}

type KeyGenerator[T ~[]byte | ~string] interface {
	KeyGen(alg Algorithm) (Key[T], error)
}

type KeyImporter[T ~[]byte | ~string] interface {
	KeyImport(raw interface{}, alg Algorithm) (Key[T], error)
}
