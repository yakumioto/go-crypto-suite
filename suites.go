package crypto

import "fmt"

func CryptoKeyImport[T DataType](raw interface{}, alg Algorithm) (Key[T], error) {
	switch alg {
	case HmacSha256, HmacSha512:
		return new(hmacShaKeyImportImpl[T]).KeyImport(raw, alg)
	default:
		return nil, fmt.Errorf("not found key importer: %v", alg)
	}
}
