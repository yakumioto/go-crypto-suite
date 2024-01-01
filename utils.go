package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"strings"
)

type randomSizeFunc func(len int) ([]byte, error)

var (
	ErrEmptyKey          = errors.New("key cannot be empty")
	ErrUnsupportedKey    = errors.New("unsupported key type, only string or []byte keys are allowed")
	ErrUnsupportedMethod = errors.New("this method is not applicable for the given key type")

	randomSize randomSizeFunc = func(len int) ([]byte, error) {
		iv := make([]byte, len)
		if _, err := rand.Read(iv); err != nil {
			return nil, err
		}

		return iv, nil
	}
)

func checkAndConvertKey(key interface{}) ([]byte, error) {
	switch key := key.(type) {
	case []byte:
		if len(key) == 0 {
			return nil, ErrEmptyKey
		}
		return key, nil
	case string:
		if key == "" {
			return nil, ErrEmptyKey
		}
		return []byte(key), nil
	default:
		return nil, ErrUnsupportedKey
	}
}

func convertToT[T DataType](src T) (dest T) {
	switch any(dest).(type) {
	case []byte:
		return T(toBytes(src))
	case string:
		return T(toString(src))
	}
	return
}

func toString[T DataType](b T) string {
	switch b := any(b).(type) {
	case []byte:
		return string(b)
	case string:
		return b
	}

	return ""
}

func toBytes[T DataType](s T) []byte {
	switch b := any(s).(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	}

	return nil
}

func pkcs7Padding[T DataType](src T, blockSize int) []byte {
	padding := blockSize - len(toBytes[T](src))%blockSize

	var paddingText []byte
	if padding == 0 {
		paddingText = bytes.Repeat([]byte{byte(blockSize)}, blockSize)
	} else {
		paddingText = bytes.Repeat([]byte{byte(padding)}, padding)
	}
	return append(toBytes[T](src), paddingText...)
}

func pkcs7UnPadding[T DataType](src T) []byte {
	unPadding := int(toBytes[T](src)[len(toBytes[T](src))-1])
	return toBytes[T](src)[:(len(toBytes[T](src)) - unPadding)]
}

func splitN[T DataType](s, sep T, n int) []T {
	switch s := any(s).(type) {
	case string:
		return any(strings.SplitN(s, any(sep).(string), n)).([]T)
	case []byte:
		return any(bytes.SplitN(s, any(sep).([]byte), n)).([]T)
	default:
		panic("Unsupported type")
	}
}
