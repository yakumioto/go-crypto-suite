package crypto

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
