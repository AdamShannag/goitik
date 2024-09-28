package validator

import "strings"

type Func func(string, string) bool

func Equals(v1, v2 string) bool {
	return v1 == v2
}

func StartsWith(v1, v2 string) bool {
	return strings.HasPrefix(v1, v2)
}

func EndsWith(v1, v2 string) bool {
	return strings.HasSuffix(v1, v2)
}

func Contains(v1, v2 string) bool {
	return strings.Contains(v1, v2)
}
