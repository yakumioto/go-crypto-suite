package crypto

import (
	"fmt"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Crypto Suite")
}

func ExampleCryptoKeyImport() {
	key, err := CryptoKeyImport[string]("123456", HmacSha256)
	if err != nil {
		panic(err)
	}

	digest, err := key.Sign("hello world")
	if err != nil {
		panic(err)
	}
	fmt.Println("digest:", digest)

	fmt.Println("verify:", key.Verify("hello world", digest))
}
