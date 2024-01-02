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

func ExampleKeyImport() {
	key, err := KeyImport[string]("123456", HmacSha256)
	if err != nil {
		panic(err)
	}

	digest, err := key.Sign("hello world")
	if err != nil {
		panic(err)
	}
	fmt.Println("digest:", digest)

	fmt.Println("verify:", key.Verify("hello world", digest))
	// output:
	// digest: 101.g7PrJ4hFe0ai8XqqBI95WvDZ2ruOWSTdL8DqaC2Sn+U=
	// verify: true
}
