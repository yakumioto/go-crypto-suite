package crypto

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestHmacShaKey(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "HmacShaKey Suite")
}

var _ = Describe("HmacShaKey", func() {
	Describe("key by bytes", func() {
		var (
			key       Key[[]byte]
			signature []byte
			err       error
		)

		Context("", func() {
			It("should be created successfully", func() {
				key, err = (new(hmacShaKeyImportImpl[[]byte])).KeyImport([]byte("123456"), HmacSha256)
				Expect(err).To(BeNil())
			})
		})

		Context("", func() {
			It("should be signed successfully", func() {
				signature, err = key.Sign([]byte("hello world"))
				Expect(err).To(BeNil())
				Expect(signature).ToNot(BeNil())
			})
		})

		Context("", func() {
			It("should be verified successfully", func() {
				Expect(key.Verify([]byte("hello world"), signature)).To(BeTrue())
			})
		})
	})

	Describe("key by string", func() {
		var (
			key       Key[string]
			signature string
			err       error
		)

		Context("", func() {
			It("should be created successfully", func() {
				key, err = (new(hmacShaKeyImportImpl[string])).KeyImport("123456", HmacSha256)
				Expect(err).To(BeNil())
			})
		})

		Context("", func() {
			It("should be signed successfully", func() {
				signature, err = key.Sign("hello world")
				Expect(err).To(BeNil())
				Expect(signature).ToNot(BeNil())
			})
		})

		Context("", func() {
			It("should be verified successfully", func() {
				Expect(key.Verify("hello world", signature)).To(BeTrue())
			})
		})
	})
})
