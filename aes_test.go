package crypto

import (
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AesCbcKey", func() {
	Describe("key by bytes", func() {
		var (
			key        Key[[]byte]
			ciphertext []byte
			err        error
		)

		Context("with valid parameters", func() {
			It("should be created successfully", func() {
				key, err = new(aesKeyImportImpl[[]byte]).KeyImport([]byte("123456"), AesCbc128)
				Expect(err).To(BeNil())
			})

			It("should be signed successfully", func() {
				ciphertext, err = key.Encrypt([]byte("hello world"))
				Expect(err).To(BeNil())
				Expect(ciphertext).ToNot(BeNil())
				By(fmt.Sprintf("ciphertext is: %v", string(ciphertext)))
			})

			It("should be verified successfully", func() {
				plaintext, err := key.Decrypt(ciphertext)
				Expect(err).To(BeNil())
				Expect(plaintext).To(BeComparableTo([]byte("hello world")))
			})
		})

		Context("with invalid key", func() {
			It("should fail to create key", func() {
				_, err = new(aesKeyImportImpl[[]byte]).KeyImport([]byte(""), AesCbc128)
				Expect(err).ToNot(BeNil())
			})
		})

		Context("when attempting to decrypt with incorrect data", func() {
			It("should not decrypt successfully", func() {
				_, err := key.Decrypt([]byte("incorrect_encryptedData"))
				Expect(err).ToNot(BeNil())
			})
		})
	})

	Describe("key by string", func() {
		var (
			key        Key[string]
			ciphertext string
			err        error
		)

		Context("with valid parameters", func() {
			It("should be created successfully", func() {
				key, err = new(aesKeyImportImpl[string]).KeyImport("123456", AesCbc128)
				Expect(err).To(BeNil())
			})

			It("should be signed successfully", func() {
				ciphertext, err = key.Encrypt("hello world")
				Expect(err).To(BeNil())
				Expect(ciphertext).ToNot(BeNil())
				By(fmt.Sprintf("ciphertext is: %v", ciphertext))
			})

			It("should be verified successfully", func() {
				plaintext, err := key.Decrypt(ciphertext)
				Expect(err).To(BeNil())
				Expect(plaintext).To(BeComparableTo("hello world"))
			})
		})

		Context("with invalid key", func() {
			It("should fail to create key", func() {
				_, err = new(aesKeyImportImpl[string]).KeyImport("", AesCbc128)
				Expect(err).ToNot(BeNil())
			})
		})

		Context("when attempting to decrypt with incorrect data", func() {
			It("should not decrypt successfully", func() {
				_, err := key.Decrypt("incorrect_encryptedData")
				Expect(err).ToNot(BeNil())
			})
		})
	})
})

var _ = Describe("AesGcmKey", func() {
	Describe("key by bytes", func() {
		var (
			key        Key[[]byte]
			ciphertext []byte
			err        error
		)

		Context("with valid parameters", func() {
			It("should be created successfully", func() {
				key, err = new(aesKeyImportImpl[[]byte]).KeyImport([]byte("123456"), AesGcm128)
				Expect(err).To(BeNil())
			})

			It("should be signed successfully", func() {
				ciphertext, err = key.Encrypt([]byte("hello world"))
				Expect(err).To(BeNil())
				Expect(ciphertext).ToNot(BeNil())
				By(fmt.Sprintf("ciphertext is: %v", string(ciphertext)))
			})

			It("should be verified successfully", func() {
				plaintext, err := key.Decrypt(ciphertext)
				Expect(err).To(BeNil())
				Expect(plaintext).To(BeComparableTo([]byte("hello world")))
			})
		})

		Context("with invalid key", func() {
			It("should fail to create key", func() {
				_, err = new(aesKeyImportImpl[[]byte]).KeyImport([]byte(""), AesGcm128)
				Expect(err).ToNot(BeNil())
			})
		})

		Context("when attempting to decrypt with incorrect data", func() {
			It("should not decrypt successfully", func() {
				_, err := key.Decrypt([]byte("incorrect_encryptedData"))
				Expect(err).ToNot(BeNil())
			})
		})
	})

	Describe("key by string", func() {
		var (
			key        Key[string]
			ciphertext string
			err        error
		)

		Context("with valid parameters", func() {
			It("should be created successfully", func() {
				key, err = new(aesKeyImportImpl[string]).KeyImport("123456", AesGcm128)
				Expect(err).To(BeNil())
			})

			It("should be signed successfully", func() {
				ciphertext, err = key.Encrypt("hello world")
				Expect(err).To(BeNil())
				Expect(ciphertext).ToNot(BeNil())
				By(fmt.Sprintf("ciphertext is: %v", ciphertext))
			})

			It("should be verified successfully", func() {
				plaintext, err := key.Decrypt(ciphertext)
				Expect(err).To(BeNil())
				Expect(plaintext).To(BeComparableTo("hello world"))
			})
		})

		Context("with invalid key", func() {
			It("should fail to create key", func() {
				_, err = new(aesKeyImportImpl[string]).KeyImport("", AesGcm128)
				Expect(err).ToNot(BeNil())
			})
		})

		Context("when attempting to decrypt with incorrect data", func() {
			It("should not decrypt successfully", func() {
				_, err := key.Decrypt("incorrect_encryptedData")
				Expect(err).ToNot(BeNil())
			})
		})
	})
})
