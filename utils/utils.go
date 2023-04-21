package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"

	"github.com/spacemonkeygo/openssl"
)

func ResolveKey(key string) *rsa.PrivateKey {
	private_key, err := ReadPrivateKey(key)
	if err != nil {
		panic(err)
	}
	marshal, err := private_key.MarshalPKCS1PrivateKeyPEM()
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(marshal)
	rsa_private_key, _ := x509.ParsePKCS1PrivateKey(block.Bytes)

	return rsa_private_key
}

func ReadPrivateKey(key string) (openssl.PrivateKey, error) {
	// generate private key if it does not exist
	// read private key if it exists
	private_key_filepath := os.Getenv(key)
	if private_key_filepath == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		os.Setenv(key, wd+"/keys/private_key.pem")
	}
	_, err := os.Stat(private_key_filepath)
	if os.IsNotExist(err) {
		// generate private key using openssl
		private_key, err := openssl.GenerateRSAKey(4096)
		if err != nil {
			return nil, err
		}
		pem_blocks, err := private_key.MarshalPKCS1PrivateKeyPEM()
		if err != nil {
			return nil, err
		}
		pemdata := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: pem_blocks,
		})
		err = os.WriteFile(os.Getenv(key), pemdata, 0644)
		return private_key, nil
	}
	pem_encoded_private_key, err := os.ReadFile(private_key_filepath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pem_encoded_private_key)

	private_key, err := openssl.LoadPrivateKeyFromPEM(block.Bytes)
	return private_key, err
}

func Encrypt(plaintext []byte, public_key *rsa.PublicKey) ([]byte, error) {
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, public_key, plaintext)
	if err != nil {
		return nil, err
	}
	return ciphertext, nil
}

func Decrypt(ciphertext []byte, private_key *rsa.PrivateKey) ([]byte, error) {
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, private_key, ciphertext)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func HashKey(key *rsa.PublicKey) string {
	bytes := x509.MarshalPKCS1PublicKey(key)
	hash := sha256.Sum256(bytes)
	return hex.EncodeToString(hash[:])
}
