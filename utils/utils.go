package utils

import (
	"encoding/pem"
	"os"

	"github.com/spacemonkeygo/openssl"
)

func read_private_key(key string) (openssl.PrivateKey, error) {
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
