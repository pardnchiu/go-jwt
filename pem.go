package goJwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

func handlePEM(c Config) error {
	if c.File != nil {
		if c.File.PrivateKeyPath != "" {
			bytes, err := os.ReadFile(c.File.PrivateKeyPath)
			if err != nil {
				return fmt.Errorf("Private key not exist: %v", err)
			}
			c.Option.PrivateKey = string(bytes)
		}

		if c.File.PublicKeyPath != "" {
			bytes, err := os.ReadFile(c.File.PublicKeyPath)
			if err != nil {
				return fmt.Errorf("Public key not exist: %v", err)
			}
			c.Option.PublicKey = string(bytes)
		}
	}

	// * 無私鑰檔案或是純文本配置，檢查本地檔案
	if c.Option.PrivateKey == "" && c.Option.PublicKey == "" {
		var privateByte, publicByte []byte
		var err error

		if checkFileExist(defaultPrivateKeyPath) && checkFileExist(defaultPublicKeyPath) {
			privateByte, err = os.ReadFile(defaultPrivateKeyPath)
			if err != nil {
				return fmt.Errorf("No default private key: %v", err)
			}

			publicByte, err = os.ReadFile(defaultPublicKeyPath)
			if err != nil {
				return fmt.Errorf("No default public key: %v", err)
			}
		} else {
			// * 創建新的私鑰
			if err := createPEM(defaultPrivateKeyPath, defaultPublicKeyPath); err != nil {
				return fmt.Errorf("Failed to create keys: %v", err)
			}

			privateByte, err = os.ReadFile(defaultPrivateKeyPath)
			if err != nil {
				return fmt.Errorf("Failed to create private key: %v", err)
			}

			publicByte, err = os.ReadFile(defaultPublicKeyPath)
			if err != nil {
				return fmt.Errorf("Failed to create public key: %v", err)
			}
		}

		c.Option.PrivateKey = string(privateByte)
		c.Option.PublicKey = string(publicByte)
	} else if c.Option.PrivateKey == "" || c.Option.PublicKey == "" {
		return fmt.Errorf("Both private key and public key are required")
	}

	return nil
}

func parsePEM(c Config) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	privateDecode, _ := pem.Decode([]byte(c.Option.PrivateKey))
	if privateDecode == nil {
		return nil, nil, fmt.Errorf("Failed to decode private key")
	}

	parsedPrivateKey, err := x509.ParsePKCS8PrivateKey(privateDecode.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Invalid private key: %v", err)
	}

	privateKey, ok := parsedPrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("Private key is not ECDSA")
	}

	publicDecode, _ := pem.Decode([]byte(c.Option.PublicKey))
	if publicDecode == nil {
		return nil, nil, fmt.Errorf("Failed to decode public key")
	}

	parsedPublicKey, err := x509.ParsePKIXPublicKey(publicDecode.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("Invalid public key: %v", err)
	}

	publicKey, ok := parsedPublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("Public key is not ECDSA")
	}

	if !privateKey.PublicKey.Equal(publicKey) {
		return nil, nil, fmt.Errorf("Private/Public key not match")
	}

	return privateKey, publicKey, nil
}

func checkFileExist(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

func createPEM(privateKeyPath, publicKeyPath string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("Failed to create private key: %v", err)
	}

	if err := os.MkdirAll(filepath.Dir(privateKeyPath), 0755); err != nil {
		return fmt.Errorf("Failed to create folder %s: %v", privateKeyPath, err)
	}

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("Failed to parse private key: %v", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return fmt.Errorf("Failed to parse public key: %v", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("Failed to store private key: %v", err)
	}

	if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("Failed to store public key: %v", err)
	}

	return nil
}
