package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"io"
)

// key is 32 bytes for AES-256.
// Note: Hardcoding the key is not truly secure against reverse engineering,
// but it prevents plain text storage in the preference file.
var key = []byte("TheQuickBrownFoxJumpsOverTheLazy") // 32 chars

func encrypt(plaintext string) string {
	if plaintext == "" {
		return ""
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return plaintext // Fallback to plaintext on error (should not happen)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return plaintext
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return plaintext
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext)
}

func decrypt(ciphertext string) string {
	if ciphertext == "" {
		return ""
	}
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "" // Return empty on decoding error
	}

	c, err := aes.NewCipher(key)
	if err != nil {
		return ""
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		return ""
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return ""
	}

	nonce, ciphertextBytes := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "" // Return empty on decryption error
	}

	return string(plaintext)
}
