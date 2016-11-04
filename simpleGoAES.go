package simpleGoAES

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// We learned quite a bit from this post http://stackoverflow.com/questions/18817336/golang-encrypting-a-string-with-aes-and-base64 (Intermernet's answer)

var isEncryptionOn = true

//TurnEncryptionOn : A simple system for turning on encryption (default is On)
func TurnEncryptionOn() {
	isEncryptionOn = true
}

//TurnEncryptionOff : A simple system for turning off encryption (default is On)
func TurnEncryptionOff() {
	isEncryptionOn = false
}

//EncryptString : AES256 encryption function to work with strings
//(depends on EncryptByteArray)
func EncryptString(key, stringToEncrypt string) (string, error) {
	keyBytes := []byte(key)
	stringToEncryptBytes := []byte(stringToEncrypt)
	encryptedByteArray, err := EncryptByteArray(keyBytes, stringToEncryptBytes)
	encryptedString := string(encryptedByteArray[:len(encryptedByteArray)])
	return encryptedString, err
}

//DecryptString : AES256 decryption function to work with strings
//(depends on DecryptByteArray)
func DecryptString(key, stringToDecrypt string) (string, error) {
	keyBytes := []byte(key)
	stringToDecryptBytes := []byte(stringToDecrypt)
	decryptedByteArray, err := DecryptByteArray(keyBytes, stringToDecryptBytes)
	decryptedString := string(decryptedByteArray[:len(decryptedByteArray)])
	return decryptedString, err
}

//EncryptByteArray : AES256 encryption function to work with byte arrays
func EncryptByteArray(key, byteArrayToEncrypt []byte) ([]byte, error) {
	if isEncryptionOn {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		b := base64.StdEncoding.EncodeToString(byteArrayToEncrypt)
		ciphertext := make([]byte, aes.BlockSize+len(b))
		iv := ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		cfb := cipher.NewCFBEncrypter(block, iv)
		cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(b))
		return ciphertext, nil
	}
	// Encryption was off, just return the string
	return byteArrayToEncrypt, nil
}

//DecryptByteArray : AES256 encryption function to work with byte arrays
func DecryptByteArray(key, byteArrayToDecrypt []byte) ([]byte, error) {
	if isEncryptionOn {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		if len(byteArrayToDecrypt) < aes.BlockSize {
			return nil, errors.New("ciphertext too short")
		}
		iv := byteArrayToDecrypt[:aes.BlockSize]
		byteArrayToDecrypt = byteArrayToDecrypt[aes.BlockSize:]
		cfb := cipher.NewCFBDecrypter(block, iv)
		cfb.XORKeyStream(byteArrayToDecrypt, byteArrayToDecrypt)
		data, err := base64.StdEncoding.DecodeString(string(byteArrayToDecrypt))
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	return byteArrayToDecrypt, nil
}
