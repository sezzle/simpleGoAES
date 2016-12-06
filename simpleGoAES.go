package simpleGoAES

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"

	"github.com/golang/glog"
)

// We learned quite a bit from this post http://stackoverflow.com/questions/18817336/golang-encrypting-a-string-with-aes-and-base64 (Intermernet's answer)

//IsEncryptionOn : A simple system for turning on and off encryption in case you need to see the plain text results in a database for testing (default is On)
var IsEncryptionOn = true

//EncryptStringToBase64EncodedString : AES256 encryption function to work with strings
//returns a base64 encoded string
//(depends on EncryptByteArray)
func EncryptStringToBase64EncodedString(key, stringToEncrypt string) (base64String string, err error) {
	if IsEncryptionOn == false {
		return stringToEncrypt, nil
	}
	keyBytes := []byte(key)
	stringToEncryptBytes := []byte(stringToEncrypt)
	encryptedByteArray, err := EncryptByteArray(keyBytes, stringToEncryptBytes)
	encryptedString := base64.StdEncoding.EncodeToString(encryptedByteArray)
	return encryptedString, err
}

//DecryptBase64StringToString : AES256 decryption function to work with strings
//(depends on DecryptByteArray)
func DecryptBase64StringToString(key, base64StringToDecrypt string) (decodedString string, err error) {
	if IsEncryptionOn == false {
		return base64StringToDecrypt, nil
	}
	keyBytes := []byte(key)
	stringToDecryptBytes, err := base64.StdEncoding.DecodeString(base64StringToDecrypt)
	if err != nil {
		glog.Error(err)
		return "", err
	}
	decryptedByteArray, err := DecryptByteArray(keyBytes, stringToDecryptBytes)
	decryptedString := string(decryptedByteArray[:len(decryptedByteArray)])
	return decryptedString, err
}

//EncryptByteArray : AES256 encryption function to work with byte arrays
func EncryptByteArray(key, byteArrayToEncrypt []byte) ([]byte, error) {
	if IsEncryptionOn {
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		ciphertext := make([]byte, aes.BlockSize+len(byteArrayToEncrypt))
		iv := ciphertext[:aes.BlockSize]
		if _, err := io.ReadFull(rand.Reader, iv); err != nil {
			return nil, err
		}
		cfb := cipher.NewCFBEncrypter(block, iv)
		cfb.XORKeyStream(ciphertext[aes.BlockSize:], []byte(byteArrayToEncrypt))
		return ciphertext, nil
	}
	// Encryption was off, just return the string
	return byteArrayToEncrypt, nil
}

//DecryptByteArray : AES256 encryption function to work with byte arrays
func DecryptByteArray(key, byteArrayToDecrypt []byte) ([]byte, error) {
	if IsEncryptionOn {
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
		return byteArrayToDecrypt, nil
	}
	return byteArrayToDecrypt, nil
}
