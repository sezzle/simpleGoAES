package simpleGoAES

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimpleGoAES(t *testing.T) {
	t.Log("Starting encryption.")

	key := "123456789ABCDEFX123456789ABCDEFX" //32 chars long
	t.Logf("Key = %s.", key)

	//Simple byte array
	t.Logf("Testing a simple byte array.")
	//Byte array == Sezzle
	byteArrayToEncrypt := []byte{byte(83), byte(101), byte(122), byte(122), byte(108), byte(101)}
	t.Logf("Bytes to encrypt = '%s'.", byteArrayToEncrypt)
	t.Logf("Length of bytes to encrypt = '%d'.", len(byteArrayToEncrypt))
	encryptedBytes, err := EncryptByteArray([]byte(key), byteArrayToEncrypt)
	if err != nil {
		t.Fatalf("Could not encrypt the string: %s", err.Error())
	}
	decryptedByteArray, err := DecryptByteArray([]byte(key), encryptedBytes)
	if err != nil {
		t.Fatalf("Could not decrypt the string: %s", err.Error())
	}
	t.Logf("Decrypted bytes = '%s'.", decryptedByteArray)

	//A longer string
	t.Logf("Testing a longer string.")
	stringToEncrypt := "Let's encrypt something relatively substantial."
	t.Logf("String to encrypt = '%s'.", stringToEncrypt)
	encryptedString, err := EncryptStringToBase64EncodedString(key, stringToEncrypt)
	if err != nil {
		t.Fatalf("Could not encrypt the string: %s", err.Error())
	}
	decryptedString, err := DecryptBase64StringToString(key, encryptedString)
	if err != nil {
		t.Fatalf("Could not decrypt the string: %s", err.Error())
	}
	t.Logf("Decrypted string = '%s'.", decryptedString)

	//A super short string
	t.Logf("Testing a 1-character string.")
	stringToEncrypt = "A"
	t.Logf("String to encrypt = '%s'.", stringToEncrypt)
	encryptedString, err = EncryptStringToBase64EncodedString(key, stringToEncrypt)
	if err != nil {
		t.Fatalf("Could not encrypt the string: %s", err.Error())
	}
	decryptedString, err = DecryptBase64StringToString(key, encryptedString)
	if err != nil {
		t.Fatalf("Could not decrypt the string: %s", err.Error())
	}
	t.Logf("Decrypted string = '%s'.", decryptedString)

	assert.Equal(t, stringToEncrypt, decryptedString, "The origin and processed strings were not equal.")

	//Test the encryption flag, first off
	t.Logf("Testing turning off encryption.")
	IsEncryptionOn = false
	stringToEncrypt = "Encryption turned off test."
	t.Logf("String to encrypt = '%s'.", stringToEncrypt)
	encryptedString, err = EncryptStringToBase64EncodedString(key, stringToEncrypt)
	if err != nil {
		t.Fatalf("Could not encrypt the string: %s", err.Error())
	}

	t.Logf("String as encrypted = '%s'.", encryptedString)
	decryptedString, err = DecryptBase64StringToString(key, encryptedString)
	if err != nil {
		t.Fatalf("Could not decrypt the string: %s", err.Error())
	}
	t.Logf("Decrypted string = '%s'.", decryptedString)
	assert.Equal(t, stringToEncrypt, decryptedString, "The origin and processed strings were not equal.")

	//Test the encryption flag, then on
	t.Logf("Testing turning back on encryption.")
	IsEncryptionOn = true
	stringToEncrypt = "Encryption turned on test."
	t.Logf("String to encrypt = '%s'.", stringToEncrypt)
	encryptedString, err = EncryptStringToBase64EncodedString(key, stringToEncrypt)
	if err != nil {
		t.Fatalf("Could not encrypt the string: %s", err.Error())
	}
	t.Logf("String as encrypted = '%s'.", encryptedString)
	decryptedString, err = DecryptBase64StringToString(key, encryptedString)
	if err != nil {
		t.Fatalf("Could not decrypt the string: %s", err.Error())
	}
	t.Logf("Decrypted string = '%s'.", decryptedString)
	assert.Equal(t, stringToEncrypt, decryptedString, "The origin and processed strings were not equal.")

}
