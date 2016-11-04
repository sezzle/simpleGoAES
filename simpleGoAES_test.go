package simpleGoAES

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSimpleGoAES(t *testing.T) {
	t.Log("Starting encryption.")

	key := "123456789ABCDEFX123456789ABCDEFX" //32 chars long
	t.Logf("Key = %s.", key)

	//A longer string
	t.Logf("Testing a longer string.")
	stringToEncrypt := "Let's encrypt something relatively substantial."
	t.Logf("String to encrypt = '%s'.", stringToEncrypt)
	encryptedString, err := EncryptString(key, stringToEncrypt)
	if err != nil {
		t.Fatalf("Could not encrypt the string: %s", err.Error())
	}
	decryptedString, err := DecryptString(key, encryptedString)
	if err != nil {
		t.Fatalf("Could not decrypt the string: %s", err.Error())
	}
	t.Logf("Decrypted string = '%s'.", decryptedString)

	//A super short string
	t.Logf("Testing a 1-character string.")
	stringToEncrypt = "A"
	t.Logf("String to encrypt = '%s'.", stringToEncrypt)
	encryptedString, err = EncryptString(key, stringToEncrypt)
	if err != nil {
		t.Fatalf("Could not encrypt the string: %s", err.Error())
	}
	decryptedString, err = DecryptString(key, encryptedString)
	if err != nil {
		t.Fatalf("Could not decrypt the string: %s", err.Error())
	}
	t.Logf("Decrypted string = '%s'.", decryptedString)

	assert.Equal(t, stringToEncrypt, decryptedString, "The origin and processed strings were not equal.")

	//Test the encryption flag, first off
	t.Logf("Testing turning off encryption.")
	TurnEncryptionOff()
	stringToEncrypt = "Encryption turned off test."
	t.Logf("String to encrypt = '%s'.", stringToEncrypt)
	encryptedString, err = EncryptString(key, stringToEncrypt)
	if err != nil {
		t.Fatalf("Could not encrypt the string: %s", err.Error())
	}
	decryptedString, err = DecryptString(key, encryptedString)
	if err != nil {
		t.Fatalf("Could not decrypt the string: %s", err.Error())
	}
	t.Logf("Decrypted string = '%s'.", decryptedString)
	assert.Equal(t, stringToEncrypt, decryptedString, "The origin and processed strings were not equal.")

	//Test the encryption flag, then on
	t.Logf("Testing turning back on encryption.")
	TurnEncryptionOn()
	stringToEncrypt = "Encryption turned off test."
	t.Logf("String to encrypt = '%s'.", stringToEncrypt)
	encryptedString, err = EncryptString(key, stringToEncrypt)
	if err != nil {
		t.Fatalf("Could not encrypt the string: %s", err.Error())
	}
	decryptedString, err = DecryptString(key, encryptedString)
	if err != nil {
		t.Fatalf("Could not decrypt the string: %s", err.Error())
	}
	t.Logf("Decrypted string = '%s'.", decryptedString)
	assert.Equal(t, stringToEncrypt, decryptedString, "The origin and processed strings were not equal.")

}
