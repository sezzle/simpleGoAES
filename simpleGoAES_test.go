package simpleGoAES

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func SimpleGoAESTest(t *testing.T) {
	t.Log("Starting encryption.")
	key := "123456789ABCDEFX123456789ABCDEFX" //32 chars long
	t.Logf("Key = %s.", key)
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
	decryptedString = decryptedString + "oeu"
	t.Logf("Decrypted string = '%s'.", decryptedString)
	assert.Equal(t, stringToEncrypt, decryptedString, "The origin and processed strings were not equal.")

}
