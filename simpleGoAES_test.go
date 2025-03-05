package simpleGoAES

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

var runes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.!@#$%^&*(){},=-;")
var keyLength = 32

func RandString(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = runes[rand.Intn(len(runes))]
	}
	return string(b)
}

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
	EncTest(t, key, stringToEncrypt)

	//A super short string
	t.Logf("Testing a 1-character string.")
	stringToEncrypt = "A"
	EncTest(t, key, stringToEncrypt)

	//Test something like EIN
	t.Logf("Testing an EIN string.")
	stringToEncrypt = "444221111"
	EncTest(t, key, stringToEncrypt)

	//Test the encryption flag, first off
	t.Logf("Testing turning off encryption.")
	IsEncryptionOn = false
	stringToEncrypt = "Encryption turned off test."
	EncTest(t, key, stringToEncrypt)

	//Test the encryption flag, then on
	t.Logf("Testing turning back on encryption.")
	IsEncryptionOn = true
	stringToEncrypt = "Encryption turned on test."
	EncTest(t, key, stringToEncrypt)

	//Test a 1000 sets of keys and strings to encrypt/decrypt
	for index := 0; index < 10000; index++ {
		//randomize the key
		randKey := RandString(keyLength)
		randStringLength := rand.Intn(100)
		stringToEncrypt := RandString(randStringLength)
		EncTest(t, randKey, stringToEncrypt)
	}
	return
}

func EncTest(t *testing.T, keyToTest string, stringToTest string) {
	t.Logf("Key used to encrypt = '%s'.", keyToTest)
	t.Logf("String to encrypt = '%s'.", stringToTest)
	encryptedString, err := EncryptStringToBase64EncodedString(keyToTest, stringToTest)
	if err != nil {
		t.Fatalf("Could not encrypt the string: %s", err.Error())
	}
	decryptedString, err := DecryptBase64StringToString(keyToTest, encryptedString)
	if err != nil {
		t.Fatalf("Could not decrypt the string: %s", err.Error())
	}
	t.Logf("Decrypted string = '%s'.", decryptedString)

	assert.Equal(t, stringToTest, decryptedString, "The origin and processed strings were not equal.")
	return
}
