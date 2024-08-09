package utils

import (
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestShouldEncryptAndDecriptUsingAES(t *testing.T) {
	var key [32]byte = sha256.Sum256([]byte("the key"))

	var secret = "the secret"

	encryptedSecret, err := Encrypt([]byte(secret), &key)
	assert.NoError(t, err, "")

	decryptedSecret, err := Decrypt(encryptedSecret, &key)

	assert.NoError(t, err, "")
	assert.Equal(t, secret, string(decryptedSecret))
}

func TestShouldFailDecryptOnInvalidKey(t *testing.T) {
	var key [32]byte = sha256.Sum256([]byte("the key"))

	var secret = "the secret"

	encryptedSecret, err := Encrypt([]byte(secret), &key)
	assert.NoError(t, err, "")

	key = sha256.Sum256([]byte("the key 2"))

	_, err = Decrypt(encryptedSecret, &key)

	assert.Error(t, err, "message authentication failed")
}

func TestShouldFailDecryptOnInvalidCypherText(t *testing.T) {
	var key [32]byte = sha256.Sum256([]byte("the key"))

	encryptedSecret := []byte("abc123")

	_, err := Decrypt(encryptedSecret, &key)

	assert.Error(t, err, "message authentication failed")
}

func TestTOTPSecret(t *testing.T) {
	b32Secret := "KREVIQKNI5CUETKIGNDUUN2LKFFEKQSWKJHVISSNJZIUMNRSJFHUOVSEGNHE2QRVGZGVIVCBG43FCU2JINAQ"
	s, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32Secret)
	if err != nil {
		t.Log(err)
	}

	t.Log(hex.EncodeToString(s))

	key := sha256.Sum256([]byte("dJPM367jfe5R0sx8TzLnu5Ln1vyp0lmA"))
	as, err := Encrypt(s, &key)
	if err != nil {
		t.Log(err)
		t.Fail()
		return
	}

	t.Log(hex.EncodeToString(as))
	d := base64.StdEncoding.WithPadding(base64.StdPadding).EncodeToString(as)

	fmt.Printf("secret: %s", string(d))
}

func TestTOTPdecSecret(t *testing.T) {
	b64secret := "0NjKONtul2VTvzfDpDdYaxOLNxtCcBkwgfDwK7S71XPF3crHuaU2kmeR/jLb2VDgz+nN4pCC08ACrF7w2igYaQZgPeKmCIrHAd1kt5TlMfY="

	as, err := base64.StdEncoding.WithPadding(base64.StdPadding).DecodeString(b64secret)
	if err != nil {
		t.Log(err)
		return
	}

	log.Print(hex.Dump(as))

	key := sha256.Sum256([]byte("dJPM367jfe5R0sx8TzLnu5Ln1vyp0lmA"))

	s, err := Decrypt(as, &key)
	if err != nil {
		t.Log(err)
		return
	}

	log.Print(hex.Dump(s))
	t.Log(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(s))
}
