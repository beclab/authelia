package handlers

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/templates"
)

var ErrUnPadding = errors.New("UnPadding error")

func ctxLogEvent(ctx *middlewares.AutheliaCtx, username, description string, eventDetails map[string]any) {
	var (
		details *authentication.UserDetails
		err     error
	)

	ctx.Logger.Debugf("Getting user details for notification")

	// Send Notification.
	if details, err = ctx.Providers.UserProvider.GetDetails(username, ""); err != nil {
		ctx.Logger.Error(err)
		return
	}

	if len(details.Emails) == 0 {
		ctx.Logger.Error(fmt.Errorf("user %s has no email address configured", username))
		return
	}

	data := templates.EmailEventValues{
		Title:       description,
		DisplayName: details.DisplayName,
		RemoteIP:    ctx.RemoteIP().String(),
		Details:     eventDetails,
	}

	ctx.Logger.Debugf("Getting user addresses for notification")

	addresses := details.Addresses()

	ctx.Logger.Debugf("Sending an email to user %s (%s) to inform them of an important event.", username, addresses[0])

	if err = ctx.Providers.Notifier.Send(ctx, addresses[0], description, ctx.Providers.Templates.GetEventEmailTemplate(), data); err != nil {
		ctx.Logger.Error(err)
		return
	}
}

func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origin []byte) ([]byte, error) {
	length := len(origin)
	if length == 0 {
		return origin, ErrUnPadding
	}
	unpadding := int(origin[length-1])
	if length < unpadding {
		return origin, ErrUnPadding
	}
	return origin[:(length - unpadding)], nil
}

func AesEncrypt(origin, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	origin = PKCS7Padding(origin, blockSize)
	blockMode := cipher.NewCBCEncrypter(block, key[:blockSize])
	crypted := make([]byte, len(origin))
	blockMode.CryptBlocks(crypted, origin)
	return crypted, nil
}

func AesDecrypt(crypted, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	blockSize := block.BlockSize()
	blockMode := cipher.NewCBCDecrypter(block, key[:blockSize])
	origin := make([]byte, len(crypted))
	blockMode.CryptBlocks(origin, crypted)
	origin, err = PKCS7UnPadding(origin)
	if err != nil {
		return origin, err
	}
	return origin, nil
}

func md5(str string) string {
	h := crypto.MD5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}
