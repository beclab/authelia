package utils

import (
	"crypto"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// HashSHA256FromString takes an input string and calculates the SHA256 checksum returning it as a base16 hash string.
func HashSHA256FromString(input string) (output string) {
	hash := sha256.New()

	hash.Write([]byte(input))

	return hex.EncodeToString(hash.Sum(nil))
}

// HashSHA256FromPath takes a path string and calculates the SHA256 checksum of the file at the path returning it as a base16 hash string.
func HashSHA256FromPath(path string) (output string, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}

	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

func MD5(str string) string {
	h := crypto.MD5.New()
	h.Write([]byte(str))
	return hex.EncodeToString(h.Sum(nil))
}
