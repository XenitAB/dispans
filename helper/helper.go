package helper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
)

func GenerateCodeChallengeS256() (string, string, error) {
	codeVerifier, err := GenerateRandomString(43)
	if err != nil {
		return "", "", err
	}

	hasher := sha256.New()
	hasher.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	return codeVerifier, codeChallenge, nil
}

func GenerateState() (string, error) {
	stateString, err := GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	hasher := sha256.New()
	hasher.Write([]byte(stateString))
	state := base64.RawURLEncoding.EncodeToString(hasher.Sum(nil))

	return state, nil
}

func GenerateRandomString(n int) (string, error) {
	const letters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz-"
	ret := make([]byte, n)
	for i := 0; i < n; i++ {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			return "", err
		}
		ret[i] = letters[num.Int64()]
	}

	return string(ret), nil
}
