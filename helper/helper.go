package helper

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"
)

func GenerateCodeChallengeS256() (string, string, error) {
	codeVerifier, err := generateRandomString(32)
	if err != nil {
		return "", "", err
	}
	s256 := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.URLEncoding.EncodeToString(s256[:])

	return codeVerifier, codeChallenge, nil
}

func GenerateState() (string, error) {
	stateString, err := generateRandomString(32)
	if err != nil {
		return "", err
	}

	s256 := sha256.Sum256([]byte(stateString))
	state := base64.URLEncoding.EncodeToString(s256[:])
	state = strings.TrimSuffix(state, "=")

	return state, nil
}

func generateRandomString(length int) (string, error) {
	result := ""
	for {
		if len(result) >= length {
			return result, nil
		}

		num, err := rand.Int(rand.Reader, big.NewInt(int64(127)))
		if err != nil {
			return "", err
		}

		n := num.Int64()

		if n > 32 && n < 127 {
			result += fmt.Sprint(n)
		}
	}
}
