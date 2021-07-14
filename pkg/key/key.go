package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/xenitab/dispans/pkg/models"
)

type handler struct {
	privateKey models.PrivateKey
	publicKey  models.PublicKey
}

func NewHandler() (*handler, error) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate new ECDSA privatre key: %s\n", err)
		return nil, err
	}

	key, err := jwk.New(ecdsaKey)
	if err != nil {
		return nil, err
	}

	if _, ok := key.(jwk.ECDSAPrivateKey); !ok {
		return nil, fmt.Errorf("expected jwk.ECDSAPrivateKey, got %T", key)
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}

	keyID := fmt.Sprintf("%x", thumbprint)
	key.Set(jwk.KeyIDKey, keyID)

	pubKey, err := jwk.New(ecdsaKey.PublicKey)
	if err != nil {
		return nil, err
	}

	if _, ok := pubKey.(jwk.ECDSAPublicKey); !ok {
		return nil, fmt.Errorf("expected jwk.ECDSAPublicKey, got %T", key)
	}

	pubKey.Set(jwk.KeyIDKey, keyID)
	pubKey.Set(jwk.AlgorithmKey, jwa.ES384)

	return &handler{
		privateKey: key,
		publicKey:  pubKey,
	}, nil
}

func (h *handler) GetPrivateKey() models.PrivateKey {
	return h.privateKey
}

func (h *handler) GetPublicKey() models.PublicKey {
	return h.publicKey
}
