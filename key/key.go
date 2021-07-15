package key

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/lestrrat-go/jwx/jwa"
	"github.com/lestrrat-go/jwx/jwk"
	"github.com/xenitab/dispans/models"
)

type handler struct {
	sync.RWMutex
	privateKeys []models.PrivateKey
	publicKeys  []models.PublicKey
}

func NewHandler() (*handler, error) {
	h := &handler{
		privateKeys: []models.PrivateKey{},
		publicKeys:  []models.PublicKey{},
	}

	err := h.AddNewKey()
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *handler) AddNewKey() error {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		fmt.Printf("failed to generate new ECDSA privatre key: %s\n", err)
		return err
	}

	key, err := jwk.New(ecdsaKey)
	if err != nil {
		return err
	}

	if _, ok := key.(jwk.ECDSAPrivateKey); !ok {
		return fmt.Errorf("expected jwk.ECDSAPrivateKey, got %T", key)
	}

	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return err
	}

	keyID := fmt.Sprintf("%x", thumbprint)
	key.Set(jwk.KeyIDKey, keyID)

	pubKey, err := jwk.New(ecdsaKey.PublicKey)
	if err != nil {
		return err
	}

	if _, ok := pubKey.(jwk.ECDSAPublicKey); !ok {
		return fmt.Errorf("expected jwk.ECDSAPublicKey, got %T", key)
	}

	pubKey.Set(jwk.KeyIDKey, keyID)
	pubKey.Set(jwk.AlgorithmKey, jwa.ES384)

	h.Lock()

	h.privateKeys = append(h.privateKeys, key)
	h.publicKeys = append(h.publicKeys, pubKey)

	h.Unlock()

	return nil
}

func (h *handler) RemoveOldestKey() error {
	h.RLock()
	privKeysLen := len(h.privateKeys)
	pubKeysLen := len(h.publicKeys)
	h.RUnlock()

	if privKeysLen != pubKeysLen {
		return fmt.Errorf("Private keys length (%d) isn't equal private keys length (%d).", privKeysLen, pubKeysLen)
	}

	if privKeysLen <= 1 {
		return fmt.Errorf("Keys length smaller or equal 1: %d", privKeysLen)
	}

	h.Lock()
	h.privateKeys = h.privateKeys[1:]
	h.publicKeys = h.publicKeys[1:]
	h.Unlock()

	return nil
}

func (h *handler) GetPrivateKey() models.PrivateKey {
	h.RLock()

	lastKeyIndex := len(h.privateKeys) - 1
	privKey := h.privateKeys[lastKeyIndex]

	h.RUnlock()

	return privKey
}

func (h *handler) GetPublicKey() models.PublicKey {
	h.RLock()

	lastKeyIndex := len(h.publicKeys) - 1
	pubKey := h.publicKeys[lastKeyIndex]

	h.RUnlock()

	return pubKey
}

func (h *handler) GetPublicKeySet() models.PublicKeySet {
	keySet := jwk.NewSet()

	h.RLock()

	for _, pubKey := range h.publicKeys {
		keySet.Add(pubKey)
	}

	h.RUnlock()

	return keySet
}
