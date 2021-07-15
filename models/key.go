package models

import "github.com/lestrrat-go/jwx/jwk"

type PrivateKey jwk.Key
type PublicKey jwk.Key

type PublicKeySet jwk.Set

type PrivateKeyGetter interface {
	GetPrivateKey() PrivateKey
}

type PublicKeyGetter interface {
	GetPublicKey() PublicKey
	GetPublicKeySet() PublicKeySet
}

type KeysGetter interface {
	PrivateKeyGetter
	PublicKeyGetter
}

type KeysAdder interface {
	AddNewKey() error
}

type KeysRemover interface {
	RemoveOldestKey() error
}

type KeysUpdater interface {
	KeysAdder
	KeysRemover
}
