package models

import "github.com/lestrrat-go/jwx/jwk"

type PrivateKey jwk.Key
type PublicKey jwk.Key

type PrivateKeyGetter interface {
	GetPrivateKey() PrivateKey
}

type PublicKeyGetter interface {
	GetPublicKey() PublicKey
}

type KeysGetter interface {
	PrivateKeyGetter
	PublicKeyGetter
}
