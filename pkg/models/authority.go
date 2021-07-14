package models

type IssuerGetter interface {
	GetIssuer() string
}

type IssuerSetter interface {
	SetIssuer(newIssuer string)
}

type IssuerGetSetter interface {
	IssuerGetter
	IssuerSetter
}
