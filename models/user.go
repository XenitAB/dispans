package models

type User struct {
	UserID        string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	Locale        string `json:"locale,omitempty"`
}

type Users map[string]User

type UserGetter interface {
	GetUserByID(userID string) (User, error)
}
