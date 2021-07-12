package authorizationserver

type User struct {
	UserID        string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified *bool  `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	FamilyName    string `json:"family_name,omitempty"`
	GivenName     string `json:"given_name,omitempty"`
	Locale        string `json:"locale,omitempty"`
}

func GetUserByID(userID string) (User, error) {
	return User{
		UserID:        userID,
		Email:         "test@test.com",
		EmailVerified: boolPtr(true),
		Name:          "test testsson",
		FamilyName:    "testsson",
		GivenName:     "test",
		Locale:        "US",
	}, nil
}

func boolPtr(b bool) *bool {
	return &b
}
