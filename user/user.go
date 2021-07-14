package user

import (
	"fmt"

	"github.com/xenitab/dispans/models"
)

type Handler struct {
	Users models.Users
}

func NewHandler() *Handler {
	users := models.Users{
		"test": {
			UserID:        "test",
			Email:         "test@test.com",
			EmailVerified: boolPtr(true),
			Name:          "test testsson",
			FamilyName:    "testsson",
			GivenName:     "test",
			Locale:        "US",
		},
	}

	return &Handler{

		Users: users,
	}
}

func (h *Handler) GetUserByID(userID string) (models.User, error) {
	user, ok := h.Users[userID]
	if !ok {
		return models.User{}, fmt.Errorf("user not found")
	}

	return user, nil
}

func boolPtr(b bool) *bool {
	return &b
}
