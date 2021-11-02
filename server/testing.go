package server

import (
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

type handlerTesting struct {
	opHandler *OpHandler
}

func NewTesting(t testing.TB) *handlerTesting {
	t.Helper()

	op, err := NewDefault()
	require.NoError(t, err)

	return &handlerTesting{
		opHandler: op,
	}
}

func (h *handlerTesting) Close(t testing.TB) {
	t.Helper()

	h.opHandler.Close()
}

func (h *handlerTesting) GetURL(t testing.TB) string {
	t.Helper()
	return h.opHandler.GetURL()
}

func (h *handlerTesting) GetClientID(t testing.TB) string {
	t.Helper()

	return h.opHandler.clientID
}

func (h *handlerTesting) GetClientSecret(t testing.TB) string {
	t.Helper()

	return h.opHandler.clientID
}

func (h *handlerTesting) GetRedirectURI(t testing.TB) string {
	t.Helper()

	return h.opHandler.redirectURI
}

func (h *handlerTesting) RotateKeys(t testing.TB) {
	t.Helper()

	err := h.opHandler.RotateKeys()
	require.NoError(t, err)
}

func (h *handlerTesting) GetToken(t testing.TB) *oauth2.Token {
	t.Helper()

	token, err := h.opHandler.GetToken()
	require.NoError(t, err)

	return token
}
