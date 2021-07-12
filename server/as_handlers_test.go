package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPasswordAuthorization(t *testing.T) {
	asHandlers, err := newASHandlers(ASHandlersOptions{})
	require.NoError(t, err)

	username, err := asHandlers.passwordAuthorization("test", "test")
	require.NoError(t, err)
	require.Equal(t, "test", username)

	username, err = asHandlers.passwordAuthorization("foo", "bar")
	require.Error(t, err)
	require.Equal(t, "", username)
}
