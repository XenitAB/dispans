package key

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewHandler(t *testing.T) {
	keyHandler, err := NewHandler()
	require.NoError(t, err)

	require.Equal(t, 1, len(keyHandler.privateKeys))
	require.Equal(t, 1, len(keyHandler.publicKeys))
}

func TestAddNewKey(t *testing.T) {
	keyHandler, err := NewHandler()
	require.NoError(t, err)

	err = keyHandler.AddNewKey()
	require.NoError(t, err)

	require.Equal(t, 2, len(keyHandler.privateKeys))
	require.Equal(t, 2, len(keyHandler.publicKeys))
}

func TestRemoveOldestKey(t *testing.T) {
	keyHandler, err := NewHandler()
	require.NoError(t, err)

	err = keyHandler.RemoveOldestKey()
	require.Error(t, err)

	err = keyHandler.AddNewKey()
	require.NoError(t, err)

	require.Equal(t, 2, len(keyHandler.privateKeys))
	require.Equal(t, 2, len(keyHandler.publicKeys))

	secondPrivKey := keyHandler.privateKeys[1]
	secondPubKey := keyHandler.publicKeys[1]

	err = keyHandler.RemoveOldestKey()
	require.NoError(t, err)

	require.Equal(t, secondPrivKey, keyHandler.privateKeys[0])
	require.Equal(t, secondPubKey, keyHandler.publicKeys[0])
}

func TestGetPrivateKey(t *testing.T) {
	keyHandler, err := NewHandler()
	require.NoError(t, err)

	require.Equal(t, keyHandler.privateKeys[0], keyHandler.GetPrivateKey())

	err = keyHandler.AddNewKey()
	require.NoError(t, err)

	require.Equal(t, keyHandler.privateKeys[1], keyHandler.GetPrivateKey())

	err = keyHandler.RemoveOldestKey()
	require.NoError(t, err)

	require.Equal(t, keyHandler.privateKeys[0], keyHandler.GetPrivateKey())
}

func TestGetPublicKey(t *testing.T) {
	keyHandler, err := NewHandler()
	require.NoError(t, err)

	require.Equal(t, keyHandler.publicKeys[0], keyHandler.GetPublicKey())

	err = keyHandler.AddNewKey()
	require.NoError(t, err)

	require.Equal(t, keyHandler.publicKeys[1], keyHandler.GetPublicKey())

	err = keyHandler.RemoveOldestKey()
	require.NoError(t, err)

	require.Equal(t, keyHandler.publicKeys[0], keyHandler.GetPublicKey())
}

func TestGetPublicKeySet(t *testing.T) {
	keyHandler, err := NewHandler()
	require.NoError(t, err)

	keySet := keyHandler.GetPublicKeySet()
	key, ok := keySet.Get(0)
	require.True(t, ok)

	require.Equal(t, keyHandler.publicKeys[0], key)

	err = keyHandler.AddNewKey()
	require.NoError(t, err)

	keySet = keyHandler.GetPublicKeySet()
	firstKey, ok := keySet.Get(0)
	require.True(t, ok)

	secondKey, ok := keySet.Get(1)
	require.True(t, ok)

	require.Equal(t, keyHandler.publicKeys[0], firstKey)
	require.Equal(t, keyHandler.publicKeys[1], secondKey)

	err = keyHandler.RemoveOldestKey()
	require.NoError(t, err)

	keySet = keyHandler.GetPublicKeySet()
	key, ok = keySet.Get(0)
	require.True(t, ok)

	require.Equal(t, keyHandler.publicKeys[0], key)

	_, ok = keySet.Get(1)
	require.False(t, ok)
}
