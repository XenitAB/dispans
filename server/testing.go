package server

import (
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/xenitab/dispans/helper"
)

type handlerTesting struct {
	t              *testing.T
	httpTestServer *httptest.Server
	clientID       string
	clientSecret   string
	redirectURI    string
}

func NewTesting(t *testing.T) (*handlerTesting, error) {
	t.Helper()

	testServer := httptest.NewServer(nil)

	hostPort := testServer.Listener.Addr().String()
	addr := strings.Split(hostPort, ":")[0]
	portString := strings.Split(hostPort, ":")[1]

	port, err := strconv.Atoi(portString)
	require.NoError(t, err)

	clientID := "test-client"
	clientSecret := "test-secret"
	redirectURI := "http://test.foo.bar/callback"

	opts := Options{
		Address:      addr,
		Port:         port,
		Issuer:       testServer.URL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
	}

	err = opts.Validate()
	require.NoError(t, err)

	router, err := new(opts)
	require.NoError(t, err)

	testServer.Config.Handler = router

	return &handlerTesting{
		t:              t,
		httpTestServer: testServer,
		clientID:       clientID,
		clientSecret:   clientSecret,
		redirectURI:    redirectURI,
	}, nil
}

func (h *handlerTesting) Close() {
	h.t.Helper()

	h.httpTestServer.Close()
}

func (h *handlerTesting) GetHTTPClient() *http.Client {
	h.t.Helper()

	httpClient := h.httpTestServer.Client()
	jar, err := cookiejar.New(nil)
	require.NoError(h.t, err)
	httpClient.Jar = jar

	return httpClient
}

func (h *handlerTesting) GetURL() string {
	h.t.Helper()

	return h.httpTestServer.URL
}

func (h *handlerTesting) GetClientID() string {
	h.t.Helper()

	return h.clientID
}

func (h *handlerTesting) GetClientSecret() string {
	h.t.Helper()

	return h.clientSecret
}

func (h *handlerTesting) GetRedirectURI() string {
	h.t.Helper()

	return h.redirectURI
}

func (h *handlerTesting) GetToken() string {
	t := h.t
	t.Helper()

	codeVerifier, codeChallange, err := helper.GenerateCodeChallengeS256()
	require.NoError(t, err)

	state, err := helper.GenerateState()
	require.NoError(t, err)

	remoteUrl, err := url.Parse(h.GetURL())
	require.NoError(t, err)

	remoteUrl.Path = "/oauth/authorize"

	query := url.Values{}
	query.Add("client_id", h.clientID)
	query.Add("code_challenge", codeChallange)
	query.Add("code_challenge_method", "S256")
	query.Add("redirect_uri", h.redirectURI)
	query.Add("response_type", "code")
	query.Add("scope", "all")
	query.Add("state", state)

	remoteUrl.RawQuery = query.Encode()

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := h.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)

	resLocation := res.Header.Get("location")
	require.Contains(t, resLocation, "/login")
	require.NotEmpty(t, helper.httpClient.Jar.Cookies(remoteUrl))
}
