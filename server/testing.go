package server

import (
	"encoding/json"
	"io"
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
	httpClient     *http.Client
	clientID       string
	clientSecret   string
	redirectURI    string
}

func NewTesting(t *testing.T) *handlerTesting {
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

	httpClient := testServer.Client()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	httpClient.Jar = jar

	return &handlerTesting{
		t:              t,
		httpTestServer: testServer,
		httpClient:     httpClient,
		clientID:       clientID,
		clientSecret:   clientSecret,
		redirectURI:    redirectURI,
	}
}

func (h *handlerTesting) Close() {
	h.t.Helper()

	h.httpTestServer.Close()
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

func (h *handlerTesting) GetToken() (string, string, string) {
	t := h.t
	t.Helper()

	codeVerifier, codeChallange, err := helper.GenerateCodeChallengeS256()
	require.NoError(t, err)

	state, err := helper.GenerateState()
	require.NoError(t, err)

	h.getAuhtorize(codeChallange, state)
	h.getLogin()
	h.postLogin()
	code := h.getAuthorizeWithCookies(state)
	tokenResponseBytes := h.postToken(code, codeVerifier)

	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
	}

	err = json.Unmarshal(tokenResponseBytes, &tokenResponse)

	return tokenResponse.AccessToken, tokenResponse.IDToken, tokenResponse.RefreshToken
}

func (h *handlerTesting) getAuhtorize(codeChallange, state string) {
	t := h.t
	t.Helper()

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
}

func (h *handlerTesting) getLogin() {
	t := h.t
	t.Helper()

	remoteUrl, err := url.Parse(h.GetURL())
	require.NoError(t, err)
	remoteUrl.Path = "/login"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := h.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)
}

func (h *handlerTesting) postLogin() {
	t := h.t
	t.Helper()

	remoteUrl, err := url.Parse(h.GetURL())
	require.NoError(t, err)
	remoteUrl.Path = "/login"

	form := url.Values{}
	form.Add("username", "test")
	form.Add("password", "test")

	body := strings.NewReader(form.Encode())

	req, err := http.NewRequest("POST", remoteUrl.String(), body)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := h.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)
}

func (h *handlerTesting) getAuthorizeWithCookies(state string) string {
	t := h.t
	t.Helper()

	remoteUrl, err := url.Parse(h.GetURL())
	require.NoError(t, err)
	remoteUrl.Path = "/oauth/authorize"

	req, err := http.NewRequest("GET", remoteUrl.String(), nil)
	require.NoError(t, err)

	res, err := h.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusFound, res.StatusCode)
	resLocation := res.Header.Get("location")
	require.Contains(t, resLocation, h.redirectURI)

	resLocationUrl, err := url.Parse(res.Header.Get("location"))
	require.NoError(t, err)

	code := resLocationUrl.Query().Get("code")
	resState := resLocationUrl.Query().Get("state")
	require.NotEmpty(t, code)
	require.Equal(t, state, resState)

	return code
}

func (h *handlerTesting) postToken(code, codeVerifier string) []byte {
	t := h.t
	t.Helper()

	remoteUrl, err := url.Parse(h.GetURL())
	require.NoError(t, err)
	remoteUrl.Path = "/oauth/token"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("client_id", h.clientID)
	data.Set("code_verifier", codeVerifier)
	data.Set("code", code)
	data.Set("redirect_uri", h.redirectURI)

	body := strings.NewReader(data.Encode())

	req, err := http.NewRequest("POST", remoteUrl.String(), body)
	require.NoError(t, err)

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(h.clientID), url.QueryEscape(h.clientSecret))

	res, err := h.httpClient.Do(req)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, res.StatusCode)

	bodyBytes, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	err = res.Body.Close()
	require.NoError(t, err)

	return bodyBytes
}
