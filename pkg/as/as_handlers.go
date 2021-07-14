package as

import (
	"fmt"
	"net/http"
	"os"

	aserrors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-session/session"
)

type ASHandlersOptions struct {
}

func (opts ASHandlersOptions) Validate() error {
	return nil
}

type asHandlers struct {
	username string
	password string
}

func newASHandlers(opts ASHandlersOptions) (*asHandlers, error) {
	err := opts.Validate()
	if err != nil {
		return nil, err
	}

	return &asHandlers{
		username: "test",
		password: "test",
	}, nil
}

func (h *asHandlers) passwordAuthorization(username, password string) (string, error) {
	if username == h.username && password == h.password {
		return h.username, nil
	}

	return "", aserrors.ErrAccessDenied
}

func (h *asHandlers) internalError(err error) *aserrors.Response {
	fmt.Fprintf(os.Stderr, "Internal Error: %v\n", err)
	return nil
}

func (h *asHandlers) responseError(re *aserrors.Response) {
	fmt.Fprintf(os.Stderr, "Response Error: %v\n", re.Error)
}

func (h *asHandlers) userAuthorization(w http.ResponseWriter, r *http.Request) (string, error) {
	store, err := session.Start(r.Context(), w, r)
	if err != nil {
		return "", err
	}

	uid, ok := store.Get("LoggedInUserID")
	if !ok {
		if r.Form == nil {
			r.ParseForm()
		}

		store.Set("ReturnUri", r.Form)
		store.Save()

		w.Header().Set("Location", "/login")
		w.WriteHeader(http.StatusFound)
		return "", nil
	}

	userID := uid.(string)
	store.Delete("LoggedInUserID")
	store.Save()
	return userID, nil
}
