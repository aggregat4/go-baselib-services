package oidc

import (
	"encoding/base64"
	"log"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

var SessionCookieName = "baselib-oidc-session-cookie"

func CreateSessionBasedOidcDelegate(handleIdToken func(c echo.Context, idToken *oidc.IDToken) error, fallbackRedirectUrl string) func(c echo.Context, idToken *oidc.IDToken, state string) error {
	return func(c echo.Context, idToken *oidc.IDToken, state string) error {
		err := handleIdToken(c, idToken)
		if err != nil {
			return c.Render(http.StatusInternalServerError, "error-internal", nil)
		}
		stateParts := strings.Split(state, "|")
		if len(stateParts) > 1 {
			originalRequestUrlBase64 := stateParts[1]
			decodedOriginalRequestUrl, err := base64.StdEncoding.DecodeString(originalRequestUrlBase64)
			if err != nil {
				log.Println(err)
				return c.Render(http.StatusInternalServerError, "error-internal", nil)
			}
			return c.Redirect(http.StatusFound, string(decodedOriginalRequestUrl))
		} else {
			// this is just for robustness, if the state is valid, but does not contain a redirect URL
			// we just go to the fallback URL
			return c.Redirect(http.StatusFound, fallbackRedirectUrl)
		}
	}
}

// SetFlash sets a flash message with a given key (e.g., "success", "error")
func SetFlash(c echo.Context, key, message string) error {
	sess, err := session.Get(SessionCookieName, c)
	if err != nil {
		return err
	}

	sess.AddFlash(message, key)
	return sess.Save(c.Request(), c.Response())
}

// GetFlashes retrieves and clears flash messages for the given keys
func GetFlashes(c echo.Context) ([]string, []string, error) {
	session, err := session.Get(SessionCookieName, c)
	if err != nil {
		return nil, nil, err
	}

	var successFlashes = getFlashes(session, "success")
	var errorFlashes = getFlashes(session, "error")

	session.Save(c.Request(), c.Response())
	return successFlashes, errorFlashes, nil
}

func getFlashes(session *sessions.Session, key string) []string {
	flashes := session.Flashes(key)
	var flashesList []string
	for _, flash := range flashes {
		if msg, ok := flash.(string); ok {
			flashesList = append(flashesList, msg)
		}
	}
	return flashesList
}
