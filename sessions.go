package main

import (
	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

func getSession(name string, c echo.Context) (*sessions.Session, error) {
	sess, err := session.Get(name, c)
	if err != nil {
		return nil, err
	}

	if sess.IsNew {
		sess.Options = &sessions.Options{
			Domain:   cookieDomain,
			Path:     "/",
			HttpOnly: true,
			Secure:   true,
		}
	}

	return sess, nil
}

func saveSession(s *sessions.Session, c echo.Context) error {
	err := s.Save(c.Request(), c.Response())
	if err != nil {
		logger.Error(err)
	}
	return err
}

func oidcSession(c echo.Context) (*sessions.Session, error) {
	sess, err := getSession("oidc_session", c)
	if err != nil {
		return nil, err
	}
	sess.Options.MaxAge = 30 // short-lived session for token exchange

	return sess, nil
}

func userSession(c echo.Context) (*sessions.Session, error) {
	sess, err := getSession("user_session", c)
	if err != nil {
		return nil, err
	}
	sess.Options.MaxAge = 60 * 60 * 10 // kc session max (10hrs)

	return sess, nil
}
