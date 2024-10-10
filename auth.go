package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"git.schwem.io/schwem/pkgs/logger"
	"git.schwem.io/schwem/pkgs/oidc"
	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	oidcTypes "github.com/zitadel/oidc/v3/pkg/oidc"
)

// AuthHandler is an Echo handler that provides nginx auth request compliant behavior.
// Returns 200 if the user is authorized and 401 if the user is not authorized.
func AuthHandler(c echo.Context) error {
	userSession, err := oidc.UserSession(c)
	if err != nil {
		return logUnauthorized(c, err)
	}

	if userSession.IsNew() {
		logger.Info("no user session set. returning 401.")
		return c.NoContent(http.StatusUnauthorized)
	}

	fmt.Println("userSession.IsValid(): ", userSession.IsValid())
	if !userSession.IsValid() {
		return logUnauthorized(c, errors.New("unable to get user info from session"))
	}

	return c.NoContent(http.StatusOK)
}

// LoginHandler is an Echo handler that handles redirecting to the login page of the OIDC provider as part of the
// authorization code flow. It creates a session which stores the state for the auth flow and then redirects to the OIDC
// provider auth/login URL.
//
// The auth flow state stored is PKCE (always sent for now) and a Redirect URL for when coming back from the callback.
func LoginHandler(c echo.Context) error {
	// create the sso session (this is short lived for the oidc/oauth flow and holds pkce, etc.)
	oidcSession, err := oidc.OidcSession(c)
	if err != nil {
		return logUnauthorized(c, err)
	}

	oidcSessionValues := oidc.AuthFlowState{
		PKCE:        base64.RawURLEncoding.EncodeToString([]byte(uuid.New().String())),
		RedirectURL: c.QueryParam("rd"),
	}
	oidcSession.SetValues(oidcSessionValues)

	if err := oidcSession.Session.Save(c); err != nil {
		return logUnauthorized(c, err)
	}

	logger.Infof("[LoginHandler]  oidcSessionValues: %+v", oidcSessionValues)
	url := rp.AuthURL("", *oidc.RelyingParty, rp.WithCodeChallenge(oidcSessionValues.NewSHACodeChallenge()))
	return c.Redirect(http.StatusFound, url)
}

// CallbackHandler handles the callback/redirect from the Auth/Login endpoint of the OIDC provider. It takes the
// following steps:
//  1. Checks that the code verifier is valid.
//  2. Exchanges the code passed from the OIDC provider for an authorization token.
//  3. Retrieves the OIDC user info from the token response
//  4. Stores the relevant retrieved user info into the user session and save the session
//  5. Redirects to the URL provided in the OidcSession from the LoginHandler
func CallbackHandler(c echo.Context) error {
	oidcSession, err := oidc.OidcSession(c)
	if err != nil {
		return logUnauthorized(c, err)
	}

	// 1. ensure code verifier valid
	codeVerifier := oidcSession.AuthFlowState().PKCE
	if codeVerifier == "" {
		logger.Info("code verifier is empty")
		return logUnauthorized(c, errors.New("no code verifier set"))
	}

	// 2. exchange the code for the authorization token and ensure it's valid
	ctx := c.Request().Context()
	code := c.QueryParam("code")
	tokens, err := rp.CodeExchange[*oidcTypes.IDTokenClaims](ctx, code, *oidc.RelyingParty, rp.WithCodeVerifier(codeVerifier))
	if err != nil {
		return logUnauthorized(c, err)
	}

	// 3. get the user info from the token resposne
	respInfo, err := rp.Userinfo[*oidcTypes.UserInfo](ctx, tokens.AccessToken, tokens.TokenType, tokens.IDTokenClaims.GetSubject(), *oidc.RelyingParty)
	if err != nil {
		return logUnauthorized(c, err)
	}

	// 4. Store the relevant retrieved user info into the user session and save the session
	userSession, err := oidc.UserSession(c)
	if err != nil {
		return logUnauthorized(c, err)
	}

	userInfo := oidc.NewUserInfo().FromTokens(tokens).FromUserInfoResponse(respInfo)
	userSession.SetValues(userInfo)
	if err = userSession.Save(c); err != nil {
		return logUnauthorized(c, err)
	}

	// 5. Redirect back to the URL provided in the session (originally from LoginHandler)
	return c.Redirect(http.StatusFound, oidcSession.AuthFlowState().RedirectURL)
}

func logUnauthorized(c echo.Context, err error) error {
	logger.Error(err)
	return c.NoContent(http.StatusUnauthorized)
}
