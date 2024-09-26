package main

import (
	"flag"
	"os"

	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

var (
	listenPort string

	cookieStore *sessions.CookieStore
	logger      echo.Logger
)

func main() {
	e := echo.New()
	logger = e.Logger

	loadEnv()
	setupAuthClients()

	cookieStore = sessions.NewCookieStore(cookieAuthKey, cookieEncryptKey)
	e.Use(session.Middleware(cookieStore))

	e.GET("/auth/callback", CallbackHandler)
	e.GET("/check-token", CheckTokenHandler)
	e.GET("/login", LoginHandler)

	logger.Fatal(e.Start(":" + listenPort))
}

func loadEnv() {
	envFilePtr := flag.String("e", ".env", "the environment file to load from")
	flag.Parse()

	if err := godotenv.Load(*envFilePtr); err != nil {
		logger.Fatal(err)
	}

	listenPort = os.Getenv("OIDC_SSO_LISTEN_PORT")
	if listenPort == "" {
		logger.Fatal("missing listen port")
	}

	loadOidcParams()
}
