package main

import (
	"flag"
	"os"

	"git.schwem.io/schwem/pkgs/logger"
	"git.schwem.io/schwem/pkgs/oidc"
	"github.com/joho/godotenv"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
)

var (
	port string

	// flag variables
	envFile string
	debug   bool
)

// init parses flags, sets global logging options, and reads in environment vars/config prior to main program execution
func init() {
	flag.BoolVar(&debug, "d", false, "enable debug output")
	flag.StringVar(&envFile, "e", ".env", "the environment file to load from")
	flag.StringVar(&port, "p", "1337", "the port that the server will listen on")

	flag.Parse()

	// configure default logging settings
	logger.SetupLogger(logger.LoggerOptions{})

	// if an environment file was passed as an argument, load it
	if err := godotenv.Load(envFile); err != nil {
		logger.Fatal(err)
	}

	err := oidc.Init(oidc.Config{
		CookieDomain:     os.Getenv("COOKIE_DOMAIN"),
		CookieAuthKey:    os.Getenv("COOKIE_AUTH_KEY"),
		CookieEncryptKey: os.Getenv("COOKIE_ENCRYPT_KEY"),

		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Issuer:       os.Getenv("ISSUER_URL"),
		Redirect:     os.Getenv("REDIRECT_URL"),
	})

	if err != nil {
		logger.Fatal(err)
	}
}

// Simple OIDC/OAuth2 proxy. Performs the following flow (for my setup the routing is handled via nginx and the auth_reqest directive):
//
//  1. Calls auth endpoint. Checks if a valid user session exists.
//     a. Exists       : return HTTP 200 -- proxy should pass to protected page
//     b. Doesn't Exist: return HTTP 401 -- continue to step 2
//
//  2. On 401 have proxy redirect to /login to begin the oidc/oauth flow
//
//  3. On succesful credentials the provider will redirect back to /auth/callback
//
//  4. Ensure valid data returned back and set user session.
func main() {
	e := echo.New()

	e.Use(session.Middleware(oidc.SessionManager.CookieStore()))

	e.GET("/auth", AuthHandler)
	e.GET("/auth/callback", CallbackHandler)
	e.GET("/login", LoginHandler)

	logger.Fatal(e.Start(":" + port))
}

// initialize required variables for OIDC provider
func initOidc() {
}
