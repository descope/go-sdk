package main

import (
	"log"
	"net/http"
	"os"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/auth"
	descopegin "github.com/descope/go-sdk/descope/gin"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/gin-gonic/gin"
)

var client *descope.API

func main() {
	r := gin.Default()
	var err error
	client, err = descope.NewDescopeClient(descope.Config{LogLevel: logger.LogDebugLevel, DescopeBaseURL: "http://localhost:8191"})
	if err != nil {
		log.Println("failed to init: " + err.Error())
		os.Exit(1)
	}

	r.GET("/signup", handleSignUp)
	r.GET("/signin", handleSignIn)
	r.GET("/verify", handleVerify)

	authorized := r.Group("/")
	authorized.Use(descopegin.AuthneticationMiddleware(client.Auth, nil))
	authorized.GET("/health", handleIsHealthy)
	r.RunTLS(":8085", "../server.crt", "../server.key")
}

func handleIsHealthy(c *gin.Context) {
	setOK(c)
}

func handleSignUp(c *gin.Context) {
	method, identifier := getMethodAndIdentifier(c)
	err := client.Auth.SignUpOTP(method, identifier, &auth.User{Name: "test"})
	if err != nil {
		setError(c, err.Error())
	} else {
		setOK(c)
	}
}

func handleSignIn(c *gin.Context) {
	method, identifier := getMethodAndIdentifier(c)
	err := client.Auth.SignInOTP(method, identifier)
	if err != nil {
		setError(c, err.Error())
	} else {
		setOK(c)
	}
}

func handleVerify(c *gin.Context) {
	method, identifier := getMethodAndIdentifier(c)
	code := c.Query("code")
	if code == "" {
		setError(c, "code is empty")
		return
	}
	_, err := client.Auth.VerifyCode(method, identifier, code, descopegin.WithResponseOption(c))
	if err != nil {
		setError(c, err.Error())
		return
	}
	setOK(c)
}

func getMethodAndIdentifier(c *gin.Context) (auth.DeliveryMethod, string) {
	method := auth.MethodEmail
	identifier := ""
	if email := c.Query("email"); email != "" {
		identifier = email
	} else if sms := c.Query("email"); sms != "" {
		method = auth.MethodSMS
		identifier = sms
	} else if whatsapp := c.Query("whatsapp"); whatsapp != "" {
		method = auth.MethodWhatsApp
		identifier = whatsapp
	}
	return method, identifier
}

func setOK(c *gin.Context) {
	setResponse(c, http.StatusOK, "OK")
}

func setError(c *gin.Context, message string) {
	setResponse(c, http.StatusInternalServerError, message)
}

func setResponse(c *gin.Context, status int, message string) {
	c.String(status, message)
}
