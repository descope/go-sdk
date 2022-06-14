package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	goErrors "errors"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/auth"
	descopeerrors "github.com/descope/go-sdk/descope/errors"
	descopegin "github.com/descope/go-sdk/descope/gin"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/gin-gonic/gin"
)

const (
	TLSkeyPath  = "../key.pem"
	TLSCertPath = "../cert.pem"

	trueStr            = "true"
	verifyMagicLinkURI = "https://localhost:8085/verify"
)

var client *descope.DescopeClient

func main() {
	r := gin.Default()
	var err error
	client, err = descope.NewDescopeClient(descope.Config{LogLevel: logger.LogDebugLevel, DescopeBaseURL: "http://localhost:8191"})
	if err != nil {
		log.Println("failed to init: " + err.Error())
		os.Exit(1)
	}
	err = generateKeysIfNeeded()
	if err != nil {
		log.Println("failed to generate keys for TLS server: " + err.Error())
		os.Exit(1)
	}

	r.GET("/signup", handleSignUp)
	r.GET("/signin", handleSignIn)
	r.GET("/magiclink/signin", handleMagicLinkSignIn)
	r.GET("/magiclink/signup", handleMagicLinkSignUp)
	r.GET("/session/pending", handleGetPendingSession)
	r.GET("/verify", handleVerify)
	r.GET("/oauth", handleOAuth)

	authorized := r.Group("/")
	authorized.Use(descopegin.AuthneticationMiddleware(client.Auth, nil))
	authorized.GET("/health", handleIsHealthy)
	authorized.GET("/logout", handleLogout)
	r.RunTLS(":8085", TLSCertPath, TLSkeyPath)
}

func handleIsHealthy(c *gin.Context) {
	setOK(c)
}

func handleLogout(c *gin.Context) {
	err := client.Auth.Logout(c.Request, c.Writer)
	if err != nil {
		setError(c, err.Error())
	} else {
		setOK(c)
	}
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

func handleMagicLinkSignIn(c *gin.Context) {
	method, identifier := getMethodAndIdentifier(c)
	crossDevice := queryBool(c, "crossDevice")
	magicLinkResponse, err := client.Auth.SignInMagicLink(method, identifier, verifyMagicLinkURI, crossDevice)
	if err != nil {
		setError(c, err.Error())
	}
	c.JSON(http.StatusOK, magicLinkResponse)

}

func handleMagicLinkSignUp(c *gin.Context) {
	method, identifier := getMethodAndIdentifier(c)
	crossDevice := queryBool(c, "crossDevice")
	magicLinkResponse, err := client.Auth.SignUpMagicLink(method, identifier, verifyMagicLinkURI, crossDevice, &auth.User{Name: "test"})
	if err != nil {
		setError(c, err.Error())
	}

	c.JSON(http.StatusOK, magicLinkResponse)
}

func handleGetPendingSession(c *gin.Context) {
	pendingRef := c.Query("pendingRef")
	if pendingRef == "" {
		setError(c, "pending reference is empty")
		return
	}
	_, err := client.Auth.GetPendingSessionWithOptions(pendingRef, descopegin.WithResponseOption(c))
	if goErrors.Is(err, descopeerrors.PendingSessionTokenError) {
		setUnauthorized(c, err.Error())
	}
	if err != nil {
		setError(c, err.Error())
		return
	}
	setOK(c)
}

func handleVerify(c *gin.Context) {
	token := c.Query("t")
	if token == "" {
		setError(c, "token is empty")
		return
	}
	_, err := client.Auth.VerifyMagicLinkWithOptions(token, descopegin.WithResponseOption(c))
	if err != nil {
		setError(c, err.Error())
		return
	}
	setOK(c)
}

func handleOAuth(c *gin.Context) {
	provider := auth.OAuthProvider(c.Query("provider"))
	if provider == "" {
		provider = auth.OAuthFacebook
	}
	_, err := client.Auth.OAuthStartWithOptions(provider, descopegin.WithResponseOption(c))
	if err != nil {
		setError(c, err.Error())
	}
}

func getMethodAndIdentifier(c *gin.Context) (auth.DeliveryMethod, string) {
	method := auth.MethodEmail
	identifier := ""
	if email := c.Query("email"); email != "" {
		identifier = email
	} else if sms := c.Query("sms"); sms != "" {
		method = auth.MethodSMS
		identifier = sms
	} else if whatsapp := c.Query("whatsapp"); whatsapp != "" {
		method = auth.MethodWhatsApp
		identifier = whatsapp
	}
	return method, identifier
}

func queryBool(c *gin.Context, key string) bool {
	return strings.ToLower(c.Query(key)) == trueStr
}

func setOK(c *gin.Context) {
	setResponse(c, http.StatusOK, "OK")
}

func setError(c *gin.Context, message string) {
	setResponse(c, http.StatusInternalServerError, message)
}

func setUnauthorized(c *gin.Context, message string) {
	setResponse(c, http.StatusUnauthorized, message)
}

func setResponse(c *gin.Context, status int, message string) {
	c.String(status, message)
}

func generateKeysIfNeeded() error {
	if _, err := os.Stat(TLSkeyPath); err == nil {
		return nil
	}
	if _, err := os.Stat(TLSCertPath); err == nil {
		return nil
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"My Corp"},
		},
		DNSNames:  []string{"localhost"},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(3 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	if pemCert == nil {
		return err
	}
	if err := os.WriteFile(TLSCertPath, pemCert, 0644); err != nil {
		log.Fatal(err)
	}

	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})
	if pemKey == nil {
		return err
	}
	if err := os.WriteFile(TLSkeyPath, pemKey, 0600); err != nil {
		return err
	}
	log.Println("self signed certificates generated.")
	return nil
}
