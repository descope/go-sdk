package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	goErrors "errors"
	"fmt"
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
	port        = "8085"

	trueStr            = "true"
	verifyMagicLinkURI = "https://localhost:8085/magiclink/verify"
)

var client *descope.DescopeClient

func main() {
	log.Println("starting server on port " + port)
	r := gin.Default()
	var err error
	client, err = descope.NewDescopeClientWithConfig(&descope.Config{LogLevel: logger.LogDebugLevel, DescopeBaseURL: "http://localhost:8191"})
	if err != nil {
		log.Println("failed to init: " + err.Error())
		os.Exit(1)
	}
	err = generateKeysIfNeeded()
	if err != nil {
		log.Println("failed to generate keys for TLS server: " + err.Error())
		os.Exit(1)
	}

	r.GET("/otp/signup", handleSignUp)
	r.GET("/otp/signin", handleSignIn)
	r.GET("/otp/verify", handleOTPVerify)

	r.GET("/oauth", handleOAuth)

	r.GET("/magiclink/signin", handleMagicLinkSignIn)
	r.GET("/magiclink/signup", handleMagicLinkSignUp)
	r.GET("/magiclink/session", handleGetMagicLinkSession)
	r.GET("/magiclink/verify", handleMagicLinkVerify)

	r.GET("/webauthn", func(c *gin.Context) {
		file, _ := os.ReadFile("../demo.html")
		c.Data(http.StatusOK, "text/html; charset=utf-8", file)
	})

	r.POST("/webauthn/signup/start", func(c *gin.Context) {
		decoder := json.NewDecoder(c.Request.Body)
		var t *auth.User
		err := decoder.Decode(&t)
		if err != nil {
			setError(c, err.Error())
			return
		}

		res, err := client.Auth.WebAuthn().SignUpStart(t.Name, t, c.Query("origin"))
		if err != nil {
			setError(c, err.Error())
		}
		c.Writer.Header().Add("Content-Type", "application/json")
		c.PureJSON(http.StatusOK, res)
	})
	r.POST("/webauthn/signup/finish", func(c *gin.Context) {
		decoder := json.NewDecoder(c.Request.Body)
		var t *auth.WebAuthnFinishRequest
		err := decoder.Decode(&t)
		if err != nil {
			setError(c, err.Error())
			return
		}

		_, err = client.Auth.WebAuthn().SignUpFinishWithOptions(t, descopegin.WithResponseOption(c))
		if err != nil {
			setError(c, err.Error())
		}
		setOK(c)
	})

	r.POST("/webauthn/signin/start", func(c *gin.Context) {
		res, err := client.Auth.WebAuthn().SignInStart(c.Query("id"), c.Query("origin"))
		if err != nil {
			setError(c, err.Error())
		}
		c.Writer.Header().Add("Content-Type", "application/json")
		c.PureJSON(http.StatusOK, res)
	})
	r.POST("/webauthn/signin/finish", func(c *gin.Context) {
		decoder := json.NewDecoder(c.Request.Body)
		var t *auth.WebAuthnFinishRequest
		err := decoder.Decode(&t)
		if err != nil {
			setError(c, err.Error())
			return
		}

		_, err = client.Auth.WebAuthn().SignInFinishWithOptions(t, descopegin.WithResponseOption(c))
		if err != nil {
			setError(c, err.Error())
		}
		setOK(c)
	})

	authorized := r.Group("/")
	authorized.Use(descopegin.AuthneticationMiddleware(client.Auth, nil, nil))
	authorized.GET("/private", handleIsHealthy)
	authorized.GET("/logout", handleLogout)
	r.RunTLS(fmt.Sprintf(":%s", port), TLSCertPath, TLSkeyPath)
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
	err := client.Auth.OTP().SignUp(method, identifier, &auth.User{Name: "test"})
	if err != nil {
		setError(c, err.Error())
	} else {
		setOK(c)
	}
}

func handleSignIn(c *gin.Context) {
	method, identifier := getMethodAndIdentifier(c)
	err := client.Auth.OTP().SignIn(method, identifier)
	if err != nil {
		setError(c, err.Error())
	} else {
		setOK(c)
	}
}

func handleMagicLinkSignIn(c *gin.Context) {
	method, identifier := getMethodAndIdentifier(c)
	var err error
	var magicLinkResponse *auth.MagicLinkResponse

	if crossDevice := queryBool(c, "crossDevice"); crossDevice {
		magicLinkResponse, err = client.Auth.MagicLink().SignInCrossDevice(method, identifier, verifyMagicLinkURI)
	} else {
		err = client.Auth.MagicLink().SignIn(method, identifier, verifyMagicLinkURI)
	}
	if err != nil {
		setError(c, err.Error())
	}
	c.JSON(http.StatusOK, magicLinkResponse)

}

func handleMagicLinkSignUp(c *gin.Context) {
	method, identifier := getMethodAndIdentifier(c)
	var err error
	var magicLinkResponse *auth.MagicLinkResponse

	user := &auth.User{Name: "test"}
	if crossDevice := queryBool(c, "crossDevice"); crossDevice {
		magicLinkResponse, err = client.Auth.MagicLink().SignUpCrossDevice(method, identifier, verifyMagicLinkURI, user)
	} else {
		err = client.Auth.MagicLink().SignUp(method, identifier, verifyMagicLinkURI, user)
	}
	if err != nil {
		setError(c, err.Error())
	}

	c.JSON(http.StatusOK, magicLinkResponse)
}

func handleGetMagicLinkSession(c *gin.Context) {
	pendingRef := c.Query("pendingRef")
	if pendingRef == "" {
		setError(c, "pending reference is empty")
		return
	}
	_, err := client.Auth.MagicLink().GetSessionWithOptions(pendingRef, descopegin.WithResponseOption(c))
	if goErrors.Is(err, descopeerrors.MagicLinkUnauthorized) {
		setUnauthorized(c, err.Error())
	}
	if err != nil {
		setError(c, err.Error())
		return
	}
	setOK(c)
}

func handleMagicLinkVerify(c *gin.Context) {
	token := c.Query("t")
	if token == "" {
		setError(c, "token is empty")
		return
	}
	_, err := client.Auth.MagicLink().VerifyWithOptions(token, descopegin.WithResponseOption(c))
	if err != nil {
		setError(c, err.Error())
		return
	}
	setOK(c)
}

func handleOTPVerify(c *gin.Context) {
	method, identifier := getMethodAndIdentifier(c)
	code := c.Query("code")
	if code == "" {
		setError(c, "code is empty")
		return
	}
	_, err := client.Auth.OTP().VerifyCodeWithOptions(method, identifier, code, descopegin.WithResponseOption(c))
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
	_, err := client.Auth.OAuth().StartWithOptions(provider, "", descopegin.WithResponseOption(c))
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
	if err := os.WriteFile(TLSCertPath, pemCert, 0600); err != nil {
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
