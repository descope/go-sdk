package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"time"

	"github.com/descope/go-sdk/v2/descope"
	"github.com/descope/go-sdk/v2/descope/client"
	descopegin "github.com/descope/go-sdk/v2/descope/gin"
	"github.com/gin-gonic/gin"
)

const (
	TLSkeyPath  = "../key.pem"
	TLSCertPath = "../cert.pem"
	port        = "8085"
)

var descopeClient *client.DescopeClient

func main() {
	log.Println("starting server on port " + port)
	log.Println("go to https://localhost:" + port + " to enjoy descope")
	r := gin.Default()
	var err error
	// Leave projectId param empty to get it from DESCOPE_PROJECT_ID env variable
	projectID := ""
	descopeClient, err = client.NewWithConfig(&client.Config{ProjectID: projectID, SessionJWTViaCookie: true})
	if err != nil {
		log.Println("failed to init: " + err.Error())
		os.Exit(1)
	}
	err = generateKeysIfNeeded()
	if err != nil {
		log.Println("failed to generate keys for TLS server: " + err.Error())
		os.Exit(1)
	}

	r.GET("/", help)
	r.GET("/otp/signupOrIn", handleSignUpOrIn)
	r.GET("/otp/verify", handleOTPVerify)

	authorized := r.Group("/")
	authorized.Use(descopegin.AuthenticationMiddleware(descopeClient.Auth, nil, nil))
	authorized.GET("/private", handleIsHealthy)
	r.RunTLS(fmt.Sprintf(":%s", port), TLSCertPath, TLSkeyPath)
}

func help(c *gin.Context) {
	helpTxt := "Sign up or in with otp email go to /otp/signupOrIn?email=\n\n"
	helpTxt += "Sign up or in with otp sms go to /otp/signupOrIn?sms=\n\n"
	helpTxt += "Sign up or in with otp whatsapp go to /otp/signupOrIn?whatsapp=\n\n"
	helpTxt += "Sign up or in with otp voice go to /otp/signupOrIn?voice=\n\n"
	helpTxt += "-------------------------------------\n\n"
	helpTxt += "See a private page /private\n\n"
	helpTxt += "To see more examples see out webapp example (../webapp)\n\n"
	setResponse(c, http.StatusOK, helpTxt)
}

func handleIsHealthy(c *gin.Context) {
	setResponse(c, http.StatusOK, "You can see this page only because you are logged in")
}

func handleSignUpOrIn(c *gin.Context) {
	method, loginID := getMethodAndLoginID(c)
	masked, err := descopeClient.Auth.OTP().SignUpOrIn(c.Request.Context(), method, loginID, nil)
	if err != nil {
		setErrorWithSignUpIn(c, err.Error(), method, loginID)
	} else {
		helpTxt := fmt.Sprintf("to verify code received to %s go to /otp/verify?%s=%s&code=<code>", masked, string(method), loginID)
		setResponse(c, http.StatusOK, helpTxt)
	}
}

func handleOTPVerify(c *gin.Context) {
	method, loginID := getMethodAndLoginID(c)
	code := c.Query("code")
	if code == "" {
		setError(c, "code is empty")
		return
	}
	authInfo, err := descopeClient.Auth.OTP().VerifyCode(c.Request.Context(), method, loginID, code, c.Writer)
	if err != nil {
		setError(c, err.Error())
		return
	}
	helpTxt := "You have properly authenticated, you can check for your JWT in the cookie\n"
	mr, _ := json.MarshalIndent(authInfo, "", "")
	helpTxt += string(mr) + "\n"
	setResponse(c, http.StatusOK, helpTxt)
}

func getMethodAndLoginID(c *gin.Context) (descope.DeliveryMethod, string) {
	method := descope.MethodEmail
	loginID := ""
	if email := c.Query("email"); email != "" {
		loginID = email
	} else if sms := c.Query("sms"); sms != "" {
		method = descope.MethodSMS
		loginID = sms
	} else if whatsapp := c.Query("whatsapp"); whatsapp != "" {
		method = descope.MethodWhatsApp
		loginID = whatsapp
	} else if voice := c.Query("voice"); voice != "" {
		method = descope.MethodVoice
		loginID = voice
	}
	return method, loginID
}

func setOK(c *gin.Context) {
	setResponse(c, http.StatusOK, "OK")
}

func setErrorWithSignUpIn(c *gin.Context, message string, method descope.DeliveryMethod, loginID string) {
	msg := message
	if method != "" {
		msg += " method: " + string(method)
	}
	if loginID != "" {
		msg += " loginID: " + loginID
	}
	setError(c, msg)
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
