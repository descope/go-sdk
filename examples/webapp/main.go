package main

import (
	"context"
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
	"os/signal"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/errors"
	"github.com/gorilla/mux"
)

const (
	TLSkeyPath  = "../key.pem"
	TLSCertPath = "../cert.pem"

	verifyMagicLinkURI = "https://localhost:8085/magiclink/verify"
)

var client *descope.DescopeClient
var port = "8085"

func main() {
	log.Println("starting server on port " + port)
	var err error
	router := mux.NewRouter()
	// Leave projectId param empty to get it from DESCOPE_PROJECT_ID env variable
	projectID := ""
	client, err = descope.NewDescopeClientWithConfig(&descope.Config{ProjectID: projectID})
	if err != nil {
		log.Println("failed to init: " + err.Error())
		os.Exit(1)
	}
	err = generateKeysIfNeeded()
	if err != nil {
		log.Println("failed to generate keys for TLS server: " + err.Error())
		os.Exit(1)
	}

	router.Use(loggingMiddleware)
	router.HandleFunc("/otp/signin", handleSignIn).Methods(http.MethodGet)
	router.HandleFunc("/otp/signup", handleSignUp).Methods(http.MethodGet)
	router.HandleFunc("/otp/verify", handleVerify).Methods(http.MethodGet)

	router.HandleFunc("/oauth", handleOAuth).Methods(http.MethodGet)

	router.HandleFunc("/magiclink/signin", handleMagicLinkSignIn).Methods(http.MethodGet)
	router.HandleFunc("/magiclink/signup", handleMagicLinkSignUp).Methods(http.MethodGet)
	router.HandleFunc("/magiclink/verify", handleMagicLinkVerify).Methods(http.MethodGet)
	router.HandleFunc("/magiclink/session", handleGetMagicLinkSession).Methods(http.MethodGet)

	router.HandleFunc("/webauthn", func(w http.ResponseWriter, r *http.Request) {
		file, _ := os.ReadFile("../demo.html")
		w.WriteHeader(http.StatusOK)
		w.Write(file)
	}).Methods(http.MethodGet)

	router.HandleFunc("/webauthn/signup/start", handleWebauthnSignupStart).Methods(http.MethodPost)
	router.HandleFunc("/webauthn/signup/finish", handleWebauthnSignupFinish).Methods(http.MethodPost)

	router.HandleFunc("/webauthn/signin/start", handleWebauthnSigninStart).Methods(http.MethodPost)
	router.HandleFunc("/webauthn/signin/finish", handleWebauthnSigninFinish).Methods(http.MethodPost)

	authRouter := router.Methods(http.MethodGet).Subrouter()
	authRouter.Use(auth.AuthenticationMiddleware(client.Auth, func(w http.ResponseWriter, r *http.Request, err error) {
		setResponse(w, http.StatusUnauthorized, "Unauthorized")
	}, nil))
	authRouter.HandleFunc("/private", handleIsHealthy)
	authRouter.HandleFunc("/logout", handleLogout).Methods(http.MethodPost) // Logout from all user's active sessions

	server := &http.Server{Addr: fmt.Sprintf(":%s", port), Handler: router}
	go func() {
		if err := server.ListenAndServeTLS(TLSCertPath, TLSkeyPath); err != nil {
			log.Println("server error " + err.Error())
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)

	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Println("server error " + err.Error())
	}
	log.Println("stopping server")
}

func handleIsHealthy(w http.ResponseWriter, r *http.Request) {
	setOK(w)
}

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	err := client.Auth.OTP().SignUp(method, identifier, &auth.User{Name: "test"})
	if err != nil {
		setError(w, err.Error())
	} else {
		setOK(w)
	}
}

func handleSignIn(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	err := client.Auth.OTP().SignIn(method, identifier, nil, nil)
	if err != nil {
		setError(w, err.Error())
	} else {
		setOK(w)
	}
}

func handleVerify(w http.ResponseWriter, r *http.Request) {
	code := ""
	method, identifier := getMethodAndIdentifier(r)
	if codes, ok := r.URL.Query()["code"]; ok {
		code = codes[0]
	}
	if code == "" {
		setError(w, "code is empty")
		return
	}
	_, err := client.Auth.OTP().VerifyCode(method, identifier, code, w)
	if err != nil {
		setError(w, err.Error())
		return
	}
	setOK(w)
}

func handleOAuth(w http.ResponseWriter, r *http.Request) {
	provider := auth.OAuthFacebook
	if p, ok := r.URL.Query()["provider"]; ok {
		provider = auth.OAuthProvider(p[0])
	}
	_, err := client.Auth.OAuth().Start(provider, "", nil, nil, w)
	if err != nil {
		setError(w, err.Error())
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	err := client.Auth.Logout(r, w)
	if err != nil {
		setError(w, err.Error())
	} else {
		setOK(w)
	}
}

func handleMagicLinkSignIn(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	var err error

	if crossDevice := queryBool(r, "crossDevice"); crossDevice {
		_, err = client.Auth.MagicLink().SignInCrossDevice(method, identifier, verifyMagicLinkURI, nil, nil)
	} else {
		err = client.Auth.MagicLink().SignIn(method, identifier, verifyMagicLinkURI, nil, nil)
	}
	if err != nil {
		setError(w, err.Error())
	}
	setOK(w)
}

func handleMagicLinkSignUp(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	var err error

	user := &auth.User{Name: "test"}
	if crossDevice := queryBool(r, "crossDevice"); crossDevice {
		_, err = client.Auth.MagicLink().SignUpCrossDevice(method, identifier, verifyMagicLinkURI, user)
	} else {
		err = client.Auth.MagicLink().SignUp(method, identifier, verifyMagicLinkURI, user)
	}
	if err != nil {
		setError(w, err.Error())
	}

	setOK(w)
}

func handleMagicLinkVerify(w http.ResponseWriter, r *http.Request) {
	tokens := r.URL.Query()["t"]
	if len(tokens) == 0 {
		setError(w, "token is empty")
		return
	}
	token := tokens[0]
	if token == "" {
		setError(w, "token is empty")
		return
	}
	_, err := client.Auth.MagicLink().Verify(token, w)
	if err != nil {
		setError(w, err.Error())
		return
	}
	setOK(w)
}

func handleGetMagicLinkSession(w http.ResponseWriter, r *http.Request) {
	pendingRef := getQuery(r, "pendingRef")
	if pendingRef == "" {
		setError(w, "pending reference is empty")
		return
	}
	_, err := client.Auth.MagicLink().GetSession(pendingRef, w)
	if goErrors.Is(err, errors.MagicLinkUnauthorized) {
		setUnauthorized(w, err.Error())
	}
	if err != nil {
		setError(w, err.Error())
		return
	}
	setOK(w)
}

func handleWebauthnSigninFinish(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var t *auth.WebAuthnFinishRequest
	err := decoder.Decode(&t)
	if err != nil {
		setError(w, err.Error())
		return
	}

	_, err = client.Auth.WebAuthn().SignInFinish(t, w)
	if err != nil {
		setError(w, err.Error())
	}
	setOK(w)
}

func handleWebauthnSigninStart(w http.ResponseWriter, r *http.Request) {
	res, err := client.Auth.WebAuthn().SignInStart(getQuery(r, "id"), getQuery(r, "origin"), nil, nil)
	if err != nil {
		setError(w, err.Error())
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}

func handleWebauthnSignupStart(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var t *auth.User
	err := decoder.Decode(&t)
	if err != nil {
		setError(w, err.Error())
		return
	}

	res, err := client.Auth.WebAuthn().SignUpStart(t.Name, t, getQuery(r, "origin"))
	if err != nil {
		setError(w, err.Error())
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(res)
}

func handleWebauthnSignupFinish(w http.ResponseWriter, r *http.Request) {
	decoder := json.NewDecoder(r.Body)
	var t *auth.WebAuthnFinishRequest
	err := decoder.Decode(&t)
	if err != nil {
		setError(w, err.Error())
		return
	}

	_, err = client.Auth.WebAuthn().SignUpFinish(t, w)
	if err != nil {
		setError(w, err.Error())
	}
	setOK(w)
}

func queryBool(r *http.Request, key string) bool {
	values := r.URL.Query()[key]
	return len(values) > 0
}

func getQuery(r *http.Request, key string) string {
	values := r.URL.Query()[key]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Url requested: %s", r.RequestURI)
		next.ServeHTTP(w, r)
		log.Println("Request finished")
	})
}

func setOK(w http.ResponseWriter) {
	setResponse(w, http.StatusOK, "OK")
}

func setUnauthorized(w http.ResponseWriter, message string) {
	setResponse(w, http.StatusUnauthorized, message)
}

func setError(w http.ResponseWriter, message string) {
	setResponse(w, http.StatusInternalServerError, message)
}

func setResponse(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	w.Write([]byte(message))
}

func getMethodAndIdentifier(r *http.Request) (auth.DeliveryMethod, string) {
	method := auth.MethodEmail
	identifier := ""
	if email, ok := r.URL.Query()["email"]; ok {
		identifier = email[0]
	} else if sms, ok := r.URL.Query()["sms"]; ok {
		method = auth.MethodSMS
		identifier = sms[0]
	} else if whatsapp, ok := r.URL.Query()["whatsapp"]; ok {
		method = auth.MethodWhatsApp
		identifier = whatsapp[0]
	}
	return method, identifier
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
