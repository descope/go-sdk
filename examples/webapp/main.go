package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/gorilla/mux"
)

const (
	TLSkeyPath  = "../key.pem"
	TLSCertPath = "../cert.pem"
)

var client *descope.DescopeClient

func main() {
	port := "8085"
	log.Println("starting server on port " + port)
	var err error
	router := mux.NewRouter()
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

	router.Use(loggingMiddleware)
	router.HandleFunc("/signin", handleSignIn).Methods(http.MethodGet)
	router.HandleFunc("/signup", handleSignUp).Methods(http.MethodGet)
	router.HandleFunc("/oauth", handleOAuth).Methods(http.MethodGet)
	router.HandleFunc("/verify", handleVerify).Methods(http.MethodGet)
	authRouter := router.Methods(http.MethodGet).Subrouter()
	authRouter.Use(auth.AuthenticationMiddleware(client.Auth, func(w http.ResponseWriter, r *http.Request, err error) {
		setResponse(w, http.StatusUnauthorized, "Unauthorized")
	}))
	authRouter.HandleFunc("/health", handleIsHealthy)
	authRouter.HandleFunc("/logout", handleLogout)

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

func handleLogout(w http.ResponseWriter, r *http.Request) {
	err := client.Auth.Logout(r, w)
	if err != nil {
		setError(w, err.Error())
	} else {
		setOK(w)
	}
}

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	err := client.Auth.SignUpOTP(method, identifier, &auth.User{Name: "test"})
	if err != nil {
		setError(w, err.Error())
	} else {
		setOK(w)
	}
}

func handleOAuth(w http.ResponseWriter, r *http.Request) {
	provider := auth.OAuthFacebook
	if p, ok := r.URL.Query()["provider"]; ok {
		provider = auth.OAuthProvider(p[0])
	}
	_, err := client.Auth.OAuthStart(provider, w)
	if err != nil {
		setError(w, err.Error())
	}
}

func handleSignIn(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	err := client.Auth.SignInOTP(method, identifier)
	if err != nil {
		setError(w, err.Error())
	} else {
		setOK(w)
	}
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
	_, err := client.Auth.VerifyCode(method, identifier, code, w)
	if err != nil {
		setError(w, err.Error())
		return
	}
	setOK(w)
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

func setError(w http.ResponseWriter, message string) {
	setResponse(w, http.StatusInternalServerError, message)
}

func setResponse(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	w.Write([]byte(message))
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
