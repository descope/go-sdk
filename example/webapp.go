package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/auth"
	"github.com/descope/go-sdk/descope/logger"
	"github.com/gorilla/mux"
)

var client *descope.API

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
	router.Use(loggingMiddleware)
	router.HandleFunc("/signin", handleSignIn).Methods(http.MethodGet)
	router.HandleFunc("/signup", handleSignUp).Methods(http.MethodGet)
	router.HandleFunc("/verify", handleVerify).Methods(http.MethodGet)
	authRouter := router.Methods(http.MethodGet).Subrouter()
	authRouter.Use(client.Auth.AuthenticationMiddleware(func(w http.ResponseWriter, r *http.Request, err error) { setResponse(w, http.StatusUnauthorized, "Unauthorized") }))
	authRouter.HandleFunc("/health", handleIsHealthy)

	server := &http.Server{Addr: fmt.Sprintf(":%s", port), Handler: router}
	go func() {
		if err := server.ListenAndServeTLS("server.crt", "server.key"); err != nil {
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
	err := client.Auth.SignUpOTP(method, identifier, &auth.User{Name: "test"})
	if err != nil {
		setError(w, err.Error())
	} else {
		setOK(w)
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
	cookies, err := client.Auth.VerifyCode(method, identifier, code)
	if err != nil {
		setError(w, err.Error())
		return
	}
	for i := range cookies {
		http.SetCookie(w, cookies[i])
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
