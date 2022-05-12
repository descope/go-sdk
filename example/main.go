package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/descope/go-sdk/pkg/auth"
	"github.com/gorilla/mux"
)

var client auth.IAuth

func main() {
	log.Println("starting server")
	router := mux.NewRouter()
	client = auth.NewAuth(auth.Config{LogLevel: auth.LogDebug})

	router.Use(loggingMiddleware)
	router.HandleFunc("/signin", handleSignIn).Methods(http.MethodGet)
	router.HandleFunc("/verify", handleVerify).Methods(http.MethodGet)
	authRouter := router.Methods(http.MethodGet).Subrouter()
	authRouter.Use(authenticationMiddleware)
	authRouter.HandleFunc("/health", handleIsHealthy)

	server := &http.Server{Addr: ":8085", Handler: router}
	go func() {
        if err := server.ListenAndServe(); err != nil {
			fmt.Println("server error " + err.Error())
        }
    }()

    stop := make(chan os.Signal, 1)
    signal.Notify(stop, os.Interrupt)

    // Waiting for SIGINT (kill -2)
    <-stop

    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    if err := server.Shutdown(ctx); err != nil {
		fmt.Println("server error " + err.Error())
    }
	log.Println("stopping server")
}

func handleIsHealthy(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	log.Println("Returning 200 - Healthy")
	w.Write([]byte("Healthy"))
}

func handleSignIn(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	err := client.SignInOTP(method, identifier)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
	} else {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Ok"))
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
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("code is empty"))
		return
	}
	cookies, err := client.VerifyCode(method, identifier, code)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(err.Error()))
		return
	}
	for i := range cookies {
		http.SetCookie(w, cookies[i])
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Ok"))
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Url requested: %s", r.RequestURI)
		next.ServeHTTP(w, r)
		log.Println("Request finished")
	})
}

func authenticationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Println(r.Cookies())
		if ok, err := client.ValidateSessionRequest(r); ok {
			next.ServeHTTP(w, r)
		} else {
			log.Println("request failed because token is invalid = " + err.Error())
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte("Unauthorized"))
		}
	})
}
