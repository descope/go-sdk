package example

import (
	"log"
	"net/http"

	"github.com/descope/go-sdk/pkg/auth"
	"github.com/gorilla/mux"
)

var client auth.IAuth

func main() {
	router := mux.NewRouter()
	client = auth.NewAuth(auth.Config{ProjectID: "28vNOCXJdnllQqmw7oqcshoiir8"})

	router.Use(loggingMiddleware)
	router.HandleFunc("/health", handleIsHealthy).Methods(http.MethodGet)
	router.HandleFunc("/signup", handleSignUp).Methods(http.MethodGet)
	http.ListenAndServe(":8081", router)
}

func handleIsHealthy(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	log.Println("Returning 200 - Healthy")
	w.Write([]byte("Healthy"))
}

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Url requested: %s", r.RequestURI)
		next.ServeHTTP(w, r)
		log.Println("Request finished")
	})
}
