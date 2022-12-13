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
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/auth"
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
	log.Println("go to https://localhost:" + port + " to enjoy descope")
	var err error
	router := mux.NewRouter()
	// Leave projectId param empty to get it from DESCOPE_PROJECT_ID env variable
	projectID := ""
	client, err = descope.NewDescopeClientWithConfig(&descope.Config{ProjectID: projectID, SessionJWTViaCookie: true})
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
	router.HandleFunc("/", help).Methods(http.MethodGet)

	router.HandleFunc("/otp/signin", handleSignIn).Methods(http.MethodGet)
	router.HandleFunc("/otp/signup", handleSignUp).Methods(http.MethodGet)
	router.HandleFunc("/otp/verify", handleVerify).Methods(http.MethodGet)

	router.HandleFunc("/oauth", handleOAuth).Methods(http.MethodGet)
	router.HandleFunc("/oauth/exchange", finalizeOAuth).Methods(http.MethodGet)

	router.HandleFunc("/magiclink/signin", handleMagicLinkSignIn).Methods(http.MethodGet)
	router.HandleFunc("/magiclink/signup", handleMagicLinkSignUp).Methods(http.MethodGet)
	router.HandleFunc("/magiclink/verify", handleMagicLinkVerify).Methods(http.MethodGet)

	router.HandleFunc("/enchantedlink/signin", handleEnchantedLinkSignIn).Methods(http.MethodGet)
	router.HandleFunc("/enchantedlink/signup", handleEnchantedLinkSignUp).Methods(http.MethodGet)
	router.HandleFunc("/enchantedlink/verify", handleEnchantedLinkVerify).Methods(http.MethodGet)
	router.HandleFunc("/enchantedlink/session", handleEnchantedLinkSession).Methods(http.MethodGet)

	router.HandleFunc("/webauthn", func(w http.ResponseWriter, r *http.Request) {
		file, _ := os.ReadFile("./demo.html")
		w.WriteHeader(http.StatusOK)
		w.Write(file)
	}).Methods(http.MethodGet)

	router.HandleFunc("/webauthn/signup/start", handleWebauthnSignupStart).Methods(http.MethodPost)
	router.HandleFunc("/webauthn/signup/finish", handleWebauthnSignupFinish).Methods(http.MethodPost)

	router.HandleFunc("/webauthn/signin/start", handleWebauthnSigninStart).Methods(http.MethodPost)
	router.HandleFunc("/webauthn/signin/finish", handleWebauthnSigninFinish).Methods(http.MethodPost)

	router.HandleFunc("/stepup", handleStepup).Methods(http.MethodGet)
	router.HandleFunc("/stepup/conf", handleStepupSignUpInEmail).Methods(http.MethodGet)
	router.HandleFunc("/stepup/conf/verify", handleStepupConfVerify).Methods(http.MethodGet)
	router.HandleFunc("/stepup/conf/update", handleStepupConfUpdate).Methods(http.MethodGet)
	router.HandleFunc("/stepup/conf/update/verify", handleStepupConfUpdateVerify).Methods(http.MethodGet)
	router.HandleFunc("/stepup/login", handleStepupLogin).Methods(http.MethodGet)
	router.HandleFunc("/stepup/login/verify", handleStepupLoginVerify).Methods(http.MethodGet)
	router.HandleFunc("/stepup/stepup", handleStepupStepup).Methods(http.MethodGet)
	router.HandleFunc("/stepup/stepup/verify", handleStepupStepupVerify).Methods(http.MethodGet)

	authRouter := router.Methods(http.MethodGet).Subrouter()
	authRouter.Use(auth.AuthenticationMiddleware(client.Auth, func(w http.ResponseWriter, r *http.Request, err error) {
		setResponse(w, http.StatusUnauthorized, "Unauthorized")
	}, nil))
	authRouter.HandleFunc("/private", handleIsHealthy).Methods(http.MethodGet)

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
	setResponse(w, http.StatusOK, "You can see this page only since you are logged in")
}

func help(w http.ResponseWriter, r *http.Request) {
	helpTxt := "Sign up with otp email go to: /otp/signup?email=\n\n"
	helpTxt += "Sign up with otp sms go to: /otp/signup?sms=\n\n"
	helpTxt += "Sign up with otp whatsapp go to: /otp/signup?whatsapp=\n\n"
	helpTxt += "Sign in of existing user with otp email go to: /otp/signin?email=\n\n"
	helpTxt += "Sign in of existing user with otp sms go to: /otp/signin?sms=\n\n"
	helpTxt += "Sign in of existing user with otp whatsapp go to: /otp/signin?whatsapp=\n\n"
	helpTxt += "---------------------------------------------------------\n\n"
	helpTxt += "Sign up/in with OAuth go to: /oauth?provider=[google|github|facebook]\n\n"
	helpTxt += "---------------------------------------------------------\n\n"
	helpTxt += "Use Webauthn features go to: /webauthn\n"
	helpTxt += "---------------------------------------------------------\n\n"
	helpTxt += "Sign up with magiclink and email go to: /magiclink/signup?email=\n\n"
	helpTxt += "Sign up with magiclink and sms go to: /magiclink/signup?sms=\n\n"
	helpTxt += "Sign up with magiclink and whatsapp go to: /magiclink/signup?whatsapp=\n\n"
	helpTxt += "Sign in of existing user with magiclink email go to: /magiclink/signin?email=\n\n"
	helpTxt += "Sign in of existing user with magiclink sms go to: /magiclink/signin?sms=\n\n"
	helpTxt += "Sign in of existing user with magiclink whatsapp go to: /magiclink/signin?whatsapp=\n\n"
	helpTxt += "---------------------------------------------------------\n\n"
	helpTxt += "Sign up with enchanted link go to: /enchantedlink/signup?email=\n\n"
	helpTxt += "Sign in of existing user with enchanted link email go to: /enchantedlink/signin?email=\n\n"
	helpTxt += "---------------------------------------------------------\n\n"
	helpTxt += "Start a stepup flow go to: /stepup\n\n"
	helpTxt += "---------------------------------------------------------\n\n"
	helpTxt += "See that you are actually logged in go to: /private \n\n"
	setResponse(w, http.StatusOK, helpTxt)
}

func handleSignUp(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	err := client.Auth.OTP().SignUp(method, identifier, &auth.User{Name: "test"})
	if err != nil {
		setErrorWithSignUpIn(w, err.Error(), method, identifier)
	} else {
		helpTxt := "to verify code received go to /otp/verify?" + string(method) + "=" + identifier + "&code=<code>"
		setResponse(w, http.StatusOK, helpTxt)
	}
}

func handleSignIn(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	err := client.Auth.OTP().SignIn(method, identifier, nil, nil)
	if err != nil {
		setErrorWithSignUpIn(w, err.Error(), method, identifier)
	} else {
		helpTxt := "to verify code received go to /otp/verify?" + string(method) + "=" + identifier + "&code=<code>"
		setResponse(w, http.StatusOK, helpTxt)
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
	authInfo, err := client.Auth.OTP().VerifyCode(method, identifier, code, w)
	if err != nil {
		setError(w, err.Error())
		return
	}
	sendSuccessAuthResponse(w, authInfo)
}

func handleOAuth(w http.ResponseWriter, r *http.Request) {
	provider := auth.OAuthFacebook
	if p, ok := r.URL.Query()["provider"]; ok {
		provider = auth.OAuthProvider(p[0])
	}
	_, err := client.Auth.OAuth().Start(provider, "https://localhost:8085/oauth/exchange", nil, nil, w)
	if err != nil {
		setError(w, err.Error())
	}
}

func finalizeOAuth(w http.ResponseWriter, r *http.Request) {
	var code string
	if codes, ok := r.URL.Query()["code"]; ok {
		code = codes[0]
	}
	if code == "" {
		setError(w, "code is empty")
		return
	}
	authInfo, err := client.Auth.OAuth().ExchangeToken(code, w)
	if err != nil {
		setError(w, err.Error())
		return
	}
	sendSuccessAuthResponse(w, authInfo)
}

func sendSuccessAuthResponse(w http.ResponseWriter, authInfo *auth.AuthenticationInfo) {
	helpTxt := "You have properly authenticated, you can check for your JWT in the cookie\n"
	mr, _ := json.MarshalIndent(authInfo, "", "")
	helpTxt += string(mr) + "\n"
	setResponse(w, http.StatusOK, helpTxt)
}

func handleMagicLinkSignIn(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	err := client.Auth.MagicLink().SignIn(method, identifier, verifyMagicLinkURI, nil, nil)
	if err != nil {
		setErrorWithSignUpIn(w, err.Error(), method, identifier)
		return
	}
	helpTxt := "You should have received a magiclink by " + string(method) + "\n"
	helpTxt += "Copy it to this browser in order to complete the signin"
	setResponse(w, http.StatusOK, helpTxt)
}

func handleMagicLinkSignUp(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	user := &auth.User{Name: "test"}
	err := client.Auth.MagicLink().SignUp(method, identifier, verifyMagicLinkURI, user)
	if err != nil {
		setErrorWithSignUpIn(w, err.Error(), method, identifier)
		return
	}
	helpTxt := "You should have received a magiclink by " + string(method) + "\n"
	helpTxt += "Copy it to this browser in order to complete the sign up"
	setResponse(w, http.StatusOK, helpTxt)
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
	authInfo, err := client.Auth.MagicLink().Verify(token, w)
	if err != nil {
		setError(w, err.Error())
		return
	}
	sendSuccessAuthResponse(w, authInfo)
}

func handleEnchantedLinkSignIn(w http.ResponseWriter, r *http.Request) {
	_, identifier := getMethodAndIdentifier(r)
	enchantedRes, err := client.Auth.EnchantedLink().SignIn(identifier, verifyMagicLinkURI, nil, nil)
	if err != nil {
		setErrorWithSignUpIn(w, err.Error(), "", identifier)
		return
	}
	helpTxt := "You should have received an enchanted link by email\n"
	helpTxt += "Clink on the link labeled " + enchantedRes.LinkID + "\n"
	helpTxt += "Once done, copy the following to the url, so you will get a session on your original page:\n"
	helpTxt += "/enchantedlink/session?pendingRef=" + enchantedRes.PendingRef
	setResponse(w, http.StatusOK, helpTxt)
}

func handleEnchantedLinkSignUp(w http.ResponseWriter, r *http.Request) {
	_, identifier := getMethodAndIdentifier(r)
	user := &auth.User{Name: "test"}
	enchantedRes, err := client.Auth.EnchantedLink().SignUp(identifier, verifyMagicLinkURI, user)
	if err != nil {
		setErrorWithSignUpIn(w, err.Error(), "", identifier)
		return
	}
	helpTxt := "You should have received an enchanted link by email\n"
	helpTxt += "Clink on the link labeled " + enchantedRes.LinkID + "\n"
	helpTxt += "Once done, copy the following to the url, so you will get a session on your original page:\n"
	helpTxt += "/enchantedlink/session?pendingRef=" + enchantedRes.PendingRef
	setResponse(w, http.StatusOK, helpTxt)
}

func handleEnchantedLinkVerify(w http.ResponseWriter, r *http.Request) {
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
	err := client.Auth.EnchantedLink().Verify(token)
	if err != nil {
		setError(w, err.Error())
		return
	}
	setResponse(w, http.StatusOK, "Go back to original tab and follow the instructions")
}

func handleEnchantedLinkSession(w http.ResponseWriter, r *http.Request) {
	tokens := r.URL.Query()["pendingRef"]
	if len(tokens) == 0 {
		setError(w, "token is empty")
		return
	}
	token := tokens[0]
	if token == "" {
		setError(w, "token is empty")
		return
	}
	authInfo, err := client.Auth.EnchantedLink().GetSession(tokens[0], w)
	if err != nil {
		setError(w, err.Error())
		return
	}
	sendSuccessAuthResponse(w, authInfo)
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

	res, err := client.Auth.WebAuthn().SignUpStart(t.Email, t, getQuery(r, "origin"))
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

func handleStepup(w http.ResponseWriter, r *http.Request) {
	helpTxt := "First we will make sure we have a user in the system with email and phone go to /stepup/conf?email=\n\n"
	setResponse(w, http.StatusOK, helpTxt)
}

func handleStepupSignUpInEmail(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	err := client.Auth.OTP().SignUpOrIn(method, identifier)
	if err != nil {
		setErrorWithSignUpIn(w, err.Error(), method, identifier)
	} else {
		helpTxt := "to verify code received go to /stepup/conf/verify?" + string(method) + "=" + identifier + "&code=<code>"
		setResponse(w, http.StatusOK, helpTxt)
	}
}

func handleStepupConfVerify(w http.ResponseWriter, r *http.Request) {
	code := ""
	method, identifier := getMethodAndIdentifier(r)
	if codes, ok := r.URL.Query()["code"]; ok {
		code = codes[0]
	}
	if code == "" {
		setError(w, "code is empty")
		return
	}
	authInfo, err := client.Auth.OTP().VerifyCode(method, identifier, code, w)
	if err != nil {
		setError(w, err.Error())
		return
	}
	helpTxt := "Great !\n"
	helpTxt += "Now lets update our user with a phone number go to /stepup/conf/update?identifier=" + authInfo.User.ExternalIDs[0] + "&sms=<phone>"
	setResponse(w, http.StatusOK, helpTxt)
}

func handleStepupConfUpdate(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	var exID string
	if codes, ok := r.URL.Query()["identifier"]; ok {
		exID = codes[0]
	}
	err := client.Auth.OTP().UpdateUserPhone(method, exID, identifier, r)
	if err != nil {
		setErrorWithSignUpIn(w, err.Error(), method, identifier)
	} else {
		helpTxt := "to verify code received go to /stepup/conf/update/verify?" + string(method) + "=" + exID + "&code=<code>"
		setResponse(w, http.StatusOK, helpTxt)
	}
}

func handleStepupConfUpdateVerify(w http.ResponseWriter, r *http.Request) {
	code := ""
	method, identifier := getMethodAndIdentifier(r)
	if codes, ok := r.URL.Query()["code"]; ok {
		code = codes[0]
	}
	if code == "" {
		setError(w, "code is empty")
		return
	}
	authInfo, err := client.Auth.OTP().VerifyCode(method, identifier, code, nil)
	if err != nil {
		setErrorWithSignUpIn(w, err.Error(), method, identifier)
		return
	}
	helpTxt := "Great, we have a user with 2 factors, now lets start the actual step flow !\n"
	helpTxt += "go to /stepup/login?email=" + authInfo.User.ExternalIDs[0]
	setResponse(w, http.StatusOK, helpTxt)
}

func handleStepupLogin(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	err := client.Auth.OTP().SignUpOrIn(method, identifier)
	if err != nil {
		setErrorWithSignUpIn(w, err.Error(), method, identifier)
	} else {
		helpTxt := "to verify code received go to /stepup/login/verify?" + string(method) + "=" + identifier + "&code=<code>"
		setResponse(w, http.StatusOK, helpTxt)
	}
}

func handleStepupLoginVerify(w http.ResponseWriter, r *http.Request) {
	code := ""
	method, identifier := getMethodAndIdentifier(r)
	if codes, ok := r.URL.Query()["code"]; ok {
		code = codes[0]
	}
	if code == "" {
		setError(w, "code is empty")
		return
	}
	authInfo, err := client.Auth.OTP().VerifyCode(method, identifier, code, w)
	if err != nil {
		setError(w, err.Error())
		return
	}
	helpTxt := "You have logged in !\n"
	mr, _ := json.MarshalIndent(authInfo, "", "")
	helpTxt += string(mr) + "\n\n"
	helpTxt += "Now lets stepup go to /stepup/stepup?sms=" + authInfo.User.ExternalIDs[0]
	setResponse(w, http.StatusOK, helpTxt)
}

func handleStepupStepup(w http.ResponseWriter, r *http.Request) {
	method, identifier := getMethodAndIdentifier(r)
	err := client.Auth.OTP().SignIn(method, identifier, r, &auth.LoginOptions{Stepup: true, CustomClaims: map[string]interface{}{"demoKey": "demoValue"}})
	if err != nil {
		setErrorWithSignUpIn(w, err.Error(), method, identifier)
	} else {
		helpTxt := "to verify code received go to /stepup/stepup/verify?" + string(method) + "=" + identifier + "&code=<code>"
		setResponse(w, http.StatusOK, helpTxt)
	}
}

func handleStepupStepupVerify(w http.ResponseWriter, r *http.Request) {
	code := ""
	method, identifier := getMethodAndIdentifier(r)
	if codes, ok := r.URL.Query()["code"]; ok {
		code = codes[0]
	}
	if code == "" {
		setError(w, "code is empty")
		return
	}
	authInfo, err := client.Auth.OTP().VerifyCode(method, identifier, code, w)
	if err != nil {
		setError(w, err.Error())
		return
	}
	helpTxt := "You have stepped up, pay attention to the custom claims !\n"
	mr, _ := json.MarshalIndent(authInfo, "", "")
	helpTxt += string(mr)
	setResponse(w, http.StatusOK, helpTxt)
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
	setResponse(w, http.StatusInternalServerError, message+" ")
}

func setErrorWithSignUpIn(w http.ResponseWriter, message string, method auth.DeliveryMethod, identifier string) {
	msg := message
	if method != "" {
		msg += " method: " + string(method)
	}
	if identifier != "" {
		msg += " identifier: " + identifier
	}
	setError(w, msg)
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
