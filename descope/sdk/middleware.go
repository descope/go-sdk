package sdk

import (
	"context"
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/logger"
)

// AuthenticationMiddleware - middleware used to validate session and invoke if provided a failure and
// success callbacks after calling ValidateSession().
// onFailure will be called when the authentication failed, if empty, will write unauthorized (401) on the response writer.
// onSuccess will be called when the authentication succeeded, if empty, it will generate a new context with the descope user id associated with the given token and runs next.
func AuthenticationMiddleware(auth Authentication, onFailure func(http.ResponseWriter, *http.Request, error), onSuccess func(http.ResponseWriter, *http.Request, http.Handler, *descope.Token)) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if ok, token, err := auth.ValidateAndRefreshSessionWithRequest(r.Context(), r, w); ok {
				if onSuccess != nil {
					onSuccess(w, r, next, token)
				} else {
					newCtx := context.WithValue(r.Context(), descope.ContextUserIDPropertyKey, token.ID)
					r = r.WithContext(newCtx)
					next.ServeHTTP(w, r)
				}
			} else {
				if err != nil {
					logger.LogError("Request failed because token is invalid", err)
				}
				if onFailure != nil {
					onFailure(w, r, err)
				} else {
					w.WriteHeader(http.StatusUnauthorized)
				}
			}
		})
	}
}
