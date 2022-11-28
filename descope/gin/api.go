package gin

import (
	"net/http"

	"github.com/descope/go-sdk/descope/auth"
	"github.com/gin-gonic/gin"
)

func AuthenticationMiddleware(client auth.Authentication, onFailure func(*gin.Context, error), onSuccess func(*gin.Context, *auth.Token)) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ok, token, err := client.ValidateSession(c.Request, c.Writer); ok {
			if onSuccess != nil {
				onSuccess(c, token)
			} else {
				c.Set(auth.ContextUserIDProperty, token.ID)
				c.Next()
			}
		} else {
			if onFailure != nil {
				onFailure(c, err)
			} else {
				c.AbortWithError(http.StatusUnauthorized, err)
			}
		}
	}
}
