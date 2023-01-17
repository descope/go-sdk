package gin

import (
	"net/http"

	"github.com/descope/go-sdk/descope"
	"github.com/descope/go-sdk/descope/client"
	"github.com/gin-gonic/gin"
)

func AuthenticationMiddleware(client *client.DescopeClient, onFailure func(*gin.Context, error), onSuccess func(*gin.Context, *descope.Token)) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ok, token, err := client.Auth.ValidateSession(c.Request, c.Writer); ok {
			if onSuccess != nil {
				onSuccess(c, token)
			} else {
				c.Set(descope.ContextUserIDProperty, token.ID)
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
