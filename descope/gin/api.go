package gin

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/descope/go-sdk/descope/auth"
)

func AuthneticationMiddleware(client auth.IAuth, onFailure func(*gin.Context, error)) gin.HandlerFunc {
	return func(c *gin.Context) {
		if ok, _, err := client.ValidateSession(c.Request, c.Writer); ok {
			c.Next()
		} else {
			if onFailure != nil {
				onFailure(c, err)
			} else {
				c.AbortWithError(http.StatusUnauthorized, err)
			}
		}
	}
}

func WithResponseOption(c *gin.Context) auth.Option {
	return auth.WithResponseOption(c.Writer)
}
