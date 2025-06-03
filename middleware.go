package goJwt

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/gin-gonic/gin"
)

func (j *JWTAuth) GinMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		result := j.Verify(c.Writer, c.Request)
		if !result.Success {
			c.JSON(result.StatusCode, gin.H{
				"error": result.Error,
			})
			c.Abort()
			return
		}

		c.Set("user", result.Data)
		c.Next()
	}
}

func GetAuthDataFromGinContext(c *gin.Context) (*Auth, bool) {
	user, exists := c.Get("user")
	if !exists {
		return nil, false
	}

	userData, ok := user.(*Auth)
	return userData, ok
}

func (j *JWTAuth) HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verify := j.Verify(w, r)

		if !verify.Success {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(verify.StatusCode)
			json.NewEncoder(w).Encode(map[string]string{
				"error": verify.Error,
			})
			return
		}

		contextValue := context.WithValue(r.Context(), "user", verify.Data)
		next.ServeHTTP(w, r.WithContext(contextValue))
	})
}

func GetAuthDataFromHTTPRequest(r *http.Request) (*Auth, bool) {
	user := r.Context().Value("user")
	if user == nil {
		return nil, false
	}

	userData, ok := user.(*Auth)
	return userData, ok
}
