package main

import (
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
	goJwt "github.com/pardnchiu/go-jwt"
)

var websocketUpgrade = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func main() {
	config := goJwt.Config{
		Redis: goJwt.Redis{
			Host:     "localhost",
			Port:     6379,
			Password: "0123456789",
			DB:       0,
		},
		CheckAuth: func(userData goJwt.Auth) (bool, error) {
			return userData.ID == "1", nil
		},
	}

	auth, err := goJwt.New(config)
	if err != nil {
		log.Fatal("failed to init:", err)
	}
	defer auth.Close()

	r := gin.Default()
	r.LoadHTMLGlob("./model/*")

	r.GET("/", func(c *gin.Context) {
		check := auth.Verify(c.Writer, c.Request)
		c.Header("Content-Type", "text/html")
		if check.Success {
			c.HTML(http.StatusOK, "index.html", gin.H{
				"name":   check.Data.Name,
				"isAuth": true,
			})
			return
		}

		c.HTML(http.StatusOK, "index.html", gin.H{
			"name":     "Guest",
			"isUnAuth": true,
		})
	})

	r.GET("/login", func(c *gin.Context) {
		check := auth.Verify(c.Writer, c.Request)
		if check.Success {
			c.Redirect(http.StatusFound, "/")
			return
		}

		user := &goJwt.Auth{
			ID:    "1",
			Name:  "John",
			Email: "john@example.com",
			Scope: []string{"read", "write"},
		}

		c.Header("Content-Type", "text/html")

		result := auth.Create(c.Writer, c.Request, user)
		if !result.Success {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to login"})
			return
		}

		c.HTML(http.StatusOK, "index.html", gin.H{
			"name":    user.Name,
			"token":   result.Token,
			"isLogin": true,
		})
	})

	r.GET("/logout", func(c *gin.Context) {
		c.Header("Content-Type", "text/html")

		check := auth.Verify(c.Writer, c.Request)
		if !check.Success {
			c.HTML(http.StatusOK, "index.html", gin.H{
				"error":    "please login first",
				"isLogout": true,
			})
			return
		}

		result := auth.Revoke(c.Writer, c.Request)
		if !result.Success {
			c.HTML(http.StatusOK, "index.html", gin.H{
				"error":    result.Error,
				"isLogout": true,
			})
			return
		}

		c.HTML(http.StatusOK, "index.html", gin.H{
			"isLogout": true,
		})
	})

	r.GET("/ws", handleWebSocket(auth))

	protected := r.Group("/protected")
	protected.Use(auth.GinMiddleware())
	{
		protected.GET("/user", func(c *gin.Context) {
			user, _ := goJwt.GetAuthDataFromGinContext(c)
			c.JSON(http.StatusOK, gin.H{"user": user})
		})
	}

	r.Run(":8080")
}

func handleWebSocket(auth *goJwt.JWTAuth) gin.HandlerFunc {
	return func(c *gin.Context) {
		check := auth.Verify(c.Writer, c.Request)
		if !check.Success {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		conn, err := websocketUpgrade.Upgrade(c.Writer, c.Request, nil)
		if err != nil {
			log.Printf("WebSocket upgrade failed: %v", err)
			return
		}
		defer conn.Close()

		welcomeMsg := map[string]interface{}{
			"time":    time.Now(),
			"user":    "System",
			"message": "Welcome",
		}
		conn.WriteJSON(welcomeMsg)

		count := 0
		for {
			var msg map[string]interface{}
			err := conn.ReadJSON(&msg)
			if err != nil {
				log.Printf("WebSocket read error: %v", err)
				break
			}

			count++
			response := map[string]interface{}{
				"time":    time.Now(),
				"user":    check.Data.Name,
				"message": msg["message"].(string),
			}
			conn.WriteJSON(response)
			welcomeMsg1 := map[string]interface{}{
				"time":    time.Now(),
				"user":    "System",
				"message": "Received your message: " + strconv.Itoa(count),
			}
			conn.WriteJSON(welcomeMsg1)
		}
	}
}
