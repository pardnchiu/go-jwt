package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	golangJwtAuth "github.com/pardnchiu/golang-jwt-auth"
)

func main() {
	config := &golangJwtAuth.Config{
		// 使用 ECDSA 演算法
		// P***Path: 塞入公鑰與私鑰的路徑
		// P***: 塞入公鑰與私鑰的內容
		PrivateKeyPath: "./keys/private-key.pem",
		PublicKeyPath:  "./keys/public-key.pem",
		// PrivateKey: "",
		// PublicKey:  "",
		// Redis 設定
		Redis: golangJwtAuth.RedisConfig{
			Host:     "localhost",
			Port:     6379,
			Password: "0123456789",
			DB:       0,
		},
		// 自訂 Cookie 欄位名稱
		AccessTokenCookieKey: "access_token",
		RefreshIdCookieKey:   "refresh_id",
		// 自訂 Token 失效時間
		AccessTokenExpires: 1 * time.Minute,
		RefreshIdExpires:   7 * 24 * time.Hour,
		// 生產環境: Domain = Domain, SameSite = None, Secure = true
		// 測試環境: Domain = "localhost", SameSite = Lax, Secure = false
		IsProd: false,
		Domain: "axonews.ai",
		// 用於 refresh token 時判斷資料庫中會員是否存在來決定是否重簽
		// 回傳 false 則會取消重簽清除 token
		CheckUserExists: func(userData golangJwtAuth.AuthData) (bool, error) {
			return userData.ID == "1", nil
		},
	}

	auth, err := golangJwtAuth.New(config)
	if err != nil {
		log.Fatal("failed to init:", err)
	}
	defer auth.Close()

	r := gin.Default()

	r.GET("/", func(c *gin.Context) {
		check := auth.Verify(c.Request, c.Writer)
		if check.Success {
			c.JSON(http.StatusOK, gin.H{
				"message": "hello " + check.Data.Name,
			})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "hello world",
		})
	})

	r.GET("/login", func(c *gin.Context) {
		check := auth.Verify(c.Request, c.Writer)
		if check.Success {
			c.Redirect(http.StatusFound, "/")
			return
		}

		user := &golangJwtAuth.AuthData{
			ID:    "1",
			Name:  "John",
			Email: "john@example.com",
			Scope: []string{"read", "write"},
		}

		result, err := auth.Create(c.Request, c.Writer, user)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to login"})
			return
		}

		c.JSON(http.StatusOK, gin.H{
			"message": "successful",
			"token":   result.Token,
		})
	})

	r.GET("/logout", func(c *gin.Context) {
		check := auth.Verify(c.Request, c.Writer)
		if !check.Success {
			c.JSON(http.StatusOK, gin.H{
				"message": "please login first",
			})
			return
		}

		auth.Revoke(c.Request, c.Writer)
		c.JSON(http.StatusOK, gin.H{
			"message": "logout successful",
		})
	})

	// 直接使用中間件阻擋範例
	protected := r.Group("/protected")
	protected.Use(auth.GinMiddleware())
	{
		protected.GET("/user", func(c *gin.Context) {
			user, _ := golangJwtAuth.GetAuthDataFromGinContext(c)
			c.JSON(http.StatusOK, gin.H{"user": user})
		})
	}

	r.Run(":8080")
}
