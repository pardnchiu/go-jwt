package goJwt

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// Refresh Data ID 結構
type RefreshId struct {
	ID          string `json:"id"`    // 使用者 ID
	Name        string `json:"name"`  // 使用者名稱
	Email       string `json:"email"` // 電子郵件
	Fingerprint string `json:"fp"`    // 設備指紋
	Iat         int64  `json:"iat"`   // 發行時間
	Jti         string `json:"jti"`   // JWT ID
}

func (j *JWTAuth) createRefreshId(
	auth *Auth,
	fp string,
	jti string,
) (string, error) {
	data, err := json.Marshal(&RefreshId{
		ID:          auth.ID,
		Name:        auth.Name,
		Email:       auth.Email,
		Fingerprint: fp,
		Iat:         time.Now().Unix(),
		Jti:         jti,
	})
	if err != nil {
		return "", j.logger.Error(err, "[Failed] Parse Refresh Data")
	}

	hash := sha256.Sum256(data)

	return hex.EncodeToString(hash[:]), nil
}

// * private method
func (j *JWTAuth) getFingerprint(w http.ResponseWriter, r *http.Request) string {
	if fp := r.Header.Get(headerKeyDeviceFP); fp != "" {
		return fp
	}

	userAgent := r.UserAgent()
	deviceID := r.Header.Get(headerKeyDeviceID)
	if deviceID != "" {
		// no action, use the deviceID from header
	} else if cookie, err := r.Cookie(cookieKeyDeviceID); err == nil && cookie != nil {
		deviceID = cookie.Value
	} else {
		deviceID = uuid()
	}

	j.setCookie(w, cookieKeyDeviceID, deviceID, time.Now().Add(90*24*time.Hour))

	os := "OS:" + uuid()
	browser := "Browser:" + uuid()
	device := "Desktop"

	switch {
	case strings.Contains(userAgent, "Windows"):
		os = "Windows"
	case strings.Contains(userAgent, "Macintosh") || strings.Contains(userAgent, "Mac OS X"):
		os = "MacOS"
	case strings.Contains(userAgent, "Linux"):
		os = "Linux"
	case strings.Contains(userAgent, "Android"):
		os = "Android"
	case strings.Contains(userAgent, "iPhone") || strings.Contains(userAgent, "iPad") || strings.Contains(userAgent, "iPod"):
		os = "iOS"
	}

	switch {
	case strings.Contains(userAgent, "Edge") || strings.Contains(userAgent, "Edg"):
		browser = "Edge"
	case strings.Contains(userAgent, "Firefox"):
		browser = "Firefox"
	case strings.Contains(userAgent, "Chrome"):
		browser = "Chrome"
	case strings.Contains(userAgent, "Safari"):
		browser = "Safari"
	case strings.Contains(userAgent, "Opera") || strings.Contains(userAgent, "OPR"):
		browser = "Opera"
	}

	switch {
	case strings.Contains(userAgent, "iPad"):
		device = "Tablet"
	case strings.Contains(userAgent, "iPhone") || strings.Contains(userAgent, "iPod") ||
		(strings.Contains(userAgent, "Android") && strings.Contains(userAgent, "Mobile")) ||
		strings.Contains(userAgent, "BlackBerry") || strings.Contains(userAgent, "IEMobile") ||
		strings.Contains(userAgent, "Opera Mini"):
		device = "Mobile"
	}
	fingerprint := map[string]string{
		"os":       os,
		"browser":  browser,
		"device":   device,
		"deviceId": deviceID,
	}
	bytes, _ := json.Marshal(fingerprint)
	hash := sha256.Sum256(bytes)

	return hex.EncodeToString(hash[:])
}

func (j *JWTAuth) getAccessToken(r *http.Request) string {
	if cookie, err := r.Cookie(j.config.Option.AccessTokenCookieKey); err == nil {
		return cookie.Value
	}

	auth := r.Header.Get("Authorization")

	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}
