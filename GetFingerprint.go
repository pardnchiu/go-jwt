package golangJwtAuth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

func (j *JWTAuth) GetFingerprint(r *http.Request) string {
	if fp := r.Header.Get("X-Session-FP"); fp != "" {
		return fp
	}

	userAgent := r.Header.Get("User-Agent")
	deviceID := r.Header.Get("X-Device-ID")
	if deviceID == "" {
		deviceID = "Unknown"
	}

	os := "Unknown_OS"
	browser := "Unknown_Browser"
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

	fpData := fmt.Sprintf(`{"os":"%s","browser":"%s","device":"%s","deviceId":"%s"}`, os, browser, device, deviceID)
	hash := sha256.Sum256([]byte(fpData))

	return hex.EncodeToString(hash[:])
}
