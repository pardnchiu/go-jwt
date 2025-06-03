package goJwt

import (
	"net/http"
	"time"
)

// * private method
func (j *JWTAuth) setCookie(
	w http.ResponseWriter,
	key string,
	value string,
	expires time.Time,
) {
	cookie := j.validCookieData(&http.Cookie{
		Name:     key,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, cookie)
}

// * private method
func (j *JWTAuth) clearCookie(
	w http.ResponseWriter,
	key string,
) {
	cookie := j.validCookieData(&http.Cookie{
		Name:     key,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, cookie)
}

func (j *JWTAuth) validCookieData(cookie *http.Cookie) *http.Cookie {
	// * 如果沒有設定 Cookie 的相關屬性，則使用預設值
	if j.config.Cookie == nil {
		return cookie
	}
	if j.config.Cookie.Domain != nil {
		cookie.Domain = *j.config.Cookie.Domain
	}
	if j.config.Cookie.Path != nil {
		cookie.Path = *j.config.Cookie.Path
	}
	if j.config.Cookie.SameSite != nil {
		cookie.SameSite = *j.config.Cookie.SameSite
	}
	if j.config.Cookie.Secure != nil {
		cookie.Secure = *j.config.Cookie.Secure
	}
	if j.config.Cookie.HttpOnly != nil {
		cookie.HttpOnly = *j.config.Cookie.HttpOnly
	}
	return cookie
}
