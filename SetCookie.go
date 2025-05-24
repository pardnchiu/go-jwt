package golangJwtAuth

import (
	"net/http"
	"time"
)

func (j *JWTAuth) SetCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   j.config.IsProd,
	}

	if j.config.IsProd {
		cookie.SameSite = http.SameSiteNoneMode
		cookie.Domain = j.config.Domain
	} else {
		cookie.SameSite = http.SameSiteLaxMode
		cookie.Domain = "localhost"
	}

	http.SetCookie(w, cookie)
}

func (j *JWTAuth) ClearCookie(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   j.config.IsProd,
	}

	if j.config.IsProd {
		cookie.SameSite = http.SameSiteNoneMode
		cookie.Domain = j.config.Domain
	} else {
		cookie.SameSite = http.SameSiteLaxMode
		cookie.Domain = "localhost"
	}

	http.SetCookie(w, cookie)
}
