package golangJwtAuth

import (
	"net/http"
	"time"
)

// * private method
func (j *JWTAuth) setCookie(w http.ResponseWriter, name string, value string, expires time.Time) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int(time.Until(expires).Seconds()),
		HttpOnly: true,
		Secure:   j.Config.IsProd,
	}

	if j.Config.IsProd {
		cookie.SameSite = http.SameSiteNoneMode
		cookie.Domain = j.Config.Domain
	} else {
		cookie.SameSite = http.SameSiteLaxMode
		cookie.Domain = "localhost"
	}

	http.SetCookie(w, cookie)
}

// * private method
func (j *JWTAuth) clearCookie(w http.ResponseWriter, name string) {
	cookie := &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   j.Config.IsProd,
	}

	if j.Config.IsProd {
		cookie.SameSite = http.SameSiteNoneMode
		cookie.Domain = j.Config.Domain
	} else {
		cookie.SameSite = http.SameSiteLaxMode
		cookie.Domain = "localhost"
	}

	http.SetCookie(w, cookie)
}
