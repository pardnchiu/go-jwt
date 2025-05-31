package golangJwtAuth

import (
	"net/http"
	"time"
)

func (j *JWTAuth) Revoke(r *http.Request, w http.ResponseWriter) error {
	refreshId := j.getRefreshId(r)
	accessToken := j.getAccessToken(r)

	j.clearCookie(w, j.Config.AccessTokenCookieKey)
	j.clearCookie(w, j.Config.RefreshIdCookieKey)

	if refreshId != "" {
		result, err := j.Redis.Get(j.Context, "refresh:"+refreshId).Result()
		if err == nil {
			j.Redis.SetEx(j.Context, "refresh:"+refreshId, result, 5*time.Second)

			ttl, err := j.Redis.TTL(j.Context, "refresh:"+refreshId).Result()
			if err == nil && ttl > 0 {
				j.Redis.SetEx(j.Context, "revoke:"+accessToken, "1", j.Config.AccessTokenExpires)
			}
		}
	}

	return nil
}
