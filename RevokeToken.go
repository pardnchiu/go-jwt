package golangJwtAuth

import (
	"net/http"
	"time"
)

func (j *JWTAuth) Revoke(r *http.Request, w http.ResponseWriter) error {
	refreshId := j.GetRefreshId(r)
	accessToken := j.GetAccessToken(r)

	j.ClearCookie(w, j.config.AccessTokenCoolieKey)
	j.ClearCookie(w, j.config.RefreshIdCookieKey)

	if refreshId != "" {
		result, err := j.redisClient.Get(j.context, "refresh:"+refreshId).Result()
		if err == nil {
			j.redisClient.SetEx(j.context, "refresh:"+refreshId, result, 5*time.Second)

			ttl, err := j.redisClient.TTL(j.context, "refresh:"+refreshId).Result()
			if err == nil && ttl > 0 {
				j.redisClient.SetEx(j.context, "revoke:"+accessToken, "1", j.config.AccessTokenExpires)
			}
		}
	}

	return nil
}
