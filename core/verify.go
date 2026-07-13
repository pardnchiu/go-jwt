package goJwt

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func (j *JWTAuth) Verify(w http.ResponseWriter, r *http.Request) JWTAuthResult {
	refreshID := j.getRefreshID(r)
	accessToken := j.getAccessToken(r)
	fp := j.getFingerprint(w, r)

	// * No Access Token provided
	if accessToken == "" {
		// * No Refresh ID provided (not logged in)
		if refreshID == "" {
			logger.Error("Authentication required: Not logged in")
			return JWTAuthResult{
				StatusCode: http.StatusUnauthorized,
				Error:      "Authentication required: Not logged in",
				ErrorTag:   errorUnAuthorized,
			}
		}
		// * Attempt to re-sign Access Token (follow Refresh flow)
		return j.refresh(w, r)
	}

	keyRevoke := fmt.Sprintf(redisKeyRevoke, accessToken)
	resultRevoke, err := j.redis.Get(j.context, keyRevoke).Result()
	// * Redis error
	if err != nil && err.Error() != "redis: nil" {
		logger.Error("Failed to check token status in Redis", "error", err)
		return JWTAuthResult{
			StatusCode: http.StatusInternalServerError,
			Error:      fmt.Errorf("failed to check token status in Redis: %w", err).Error(),
			ErrorTag:   errorFailedToGet,
		}
	}
	// * Access Token revocation record exists (logged out)
	if resultRevoke != "" {
		return JWTAuthResult{
			StatusCode: http.StatusUnauthorized,
			Error:      "Session expired: Token revoked",
			ErrorTag:   errorRevoked,
		}
	}

	auth, err := j.parseJWT(accessToken, refreshID, fp)
	// * JWT parsing failed
	if err != nil {
		// * JWT parsing failed due to expiration
		if strings.Contains(err.Error(), "expired") {
			return j.refresh(w, r)
		}

		logger.Error("Invalid token", "error", err)
		return JWTAuthResult{
			StatusCode: http.StatusBadRequest,
			Error:      fmt.Errorf("invalid token: %w", err).Error(),
			ErrorTag:   errorDataInvalid,
		}
	}

	return JWTAuthResult{
		Success:    true,
		StatusCode: http.StatusOK,
		Data:       auth,
	}
}

func (j *JWTAuth) parseJWT(txt string, refreshID string, fp string) (*Auth, error) {
	token, err := jwt.Parse(txt, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodECDSA); !ok {
			logger.Error("Unexpected signing method", "method", token.Header["alg"])
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return j.pem.public, nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		now := time.Now()

		if nbf, exists := claims["nbf"]; exists {
			if nbfTime := time.Unix(int64(nbf.(float64)), 0); now.Before(nbfTime) {
				logger.Error("Token not valid yet", "nbf", nbfTime)
				return nil, fmt.Errorf("token not valid yet: %v", nbfTime)
			}
		}

		if iat, exists := claims["iat"]; exists {
			if iatTime := time.Unix(int64(iat.(float64)), 0); now.Before(iatTime.Add(-5 * time.Minute)) {
				logger.Error("Token issued in the future", "iat", iatTime)
				return nil, fmt.Errorf("token issued in the future: %v", iatTime)
			}
		}

		if claims[j.config.Option.RefreshIdCookieKey].(string) != refreshID {
			logger.Error("Refresh ID does not match", "expected", refreshID, "actual", claims[j.config.Option.RefreshIdCookieKey])
			return nil, fmt.Errorf("refresh ID does not match: expected %s, actual %s", refreshID, claims[j.config.Option.RefreshIdCookieKey])
		}

		if claims["fp"].(string) != fp {
			logger.Error("Fingerprint does not match", "expected", fp, "actual", claims["fp"])
			return nil, fmt.Errorf("fingerprint does not match: expected %s, actual %s", fp, claims["fp"])
		}

		if err := j.validateJTI(claims["jti"].(string)); err != nil {
			return nil, err
		}

		auth := j.getAuth(claims)

		return &auth, nil
	}

	logger.Error("JWT claims are not valid", "claims", token.Claims)
	return nil, fmt.Errorf("JWT claims are not valid: %v", token.Claims)
}

func (j *JWTAuth) getAuth(data map[string]interface{}) Auth {
	return Auth{
		ID:        getStr(data, "id"),
		Name:      getStr(data, "name"),
		Email:     getStr(data, "email"),
		Thumbnail: getStr(data, "thumbnail"),
		Role:      getStr(data, "role"),
		Level:     getInt(data, "level"),
		Scope:     getScope(data, "scope"),
	}
}

func (j *JWTAuth) validateJTI(jti string) error {
	if jti == "" {
		return fmt.Errorf("JWT ID is empty")
	}

	keyJTI := fmt.Sprintf(redisKeyJTI, jti)
	isExist, err := j.redis.Exists(j.context, keyJTI).Result()
	if err != nil {
		return fmt.Errorf("Failed to check JWT ID existence: %w", err)
	}

	if isExist == 0 {
		return fmt.Errorf("JWT ID does not exist")
	}

	return nil
}
