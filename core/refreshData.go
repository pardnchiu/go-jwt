package goJwt

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

func getStr(data map[string]interface{}, key string) string {
	v, exists := data[key]
	if !exists || v == nil {
		return ""
	}

	switch val := v.(type) {
	case string:
		return val
	case int:
		return fmt.Sprintf("%d", val)
	case int64:
		return fmt.Sprintf("%d", val)
	case float64:
		return fmt.Sprintf("%g", val)
	default:
		return ""
	}
}

func getInt(data map[string]interface{}, key string) int {
	v, exists := data[key]
	if !exists || v == nil {
		return 0
	}

	switch val := v.(type) {
	case int:
		return val
	case int64:
		return int(val)
	case float64:
		return int(val)
	default:
		return 0
	}
}

func getScope(data map[string]interface{}, key string) []string {
	v, exists := data[key]
	if !exists || v == nil {
		return nil
	}

	switch val := v.(type) {
	case []string:
		return val
	case []interface{}:
		scope := make([]string, len(val))
		for i, v := range val {
			if s, ok := v.(string); ok {
				scope[i] = s
			}
		}
		return scope
	default:
		return nil
	}
}

func (j *JWTAuth) getRefreshID(r *http.Request) string {
	if refreshId := r.Header.Get(headerKeyRefreshID); refreshId != "" {
		return refreshId
	}

	if cookie, err := r.Cookie(j.config.Option.RefreshIdCookieKey); err == nil {
		return cookie.Value
	}

	return ""
}

func (j *JWTAuth) getRefreshData(refreshID string, fp string) (*RefreshData, time.Duration, error) {
	key := fmt.Sprintf(redisKeyRefreshID, refreshID)

	result, err := j.redis.Get(j.context, key).Result()
	if err != nil {
		return nil, 0, err
	}

	ttl, err := j.redis.TTL(j.context, key).Result()
	if err != nil || ttl < 1 {
		return nil, 0, err
	}

	var refreshData RefreshData
	if err := json.Unmarshal([]byte(result), &refreshData); err != nil {
		return nil, 0, err
	}

	if refreshData.Fingerprint != fp {
		return nil, 0, fmt.Errorf("Fingerprint mismatch: expected %s, got %s", refreshData.Fingerprint, fp)
	}

	return &refreshData, ttl, nil
}
