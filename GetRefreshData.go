package golangJwtAuth

import (
	"encoding/json"
	"fmt"
	"net/http"
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

func (j *JWTAuth) GetRefreshId(r *http.Request) string {
	if refreshId := r.Header.Get("X-Refresh-ID"); refreshId != "" {
		return refreshId
	}
	if cookie, err := r.Cookie(j.config.RefreshIdCookieKey); err == nil {
		return cookie.Value
	}
	return ""
}

func (j *JWTAuth) GetRefreshData(refreshId, fp string) (*RefreshData, error) {
	refreshDataJson, err := j.redisClient.Get(j.context, "refresh:"+refreshId).Result()
	if err != nil {
		return nil, err
	}

	var refreshData RefreshData

	if err := json.Unmarshal([]byte(refreshDataJson), &refreshData); err != nil {
		return nil, fmt.Errorf("failed to parse json: %w", err)
	}

	if refreshData.Fingerprint != fp {
		return nil, fmt.Errorf("fingerprint invalid")
	}

	return &refreshData, nil
}

// set user data from json and return AuthData
func (j *JWTAuth) GetUserData(data map[string]interface{}) AuthData {
	return AuthData{
		ID:        getStr(data, "id"),
		Name:      getStr(data, "name"),
		Email:     getStr(data, "email"),
		Thumbnail: getStr(data, "thumbnail"),
		Role:      getStr(data, "role"),
		Level:     getInt(data, "level"),
		Scope:     getScope(data, "scope"),
	}
}
