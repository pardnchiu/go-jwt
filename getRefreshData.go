package golangJwtAuth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// * private method
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

// * private method
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

// * private method
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

// * private method
func (j *JWTAuth) getRefreshId(r *http.Request) string {
	if refreshId := r.Header.Get("X-Refresh-ID"); refreshId != "" {
		return refreshId
	}
	if cookie, err := r.Cookie(j.Config.RefreshIdCookieKey); err == nil {
		return cookie.Value
	}
	return ""
}

// * private method
func (j *JWTAuth) getRefreshData(refreshId, fp string) (*RefreshData, error) {
	refreshDataJson, err := j.Redis.Get(j.Context, "refresh:"+refreshId).Result()
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

// * private method
func (j *JWTAuth) getUserData(data map[string]interface{}) AuthData {
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
