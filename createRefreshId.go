package golangJwtAuth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// * private method
func (j *JWTAuth) createRefreshId(userID, name, email, fp string) (string, error) {
	data := map[string]interface{}{
		"id":    userID,
		"name":  name,
		"email": email,
		"fp":    fp,
		"iat":   time.Now().Unix(),
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("Failed to parse json in createRefreshId(): %v", err)
	}

	hash := sha256.Sum256(jsonData)

	return hex.EncodeToString(hash[:]), nil
}
