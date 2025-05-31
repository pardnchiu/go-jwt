package golangJwtAuth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

// * private method
func (j *JWTAuth) createRefreshId(userID string, name string, email string, fp string, jti string) (string, error) {
	data := &RefreshID{
		ID:          userID,
		Name:        name,
		Email:       email,
		Fingerprint: fp,
		IAT:         time.Now().Unix(),
		JTI:         jti,
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", fmt.Errorf("Failed to parse json in createRefreshId(): %v", err)
	}

	hash := sha256.Sum256(jsonData)

	return hex.EncodeToString(hash[:]), nil
}
