package minijwt

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

func (svc *Service) Verify(token string, secret string) (map[string]interface{}, error) {
	splits := strings.Split(token, ".")
	if len(splits) != 3 {
		return nil, errors.New("invalid token")
	}

	encodedHeader := splits[0]
	encodedPayload := splits[1]
	encryptedSignature := splits[2]

	targetToken := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)

	decryptedSignature, _ := decrypt([]byte(secret), encryptedSignature)

	if decryptedSignature != targetToken {
		return nil, errors.New("invalid token")
	}

	var payload map[string]interface{}
	decodedPayload := decodeBase64(encodedPayload)

	err := json.Unmarshal([]byte(decodedPayload), &payload)
	if err != nil {
		return nil, errors.New("invalid token")
	}

	// check expiry
	payloadExpiry := payload["eat"].(string)
	if payloadExpiry <= fmt.Sprint(time.Now().Unix()) {
		return nil, errors.New("token expired")
	}

	return payload, nil
}
