package minijwt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	b64 "encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"go.uber.org/zap"
)

type Service struct {
	logger *zap.SugaredLogger
}

func NewService(logger *zap.SugaredLogger) *Service {
	return &Service{
		logger: logger,
	}
}

func getHeader() map[string]string {
	return map[string]string{
		"algorithm": "AES",
		"type":      "minijwt",
	}
}

func decodeBase64(data string) string {
	decoded, _ := b64.RawStdEncoding.Strict().WithPadding(b64.NoPadding).DecodeString(data)
	return string(decoded)
}

func toBase64(data string) string {
	enc := b64.RawStdEncoding.Strict().WithPadding(b64.NoPadding).EncodeToString([]byte(data))
	return enc
}

func encrypt(key []byte, message string) (encoded string, err error) {
	//Create byte array from the input string
	plainText := []byte(message)

	//Create a new AES cipher using the key
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		return
	}

	//Make the cipher text a byte array of size BlockSize + the length of the message
	cipherText := make([]byte, aes.BlockSize+len(plainText))

	//iv is the ciphertext up to the blocksize (16)
	iv := cipherText[:aes.BlockSize]
	if _, err = io.ReadFull(rand.Reader, iv); err != nil {
		return
	}

	//Encrypt the data:
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)

	//Return string encoded in base64
	return base64.RawStdEncoding.EncodeToString(cipherText), err
}

func decrypt(key []byte, secure string) (decoded string, err error) {
	//Remove base64 encoding:
	cipherText, err := base64.RawStdEncoding.DecodeString(secure)

	//IF DecodeString failed, exit:
	if err != nil {
		return
	}

	//Create a new AES cipher with the key and encrypted message
	block, err := aes.NewCipher(key)

	//IF NewCipher failed, exit:
	if err != nil {
		return
	}

	//IF the length of the cipherText is less than 16 Bytes:
	if len(cipherText) < aes.BlockSize {
		err = errors.New("Ciphertext block size is too short!")
		return
	}

	iv := cipherText[:aes.BlockSize]
	cipherText = cipherText[aes.BlockSize:]

	//Decrypt the message
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(cipherText, cipherText)

	return string(cipherText), err
}

func decryptAES(key []byte, ct string) string {
	ciphertext, _ := hex.DecodeString(ct)

	c, _ := aes.NewCipher(key)

	pt := make([]byte, len(ciphertext))
	c.Decrypt(pt, ciphertext)

	s := string(pt[:])
	// return string(pt)
	return s
}

// signs data, returns token
// xxxx.yyyy.zzzz
func (svc *Service) Sign(payload map[string]interface{}, secret string) (string, error) {
	// header
	// 1st part
	header := getHeader()
	headerString := fmt.Sprint(header)
	encodedHeader := toBase64(headerString)

	// payload
	// 2nd part
	payload["eat"] = fmt.Sprint(time.Now().Local().Add(1 * time.Hour).Unix())

	jsonPayload, _ := json.Marshal(payload)
	encodedPayload := toBase64(string(jsonPayload))

	// signature
	// 3rd part
	rawToken := fmt.Sprintf("%s.%s", encodedHeader, encodedPayload)
	signature, _ := encrypt([]byte(secret), rawToken)

	// dec, _ := decrypt([]byte(secret), token)
	token := fmt.Sprintf("%s.%s.%s", encodedHeader, encodedPayload, signature)

	return token, nil
}

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
