package l9l4gfuzz

import (
	"crypto/hmac"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"time"
)

type TokenTranslator struct {
	Secret []byte
}

type Token struct {
	SourceUrl     string
	PayloadSource string
	IssueDate     time.Time
}

var ErrInvalidToken = errors.New("invalid token")
var ErrTokenValidationFailed = errors.New("token validation faild")

func (tt *TokenTranslator) GetTokenFromHash(input string) (*Token, error) {
	data, err := hex.DecodeString(input)
	if err != nil {
		return nil, ErrInvalidToken
	}
	if len(data) < 20 {
		return nil, ErrInvalidToken
	}
	unsignedData := data[0 : len(data)-16]
	currentHash := data[len(data)-16:]
	h := hmac.New(fnv.New128, tt.Secret)
	h.Write(unsignedData)
	verifyHash := h.Sum(nil)
	if !hmac.Equal(currentHash, verifyHash) {
		return nil, ErrTokenValidationFailed
	}
	var token Token
	err = json.Unmarshal(unsignedData, &token)
	return &token, err
}

func (tt *TokenTranslator) GetHashFromToken(token Token) string {
	h := hmac.New(fnv.New128, tt.Secret)
	payload, _ := json.Marshal(token)
	h.Write(payload)
	payload = append(payload, h.Sum(nil)...)
	return fmt.Sprintf("%x", payload)
}
