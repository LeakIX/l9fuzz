package l9l4gfuzz

import (
	"testing"
	"time"
)

var tokenTranslatorA = &TokenTranslator{Secret: []byte("TranslatorA pre-shared-key")}
var tokenTranslatorB = &TokenTranslator{Secret: []byte("TranslatorB pre-shared-key")}

var tokenAHash = "7b22536f7572636555726c223a22687474703a2f2f3132372e302e302e313a333232222c225061796c6f6164536f75726365223a227373682075736572222c22497373756544617465223a22313937302d30312d30315430313a30303a30302b30313a3030227dbf2f4bb3942e659c2a60cd7a747d2cf0"

//var tokenABadHash = "ffff71000001bb010a00000000000000004774347a2fd1e8b82c05af1ccf40af40"

var tokenA = Token{
	SourceUrl:     "http://127.0.0.1:322",
	PayloadSource: "ssh user",
	IssueDate:     time.Unix(0, 0),
}

var tokenB = Token{
	SourceUrl:     "http://8.8.8.8",
	PayloadSource: "http user",
	IssueDate:     time.Unix(0, 0),
}

func BenchmarkTokenTranslator_GetHashFromToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		tokenTranslatorA.GetHashFromToken(tokenA)
	}
}

func TestTokenTranslator_SelfTest(t *testing.T) {
	hash := tokenTranslatorA.GetHashFromToken(tokenB)
	token, err := tokenTranslatorA.GetTokenFromHash(hash)
	if err != nil {
		t.Error(err)
		return
	}
	if token.SourceUrl != tokenB.SourceUrl {
		t.Error("token ip is incorrect")
	}
	if token.IssueDate != tokenB.IssueDate {
		t.Error("token date is incorrect")
	}
	if token.PayloadSource != tokenB.PayloadSource {
		t.Error("token payloadtype is incorrect")
	}
}

func TestTokenTranslator_GetHashFromToken(t *testing.T) {
	hash := tokenTranslatorA.GetHashFromToken(tokenA)
	if hash != tokenAHash {
		t.Error("token hash is incorrect", hash)
	}
}

func TestTokenTranslator_GetTokenFromHash(t *testing.T) {
	if token, err := tokenTranslatorA.GetTokenFromHash(tokenAHash); err != nil {
		t.Error(err)
	} else {
		if token.SourceUrl != tokenA.SourceUrl {
			t.Error("token ip is incorrect")
		}
		if token.IssueDate != tokenA.IssueDate {
			t.Error("token date is incorrect")
		}
		if token.PayloadSource != tokenA.PayloadSource {
			t.Error("token payloadtype is incorrect")
		}
	}
	if _, err := tokenTranslatorB.GetTokenFromHash(tokenAHash); err != ErrTokenValidationFailed {
		t.Error("token error should be ErrTokenValidationFailed")
	}
}
