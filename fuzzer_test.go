package l9l4gfuzz

import (
	"encoding/json"
	"errors"
	"testing"
)

type TestPayloadResult struct {
	Hash     string
	HTTPPort string
	LDAPPort string
	ListenIp string
}

func TestFuzzer_Payload(t *testing.T) {
	l4j215Fuzzer, err := NewFuzzer(
		WithTimeout(1),
		WithPayloadTemplate("tests/payload_test.txt"),
		WithListenAddress("127.0.0.1:65021"))
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	var payloadTestResult TestPayloadResult
	jsonTest := l4j215Fuzzer.Payload("http://test.com", "test")
	err = json.Unmarshal([]byte(jsonTest), &payloadTestResult)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if payloadTestResult.ListenIp != "127.0.0.1" {
		t.Error("listen ip should be 127.0.0.1")
	}
	if payloadTestResult.LDAPPort != "65021" {
		t.Error("ldap port should be 65021")
	}
	if payloadTestResult.HTTPPort != "65022" {
		t.Error("http port should be 65022")
	}
	token, err := l4j215Fuzzer.tokenTranslator.GetTokenFromHash(payloadTestResult.Hash)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if token.PayloadSource != "test" {
		t.Error(errors.New("token payload source should be test"))
	}
	if token.SourceUrl != "http://test.com" {
		t.Error(errors.New("token url should be http://test.com"))
	}
}
