package l9l4gfuzz

import (
	"errors"
	"github.com/LeakIX/l9format"
	"github.com/gboddin/ldapserver"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"text/template"
	"time"
)

type fuzzer struct {
	ldapserverOutput io.Writer
	httpServer       *http.Server
	listenAddress    string
	ListenIp         string
	LDAPPort         string
	HTTPPort         string
	SSHPort          string
	GenericPort      string
	timeout          time.Duration

	tokenTranslator     *TokenTranslator
	ldapserver          *ldapserver.Server
	l9Helper            l9format.ServicePluginBase
	fuzzerOutputChannel FuzzerChannel
	requestTemplate     *template.Template
	payloadTemplate     *template.Template
}

type FuzzerResult struct {
	Ip       string
	Port     string
	Protocol string
	Token    *Token
}

type FuzzerContext struct {
	Fuzzer *fuzzer
	Url    *url.URL
}

type FuzzerChannel chan FuzzerResult

func NewFuzzer(opts ...FuzzerOption) (*fuzzer, error) {
	var err error
	// create a new instance
	newfuzzer := &fuzzer{}
	for _, opt := range opts {
		// Call the option
		err := opt(newfuzzer)
		if err != nil {
			return nil, err
		}
	}
	// Fix defaults :
	if newfuzzer.tokenTranslator == nil {
		newfuzzer.tokenTranslator = &TokenTranslator{Secret: []byte("insecure")}
	}
	newfuzzer.ListenIp, newfuzzer.LDAPPort, err = net.SplitHostPort(newfuzzer.listenAddress)
	if err != nil {
		return nil, err
	}
	baseport, err := strconv.Atoi(newfuzzer.LDAPPort)
	if err != nil {
		return nil, err
	}
	// Set ports for listeners
	if newfuzzer.HTTPPort == "" {
		newfuzzer.HTTPPort = strconv.Itoa(baseport + 1)
	}
	if newfuzzer.SSHPort == "" {
		newfuzzer.SSHPort = strconv.Itoa(baseport + 2)
	}
	if newfuzzer.GenericPort == "" {
		newfuzzer.GenericPort = strconv.Itoa(baseport + 3)
	}
	if newfuzzer.timeout == 0 {
		newfuzzer.timeout = 2 * time.Second
	}
	if newfuzzer.ldapserverOutput == nil {
		newfuzzer.ldapserverOutput = ioutil.Discard
	}
	newfuzzer.startLdapServer()
	newfuzzer.startHttpServer()
	// return fuzzer
	return newfuzzer, nil
}

var ErrNoFuzzerForScheme = errors.New("no fuzzer for scheme")
