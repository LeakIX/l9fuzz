package l9l4gfuzz

import (
	"errors"
	"github.com/LeakIX/l9format"
	"github.com/gboddin/ldapserver"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"text/template"
	"time"
)

type fuzzer struct {
	ldapserverOutput io.Writer
	listenAddress    string
	ListenIp         string
	ListenPort       string
	timeout          time.Duration

	tokenTranslator     *TokenTranslator
	ldapserver          *ldapserver.Server
	l9Helper            l9format.ServicePluginBase
	fuzzerOutputChannel FuzzerChannel
	genericTemplate     *template.Template
}

type FuzzerResult struct {
	Ip    string
	Port  string
	Token *Token
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
	newfuzzer.ListenIp, newfuzzer.ListenPort, err = net.SplitHostPort(newfuzzer.listenAddress)
	if err != nil {
		return nil, err
	}
	if newfuzzer.timeout == 0 {
		newfuzzer.timeout = 2 * time.Second
	}
	if newfuzzer.ldapserverOutput == nil {
		newfuzzer.ldapserverOutput = ioutil.Discard
	}
	// Send LDAP logs to selected output
	ldapserver.Logger = log.New(newfuzzer.ldapserverOutput, "[ldapserver] ", log.LstdFlags)
	// attach ldap server to instance
	newfuzzer.ldapserver = ldapserver.NewServer()
	newfuzzer.ldapserver.ReadTimeout = newfuzzer.timeout
	newfuzzer.ldapserver.WriteTimeout = newfuzzer.timeout
	// attach routes to ldap server
	ldaproutes := ldapserver.NewRouteMux()
	ldaproutes.Bind(newfuzzer.handleLDAPBind)
	ldaproutes.Search(newfuzzer.handleSearch)
	newfuzzer.ldapserver.Handle(ldaproutes)
	// Start LDAP server
	go func() {
		err := newfuzzer.ldapserver.ListenAndServe(newfuzzer.listenAddress)
		if err != nil {
			panic(err)
		}
	}()
	// return fuzzer
	return newfuzzer, nil
}

func (f *fuzzer) handleLDAPBind(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	w.Write(ldapserver.NewBindResponse(ldapserver.LDAPResultSuccess))
}

func (f *fuzzer) handleSearch(w ldapserver.ResponseWriter, m *ldapserver.Message) {
	defer m.Client.GetConn().Close()
	r := m.GetSearchRequest()
	DN := string(r.BaseObject())
	e := ldapserver.NewSearchResultEntry("")
	e.AddAttribute("vendorName", "LeakIX")
	e.AddAttribute("vendorVersion", "0.0.1")
	w.Write(e)
	res := ldapserver.NewSearchResultDoneResponse(ldapserver.LDAPResultSuccess)
	w.Write(res)
	token, err := f.tokenTranslator.GetTokenFromHash(DN)
	if err == nil {
		ip, port, err := net.SplitHostPort(m.Client.Addr().String())
		if err != nil {
			return
		}
		f.fuzzerOutputChannel <- FuzzerResult{
			Ip:    ip,
			Port:  port,
			Token: token,
		}
	}
}

type Fuzzer func(parsedUrl *url.URL) (err error)

var ErrNoFuzzerForScheme = errors.New("no fuzzer for scheme")
