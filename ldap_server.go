package l9l4gfuzz

import (
	"github.com/gboddin/ldapserver"
	"log"
	"net"
)

func (f *fuzzer) startLdapServer() {
	// Send LDAP logs to selected output
	ldapserver.Logger = log.New(f.ldapserverOutput, "[ldapserver] ", log.LstdFlags)
	// attach ldap server to instance
	f.ldapserver = ldapserver.NewServer()
	f.ldapserver.ReadTimeout = f.timeout
	f.ldapserver.WriteTimeout = f.timeout
	// attach routes to ldap server
	ldaproutes := ldapserver.NewRouteMux()
	ldaproutes.Bind(f.handleLDAPBind)
	ldaproutes.Search(f.handleSearch)
	f.ldapserver.Handle(ldaproutes)
	// Start LDAP server
	go func() {
		err := f.ldapserver.ListenAndServe(f.listenAddress)
		if err != nil {
			panic(err)
		}
	}()
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
			Ip:       ip,
			Port:     port,
			Token:    token,
			Protocol: "ldap",
		}
	}
}
