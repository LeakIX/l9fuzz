package l9l4gfuzz

import (
	"net"
	"net/http"
	"strings"
)

func (f *fuzzer) startHttpServer() {
	handler := http.NewServeMux()
	handler.HandleFunc("/", f.handleHttp)
	f.httpServer = &http.Server{Addr: net.JoinHostPort(f.ListenIp, f.HTTPPort), Handler: handler}
	f.httpServer.SetKeepAlivesEnabled(false)
	go func() {
		err := f.httpServer.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}()
}

func (f *fuzzer) handleHttp(w http.ResponseWriter, r *http.Request) {
	hash := strings.Trim(r.URL.Path, "/")
	token, err := f.tokenTranslator.GetTokenFromHash(hash)
	if err == nil {
		ip, port, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			return
		}
		f.fuzzerOutputChannel <- FuzzerResult{
			Ip:       ip,
			Port:     port,
			Token:    token,
			Protocol: "http",
		}
	}
	w.Header().Set("vendor", "LeakIX")
	w.Header().Set("version", "0.0.1")
	w.WriteHeader(200)
}
