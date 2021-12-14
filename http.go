package l9l4gfuzz

import (
	"context"
	"crypto/tls"
	"github.com/LeakIX/l9format"
	"net"
	"net/http"
	"time"
)

func HttpClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network string, address string) (net.Conn, error) {
				return l9format.ServicePluginBase{}.DialContext(ctx, "tcp", address)
			},
			// #nosec because we're a scanner
			TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
			MaxConnsPerHost:       2,
			DisableKeepAlives:     true,
			ResponseHeaderTimeout: 2 * time.Second,
			ExpectContinueTimeout: 2 * time.Second,
		},
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
