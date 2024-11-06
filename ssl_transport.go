package client

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httputil"
)

type SSLTransport struct {
	ctx    *SSLContext
	dialer *SSLDialer
}

// RoundTrip is used to do a single HTTP transaction using openssl
func (t *SSLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	address := net.JoinHostPort(req.URL.Hostname(), req.URL.Port())
	conn, err := t.dialer.DialTLSContext(context.Background(), "tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	b, err := httputil.DumpRequestOut(req, true)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(b); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}
