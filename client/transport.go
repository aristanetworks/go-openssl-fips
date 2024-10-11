package client

import (
	"bufio"
	"net/http"
	"net/http/httputil"
	"time"
)

// SSLTransport is used for piping requests to an openssl s_client subprocess proxy.
type SSLTransport struct {
	Timeout time.Duration
}

// RoundTrip is used to do a single HTTP transaction using openssl.
func (t *SSLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	conn, err := NewSSLConn(req.URL.Host, t.Timeout)
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
