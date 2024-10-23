package client

import (
	"bufio"
	"net/http"
	"net/http/httputil"
	"time"

	"github.com/golang-fips/openssl/v2/client/conn"
)

// SSLTransport sends the request over an SSLConn.
type SSLTransport struct {
	Timeout time.Duration
	Headers map[string]string
	TLSConfig *conn.Config
}

// RoundTrip is used to do a single HTTP transaction using openssl.
func (t *SSLTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add additional Headers to the request headers
	for k, v := range t.Headers {
		req.Header.Add(k, v)
	}

	conn, err := conn.NewSSLConn(req.URL, t.Timeout, t.TLSConfig)
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
