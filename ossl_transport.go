package ossl

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
)

type Transport struct {
	Dialer             *Dialer
	DisableCompression bool
}

// RoundTrip does a single HTTP transaction. It dials a new [SSL] connection every roundtrip.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	port := req.URL.Port()
	if port == "" {
		port = "443"
	}
	address := net.JoinHostPort(req.URL.Hostname(), port)
	conn, err := t.Dialer.DialContext(req.Context(), "tcp", address)
	if err != nil {
		return nil, err
	}

	if deadline, ok := req.Context().Deadline(); ok {
		conn.SetDeadline(deadline)
	}

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

	if !t.DisableCompression && resp.Header.Get("Content-Encoding") == "gzip" {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		// Wrap the gzip reader with a closer that also closes the connection
		resp.Body = &gzipReaderWithClose{
			conn:   conn,
			reader: gzReader,
		}
		resp.Header.Del("Content-Encoding")
		resp.Header.Del("Content-Length")
		resp.ContentLength = -1
		resp.Uncompressed = true
	} else {
		defer conn.Close()
	}
	return resp, nil
}

// gzipReaderWithConnClose is a custom io.ReadCloser that closes the
// underlying gzip reader and the connection
type gzipReaderWithClose struct {
	reader io.Reader
	conn   io.Closer
}

func (gz *gzipReaderWithClose) Read(p []byte) (n int, err error) {
	return gz.reader.Read(p)
}

func (gz *gzipReaderWithClose) Close() error {
	if closer, ok := gz.reader.(io.Closer); ok {
		err := closer.Close()
		if err != nil {
			return err
		}
	}
	return gz.conn.Close()
}
