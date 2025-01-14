package fipstls

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
)

// Transport implements [http.RoundTripper] by dialing TLS [Conn] using [Dialer].
type Transport struct {
	// Dialer is used for creating TLS connections.
	Dialer *Dialer

	// ModifyHeader is called in RoundTrip to modify the request headers before making the request.
	ModifyHeader func(*http.Header)

	// DisableCompression, if true, prevents the Transport from
	// requesting compression with an "Accept-Encoding: gzip"
	// request header when the Request contains no existing
	// Accept-Encoding value. If the Transport requests gzip on
	// its own and gets a gzipped response, it's transparently
	// decoded in the Response.Body. However, if the user
	// explicitly requested gzip it is not automatically
	// uncompressed.
	DisableCompression bool
}

// RoundTrip does a single HTTP transaction. It dials a new [Conn] connection every roundtrip.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.ModifyHeader != nil {
		t.ModifyHeader(&req.Header)
	}

	// Ask for a compressed version if the caller didn't set their
	// own value for Accept-Encoding. We only attempt to
	// uncompress the gzip stream if we were the layer that
	// requested it.
	requestedGzip := false
	if !t.DisableCompression &&
		req.Header.Get("Accept-Encoding") == "" &&
		req.Header.Get("Range") == "" &&
		req.Method != "HEAD" {
		// Request gzip only, not deflate. Deflate is ambiguous and
		// not as universally supported anyway.
		// See: https://zlib.net/zlib_faq.html#faq39
		//
		// Note that we don't request this for HEAD requests,
		// due to a bug in nginx:
		//   https://trac.nginx.org/nginx/ticket/358
		//   https://golang.org/issue/5522
		//
		// We don't request gzip if the request is for a range, since
		// auto-decoding a portion of a gzipped document will just fail
		// anyway. See https://golang.org/issue/8923
		requestedGzip = true
		req.Header.Set("Accept-Encoding", "gzip")
	}

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

	if requestedGzip && resp.Header.Get("Content-Encoding") == "gzip" {
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
