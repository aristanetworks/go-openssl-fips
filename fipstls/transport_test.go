package fipstls_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils"
)

func TestTransportConcurrency(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	ts := testutils.NewServer(t, *enableServerTrace)
	defer ts.Close()

	t.Run("SSL Transport", func(t *testing.T) {
		opts := []fipstls.DialOption{}
		if *enableClientTrace {
			opts = append(opts, fipstls.WithConnTracingEnabled())
		}

		client := fipstls.NewClient(&fipstls.Config{CaFile: ts.CaFile}, opts...)
		createRequests(t, ts, client)
	})
}

func createRequests(t *testing.T, ts *testutils.TestServer, client *http.Client) {
	const concurrentRequests = 20
	var wg sync.WaitGroup
	wg.Add(concurrentRequests)

	errCh := make(chan error, concurrentRequests)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Launch concurrent requests
	for i := 0; i < concurrentRequests; i++ {
		go func(num int) {
			defer wg.Done()

			req, err := http.NewRequestWithContext(ctx, "GET", ts.URL, nil)
			if err != nil {
				errCh <- fmt.Errorf("request %d creation failed: %w", num, err)
				return
			}

			resp, err := client.Do(req)
			if err != nil {
				errCh <- fmt.Errorf("request %d failed: %w", num, err)
				return
			}
			defer resp.Body.Close()

			_, err = io.ReadAll(resp.Body)
			if err != nil {
				errCh <- fmt.Errorf("request %d body read failed: %w", num, err)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errCh)

	var errors []error
	for err := range errCh {
		errors = append(errors, err)
	}

	if len(errors) > 0 {
		t.Errorf("Got %d errors during concurrent requests:", len(errors))
		for _, err := range errors {
			t.Errorf("  %v", err)
		}
	}
}
