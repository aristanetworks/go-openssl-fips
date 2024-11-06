package client_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	ossl "github.com/golang-fips/openssl/v2"
)

// Response represents each JSON object in the stream
type Response struct {
	ID     int    `json:"id"`
	Method string `json:"method"`
	URL    string `json:"url"`
}

// Progress tracks streaming progress
type Progress struct {
	MessagesRead int64
	TotalBytes   int64
	BytesRead    int64
	BytesPerSec  float64
	LastUpdate   time.Time
}

func init() {
	if err := ossl.Init(""); err != nil {
		panic(err)
	}
}

func TestStreamJSON(t *testing.T) {
	client, err := ossl.NewClient()
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	tests := []struct {
		name          string
		n             int // number of messages to stream
		expectSuccess bool
	}{
		{"Stream 5 messages", 5, true},
		{"Stream 10 messages", 10, true},
		{"Stream 50 messages", 50, true},
		{"Stream 100 messages", 100, true},
	}

	// Create a mutex to protect access to t
	var logMu sync.Mutex

	// Safe logging helper
	safeLog := func(format string, args ...interface{}) {
		logMu.Lock()
		t.Logf(format, args...)
		logMu.Unlock()
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := fmt.Sprintf("https://httpbingo.org/stream/%d", tt.n)
			progressChan := make(chan Progress, 1)
			messagesChan := make(chan Response, tt.n)
			errorChan := make(chan error, 1)

			go func() {
				if err := streamWithProgress(t, client, url, progressChan, messagesChan); err != nil {
					errorChan <- err
					close(messagesChan)
					return
				}
				close(messagesChan)
				close(errorChan)
			}()

			go func() {
				for progress := range progressChan {
					safeLog("Progress: Messages=%d, Bytes=%d, Speed=%.2f KB/s",
						progress.MessagesRead,
						progress.BytesRead,
						progress.BytesPerSec/1024)
				}
			}()

			var messages []Response
			for msg := range messagesChan {
				safeLog("Received message: %+v", msg)
				messages = append(messages, msg)
			}

			if err := <-errorChan; err != nil {
				if tt.expectSuccess {
					t.Errorf("Expected success but got error: %v", err)
				}
				return
			}

			// Verify number of messages
			if len(messages) != tt.n {
				t.Errorf("Expected %d messages, got %d", tt.n, len(messages))
			}

			// Verify message IDs are sequential
			for i, msg := range messages {
				if msg.ID != i {
					t.Errorf("Message ID mismatch: expected %d, got %d", i, msg.ID)
				}
			}
		})
	}
}

func streamWithProgress(t *testing.T, client *ossl.Client, url string, progressChan chan<- Progress, messagesChan chan<- Response) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("making request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	decoder := json.NewDecoder(resp.Body)
	var bytesRead int64
	var messagesRead int64
	startTime := time.Now()
	lastUpdate := startTime

	for {
		var response Response
		err := decoder.Decode(&response)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("decoding response: %w", err)
		}

		messagesRead++
		bytesRead = decoder.InputOffset()
		messagesChan <- response

		now := time.Now()
		duration := now.Sub(lastUpdate)
		if duration >= 100*time.Millisecond {
			progress := Progress{
				MessagesRead: messagesRead,
				TotalBytes:   resp.ContentLength,
				BytesRead:    bytesRead,
				BytesPerSec:  float64(bytesRead) / time.Since(startTime).Seconds(),
				LastUpdate:   now,
			}
			progressChan <- progress
			lastUpdate = now
		}
	}

	progress := Progress{
		MessagesRead: messagesRead,
		TotalBytes:   resp.ContentLength,
		BytesRead:    bytesRead,
		BytesPerSec:  float64(bytesRead) / time.Since(startTime).Seconds(),
		LastUpdate:   time.Now(),
	}
	progressChan <- progress
	close(progressChan)

	return nil
}
