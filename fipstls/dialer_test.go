package fipstls_test

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils"
	pb "github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils/proto"
)

func TestDialTimeout(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	// Create and start the server directly
	ts := testutils.NewServer(t, *enableServerTrace)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	d := fipstls.NewDialer(
		&fipstls.Config{CaFile: ts.CaFile},
		getFipsDialOpts()...,
	)
	conn, err := d.DialContext(context.Background(), "tcp", u.Host)
	if err != nil {
		t.Fatalf("Failed to create SSLConn: %v", err)
	}
	defer conn.Close()

	tests := []struct {
		name          string
		writeDeadline time.Duration
		readDeadline  time.Duration
		wantErr       error
		checkResponse bool
	}{
		{
			name:          "basic connection",
			checkResponse: true,
		},
		{
			name:          "read deadline exceeded",
			readDeadline:  400 * time.Millisecond,
			wantErr:       os.ErrDeadlineExceeded,
			checkResponse: false,
		},
		{
			name:          "write deadline exceeded",
			writeDeadline: 400 * time.Millisecond,
			wantErr:       os.ErrDeadlineExceeded,
			checkResponse: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			// default request
			request := fmt.Sprintf("GET /get HTTP/1.1\r\nHost: %s\r\n\r\n", u.Host)
			// For read timeout tests, send a GET that will sleep
			if tt.readDeadline > 0 {
				t.Logf("Testing read deadline")
				conn.SetReadDeadline(time.Now().Add(tt.readDeadline))
				request = fmt.Sprintf("GET /sleep/%d HTTP/1.1\r\nHost: %s\r\n\r\n",
					tt.readDeadline.Milliseconds()*2, u.Host)
			}
			// For write tests, sleep before completing the write
			if tt.writeDeadline > 0 {
				t.Logf("Testing write deadline")
				conn.SetReadDeadline(time.Now().Add(tt.writeDeadline))
				// Write first half of request
				if _, err := conn.Write([]byte(request[:len(request)/2])); err != nil {
					t.Fatalf("Failed to write first half: %v", err)
				}
				// Sleep to trigger deadline
				time.Sleep(tt.writeDeadline * 2)
				// Try to write second half
				request = request[len(request)/2:]
			}

			t.Logf("Attempting to write request")
			_, err = conn.Write([]byte(request))
			if err != nil {
				if tt.wantErr != nil {
					if !errors.Is(err, tt.wantErr) {
						t.Errorf("Write error = %v, want %v", err, tt.wantErr)
					}
					return
				}
				t.Fatalf("Failed to write request: %v", err)
			}

			t.Logf("Attempting to read response")
			reader := bufio.NewReader(conn)
			response, err := reader.ReadString('\n')

			if tt.wantErr != nil {
				if err == nil {
					t.Fatal("Expected an error but got none")
				}
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("Read error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if tt.checkResponse {
				if err != nil {
					t.Fatalf("Failed to read response: %v", err)
				}
				if !strings.Contains(response, "HTTP/1.1") {
					t.Errorf("Unexpected response: %s", response)
				}
				t.Logf("Response: %s", response)
			}
		})
	}
}

func TestGrpcDial(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	lis, cleanupSrv := testutils.NewGrpcTestServer(t)
	defer cleanupSrv()

	addr := lis.Addr().String()
	t.Logf("Server listening on: %s", addr)

	t.Log("Creating new DialFn")
	dialFn := fipstls.NewDialContext(&fipstls.Config{CaFile: testutils.CertPath},
		getFipsDialOpts()...)

	t.Log("Attempting raw connection...")
	rawConn, err := dialFn(context.Background(), addr)
	if err != nil {
		t.Fatalf("Direct dial failed: %v", err)
	}
	rawConn.Close()
	t.Log("Raw connection succeeded")

	t.Log("Attempting grpc connection...")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dialConn, err := grpc.DialContext(
		ctx,
		addr,
		testutils.NewDialOpts(t, *useNetDial, getFipsDialOpts()...)...,
	)
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}
	t.Log("Grpc dial successful")
	defer dialConn.Close()
}

func TestGrpcClient(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	client, cleanup := testutils.NewGrpcTestClientServer(t, *useNetDial, getFipsDialOpts()...)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Test server streaming
	t.Run("ServerStreaming", func(t *testing.T) {
		stream, err := client.ServerStream(ctx, &pb.Request{Message: "start"})
		if err != nil {
			t.Fatalf("Failed to start server stream: %v", err)
		}

		var messages []string
		for {
			resp, err := stream.Recv()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatalf("Failed to receive: %v", err)
			}
			messages = append(messages, resp.Message)
		}

		expected := []string{"msg1", "msg2", "msg3"}
		if !reflect.DeepEqual(messages, expected) {
			t.Errorf("Got messages %v, want %v", messages, expected)
		}
	})

	// Test client streaming
	t.Run("ClientStreaming", func(t *testing.T) {
		// t.Skip("test one rn")
		stream, err := client.ClientStream(ctx)
		if err != nil {
			t.Fatalf("Failed to start client stream: %v", err)
		}

		messages := []string{"client1", "client2", "client3"}
		for _, msg := range messages {
			if err := stream.Send(&pb.Request{Message: msg}); err != nil {
				t.Fatalf("Failed to send: %v", err)
			}
		}

		resp, err := stream.CloseAndRecv()
		if err != nil {
			t.Fatalf("Failed to receive response: %v", err)
		}

		if resp.Message != "Received all messages" {
			t.Errorf("Got response %q, want 'Received all messages'", resp.Message)
		}
	})

	// Test bidirectional streaming
	t.Run("BidirectionalStreaming", func(t *testing.T) {
		stream, err := client.BidiStream(ctx)
		if err != nil {
			t.Fatalf("Failed to start bidi stream: %v", err)
		}

		messages := []string{"bidi1", "bidi2", "bidi3"}
		waitc := make(chan struct{})

		go func() {
			for _, msg := range messages {
				if err := stream.Send(&pb.Request{Message: msg}); err != nil {
					t.Errorf("Failed to send: %v", err)
					return
				}
			}
			stream.CloseSend()
		}()

		go func() {
			i := 0
			for {
				resp, err := stream.Recv()
				if err == io.EOF {
					close(waitc)
					return
				}
				if err != nil {
					t.Errorf("Failed to receive: %v", err)
					return
				}

				if i < len(messages) {
					expected := "Echo: " + messages[i]
					if resp.Message != expected {
						t.Errorf("Got message %q, want %q", resp.Message, expected)
					}
					i++
				} else {
					t.Error("Received more messages than expected")
				}
			}
		}()

		select {
		case <-waitc:
			// Success
		case <-time.After(time.Second):
			t.Fatal("Timeout waiting for stream completion")
		}
	})
}

func TestGrpcBidiStress(t *testing.T) {
	initTest(t)
	if !*runStressTest {
		t.Skip("Skipping... to run this, use '-stresstest'")
	}
	defer testutils.LeakCheck(t)
	client, cleanup := testutils.NewGrpcTestClientServer(t, *useNetDial, getFipsDialOpts()...)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	t.Run("BidirectionalStreamingStressTest", func(t *testing.T) {
		numStreams := 100
		numMessages := 10000
		intervalPercent := 10.0
		sampleSize := int(float64(numMessages) * (intervalPercent / 100.0))

		var wg sync.WaitGroup
		wg.Add(numStreams)

		r := testutils.NewProgressRecorder(t, *enableProgRecorder, numStreams, numMessages,
			sampleSize, 50*time.Millisecond)
		defer r.Close()
		for i := 0; i < numStreams; i++ {
			go func(streamID int) {
				defer wg.Done()

				stream, err := client.BidiStream(ctx)
				if err != nil {
					t.Errorf("Stream %d: Failed to start bidi stream: %v", streamID, err)
					return
				}

				// send
				go func() {
					for j := 0; j < numMessages; j++ {
						msg := fmt.Sprintf("Stream %d, Message %d", streamID, j)
						if err := stream.Send(&pb.Request{Message: msg}); err != nil {
							t.Errorf("Stream %d: Failed to send: %v", streamID, err)
							return
						}
						r.RecordProgress(streamID, i, true)
					}
					stream.CloseSend()

				}()

				// receive
				i := 0
				for {
					resp, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						t.Errorf("Stream %d: Failed to receive: %v", streamID, err)
						return
					}

					if i < numMessages {
						expected := "Echo: " + fmt.Sprintf("Stream %d, Message %d", streamID, i)
						if resp.Message != expected {
							t.Errorf("Stream %d: Got message %q, want %q", streamID, resp.Message, expected)
						}
						i++
						r.RecordProgress(streamID, i, false)
					} else {
						t.Errorf("Stream %d: Received more messages than expected", streamID)
					}
				}
			}(i)
		}

		wg.Wait()
	})
}

func BenchmarkGrpcBidiStream(b *testing.B) {
	initTest(nil)
	// Setup test server and client (extracted to helper function)
	client, cleanup := testutils.NewGrpcTestClientServer(b, *useNetDial, getFipsDialOpts()...)
	defer cleanup()

	// Test configuration - fixed size for each iteration
	const (
		numStreams        = 100
		messagesPerStream = 1000 // Fixed number of messages per stream per iteration
		intervalPercent   = 10.0
	)

	totalMessages := numStreams * messagesPerStream

	// Reset timer after setup
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Start memory stats
		var memStats runtime.MemStats
		runtime.ReadMemStats(&memStats)
		startAlloc := memStats.TotalAlloc

		// Create progress recorder with benchmark-appropriate settings
		sampleSize := int(float64(messagesPerStream) * (intervalPercent / 100.0))
		r := testutils.NewProgressRecorder(b, *enableProgRecorder, numStreams, totalMessages,
			sampleSize, 500*time.Millisecond)
		defer r.Close()

		var wg sync.WaitGroup
		wg.Add(numStreams)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		// Launch streams
		for i := 0; i < numStreams; i++ {
			go func(streamID int) {
				defer wg.Done()

				stream, err := client.BidiStream(ctx)
				if err != nil {
					b.Errorf("Stream %d: Failed to start bidi stream: %v", streamID, err)
					return
				}

				// Send goroutine
				go func() {
					for j := 0; j < messagesPerStream; j++ {
						msg := fmt.Sprintf("Stream %d, Message %d", streamID, j)
						if err := stream.Send(&pb.Request{Message: msg}); err != nil {
							b.Errorf("Stream %d: Failed to send: %v", streamID, err)
							return
						}
						r.RecordProgress(streamID, j, true)
					}
					stream.CloseSend()
				}()

				// Receive messages
				received := 0
				for {
					_, err := stream.Recv()
					if err == io.EOF {
						break
					}
					if err != nil {
						b.Errorf("Stream %d: Failed to receive: %v", streamID, err)
						return
					}
					received++
					r.RecordProgress(streamID, received, false)
				}

				if received != messagesPerStream {
					b.Errorf("Stream %d: Got %d messages, want %d", streamID,
						received, messagesPerStream)
				}
			}(i)
		}

		wg.Wait()

		// Collect final memory stats
		runtime.ReadMemStats(&memStats)
		b.ReportMetric(float64(memStats.TotalAlloc-startAlloc)/float64(totalMessages), "B/msg")
	}
}
