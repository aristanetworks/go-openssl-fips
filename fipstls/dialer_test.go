package fipstls_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/stats"

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

	opts := []fipstls.DialOption{}
	if *enableClientTrace {
		opts = append(opts, fipstls.WithConnTracingEnabled())
	}

	d := fipstls.NewDialer(
		&fipstls.Config{CaFile: ts.CaFile},
		opts...,
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

// First, let's define a test server that implements streaming
type testServer struct {
	pb.UnimplementedTestServiceServer
	// Add test tracking fields if needed
	receivedMessages []string
	t                testing.TB
}

// Server streaming implementation
func (s *testServer) ServerStream(req *pb.Request, stream pb.TestService_ServerStreamServer) error {
	messages := []string{"msg1", "msg2", "msg3"}
	for _, msg := range messages {
		if err := stream.Send(&pb.Response{Message: msg}); err != nil {
			return err
		}
	}
	return nil
}

// Client streaming implementation
func (s *testServer) ClientStream(stream pb.TestService_ClientStreamServer) error {
	s.receivedMessages = []string{} // Reset for test
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Response{
				Message: "Received all messages",
			})
		}
		if err != nil {
			return err
		}
		s.receivedMessages = append(s.receivedMessages, msg.Message)
	}
}

// Bidirectional streaming implementation
func (s *testServer) BidiStream(stream pb.TestService_BidiStreamServer) error {
	for {
		msg, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		// Echo back the message
		if err := stream.Send(&pb.Response{
			Message: "Echo: " + msg.Message,
		}); err != nil {
			return err
		}
	}
}

type StatsHandler struct {
	t testing.TB
}

func (h *StatsHandler) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	h.t.Logf("ConnTagInfo: %+v", info)
	return ctx
}

func (h *StatsHandler) HandleConn(ctx context.Context, s stats.ConnStats) {
	// Can check connection state changes
	switch s.(type) {
	case *stats.ConnBegin:
		if s.IsClient() {
			h.t.Logf("ConnBegin: %+v", s)
		}
	case *stats.ConnEnd:
		if s.IsClient() {
			h.t.Logf("ConnEnd: %+v", s)
		}
	}
}

// TagRPC can attach some information to the given context.
// The context used for the rest lifetime of the RPC will be derived from
// the returned context.
func (h *StatsHandler) TagRPC(ctx context.Context, s *stats.RPCTagInfo) context.Context {
	return ctx
}

// HandleRPC processes the RPC stats.
func (h *StatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
	switch s.(type) {
	case *stats.InHeader:
		if s.IsClient() {
			h.t.Logf("InHeader: %+v", s)
		}
	case *stats.OutHeader:
		if s.IsClient() {
			h.t.Logf("OutHeader: %+v", s)
		}
	}
}

func TestGrpcDial(t *testing.T) {
	initTest(t)
	defer testutils.LeakCheck(t)
	lis, cleanupSrv := newTestServer(t)
	defer cleanupSrv()

	addr := lis.Addr().String()
	t.Logf("Server listening on: %s", addr)

	t.Log("Creating new DialFn")
	fipsOpts := []fipstls.DialOption{}
	if *enableClientTrace {
		fipsOpts = append(fipsOpts, fipstls.WithConnTracingEnabled())
	}
	dialFn, err := fipstls.NewGrpcDialFn(
		&fipstls.Config{CaFile: "./internal/testutils/certs/cert.pem"},
		fipsOpts...)
	if err != nil {
		t.Fatalf("Failed to create grpc dialer: %v", err)
	}

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
		newClientOpts(t)...,
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
	client, cleanup := newTestClientServer(t)
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

type recorder interface {
	RecordProgress(streamID int, msgCount int, isSender bool)
	io.Closer
}

type emptyRecorder struct{}

func (emptyRecorder) RecordProgress(streamID int, msgCount int, isSender bool) {}
func (emptyRecorder) Close() error                                             { return nil }

// StreamEvent represents a progress update from a single stream.
type StreamEvent struct {
	StreamID int
	Interval int
	IsSender bool // distinguish between send/receive progress
}

// ProgressRecorder tracks and reports progress across multiple concurrent streams.
// It collects progress events from individual streams and periodically reports
// aggregated progress statistics.
type ProgressRecorder struct {
	t              testing.TB
	eventChan      chan StreamEvent
	numStreams     int
	numMessages    int
	sampleSize     int
	printTicker    *time.Ticker
	currentStats   map[int]map[int]bool // map[interval]map[streamID]received
	streamProgress sync.Map             // map[int]int - streamID -> lastRecordedInterval
	done           chan struct{}
}

// NewProgressRecorder creates a new ProgressRecorder that tracks progress
// for the specified number of streams and interval size.
//
// Parameters:
//   - numStreams: total number of streams to track
//   - intervalSize: number of messages that constitute one interval
func NewProgressRecorder(t testing.TB, numStreams, numMessages, sampleSize int, runPeriod time.Duration) recorder {
	if !*enableProgRecorder {
		return &emptyRecorder{}
	}
	pr := &ProgressRecorder{
		t:            t,
		eventChan:    make(chan StreamEvent, numStreams*2),
		numStreams:   numStreams,
		numMessages:  numMessages,
		sampleSize:   sampleSize,
		currentStats: make(map[int]map[int]bool),
		printTicker:  time.NewTicker(runPeriod),
		done:         make(chan struct{}),
	}
	go pr.run()
	return pr
}

// RecordProgress records a progress update for a specific stream.
// It only records the progress if the stream has reached a new interval.
func (pr *ProgressRecorder) RecordProgress(streamID int, msgCount int, isSender bool) {
	interval := msgCount / pr.sampleSize

	lastInterval, exists := pr.streamProgress.Load(streamID)
	if !exists || interval > lastInterval.(int) {
		pr.streamProgress.Store(streamID, interval)
		pr.eventChan <- StreamEvent{
			StreamID: streamID,
			Interval: interval,
			IsSender: isSender,
		}
	}
}

// run is the main event loop that processes incoming stream events and triggers
// periodic progress updates. It runs in its own goroutine until Close() is called.
func (pr *ProgressRecorder) run() {
	for {
		select {
		case event := <-pr.eventChan:
			if _, exists := pr.currentStats[event.Interval]; !exists {
				pr.currentStats[event.Interval] = make(map[int]bool)
			}
			pr.currentStats[event.Interval][event.StreamID] = true

		case <-pr.printTicker.C:
			pr.printProgress()

		case <-pr.done:
			pr.printTicker.Stop()
			return
		}
	}
}

// printProgress prints the current progress for all active intervals.
// It displays the percentage of streams that have completed each interval
// and cleans up completed intervals.
func (pr *ProgressRecorder) printProgress() {
	// Sort intervals for ordered printing
	var intervals []int
	for interval := range pr.currentStats {
		intervals = append(intervals, interval)
	}
	sort.Ints(intervals)

	for _, interval := range intervals {
		streams := pr.currentStats[interval]
		count := len(streams)
		if count == pr.numStreams {
			msgsDone := float64((interval+1)*pr.sampleSize) / float64(pr.numMessages) * 100
			msgsLeft := math.Round(((1 - (msgsDone / 100)) * float64(pr.numMessages)))
			pr.t.Logf("interval%2d: %2.0f%% per-stream messages processed. %7d messages left.\n",
				interval,
				msgsDone,
				int(msgsLeft),
			)
			delete(pr.currentStats, interval)
		} else {
			percentage := float64(count) / float64(pr.numStreams) * 100
			pr.t.Logf("interval%2d: %2.0f%% of streams done processing...\n", interval, percentage)
		}
	}
}

func (pr *ProgressRecorder) Close() error {
	close(pr.done)
	return nil
}

func TestGrpcBidiStress(t *testing.T) {
	initTest(t)
	if !*runStressTest {
		t.Skip("Skipping... to run this, use '-stresstest'")
	}
	defer testutils.LeakCheck(t)
	client, cleanup := newTestClientServer(t)
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

		r := NewProgressRecorder(t, numStreams, numMessages, sampleSize, 50*time.Millisecond)
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
	client, cleanup := newTestClientServer(b)
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
		r := NewProgressRecorder(b, numStreams, totalMessages, sampleSize, 500*time.Millisecond)
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

func newTestServer(b testing.TB) (net.Listener, func()) {
	cert, err := tls.LoadX509KeyPair("./internal/testutils/certs/cert.pem",
		"./internal/testutils/certs/key.pem")
	if err != nil {
		b.Fatalf("failed to load test certs: %v", err)
	}
	b.Logf("Creating new TCP listener...")
	lis, err := net.Listen("tcp", "localhost:0")
	if err != nil {
		b.Fatalf("failed to create TLS listener: %v", err)
	}

	b.Logf("Creating new grpc TLS server...")
	s := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h2"},
			GetConfigForClient: func(info *tls.ClientHelloInfo) (*tls.Config, error) {
				b.Logf("[Server] TLS ClientHello from %v: Version=%x, CipherSuites=%v, LocalAddr=%s",
					info.Conn.RemoteAddr(),
					info.SupportedVersions,
					info.CipherSuites,
					info.Conn.LocalAddr())
				b.Logf("Server got ClientHello with ALPN protos: %v", info.SupportedProtos)
				return nil, nil // return nil to use default config
			},
		})),
		grpc.StatsHandler(&StatsHandler{t: b}),
	)
	srv := &testServer{t: b}
	pb.RegisterTestServiceServer(s, srv)
	go s.Serve(lis)
	return lis, func() {
		s.Stop()
		lis.Close()
	}
}

func newClientOpts(b testing.TB) []grpc.DialOption {
	var clientOpts []grpc.DialOption
	if *useNetDial {
		b.Log("Running tests with net.Dialer")
		creds := credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		clientOpts = []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	} else {
		b.Log("Running tests with fipstls.Dialer")
		dialFn, err := fipstls.NewGrpcDialFn(
			&fipstls.Config{CaFile: "./internal/testutils/certs/cert.pem"},
			getDialOpts()...)
		if err != nil {
			b.Fatalf("Failed to create grpc dialer: %v", err)
		}
		clientOpts = []grpc.DialOption{
			grpc.WithContextDialer(dialFn),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}
	}
	return clientOpts
}

// newTestClientServer creates a test server and client, returning cleanup function
func newTestClientServer(b testing.TB) (pb.TestServiceClient, func()) {
	lis, cleanupSrv := newTestServer(b)
	b.Log("Creating new client...")

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		newClientOpts(b)...,
	)
	if err != nil {
		b.Fatalf("failed to create client: %v", err)
	}
	cleanup := func() {
		conn.Close()
		cleanupSrv()
	}
	return pb.NewTestServiceClient(conn), cleanup
}
