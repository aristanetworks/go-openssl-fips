package fipstls_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	pb "github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils/proto"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	"github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

func TestDialTimeout(t *testing.T) {
	defer testutils.LeakCheckLSAN(t)
	// Create and start the server directly
	ts := testutils.NewServer(t)
	defer ts.Close()

	u, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}

	d, err := fipstls.NewDialer(
		fipstls.NewCtx(fipstls.WithCaFile(ts.CaFile)),
		fipstls.WithConnTracingEnabled(),
	)
	if err != nil {
		t.Fatal(err)
	}

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

func TestDialError(t *testing.T) {
	defer testutils.LeakCheckLSAN(t)

	// This should error
	_, err := fipstls.NewDialer(
		nil,
		fipstls.WithConnTracingEnabled(),
	)
	if err == nil {
		t.Fatalf("Expected %v error but got nil", fipstls.ErrEmptyContext)
	}
	if err != nil && errors.Is(err, fipstls.ErrEmptyContext) {
		t.Logf("Got %v", fipstls.ErrEmptyContext)
	}
}

// First, let's define a test server that implements streaming
type testServer struct {
	pb.UnimplementedYourServiceServer
	// Add test tracking fields if needed
	receivedMessages []string
	t                *testing.T
}

// Server streaming implementation
func (s *testServer) ServerStream(req *pb.Request, stream pb.YourService_ServerStreamServer) error {
	s.t.Logf("ServerStream recv: %+v", req)
	messages := []string{"msg1", "msg2", "msg3"}
	for _, msg := range messages {
		if err := stream.Send(&pb.Response{Message: msg}); err != nil {
			return err
		}
	}
	return nil
}

// Client streaming implementation
func (s *testServer) ClientStream(stream pb.YourService_ClientStreamServer) error {
	s.t.Log("ClientStream recv")
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
func (s *testServer) BidiStream(stream pb.YourService_BidiStreamServer) error {
	s.t.Log("BidiStream recv")
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

func TestFIPSTLSDialerWithTLS(t *testing.T) {
	t.Skip("Skipping...")
	cert, err := tls.LoadX509KeyPair("./internal/testutils/certs/cert.pem", "./internal/testutils/certs/key.pem")
	if err != nil {
		t.Fatalf("failed to load test certs: %v", err)
	}
	lis, err := tls.Listen("tcp", "localhost:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
	})
	if err != nil {
		t.Fatalf("failed to create TLS listener: %v", err)
	}
	defer lis.Close()

	s := grpc.NewServer(
		grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
		})),
		grpc.UnaryInterceptor(func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
			t.Logf("Server unary interceptor: %v", info.FullMethod)
			return handler(ctx, req)
		}),
		// Add stream interceptor
		grpc.StreamInterceptor(func(srv interface{}, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
			t.Logf("Server stream interceptor: %v, streaming: %v", info.FullMethod, info.IsServerStream)
			return handler(srv, ss)
		}),
	)

	srv := &testServer{t: t}
	pb.RegisterYourServiceServer(s, srv)
	go s.Serve(lis)
	defer s.Stop()

	addr := lis.Addr().String()
	t.Logf("Server listening on: %s", addr)

	dialFn, err := fipstls.NewGrpcDialFn(
		fipstls.NewCtx(fipstls.WithCaFile("./internal/testutils/certs/cert.pem")),
		fipstls.WithDialTimeout(10*time.Second),
		fipstls.WithConnTracingEnabled())
	if err != nil {
		t.Fatalf("Failed to create grpc dialer: %v", err)
	}

	// t.Log("Attempting raw connection...")
	// rawConn, err := dialFn(context.Background(), addr)
	// if err != nil {
	// 	t.Fatalf("Direct dial failed: %v", err)
	// }
	// rawConn.Close()
	// t.Log("Raw connection succeeded")

	conn, err := grpc.NewClient(
		addr,
		grpc.WithContextDialer(dialFn),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithUnaryInterceptor(func(
			ctx context.Context,
			method string,
			req, reply interface{},
			cc *grpc.ClientConn,
			invoker grpc.UnaryInvoker,
			opts ...grpc.CallOption) error {
			t.Logf("Client sending request: %v", method)
			return invoker(ctx, method, req, reply, cc, opts...)
		}),
		grpc.WithStreamInterceptor(func(
			ctx context.Context,
			desc *grpc.StreamDesc,
			cc *grpc.ClientConn,
			method string,
			streamer grpc.Streamer,
			opts ...grpc.CallOption) (grpc.ClientStream, error) {
			t.Logf("Client stream interceptor: %v, server-stream: %v", method, desc.ServerStreams)
			return streamer(ctx, desc, cc, method, opts...)
		}),
	)
	if err != nil {
		t.Fatalf("creating gRPC new client failed: %v", err)
	}
	defer conn.Close()

	client := pb.NewYourServiceClient(conn)
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

		if !reflect.DeepEqual(resp.GetMessage(), messages) {
			t.Errorf("Server received %v, want %v", resp.GetMessage(), messages)
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
				expected := "Echo: "
				if resp.Message != expected {
					t.Errorf("Got message %q, want %q", resp.Message, expected)
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
