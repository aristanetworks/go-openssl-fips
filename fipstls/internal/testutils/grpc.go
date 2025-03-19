package testutils

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"testing"

	"github.com/aristanetworks/go-openssl-fips/fipstls"
	pb "github.com/aristanetworks/go-openssl-fips/fipstls/internal/testutils/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/stats"
)

type GrpcTestServer struct {
	pb.UnimplementedTestServiceServer
	// Add test tracking fields if needed
	receivedMessages []string
	t                testing.TB
}

// Server streaming implementation
func (s *GrpcTestServer) ServerStream(req *pb.Request, stream pb.TestService_ServerStreamServer) error {
	messages := []string{"msg1", "msg2", "msg3"}
	for _, msg := range messages {
		if err := stream.Send(&pb.Response{Message: msg}); err != nil {
			return err
		}
	}
	return nil
}

// Client streaming implementation
func (s *GrpcTestServer) ClientStream(stream pb.TestService_ClientStreamServer) error {
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
func (s *GrpcTestServer) BidiStream(stream pb.TestService_BidiStreamServer) error {
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

type GrpcStatsHandler struct {
	t testing.TB
}

func (h *GrpcStatsHandler) TagConn(ctx context.Context, info *stats.ConnTagInfo) context.Context {
	h.t.Logf("ConnTagInfo: %+v", info)
	return ctx
}

func (h *GrpcStatsHandler) HandleConn(ctx context.Context, s stats.ConnStats) {
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
func (h *GrpcStatsHandler) TagRPC(ctx context.Context, s *stats.RPCTagInfo) context.Context {
	return ctx
}

// HandleRPC processes the RPC stats.
func (h *GrpcStatsHandler) HandleRPC(ctx context.Context, s stats.RPCStats) {
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

func NewGrpcTestServer(b testing.TB) (net.Listener, func()) {
	cert, err := tls.LoadX509KeyPair(CertPath,
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
		grpc.StatsHandler(&GrpcStatsHandler{t: b}),
	)
	srv := &GrpcTestServer{t: b}
	pb.RegisterTestServiceServer(s, srv)
	go s.Serve(lis)
	return lis, func() {
		s.Stop()
		lis.Close()
	}
}

func NewDialOpts(b testing.TB, useNetDial bool, fipsDialOpts ...fipstls.DialOption) []grpc.DialOption {
	var clientOpts []grpc.DialOption
	if useNetDial {
		b.Log("Running tests with net.Dialer")
		creds := credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		})
		clientOpts = []grpc.DialOption{grpc.WithTransportCredentials(creds)}
	} else {
		b.Log("Running tests with fipstls.Dialer")
		dialFn := fipstls.NewDialContext(
			&fipstls.Config{CaFile: CertPath},
			fipsDialOpts...)
		clientOpts = []grpc.DialOption{
			grpc.WithContextDialer(dialFn),
			grpc.WithTransportCredentials(insecure.NewCredentials()),
		}
	}
	return clientOpts
}

// NewGrpcTestClientServer creates a test server and client, returning cleanup function
func NewGrpcTestClientServer(b testing.TB, useNetDial bool, fipsDialOpts ...fipstls.DialOption) (pb.TestServiceClient, func()) {
	lis, cleanupSrv := NewGrpcTestServer(b)
	b.Log("Creating new client...")

	conn, err := grpc.NewClient(
		lis.Addr().String(),
		NewDialOpts(b, useNetDial, fipsDialOpts...)...,
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
