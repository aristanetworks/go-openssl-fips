// internal/testutils/proto/test.proto

// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             v4.25.1
// source: test.proto

package proto

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	YourService_ServerStream_FullMethodName = "/testutils.YourService/ServerStream"
	YourService_ClientStream_FullMethodName = "/testutils.YourService/ClientStream"
	YourService_BidiStream_FullMethodName   = "/testutils.YourService/BidiStream"
)

// YourServiceClient is the client API for YourService service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type YourServiceClient interface {
	// Server Streaming
	ServerStream(ctx context.Context, in *Request, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Response], error)
	// Client Streaming
	ClientStream(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[Request, Response], error)
	// Bidirectional Streaming
	BidiStream(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[Request, Response], error)
}

type yourServiceClient struct {
	cc grpc.ClientConnInterface
}

func NewYourServiceClient(cc grpc.ClientConnInterface) YourServiceClient {
	return &yourServiceClient{cc}
}

func (c *yourServiceClient) ServerStream(ctx context.Context, in *Request, opts ...grpc.CallOption) (grpc.ServerStreamingClient[Response], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &YourService_ServiceDesc.Streams[0], YourService_ServerStream_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[Request, Response]{ClientStream: stream}
	if err := x.ClientStream.SendMsg(in); err != nil {
		return nil, err
	}
	if err := x.ClientStream.CloseSend(); err != nil {
		return nil, err
	}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type YourService_ServerStreamClient = grpc.ServerStreamingClient[Response]

func (c *yourServiceClient) ClientStream(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[Request, Response], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &YourService_ServiceDesc.Streams[1], YourService_ClientStream_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[Request, Response]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type YourService_ClientStreamClient = grpc.ClientStreamingClient[Request, Response]

func (c *yourServiceClient) BidiStream(ctx context.Context, opts ...grpc.CallOption) (grpc.BidiStreamingClient[Request, Response], error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	stream, err := c.cc.NewStream(ctx, &YourService_ServiceDesc.Streams[2], YourService_BidiStream_FullMethodName, cOpts...)
	if err != nil {
		return nil, err
	}
	x := &grpc.GenericClientStream[Request, Response]{ClientStream: stream}
	return x, nil
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type YourService_BidiStreamClient = grpc.BidiStreamingClient[Request, Response]

// YourServiceServer is the server API for YourService service.
// All implementations must embed UnimplementedYourServiceServer
// for forward compatibility.
type YourServiceServer interface {
	// Server Streaming
	ServerStream(*Request, grpc.ServerStreamingServer[Response]) error
	// Client Streaming
	ClientStream(grpc.ClientStreamingServer[Request, Response]) error
	// Bidirectional Streaming
	BidiStream(grpc.BidiStreamingServer[Request, Response]) error
	mustEmbedUnimplementedYourServiceServer()
}

// UnimplementedYourServiceServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedYourServiceServer struct{}

func (UnimplementedYourServiceServer) ServerStream(*Request, grpc.ServerStreamingServer[Response]) error {
	return status.Errorf(codes.Unimplemented, "method ServerStream not implemented")
}
func (UnimplementedYourServiceServer) ClientStream(grpc.ClientStreamingServer[Request, Response]) error {
	return status.Errorf(codes.Unimplemented, "method ClientStream not implemented")
}
func (UnimplementedYourServiceServer) BidiStream(grpc.BidiStreamingServer[Request, Response]) error {
	return status.Errorf(codes.Unimplemented, "method BidiStream not implemented")
}
func (UnimplementedYourServiceServer) mustEmbedUnimplementedYourServiceServer() {}
func (UnimplementedYourServiceServer) testEmbeddedByValue()                     {}

// UnsafeYourServiceServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to YourServiceServer will
// result in compilation errors.
type UnsafeYourServiceServer interface {
	mustEmbedUnimplementedYourServiceServer()
}

func RegisterYourServiceServer(s grpc.ServiceRegistrar, srv YourServiceServer) {
	// If the following call pancis, it indicates UnimplementedYourServiceServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&YourService_ServiceDesc, srv)
}

func _YourService_ServerStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	m := new(Request)
	if err := stream.RecvMsg(m); err != nil {
		return err
	}
	return srv.(YourServiceServer).ServerStream(m, &grpc.GenericServerStream[Request, Response]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type YourService_ServerStreamServer = grpc.ServerStreamingServer[Response]

func _YourService_ClientStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(YourServiceServer).ClientStream(&grpc.GenericServerStream[Request, Response]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type YourService_ClientStreamServer = grpc.ClientStreamingServer[Request, Response]

func _YourService_BidiStream_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(YourServiceServer).BidiStream(&grpc.GenericServerStream[Request, Response]{ServerStream: stream})
}

// This type alias is provided for backwards compatibility with existing code that references the prior non-generic stream type by name.
type YourService_BidiStreamServer = grpc.BidiStreamingServer[Request, Response]

// YourService_ServiceDesc is the grpc.ServiceDesc for YourService service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var YourService_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "testutils.YourService",
	HandlerType: (*YourServiceServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "ServerStream",
			Handler:       _YourService_ServerStream_Handler,
			ServerStreams: true,
		},
		{
			StreamName:    "ClientStream",
			Handler:       _YourService_ClientStream_Handler,
			ClientStreams: true,
		},
		{
			StreamName:    "BidiStream",
			Handler:       _YourService_BidiStream_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "test.proto",
}
