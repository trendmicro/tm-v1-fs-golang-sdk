// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v4.24.4
// source: scan.proto

package base

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// ScanClient is the client API for Scan service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type ScanClient interface {
	Run(ctx context.Context, opts ...grpc.CallOption) (Scan_RunClient, error)
}

type scanClient struct {
	cc grpc.ClientConnInterface
}

func NewScanClient(cc grpc.ClientConnInterface) ScanClient {
	return &scanClient{cc}
}

func (c *scanClient) Run(ctx context.Context, opts ...grpc.CallOption) (Scan_RunClient, error) {
	stream, err := c.cc.NewStream(ctx, &Scan_ServiceDesc.Streams[0], "/amaas.scan.v1.Scan/Run", opts...)
	if err != nil {
		return nil, err
	}
	x := &scanRunClient{stream}
	return x, nil
}

type Scan_RunClient interface {
	Send(*C2S) error
	Recv() (*S2C, error)
	grpc.ClientStream
}

type scanRunClient struct {
	grpc.ClientStream
}

func (x *scanRunClient) Send(m *C2S) error {
	return x.ClientStream.SendMsg(m)
}

func (x *scanRunClient) Recv() (*S2C, error) {
	m := new(S2C)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ScanServer is the server API for Scan service.
// All implementations must embed UnimplementedScanServer
// for forward compatibility
type ScanServer interface {
	Run(Scan_RunServer) error
	mustEmbedUnimplementedScanServer()
}

// UnimplementedScanServer must be embedded to have forward compatible implementations.
type UnimplementedScanServer struct {
}

func (UnimplementedScanServer) Run(Scan_RunServer) error {
	return status.Errorf(codes.Unimplemented, "method Run not implemented")
}
func (UnimplementedScanServer) mustEmbedUnimplementedScanServer() {}

// UnsafeScanServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to ScanServer will
// result in compilation errors.
type UnsafeScanServer interface {
	mustEmbedUnimplementedScanServer()
}

func RegisterScanServer(s grpc.ServiceRegistrar, srv ScanServer) {
	s.RegisterService(&Scan_ServiceDesc, srv)
}

func _Scan_Run_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(ScanServer).Run(&scanRunServer{stream})
}

type Scan_RunServer interface {
	Send(*S2C) error
	Recv() (*C2S, error)
	grpc.ServerStream
}

type scanRunServer struct {
	grpc.ServerStream
}

func (x *scanRunServer) Send(m *S2C) error {
	return x.ServerStream.SendMsg(m)
}

func (x *scanRunServer) Recv() (*C2S, error) {
	m := new(C2S)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// Scan_ServiceDesc is the grpc.ServiceDesc for Scan service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var Scan_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "amaas.scan.v1.Scan",
	HandlerType: (*ScanServer)(nil),
	Methods:     []grpc.MethodDesc{},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "Run",
			Handler:       _Scan_Run_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "scan.proto",
}
