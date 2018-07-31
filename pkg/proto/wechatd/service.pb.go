// Code generated by protoc-gen-go. DO NOT EDIT.
// source: service.proto

package wechatd

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

import (
	context "golang.org/x/net/context"
	grpc "google.golang.org/grpc"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConn

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion4

// Client API for WechatdService service

type WechatdServiceClient interface {
	GetWechatSession(ctx context.Context, in *GetWechatSessionRequest, opts ...grpc.CallOption) (*GetWechatSessionResponse, error)
	GetMetathingsToken(ctx context.Context, in *GetMetathingsTokenRequest, opts ...grpc.CallOption) (*GetMetathingsTokenResponse, error)
}

type wechatdServiceClient struct {
	cc *grpc.ClientConn
}

func NewWechatdServiceClient(cc *grpc.ClientConn) WechatdServiceClient {
	return &wechatdServiceClient{cc}
}

func (c *wechatdServiceClient) GetWechatSession(ctx context.Context, in *GetWechatSessionRequest, opts ...grpc.CallOption) (*GetWechatSessionResponse, error) {
	out := new(GetWechatSessionResponse)
	err := grpc.Invoke(ctx, "/ai.metathings_wechatd.service.wechatd.WechatdService/GetWechatSession", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *wechatdServiceClient) GetMetathingsToken(ctx context.Context, in *GetMetathingsTokenRequest, opts ...grpc.CallOption) (*GetMetathingsTokenResponse, error) {
	out := new(GetMetathingsTokenResponse)
	err := grpc.Invoke(ctx, "/ai.metathings_wechatd.service.wechatd.WechatdService/GetMetathingsToken", in, out, c.cc, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Server API for WechatdService service

type WechatdServiceServer interface {
	GetWechatSession(context.Context, *GetWechatSessionRequest) (*GetWechatSessionResponse, error)
	GetMetathingsToken(context.Context, *GetMetathingsTokenRequest) (*GetMetathingsTokenResponse, error)
}

func RegisterWechatdServiceServer(s *grpc.Server, srv WechatdServiceServer) {
	s.RegisterService(&_WechatdService_serviceDesc, srv)
}

func _WechatdService_GetWechatSession_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetWechatSessionRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WechatdServiceServer).GetWechatSession(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ai.metathings_wechatd.service.wechatd.WechatdService/GetWechatSession",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WechatdServiceServer).GetWechatSession(ctx, req.(*GetWechatSessionRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _WechatdService_GetMetathingsToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetMetathingsTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(WechatdServiceServer).GetMetathingsToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/ai.metathings_wechatd.service.wechatd.WechatdService/GetMetathingsToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(WechatdServiceServer).GetMetathingsToken(ctx, req.(*GetMetathingsTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _WechatdService_serviceDesc = grpc.ServiceDesc{
	ServiceName: "ai.metathings_wechatd.service.wechatd.WechatdService",
	HandlerType: (*WechatdServiceServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetWechatSession",
			Handler:    _WechatdService_GetWechatSession_Handler,
		},
		{
			MethodName: "GetMetathingsToken",
			Handler:    _WechatdService_GetMetathingsToken_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "service.proto",
}

func init() { proto.RegisterFile("service.proto", fileDescriptor_service_cdf276acc438919e) }

var fileDescriptor_service_cdf276acc438919e = []byte{
	// 189 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0xe2, 0x2d, 0x4e, 0x2d, 0x2a,
	0xcb, 0x4c, 0x4e, 0xd5, 0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0x52, 0x4d, 0xcc, 0xd4, 0xcb, 0x4d,
	0x2d, 0x49, 0x2c, 0xc9, 0xc8, 0xcc, 0x4b, 0x2f, 0x8e, 0x2f, 0x4f, 0x4d, 0xce, 0x48, 0x2c, 0x49,
	0xd1, 0x83, 0x29, 0x82, 0xf2, 0xa5, 0x24, 0xd2, 0x53, 0x4b, 0xa0, 0x92, 0xf1, 0xc5, 0xa9, 0xc5,
	0xc5, 0x99, 0xf9, 0x79, 0x10, 0x03, 0xa4, 0xa4, 0x40, 0x32, 0x48, 0x26, 0x94, 0xe4, 0x67, 0xa7,
	0x42, 0xe5, 0x8c, 0x8e, 0x31, 0x71, 0xf1, 0x85, 0x43, 0x4c, 0x08, 0x86, 0x18, 0x28, 0x34, 0x95,
	0x91, 0x4b, 0xc0, 0x3d, 0xb5, 0x04, 0x22, 0x1a, 0x0c, 0x31, 0x49, 0xc8, 0x4e, 0x8f, 0x28, 0x57,
	0xe8, 0xa1, 0x6b, 0x0c, 0x4a, 0x2d, 0x2c, 0x4d, 0x2d, 0x2e, 0x91, 0xb2, 0x27, 0x5b, 0x7f, 0x71,
	0x41, 0x7e, 0x5e, 0x71, 0xaa, 0x12, 0x83, 0xd0, 0x6c, 0x46, 0x2e, 0x21, 0xf7, 0xd4, 0x12, 0x5f,
	0xb8, 0x21, 0x21, 0x20, 0x7f, 0x08, 0x39, 0x10, 0x6f, 0x32, 0x9a, 0x56, 0x98, 0xdb, 0x1c, 0x29,
	0x30, 0x01, 0xe6, 0x3a, 0x27, 0xce, 0x28, 0x76, 0xa8, 0xba, 0x24, 0x36, 0x70, 0xd0, 0x1a, 0x03,
	0x02, 0x00, 0x00, 0xff, 0xff, 0x86, 0x39, 0xa5, 0x26, 0xc8, 0x01, 0x00, 0x00,
}