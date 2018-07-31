// Code generated by protoc-gen-go. DO NOT EDIT.
// source: get_metathings_token.proto

package wechatd

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import wrappers "github.com/golang/protobuf/ptypes/wrappers"
import _ "github.com/mwitkow/go-proto-validators"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type GetMetathingsTokenRequest struct {
	OpenId               *wrappers.StringValue `protobuf:"bytes,1,opt,name=open_id,json=openId" json:"open_id,omitempty"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *GetMetathingsTokenRequest) Reset()         { *m = GetMetathingsTokenRequest{} }
func (m *GetMetathingsTokenRequest) String() string { return proto.CompactTextString(m) }
func (*GetMetathingsTokenRequest) ProtoMessage()    {}
func (*GetMetathingsTokenRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_get_metathings_token_f5258e94fdc76201, []int{0}
}
func (m *GetMetathingsTokenRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetMetathingsTokenRequest.Unmarshal(m, b)
}
func (m *GetMetathingsTokenRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetMetathingsTokenRequest.Marshal(b, m, deterministic)
}
func (dst *GetMetathingsTokenRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetMetathingsTokenRequest.Merge(dst, src)
}
func (m *GetMetathingsTokenRequest) XXX_Size() int {
	return xxx_messageInfo_GetMetathingsTokenRequest.Size(m)
}
func (m *GetMetathingsTokenRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetMetathingsTokenRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetMetathingsTokenRequest proto.InternalMessageInfo

func (m *GetMetathingsTokenRequest) GetOpenId() *wrappers.StringValue {
	if m != nil {
		return m.OpenId
	}
	return nil
}

type GetMetathingsTokenResponse struct {
	Token                string   `protobuf:"bytes,1,opt,name=token" json:"token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetMetathingsTokenResponse) Reset()         { *m = GetMetathingsTokenResponse{} }
func (m *GetMetathingsTokenResponse) String() string { return proto.CompactTextString(m) }
func (*GetMetathingsTokenResponse) ProtoMessage()    {}
func (*GetMetathingsTokenResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_get_metathings_token_f5258e94fdc76201, []int{1}
}
func (m *GetMetathingsTokenResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetMetathingsTokenResponse.Unmarshal(m, b)
}
func (m *GetMetathingsTokenResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetMetathingsTokenResponse.Marshal(b, m, deterministic)
}
func (dst *GetMetathingsTokenResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetMetathingsTokenResponse.Merge(dst, src)
}
func (m *GetMetathingsTokenResponse) XXX_Size() int {
	return xxx_messageInfo_GetMetathingsTokenResponse.Size(m)
}
func (m *GetMetathingsTokenResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GetMetathingsTokenResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GetMetathingsTokenResponse proto.InternalMessageInfo

func (m *GetMetathingsTokenResponse) GetToken() string {
	if m != nil {
		return m.Token
	}
	return ""
}

func init() {
	proto.RegisterType((*GetMetathingsTokenRequest)(nil), "ai.metathings_wechatd.service.wechatd.GetMetathingsTokenRequest")
	proto.RegisterType((*GetMetathingsTokenResponse)(nil), "ai.metathings_wechatd.service.wechatd.GetMetathingsTokenResponse")
}

func init() {
	proto.RegisterFile("get_metathings_token.proto", fileDescriptor_get_metathings_token_f5258e94fdc76201)
}

var fileDescriptor_get_metathings_token_f5258e94fdc76201 = []byte{
	// 247 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x90, 0x31, 0x4b, 0xc4, 0x40,
	0x10, 0x85, 0x89, 0x60, 0x8e, 0x5b, 0xbb, 0x60, 0xa1, 0x41, 0xf4, 0x38, 0x10, 0x6c, 0x6e, 0x17,
	0x4e, 0xb0, 0xb3, 0xb9, 0x46, 0x2c, 0x6c, 0xa2, 0x58, 0x5c, 0x13, 0x36, 0xc9, 0xb8, 0x59, 0x2e,
	0xd9, 0x59, 0x77, 0x27, 0x97, 0x9f, 0x2b, 0xf8, 0x4b, 0xe4, 0x76, 0xcf, 0x60, 0x61, 0x37, 0x8f,
	0xc7, 0x7b, 0xf3, 0xcd, 0xb0, 0x5c, 0x01, 0x95, 0x3d, 0x90, 0xa4, 0x56, 0x1b, 0xe5, 0x4b, 0xc2,
	0x1d, 0x18, 0x6e, 0x1d, 0x12, 0x66, 0xb7, 0x52, 0xf3, 0x3f, 0xd6, 0x08, 0x75, 0x2b, 0xa9, 0xe1,
	0x1e, 0xdc, 0x5e, 0xd7, 0xc0, 0x8f, 0x3a, 0xbf, 0x56, 0x88, 0xaa, 0x03, 0x11, 0x42, 0xd5, 0xf0,
	0x21, 0x46, 0x27, 0xad, 0x05, 0xe7, 0x63, 0x4d, 0xfe, 0xa0, 0x34, 0xb5, 0x43, 0xc5, 0x6b, 0xec,
	0x45, 0x3f, 0x6a, 0xda, 0xe1, 0x28, 0x14, 0xae, 0x82, 0xb9, 0xda, 0xcb, 0x4e, 0x37, 0x92, 0xd0,
	0x79, 0x31, 0x8d, 0x31, 0xb7, 0xdc, 0xb2, 0xcb, 0x27, 0xa0, 0x97, 0x09, 0xe0, 0xed, 0x80, 0x56,
	0xc0, 0xe7, 0x00, 0x9e, 0xb2, 0x47, 0x36, 0x43, 0x0b, 0xa6, 0xd4, 0xcd, 0x45, 0xb2, 0x48, 0xee,
	0xce, 0xd6, 0x57, 0x3c, 0x62, 0xf0, 0x5f, 0x0c, 0xfe, 0x4a, 0x4e, 0x1b, 0xf5, 0x2e, 0xbb, 0x01,
	0x36, 0xe9, 0xf7, 0xd7, 0xcd, 0xc9, 0x22, 0x29, 0xd2, 0x43, 0xe8, 0xb9, 0x59, 0xae, 0x59, 0xfe,
	0x5f, 0xb7, 0xb7, 0x68, 0x3c, 0x64, 0xe7, 0xec, 0x34, 0xfc, 0x21, 0x54, 0xcf, 0x8b, 0x28, 0x36,
	0xf3, 0xed, 0xec, 0x78, 0x72, 0x95, 0x86, 0x25, 0xf7, 0x3f, 0x01, 0x00, 0x00, 0xff, 0xff, 0x4c,
	0x7c, 0xa5, 0x56, 0x3e, 0x01, 0x00, 0x00,
}
