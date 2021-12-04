// Code generated by protoc-gen-go-grpc. DO NOT EDIT.

package proto

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

// AuthServicesClient is the client API for AuthServices service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type AuthServicesClient interface {
	Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*AuthResponse, error)
	Signup(ctx context.Context, in *SignupRequest, opts ...grpc.CallOption) (*AuthResponse, error)
	UsernameUsed(ctx context.Context, in *UsernameUsedRequest, opts ...grpc.CallOption) (*UsedResponse, error)
	EmailUsed(ctx context.Context, in *EmailUsedRequest, opts ...grpc.CallOption) (*UsedResponse, error)
}

type authServicesClient struct {
	cc grpc.ClientConnInterface
}

func NewAuthServicesClient(cc grpc.ClientConnInterface) AuthServicesClient {
	return &authServicesClient{cc}
}

func (c *authServicesClient) Login(ctx context.Context, in *LoginRequest, opts ...grpc.CallOption) (*AuthResponse, error) {
	out := new(AuthResponse)
	err := c.cc.Invoke(ctx, "/proto.AuthServices/Login", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServicesClient) Signup(ctx context.Context, in *SignupRequest, opts ...grpc.CallOption) (*AuthResponse, error) {
	out := new(AuthResponse)
	err := c.cc.Invoke(ctx, "/proto.AuthServices/Signup", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServicesClient) UsernameUsed(ctx context.Context, in *UsernameUsedRequest, opts ...grpc.CallOption) (*UsedResponse, error) {
	out := new(UsedResponse)
	err := c.cc.Invoke(ctx, "/proto.AuthServices/UsernameUsed", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *authServicesClient) EmailUsed(ctx context.Context, in *EmailUsedRequest, opts ...grpc.CallOption) (*UsedResponse, error) {
	out := new(UsedResponse)
	err := c.cc.Invoke(ctx, "/proto.AuthServices/EmailUsed", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// AuthServicesServer is the server API for AuthServices service.
// All implementations must embed UnimplementedAuthServicesServer
// for forward compatibility
type AuthServicesServer interface {
	Login(context.Context, *LoginRequest) (*AuthResponse, error)
	Signup(context.Context, *SignupRequest) (*AuthResponse, error)
	UsernameUsed(context.Context, *UsernameUsedRequest) (*UsedResponse, error)
	EmailUsed(context.Context, *EmailUsedRequest) (*UsedResponse, error)
	//mustEmbedUnimplementedAuthServicesServer()
}

// UnimplementedAuthServicesServer must be embedded to have forward compatible implementations.
type UnimplementedAuthServicesServer struct {
}

func (UnimplementedAuthServicesServer) Login(context.Context, *LoginRequest) (*AuthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Login not implemented")
}
func (UnimplementedAuthServicesServer) Signup(context.Context, *SignupRequest) (*AuthResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method Signup not implemented")
}
func (UnimplementedAuthServicesServer) UsernameUsed(context.Context, *UsernameUsedRequest) (*UsedResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UsernameUsed not implemented")
}
func (UnimplementedAuthServicesServer) EmailUsed(context.Context, *EmailUsedRequest) (*UsedResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method EmailUsed not implemented")
}
func (UnimplementedAuthServicesServer) mustEmbedUnimplementedAuthServicesServer() {}

// UnsafeAuthServicesServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to AuthServicesServer will
// result in compilation errors.
type UnsafeAuthServicesServer interface {
	mustEmbedUnimplementedAuthServicesServer()
}

func RegisterAuthServicesServer(s grpc.ServiceRegistrar, srv AuthServicesServer) {
	s.RegisterService(&AuthServices_ServiceDesc, srv)
}

func _AuthServices_Login_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(LoginRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServicesServer).Login(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.AuthServices/Login",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServicesServer).Login(ctx, req.(*LoginRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthServices_Signup_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignupRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServicesServer).Signup(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.AuthServices/Signup",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServicesServer).Signup(ctx, req.(*SignupRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthServices_UsernameUsed_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UsernameUsedRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServicesServer).UsernameUsed(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.AuthServices/UsernameUsed",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServicesServer).UsernameUsed(ctx, req.(*UsernameUsedRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _AuthServices_EmailUsed_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(EmailUsedRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(AuthServicesServer).EmailUsed(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/proto.AuthServices/EmailUsed",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(AuthServicesServer).EmailUsed(ctx, req.(*EmailUsedRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// AuthServices_ServiceDesc is the grpc.ServiceDesc for AuthServices service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var AuthServices_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "proto.AuthServices",
	HandlerType: (*AuthServicesServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "Login",
			Handler:    _AuthServices_Login_Handler,
		},
		{
			MethodName: "Signup",
			Handler:    _AuthServices_Signup_Handler,
		},
		{
			MethodName: "UsernameUsed",
			Handler:    _AuthServices_UsernameUsed_Handler,
		},
		{
			MethodName: "EmailUsed",
			Handler:    _AuthServices_EmailUsed_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "services.proto",
}
