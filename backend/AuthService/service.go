package main

import (
	"context"
	"errors"
	"github.com/antisanyatariya/coursework/global"
	"github.com/antisanyatariya/coursework/proto"
	"go.mongodb.org/mongo-driver/bson"
	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"log"
	"net"
	"time"
)

type authServer struct{}

func (authServer) Login(_ context.Context, in *proto.LoginRequest) (*proto.AuthResponse, error) {
	login, password := in.GetLogin(), in.GetPassword()
	ctx, cancel := global.NewDBContext(5 * time.Second)
	defer cancel()
	var user global.User
	global.DB.Collection("user").FindOne(ctx, bson.M{"$or": []bson.M{bson.M{"username": login}, bson.M{"email": login}}}).Decode(&user)
	if user == global.NilUser { // важно как происходит сравнение
		return &proto.AuthResponse{}, errors.New("Пользователь не был найден")
	}
	if bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)) != nil {
		return &proto.AuthResponse{}, errors.New("Пароль неверный")
	}
	return &proto.AuthResponse{Token: user.GetToken()}, nil
}

func main() {
	server := grpc.NewServer()
	proto.RegisterAuthServicesServer(server, authServer{})
	listener, err := net.Listen("tcp", ":5000")
	if err != nil {
		log.Fatal("Error creating listener: ", err.Error())
	}
	server.Serve(listener)
}
