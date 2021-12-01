package main

import (
	"context"
	"github.com/antisanyatariya/coursework/global"
	"github.com/antisanyatariya/coursework/proto"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"testing"
)

func Test_authServer_Login(t *testing.T) {
	// Подключаемся к тестовой базе данных
	global.ConnectToTestDB()
	// Возьмём пароль "example", закодируем его, и добавить в базу данных пользователя
	pw, _ := bcrypt.GenerateFromPassword([]byte("example"), bcrypt.DefaultCost)
	global.DB.Collection("user").InsertOne(context.Background(), global.User{ID: primitive.NewObjectID(), Email: "test@gmail.com", Username: "Alexandr", Password: string(pw)})
	// Определим сервер ???
	server := authServer{}

	// Передаём корректные данные в метод Login. Ошибки быть не должно
	_, err := server.Login(context.Background(), &proto.LoginRequest{Login: "test@gmail.com", Password: "example"})
	if err != nil {
		t.Error("Была возвращена ошибка: ", err.Error())
	}
	// Передаём некорректный логин в метод Login. Должна быть ошибка "Пользователь не был найден"
	_, err = server.Login(context.Background(), &proto.LoginRequest{Login: "bla_bla_bla", Password: "example"})
	if err != nil {
		t.Error("Была возвращена ошибка: ", err.Error())
	}
	// Передаём некорректный пароль в метод Login. Должна быть ошибка "Пароль неверный"
	_, err = server.Login(context.Background(), &proto.LoginRequest{Login: "test@gmail.com", Password: "something"})
	if err != nil {
		t.Error("Была возвращена ошибка: ", err.Error())
	}
}
