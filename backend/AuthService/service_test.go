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
	// Возьмём пароль "example", закодируем его, и добавим базу данных пользователя для тестирования
	pw, _ := bcrypt.GenerateFromPassword([]byte("example"), bcrypt.DefaultCost)
	global.DB.Collection("user").InsertOne(context.Background(), global.User{ID: primitive.NewObjectID(), Email: "user@mail.com", Username: "alexandr", Password: string(pw)})

	server := authServer{}

	// [тест 1]: Тест при котором данные корректны. ( Для авторизации в качестве логина передаём адрес электронной почты, но можно и юзернейм)
	_, err := server.Login(context.Background(), &proto.LoginRequest{Login: "user@mail.com", Password: "example"})
	if err != nil {
		t.Error("1:  Ошибка: ", err.Error())
	}

	// [тест 2]: Тест при котором некорректный логин
	_, err = server.Login(context.Background(), &proto.LoginRequest{Login: "test@mail.com", Password: "example"})
	if err.Error() != "Пользователь не найден" {
		t.Error("2:  Ошибка: ", err.Error())
	}

	// [тест 3]: Тест при котором некорректный пароль
	_, err = server.Login(context.Background(), &proto.LoginRequest{Login: "user@mail.com", Password: "123"})
	if err.Error() != "Неверный пароль" {
		t.Error("3: Ошибка: ", err.Error())
	}
}

func Test_authServer_UsernameUsed(t *testing.T) {
	// Подключаемся к тестовой базе данных
	global.ConnectToTestDB()
	// Добавляем пользователя для тестирования
	global.DB.Collection("user").InsertOne(context.Background(), global.User{Username: "alexandr"})

	server := authServer{}

	// [тест 1]: Тест при котором в базе данных пользователя с таким юзернеймом еще не существует
	//           Нет смысла проверять ошибку err, т.к. в самом методе всегда возвращается nil
	res, _ := server.UsernameUsed(context.Background(), &proto.UsernameUsedRequest{Username: "oleg"})
	if res.GetUsed() {
		t.Error("1: Неверный результат")
	}

	// [тест 2]: Тест при котором в базе данных пользователь с таким юзернеймом уже существует
	//           Нет смысла проверять ошибку err, т.к. в самом методе всегда возвращается nil
	res, _ = server.UsernameUsed(context.Background(), &proto.UsernameUsedRequest{Username: "alexandr"})
	if !res.GetUsed() {
		t.Error("2: Неверный результат")
	}
}

func Test_authServer_EmailUsed(t *testing.T) {
	// Подключаемся к тестовой базе данных
	global.ConnectToTestDB()
	// Добавляем пользователя для тестирования
	global.DB.Collection("user").InsertOne(context.Background(), global.User{Email: "user@mail.com"})

	server := authServer{}

	// [тест 1]: Тест при котором в базе данных пользователя с таким именем электронной почты еще не существует
	//           Нет смысла проверять ошибку err, т.к. в самом методе всегда возвращается nil
	res, _ := server.EmailUsed(context.Background(), &proto.EmailUsedRequest{Email: "test@mail.com"})
	if res.GetUsed() {
		t.Error("1: Неверный результат")
	}

	// [тест 2]: Тест при котором в базе данных пользователь с таким именем электронной почты уже существует
	//           Нет смысла проверять ошибку err, т.к. в самом методе всегда возвращается nil
	res, _ = server.EmailUsed(context.Background(), &proto.EmailUsedRequest{Email: "user@mail.com"})
	if !res.GetUsed() {
		t.Error("2: Неверный результат")
	}

}

func Test_authServer_Signup(t *testing.T) {
	// Подключаемся к тестовой базе данных
	global.ConnectToTestDB()
	// Добавляем пользователя для тестирования
	global.DB.Collection("user").InsertOne(context.Background(), global.User{Username: "alexandr", Email: "user@mail.com"})

	server := authServer{}

	// [тест 1]: Тест в котором при регистрации пользователя уже существует пользователь с таким юзернеймом
	_, err := server.Signup(context.Background(), &proto.SignupRequest{Username: "alexandr", Email: "example@mail.com", Password: "examplestring"})
	if err.Error() != "Такое имя пользователя уже используется" {
		t.Error("1: Ошибка: ", err.Error())
	}

	// [тест 2]: Тест в котором при регистрации пользователя уже существует пользователь с таким именем почты
	_, err = server.Signup(context.Background(), &proto.SignupRequest{Username: "oleg", Email: "user@mail.com", Password: "examplestring"})
	if err.Error() != "Такая электронная почта уже используется" {
		t.Error("2: Ошибка: ", err.Error())
	}

	// [тест 3]: Тест в котором при регистрации пользователя все данные корректные
	_, err = server.Signup(context.Background(), &proto.SignupRequest{Username: "oleg", Email: "test@mail.com", Password: "examplestring"})
	if err != nil {
		t.Error("3: Ошибка: ", err.Error())
	}

	// [тест 4]: Тест в котором при регистрации пользователя пароль имеет недостаточное количество символов
	_, err = server.Signup(context.Background(), &proto.SignupRequest{Username: "oleg", Email: "test@mail.com", Password: "123"})
	if err.Error() != "Введены некорректные данные" {
		t.Error("4: Ошибка: ", err.Error())
	}
}
