package main

import (
	"crypto"
	"crypto/mldsa"
	"crypto/rand"
	"fmt"
	"testing"
	"time"
)

func TestMlDsa(t *testing.T) {
	// 1. Сервер генерирует долгосрочный ключ подписи
	// MLDSA44() — базовый стандартный набор параметров (аналог ES256)
	paramSet := mldsa.MLDSA44()
	privateKey, err := mldsa.GenerateKey(paramSet)
	if err != nil {
		panic(err)
	}
	publicKey := privateKey.PublicKey()

	// 2. Имитируем создание JWT-токена (Payload)
	// Допустим, мы хотим подписать ID пользователя и время жизни токена
	tokenPayload := fmt.Sprintf("user_id:777;exp:%d", time.Now().Add(time.Hour).Unix())
	msg := []byte(tokenPayload)

	// 3. СЕРВЕР ПОДПИСЫВАЕТ ТОКЕН (Аналог jwt.Sign)
	// Используется секретный базис решётки.
	// Третий аргумент требует crypto.Hash(0), так как решётки хэшируют сообщение сами внутри.
	signature, err := privateKey.Sign(rand.Reader, msg, crypto.Hash(0))
	if err != nil {
		panic(err)
	}

	fmt.Printf("Токен: %s\n", tokenPayload)
	fmt.Printf("Длина постквантовой подписи решётки: %d байт\n", len(signature))

	// ----------------------------------------------------
	// Передаём токен и сигнатуру клиенту/микросервису...
	// ----------------------------------------------------

	// 4. МИКРОСЕРВИС ПРОВЕРЯЕТ ТОКЕН (Аналог jwt.Verify)
	// Берем присланный текст, подпись и открытый косоугольный Public Key сервера.
	// Функция Verify замеряет векторы и смотрит, попала ли стрелка точно в узел решётки.
	err = mldsa.Verify(publicKey, msg, signature, nil)

	if err == nil {
		fmt.Println("Успех: Подпись токена абсолютно валидна! Доступ разрешён.")
	} else {
		fmt.Println("Ошибка: Токен подделан или повреждён!")
	}
}
