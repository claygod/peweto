package main

import (
	"crypto/mlkem"
	"fmt"
	"log"
	"testing"
)

func TestMlKem(t *testing.T) {
	// 1. Сервер генерирует свою решётку (ML-KEM-768 — стандартный уровень защиты)
	// dk — Decryption Key (секретный выпрямленный базис / Private Key)
	// ek — Encapsulation Key (открытый перекошенный базис / Public Key)
	dk, err := mlkem.GenerateKey768()
	if err != nil {
		panic(err)
	}
	encapsulationKey := dk.EncapsulationKey().Bytes()

	ek, err := mlkem.NewEncapsulationKey768(encapsulationKey)
	if err != nil {
		log.Fatal(err)
	}

	// Сервер публикует свой открытый ключ (ek.Bytes()) в сеть...

	// 2. Ваш клиент принимает ek.Bytes() и хочет отправить секретный ключ AES
	// Функция Encapsulate берёт открытый базис сервера, генерирует случайный
	// симметричный ключ (sharedSecret) и «заматывает» его в геометрию решётки с шумом (ciphertext).

	sharedSecret, sharedSecretClient := ek.Encapsulate()
	_ = sharedSecret

	// По интернету летят ciphertext (точка с шумом)

	// 3. Сервер принимает ciphertext и сбрасывает шум через inf своим секретным базисом (dk)
	sharedSecretServer, err := dk.Decapsulate(sharedSecretClient)
	if err != nil {
		panic(err)
	}

	// sharedSecret, err := dk.Decapsulate(ciphertext)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// Проверяем: у клиента и сервера в памяти оказался один и тот же ключ!
	fmt.Printf("Ключ у клиента (длина): %x\n", len(sharedSecretClient))
	fmt.Printf("Ключ у сервера: %x\n", sharedSecretServer)
}
