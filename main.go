package main

import (
	"fmt"

	"github.com/BrunoPanizzi/aes-go/aes"
)

func main() {
	key := []byte("0123456789abcdef")
	block := []byte("ATTACK AT DAWN!!")
	fmt.Printf("%x\n", aes.AesEncrypt(block, key))
}
