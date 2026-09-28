package aes

import (
	"fmt"
	"slices"
)

// PKCS#7: adiciona n bytes de valor n, onde n é quantos faltam para
// completar o bloco (1..16). Mensagem já alinhada ganha um bloco inteiro
// de 0x10, assim remover o padding nunca é ambíguo.
func padPKCS7(msg []byte) []byte {
	n := BLOCK_SIZE - len(msg)%BLOCK_SIZE
	return append(slices.Clone(msg), slices.Repeat([]byte{byte(n)}, n)...)
}

func unpadPKCS7(msg []byte) ([]byte, error) {
	if len(msg) == 0 || len(msg)%BLOCK_SIZE != 0 {
		return nil, fmt.Errorf("padded message must be a positive multiple of %d bytes", BLOCK_SIZE)
	}
	n := int(msg[len(msg)-1])
	if n < 1 || n > BLOCK_SIZE {
		return nil, fmt.Errorf("invalid padding length %d", n)
	}
	for _, b := range msg[len(msg)-n:] {
		if b != byte(n) {
			return nil, fmt.Errorf("corrupted padding")
		}
	}
	return msg[:len(msg)-n], nil
}

// ECB mode (Electronic Codebook)
//
//	C[i] = AES_K(P[i])
//
// Cada bloco só depende dele mesmo e da chave: blocos iguais no texto
// claro viram blocos iguais no cifrado.
func ECB(msg, key []byte) (out []byte, err error) {
	padded := padPKCS7(msg)
	out = make([]byte, len(padded))

	for start := 0; start < len(padded); start += BLOCK_SIZE {
		copy(out[start:], AesEncrypt(padded[start:start+BLOCK_SIZE], key))
	}
	return out, nil
}

func ECBDecrypt(msg, key []byte) (out []byte, err error) {
	if len(msg) == 0 || len(msg)%BLOCK_SIZE != 0 {
		return nil, fmt.Errorf("ECB ciphertext must be a positive multiple of %d bytes", BLOCK_SIZE)
	}
	out = make([]byte, len(msg))

	for start := 0; start < len(msg); start += BLOCK_SIZE {
		copy(out[start:], AesDecrypt(msg[start:start+BLOCK_SIZE], key))
	}
	return unpadPKCS7(out)
}

// Cifras de fluxo (CTR e OFB): a mensagem nunca entra no AES.
// O AES gera um keystream e a mensagem é XORada com ele:
//
//	C = P XOR keystream
//	P = C XOR keystream      (XOR é o próprio inverso)
//
// Por isso decifrar == cifrar e não precisa de padding: o último bloco
// usa só os primeiros bytes do keystream. A única diferença entre os
// dois modos é o que o AES cifra para produzir cada bloco de keystream.

// xorInto escreve msg XOR keystream em out, parando no menor dos dois.
func xorInto(out, msg, keystream []byte) {
	for i := range min(len(msg), len(keystream)) {
		out[i] = msg[i] ^ keystream[i]
	}
}

// CTR mode (Counter)
//
//	keystream[i] = AES_K(counterBlock + i)
//
// O counter block é público (vai junto com a mensagem), mas não pode
// repetir com a mesma chave: mesmo (chave, counter) => mesmo keystream,
// e C1 XOR C2 = P1 XOR P2. Como o bloco i só depende de i, os blocos
// podem ser calculados em qualquer ordem ou em paralelo.
func CTR(msg, key, counterBlock []byte) (out []byte, err error) {
	if len(counterBlock) != BLOCK_SIZE {
		return nil, fmt.Errorf("counter block must be exactly %d bytes", BLOCK_SIZE)
	}
	out = make([]byte, len(msg))
	counter := slices.Clone(counterBlock)

	for start := 0; start < len(msg); start += BLOCK_SIZE {
		keystream := AesEncrypt(counter, key)
		xorInto(out[start:], msg[start:], keystream)
		incrementCounter(counter)
	}
	return out, nil
}

// incrementCounter soma 1 ao counter block, tratando os últimos 4 bytes
// como um inteiro big-endian (SP 800-38A, Apêndice B.1). O "vai um"
// propaga para a esquerda: ...00ff -> ...0100. Os 12 primeiros bytes
// (o nonce) nunca mudam.
func incrementCounter(counter []byte) {
	for i := len(counter) - 1; i >= len(counter)-4; i-- {
		counter[i]++
		if counter[i] != 0 {
			return // sem vai um
		}
	}
}

// CTRDecrypt é o CTR
func CTRDecrypt(msg, key, counterBlock []byte) ([]byte, error) {
	return CTR(msg, key, counterBlock)
}

// OFB mode (Output Feedback)
//
//	keystream[0] = AES_K(IV)
//	keystream[i] = AES_K(keystream[i-1])
//
// O IV tem o mesmo papel do counter block: público, mas único por
// (chave, mensagem). Em vez de contar, cada bloco de keystream é
// realimentado como entrada do próximo, então os blocos precisam ser
// calculados em ordem.
func OFB(msg, key, iv []byte) (out []byte, err error) {
	if len(iv) != BLOCK_SIZE {
		return nil, fmt.Errorf("OFB IV must be exactly %d bytes", BLOCK_SIZE)
	}
	out = make([]byte, len(msg))
	feedback := iv

	for start := 0; start < len(msg); start += BLOCK_SIZE {
		keystream := AesEncrypt(feedback, key)
		xorInto(out[start:], msg[start:], keystream)
		feedback = keystream // a única diferença estrutural para o CTR
	}
	return out, nil
}

// OFBDecrypt é o OFB
func OFBDecrypt(msg, key, iv []byte) ([]byte, error) {
	return OFB(msg, key, iv)
}
