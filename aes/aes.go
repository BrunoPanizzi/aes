package aes

import (
	"fmt"
	"slices"
)

func sliceXor(a, b []byte) (out []byte) {
	if len(a) != len(b) {
		panic("cannot xor slices of different lengths")
	}

	out = make([]byte, len(a))

	for i := range len(a) {
		out[i] = a[i] ^ b[i]
	}

	return out
}

func getNkNrFromKey(key []byte) (nk, nr int) {
	size := len(key)
	if size == 16 {
		return 4, 10
	}
	if size == 24 {
		return 6, 12
	}
	if size == 32 {
		return 8, 14
	}

	panic("invalid key size")
}

func padMsg(msg []byte) (padded []byte, blockCount int) {
	padding := (len(msg) % BLOCK_SIZE) & 0x1
	padded = make([]byte, (len(msg)/BLOCK_SIZE+padding)*BLOCK_SIZE)

	copy(padded, msg)

	return padded, len(padded) / BLOCK_SIZE
}

func rotWord(word []byte) (out []byte) {
	return []byte{word[1], word[2], word[3], word[0]}
}

func subWord(word []byte) (out []byte) {
	out = make([]byte, 4)
	for i := range 4 {
		curr := word[i]
		out[i] = SBOX[curr>>4][0x0F&curr]
	}
	return out
}

// | bits in key | len(key) | nk | nr
// |   AES-128   |    16    | 4  | 10
// |   AES-192   |    24    | 6  | 12
// |   AES-256   |    32    | 8  | 14
func KeyExpansion(key []byte) (roundKeys [][]byte) {
	// i é preservado de um loop para o outro
	i := 0

	// nr = Number of Rounds
	// nk = Number of words of the Key
	// len(words) =  4*(nr+1)
	nk, nr := getNkNrFromKey(key)

	words := make([][]byte, 4*(nr+1))

	for ; i < nk; i++ {
		words[i] = slices.Clone(key[i*4 : (i+1)*4])
	}

	for ; i <= 4*nr+3; i++ {
		temp := words[i-1]
		if i%nk == 0 {
			temp = sliceXor(subWord(rotWord(temp)), ROUND_CONSTANTS[i/nk-1])
		} else if (nk > 6) && (i%nk == 4) {
			temp = subWord(temp)
		}

		words[i] = sliceXor(words[i-nk], temp)
	}

	preTransposeRoundKeys := make([][]byte, len(words)/4)
	// group bundles of 4 words into blocks
	for j := range len(words) / 4 {
		preTransposeRoundKeys[j] = make([]byte, 16)
		copy(preTransposeRoundKeys[j][0:4], words[4*j+0])
		copy(preTransposeRoundKeys[j][4:8], words[4*j+1])
		copy(preTransposeRoundKeys[j][8:12], words[4*j+2])
		copy(preTransposeRoundKeys[j][12:16], words[4*j+3])
	}

	roundKeys = make([][]byte, len(preTransposeRoundKeys))

	for k := range len(preTransposeRoundKeys) {
		roundKeys[k] = make([]byte, 16)
		for row := range 4 {
			for col := range 4 {
				roundKeys[k][col*4+row] = preTransposeRoundKeys[k][row*4+col]
			}
		}
	}

	return roundKeys
}

func addRoundKey(in, roundKey []byte) (out []byte) {
	return sliceXor(in, roundKey)
}

func subBytes(in []byte) (out []byte) {
	out = make([]byte, BLOCK_SIZE)

	for i := range BLOCK_SIZE {
		curr := in[i]
		out[i] = SBOX[curr>>4][0x0F&curr]
	}

	return out
}

func shiftRows(in []byte) (out []byte) {
	out = make([]byte, BLOCK_SIZE)

	for row := range 4 {
		out[row*4+0] = in[row*4+(0+row)%4]
		out[row*4+1] = in[row*4+(1+row)%4]
		out[row*4+2] = in[row*4+(2+row)%4]
		out[row*4+3] = in[row*4+(3+row)%4]
	}

	return out
}

// 0x11b = 1 0001 1011
// 0x1b  =   0001 1011
// multiplica b por 2 no campo Galois 2⁸
func galoisTimes2(b byte) byte {
	wouldOverflow := b&0x80 == 0x80
	b <<= 1
	if wouldOverflow {
		b ^= 0x1b // mágica
	}
	return b
}

// blah blah blah galois field blah blah blah
func mixColumns(in []byte) (out []byte) {
	out = make([]byte, BLOCK_SIZE)

	for col := range 4 {
		s0, s1, s2, s3 := in[0+col], in[4+col], in[8+col], in[12+col]

		out[0+col] = (galoisTimes2(s0)) ^ (galoisTimes2(s1) ^ s1) ^ (s2) ^ (s3)
		out[4+col] = (s0) ^ (galoisTimes2(s1)) ^ (galoisTimes2(s2) ^ s2) ^ (s3)
		out[8+col] = (s0) ^ (s1) ^ (galoisTimes2(s2)) ^ (galoisTimes2(s3) ^ s3)
		out[12+col] = (galoisTimes2(s0) ^ s0) ^ (s1) ^ (s2) ^ (galoisTimes2(s3))
	}

	return out
}

func Cypher(in []byte, nr int, roundKeys [][]byte) (out []byte) {
	state := make([]byte, BLOCK_SIZE)
	out = make([]byte, BLOCK_SIZE)

	for row := range 4 {
		for col := range 4 {
			state[col*4+row] = in[row*4+col]
		}
	}

	state = addRoundKey(state, roundKeys[0])

	for i := 1; i < nr; i++ {
		state = subBytes(state)
		state = shiftRows(state)
		state = mixColumns(state)
		state = addRoundKey(state, roundKeys[i])
	}

	state = subBytes(state)
	state = shiftRows(state)
	state = addRoundKey(state, roundKeys[nr])

	for row := range 4 {
		for col := range 4 {
			out[col*4+row] = state[row*4+col]
		}
	}

	return out
}

func AesEncrypt(block, key []byte) (out []byte, error error) {
	if len(block) != 16 {
		return nil, fmt.Errorf("block must be exactly 16 bytes")
	}
	_, nr := getNkNrFromKey(key)

	out = Cypher(block, nr, KeyExpansion(key))

	return out, nil
}
