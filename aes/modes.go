package aes

import (
	"encoding/binary"
	"fmt"
)

// ------------------------------------------------------------------
// Padding (PKCS#7, RFC 5652 §6.3)
//
// ECB needs whole 16-byte blocks, but real messages have arbitrary
// length. PKCS#7 appends N bytes, each with value N, where N is the
// number of missing bytes (1..16 — a full block of 0x10s is added
// when the message is already a multiple, so unpadding is never
// ambiguous).
// ------------------------------------------------------------------

func padPKCS7(msg []byte) []byte {
	n := BLOCK_SIZE - len(msg)%BLOCK_SIZE // always in 1..16
	padded := make([]byte, len(msg)+n)
	copy(padded, msg)
	for i := len(msg); i < len(padded); i++ {
		padded[i] = byte(n)
	}
	return padded
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

// ------------------------------------------------------------------
// ECB mode (Electronic Codebook, SP 800-38A)
//
// The simplest mode: pad the message, encrypt each 16-byte block
// independently. Each block's ciphertext depends only on that block
// and the key — identical plaintext blocks produce identical
// ciphertext blocks, which leaks patterns in the data.
//
// Educational mode only. Do not use to protect real data.
// ------------------------------------------------------------------

func ECB(msg, key []byte) (out []byte, err error) {
	padded := padPKCS7(msg)
	blocks := len(padded) / BLOCK_SIZE

	out = make([]byte, len(padded))
	for i := range blocks {
		block, err := AesEncrypt(padded[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE], key)
		if err != nil {
			return nil, err
		}
		copy(out[i*BLOCK_SIZE:], block)
	}
	return out, nil
}

func ECBDecrypt(msg, key []byte) (out []byte, err error) {
	if len(msg) == 0 || len(msg)%BLOCK_SIZE != 0 {
		return nil, fmt.Errorf("ECB ciphertext must be a positive multiple of %d bytes", BLOCK_SIZE)
	}

	out = make([]byte, len(msg))
	for i := range len(msg) / BLOCK_SIZE {
		block, err := AesDecrypt(msg[i*BLOCK_SIZE:(i+1)*BLOCK_SIZE], key)
		if err != nil {
			return nil, err
		}
		copy(out[i*BLOCK_SIZE:], block)
	}

	return unpadPKCS7(out)
}

// ------------------------------------------------------------------
// CTR mode (Counter, SP 800-38A §6.5)
//
// Turns the block cipher into a stream cipher: encrypt an incrementing
// counter block to produce a keystream, then XOR it with the message.
//
//   keystream_i = AES_K(counter block i)
//   ciphertext  = plaintext XOR keystream
//
// Consequences worth teaching:
//   - no padding: any message length works (last block XORs partially)
//   - encryption and decryption are the SAME operation (XOR is its own
//     inverse, and the receiver regenerates the identical keystream)
//   - the counter block must NEVER repeat under the same key: a reused
//     (key, counter) pair XORs two ciphertexts with the same keystream,
//     and the keystream cancels out
// ------------------------------------------------------------------

// CTR encrypts msg under key. counterBlock is the 16-byte initial
// counter: the last 4 bytes are incremented (big-endian) per block.
// The counter block is not secret — it must be unique per (key, message),
// like a nonce, and the receiver needs it to regenerate the keystream.
func CTR(msg, key, counterBlock []byte) (out []byte, err error) {
	if len(counterBlock) != BLOCK_SIZE {
		return nil, fmt.Errorf("counter block must be exactly %d bytes", BLOCK_SIZE)
	}

	out = make([]byte, len(msg))
	for i := 0; i*BLOCK_SIZE < len(msg); i++ {
		// counter block i = initial counter block with its last 4 bytes
		// incremented by i (big-endian, SP 800-38A §6.5 style)
		cb := make([]byte, BLOCK_SIZE)
		copy(cb, counterBlock)
		binary.BigEndian.PutUint32(cb[12:], binary.BigEndian.Uint32(counterBlock[12:])+uint32(i))
		keystream, err := AesEncrypt(cb, key)
		if err != nil {
			return nil, err
		}

		// XOR the message slice with the keystream; the last block
		// may be partial, so only len(msg)-i*16 bytes are consumed.
		for j := 0; i*BLOCK_SIZE+j < len(msg) && j < BLOCK_SIZE; j++ {
			out[i*BLOCK_SIZE+j] = msg[i*BLOCK_SIZE+j] ^ keystream[j]
		}
	}
	return out, nil
}

// CTRDecrypt is CTR: XORing with the same keystream both encrypts and
// decrypts. It exists as a name so call sites read unambiguously.
func CTRDecrypt(msg, key, counterBlock []byte) ([]byte, error) {
	return CTR(msg, key, counterBlock)
}

// ------------------------------------------------------------------
// OFB mode (Output Feedback, SP 800-38A §6.3)
//
// The other stream-cipher mode. Like CTR it XORs the message with a
// keystream of encrypted blocks — no padding, decrypt == encrypt —
// but the keystream is produced by CHAINING instead of counting:
//
//	k0 = AES_K(IV)
//	k(i+1) = AES_K(k(i))     <- the keystream feeds back as input
//	ciphertext = plaintext XOR keystream
//
// Difference vs CTR, and why it matters:
//   - CTR encrypts a PREDICTABLE counter sequence, so keystream block
//     i can be computed independently: random access, parallelism.
//     OFB must compute every block sequentially; block i needs block
//     i-1 (though a receiver can re-run the chain to seek).
//   - OFB's keystream can, in principle, enter a short cycle (if two
//     chain values ever collide, the sequence loops). CTR cannot:
//     counter blocks are distinct by construction for 2^32 blocks.
//   - In exchange, OFB only ever asks AES to encrypt IVs the sender
//     chose; CTR's counter sequence is fully determined by the start
//     value, which is one reason modern designs prefer CTR.
//
// The IV is not secret (receiver needs it) but must be unique per
// (key, message) — a repeated IV reproduces the entire keystream.
// ------------------------------------------------------------------

// OFB encrypts msg under key with the given 16-byte IV.
func OFB(msg, key, iv []byte) (out []byte, err error) {
	if len(iv) != BLOCK_SIZE {
		return nil, fmt.Errorf("OFB IV must be exactly %d bytes", BLOCK_SIZE)
	}

	out = make([]byte, len(msg))

	// ksInput is what AES encrypts next; it starts as the IV and is
	// then replaced by each keystream block as it is produced.
	ksInput := make([]byte, BLOCK_SIZE)
	copy(ksInput, iv)

	for i := 0; i*BLOCK_SIZE < len(msg); i++ {
		keystream, err := AesEncrypt(ksInput, key)
		if err != nil {
			return nil, err
		}

		// XOR the message slice with the keystream; the last block
		// may be partial, so only len(msg)-i*16 bytes are consumed.
		for j := 0; i*BLOCK_SIZE+j < len(msg) && j < BLOCK_SIZE; j++ {
			out[i*BLOCK_SIZE+j] = msg[i*BLOCK_SIZE+j] ^ keystream[j]
		}

		// THE feedback step — the only structural difference from CTR:
		// CTR would increment a counter here; OFB feeds the output back.
		copy(ksInput, keystream)
	}
	return out, nil
}

// OFBDecrypt is OFB: XORing with the same keystream both encrypts and
// decrypts. It exists as a name so call sites read unambiguously.
func OFBDecrypt(msg, key, iv []byte) ([]byte, error) {
	return OFB(msg, key, iv)
}
