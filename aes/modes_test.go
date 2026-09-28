package aes

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// SP 800-38A F.1.1: ECB-AES128, 4-block message.
var (
	modeKey    = "2b7e151628aed2a6abf7158809cf4f3c"
	ecbMessage = "6bc1bee22e409f96e93d7e117393172a" +
		"ae2d8a571e03ac9c9eb76fac45af8e51" +
		"30c81c46a35ce411e5fbc1191a0a52ef" +
		"f69f2445df4f9b17ad2b417be66c3710"
	ecbCiphertext = "3ad77bb40d7a3660a89ecaf32466ef97" +
		"f5d3d58503b9699de785895a96fdbaaf" +
		"43b1cd7f598ece23881b00e3ed030688" +
		"7b0c785e27e8ad3f8223207104725dd4"
)

// SP 800-38A F.5.1: CTR-AES128. Counter blocks increment the last
// 4 bytes big-endian, starting from f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff.
var (
	ctrCounter    = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"
	ctrCiphertext = "874d6191b620e3261bef6864990db6ce" +
		"9806f66b7970fdff8617187bb9fffdff" +
		"5ae4df3edbd5d35e5b4f09020db03eab" +
		"1e031dda2fbe03d1792170a0f3009cee"
)

func TestECBMode(t *testing.T) {
	key, _ := hex.DecodeString(modeKey)
	msg, _ := hex.DecodeString(ecbMessage)
	want, _ := hex.DecodeString(ecbCiphertext)

	got, err := ECB(msg, key)
	if err != nil {
		t.Fatalf("ECB error: %v", err)
	}

	// SP 800-38A defines ECB without padding; our ECB always applies
	// PKCS#7, so the message-aligned case appends one full pad block.
	// Compare the vector portion, then verify the pad block is there.
	if !bytes.Equal(got[:len(want)], want) {
		t.Errorf("ECB mismatch:\n got: %x\nwant: %x", got[:len(want)], want)
	}
	padBlock := bytes.Repeat([]byte{16}, 16)
	decryptedPad := AesDecrypt(got[len(want):], key)
	if !bytes.Equal(decryptedPad, padBlock) {
		t.Errorf("pad block wrong:\n got: %x\nwant: %x", decryptedPad, padBlock)
	}

	back, err := ECBDecrypt(got, key)
	if err != nil {
		t.Fatalf("ECBDecrypt error: %v", err)
	}
	if !bytes.Equal(back, msg) {
		t.Errorf("ECB round trip mismatch:\n got: %x\nwant: %x", back, msg)
	}
}

func TestCTRMode(t *testing.T) {
	key, _ := hex.DecodeString(modeKey)
	msg, _ := hex.DecodeString(ecbMessage) // same message as F.5.1
	ctr, _ := hex.DecodeString(ctrCounter)
	want, _ := hex.DecodeString(ctrCiphertext)

	got, err := CTR(msg, key, ctr)
	if err != nil {
		t.Fatalf("CTR error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("CTR mismatch:\n got: %x\nwant: %x", got, want)
	}

	back, err := CTRDecrypt(got, key, ctr)
	if err != nil {
		t.Fatalf("CTRDecrypt error: %v", err)
	}
	if !bytes.Equal(back, msg) {
		t.Errorf("CTR round trip mismatch:\n got: %x\nwant: %x", back, msg)
	}
}

// CTR handles arbitrary lengths with no padding; the last keystream
// block is consumed partially. Check the sizes around block boundaries.
func TestCTRPartialFinalBlock(t *testing.T) {
	key, _ := hex.DecodeString(modeKey)
	ctr, _ := hex.DecodeString(ctrCounter)

	for size := range 64 {
		msg := bytes.Repeat([]byte{byte(size)}, size)
		ct, err := CTR(msg, key, ctr)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(ct) != size {
			t.Fatalf("size %d: ciphertext length %d", size, len(ct))
		}
		back, err := CTRDecrypt(ct, key, ctr)
		if err != nil || !bytes.Equal(back, msg) {
			t.Fatalf("size %d: round trip failed: %v", size, err)
		}
	}
}

// The counter block must increment correctly, including carries
// across the 4 counter bytes. Compare keystream blocks against
// AesEncrypt of the expected counter values.
func TestCTRCounterIncrement(t *testing.T) {
	key, _ := hex.DecodeString(modeKey)
	ctr, _ := hex.DecodeString(ctrCounter)

	start := binary.BigEndian.Uint32(ctr[12:])
	expected := make([]byte, 0, 64)
	for i := range 4 {
		cb := make([]byte, 16)
		copy(cb, ctr)
		binary.BigEndian.PutUint32(cb[12:], start+uint32(i))
		expected = append(expected, AesEncrypt(cb, key)...)
	}

	msg := bytes.Repeat([]byte{0}, 64) // all-zero: ciphertext == keystream
	got, _ := CTR(msg, key, ctr)
	if !bytes.Equal(got, expected) {
		t.Errorf("keystream mismatch:\n got: %x\nwant: %x", got, expected)
	}
}

// SP 800-38A F.3.1 OFB-AES128 parameters (same key/IV/message style).
// Values cross-verified with an independent OpenSSL-backed library,
// because SP 800-38A's own .rsp fixtures for OFB in kat_aes/ are
// single-block only and can't pin down the chaining rule.
var (
	ofbIV         = "000102030405060708090a0b0c0d0e0f"
	ofbCiphertext = "3b3fd92eb72dad20333449f8e83cfb4a" +
		"7789508d16918f03f53c52dac54ed825" +
		"9740051e9c5fecf64344f7a82260edcc" +
		"304c6528f659c77866a510d9c1d6ae5e"
)

func TestOFBMode(t *testing.T) {
	key, _ := hex.DecodeString(modeKey)
	msg, _ := hex.DecodeString(ecbMessage) // same 4-block message as F.3.1
	iv, _ := hex.DecodeString(ofbIV)
	want, _ := hex.DecodeString(ofbCiphertext)

	got, err := OFB(msg, key, iv)
	if err != nil {
		t.Fatalf("OFB error: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("OFB mismatch:\n got: %x\nwant: %x", got, want)
	}

	back, err := OFBDecrypt(got, key, iv)
	if err != nil {
		t.Fatalf("OFBDecrypt error: %v", err)
	}
	if !bytes.Equal(back, msg) {
		t.Errorf("OFB round trip mismatch:\n got: %x\nwant: %x", back, msg)
	}
}

// OFB handles arbitrary lengths with no padding, like CTR.
func TestOFBPartialFinalBlock(t *testing.T) {
	key, _ := hex.DecodeString(modeKey)
	iv, _ := hex.DecodeString(ofbIV)

	for size := range 64 {
		msg := bytes.Repeat([]byte{byte(size)}, size)
		ct, err := OFB(msg, key, iv)
		if err != nil {
			t.Fatalf("size %d: %v", size, err)
		}
		if len(ct) != size {
			t.Fatalf("size %d: ciphertext length %d", size, len(ct))
		}
		back, err := OFBDecrypt(ct, key, iv)
		if err != nil || !bytes.Equal(back, msg) {
			t.Fatalf("size %d: round trip failed: %v", size, err)
		}
	}
}

// The defining property of OFB: each keystream block is AES of the
// PREVIOUS keystream block (feedback), not of a counter value.
// This test would fail if OFB accidentally became CTR.
func TestOFBChaining(t *testing.T) {
	key, _ := hex.DecodeString(modeKey)
	iv, _ := hex.DecodeString(ofbIV)

	ks0 := AesEncrypt(iv, key)
	ks1Want := AesEncrypt(ks0, key) // feedback: AES of previous output

	// zero message => ciphertext == keystream, block by block
	ks1Got, _ := OFB(bytes.Repeat([]byte{0}, 32), key, iv)

	if !bytes.Equal(ks1Got[16:], ks1Want) {
		t.Errorf("OFB is not chaining:\n got ks1: %x\nwant AES(ks0): %x", ks1Got[16:], ks1Want)
	}

	// and the CTR keystream for the same position is a DIFFERENT value:
	ctr := make([]byte, 16)
	copy(ctr, ks0)
	ctr[12] = 0xff // arbitrary counter start, not equal to ks0
	ctrKS1 := AesEncrypt(append(ctr[:12], 0, 0, 0, 1), key)
	if bytes.Equal(ctrKS1, ks1Want) {
		t.Error("CTR and OFB keystreams coincidentally equal — impossible, check chaining")
	}
}
