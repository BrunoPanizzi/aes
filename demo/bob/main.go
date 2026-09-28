// Bob receives the secret message Alice sent.
//
// Terminal 2:  go run ./demo/bob
//
// Bob reads the channel file, decrypts with the shared key, and
// prints the recovered plaintext. Run alice first in another terminal.
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/BrunoPanizzi/aes-go/aes"
	"github.com/BrunoPanizzi/aes-go/demo/shared"
)

func main() {
	mode, metadata, ciphertextHex, err := shared.ReceiveMessage()
	if err != nil {
		panic(err)
	}

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Bob: read %d bytes of ciphertext from channel %q (mode %s)\n\n", len(ciphertext), shared.TheChannel, mode)
	printBlockDump(ciphertext)

	var plaintext []byte
	switch mode {
	case "ecb":
		// ECB decryption: decrypt each block, strip PKCS#7 padding.
		plaintext, err = aes.ECBDecrypt(ciphertext, shared.TheKey)
		if err != nil {
			panic(err)
		}
		fmt.Println("\nBob: ECB — if the dump above shows repeated blocks,")
		fmt.Println("     that means the plaintext had repeated blocks: patterns leak.")

	case "ctr":
		// CTR decryption: regenerate the keystream from the (openly
		// transmitted) counter block and XOR again — decrypt == encrypt.
		counterBlock, err := hex.DecodeString(metadata)
		if err != nil {
			panic(err)
		}
		plaintext, err = aes.CTRDecrypt(ciphertext, shared.TheKey, counterBlock)
		if err != nil {
			panic(err)
		}
		fmt.Println("\nBob: CTR — ciphertext blocks all look random:")
		fmt.Println("     same plaintext, same key, but every block got a different keystream.")
		if err != nil {
			panic(err)
		}

	case "ofb":
		// OFB decryption: same keystream chain, XOR again.
		iv, err := hex.DecodeString(metadata)
		if err != nil {
			panic(err)
		}
		plaintext, err = aes.OFBDecrypt(ciphertext, shared.TheKey, iv)
		if err != nil {
			panic(err)
		}
		fmt.Println("\nBob: OFB — like CTR, no padding and blocks look random.")
		fmt.Println("     Under the hood the keystream is chained: ks(i+1) = AES(ks(i)),")
		fmt.Println("     so it must be computed strictly in order — CTR could go in parallel.")

	default:
		panic(fmt.Sprintf("unknown mode %q", mode))
	}

	fmt.Printf("\nBob: decrypted plaintext (%d bytes):\n%s\n", len(plaintext), plaintext)
}

// printBlockDump prints ciphertext one 16-byte block per line,
// marking repeats — the visual proof of ECB's weakness.
func printBlockDump(data []byte) {
	seen := map[string]int{}
	for i := 0; i*16 < len(data); i++ {
		end := min(i*16+16, len(data))
		block := hex.EncodeToString(data[i*16 : end])
		marker := ""
		if first, ok := seen[block]; ok {
			marker = fmt.Sprintf("  <-- same as block %d", first)
		} else {
			seen[block] = i
		}
		fmt.Printf("  block %d: %s%s\n", i, block, marker)
	}
}
