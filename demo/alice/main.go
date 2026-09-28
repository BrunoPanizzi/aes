// Alice sends a secret message to Bob.
//
// Terminal 1:  go run ./demo/alice
// Terminal 2:  go run ./demo/bob
//
// Run alice, watch the ciphertext appear, then run bob to decrypt it.
// Try both modes and compare:
//
//	go run ./demo/alice -mode ecb
//	go run ./demo/alice -mode ctr
//
// The default message is deliberately repetitive so you can SEE the
// difference: under ECB every identical 16-byte plaintext block
// produces an identical ciphertext block (the "ECB penguin" effect).
// Under CTR the same message encrypts to blocks that all look random.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"strings"

	"github.com/BrunoPanizzi/aes-go/aes"
	"github.com/BrunoPanizzi/aes-go/demo/shared"
)

// default message: 16-byte phrase repeated, so whole blocks repeat.
const defaultMsg = "ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!ATTACK AT DAWN!!"

func main() {
	mode := flag.String("mode", "ctr", "cipher mode: ecb or ctr")
	msg := flag.String("msg", defaultMsg, "message to send")
	flag.Parse()

	fmt.Printf("Alice: plaintext (%d bytes):\n%s\n\n", len(*msg), *msg)

	var ciphertext []byte
	var metadata string
	var err error

	switch strings.ToLower(*mode) {
	case "ecb":
		// ECB: no extra data needed, each block is encrypted alone.
		ciphertext, err = aes.ECB([]byte(*msg), shared.TheKey)
		if err != nil {
			panic(err)
		}
		metadata = "-"
		fmt.Println("Alice: mode ECB — each block encrypted independently.")

	case "ctr":
		// CTR: Alice picks a fresh counter block (acts as a nonce).
		// It is NOT secret — Bob needs it to rebuild the keystream —
		// so it is sent openly on the channel.
		counterBlock := make([]byte, 16)
		if _, err := rand.Read(counterBlock); err != nil {
			panic(err)
		}
		ciphertext, err = aes.CTR([]byte(*msg), shared.TheKey, counterBlock)
		if err != nil {
			panic(err)
		}
		metadata = hex.EncodeToString(counterBlock)
		fmt.Printf("Alice: mode CTR — counter block (sent openly): %s\n", metadata)

	case "ofb":
		// OFB: like CTR, a stream cipher — Alice picks a random IV,
		// sent openly because Bob needs it to rebuild the keystream.
		// The difference is invisible at this level (both produce
		// random-looking blocks); it's in HOW the keystream is made:
		// CTR counts, OFB feeds each keystream block back into AES.
		iv := make([]byte, 16)
		if _, err := rand.Read(iv); err != nil {
			panic(err)
		}
		ciphertext, err = aes.OFB([]byte(*msg), shared.TheKey, iv)
		if err != nil {
			panic(err)
		}
		metadata = hex.EncodeToString(iv)
		fmt.Printf("Alice: mode OFB — IV (sent openly): %s\n", metadata)

	default:
		panic(fmt.Sprintf("unknown mode %q (use ecb or ctr)", *mode))
	}

	fmt.Printf("\nAlice: ciphertext (%d bytes):\n", len(ciphertext))
	printBlockDump(ciphertext)

	if err := shared.SendMessage(strings.ToLower(*mode), metadata, hex.EncodeToString(ciphertext)); err != nil {
		panic(err)
	}

	fmt.Printf("\nAlice: wrote to channel %q. Now run: go run ./demo/bob\n", shared.TheChannel)
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
