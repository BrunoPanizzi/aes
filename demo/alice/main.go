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
//
// Slow mode sends one byte per Enter (or per -auto interval), so Bob,
// running `go run ./demo/bob -follow` side by side, can be watched
// decrypting the stream as it arrives:
//
//	go run ./demo/alice -mode ctr -slow
//	go run ./demo/alice -mode ecb -slow -auto 300ms
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BrunoPanizzi/aes-go/aes"
	"github.com/BrunoPanizzi/aes-go/demo/shared"
)

const defaultMsg = "ataque meio dia!ataque meio dia!ataque meio dia!ataque meio dia!"

func main() {
	mode := flag.String("mode", "ctr", "cipher mode: ecb, ctr or ofb")
	msg := flag.String("msg", defaultMsg, "message to send")
	slow := flag.Bool("slow", false, "send one byte at a time (run bob with -follow)")
	auto := flag.Duration("auto", 0, "with -slow: send a byte every interval instead of waiting for Enter")
	flag.Parse()
	*mode = strings.ToLower(*mode)

	fmt.Printf("Alice: texto claro (%d bytes): `%s`\n\n", len(*msg), *msg)

	// nonce para o counter block (CTR) ou IV (OFB)
	// Bob precisa dele para refazer o keystream
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}

	var ciphertext []byte
	var metadata string
	var err error

	switch *mode {
	case "ecb":
		ciphertext, err = aes.ECB([]byte(*msg), shared.TheKey)
		metadata = "-"
		fmt.Println("Alice: modo ECB")

	case "ctr":
		ciphertext, err = aes.CTR([]byte(*msg), shared.TheKey, nonce)
		metadata = hex.EncodeToString(nonce)
		fmt.Printf("Alice: modo CTR. Counter block: %s\n", metadata)

	case "ofb":
		ciphertext, err = aes.OFB([]byte(*msg), shared.TheKey, nonce)
		metadata = hex.EncodeToString(nonce)
		fmt.Printf("Alice: mode OFB. IV: %s\n", metadata)

	default:
		panic(fmt.Sprintf("unknown mode %q (use ecb, ctr or ofb)", *mode))
	}
	if err != nil {
		panic(err)
	}

	if *slow {
		keystream := shared.Keystream(*mode, shared.TheKey, nonce, len(ciphertext))
		sendSlowly(*mode, metadata, []byte(*msg), ciphertext, keystream, *auto)
		return
	}

	fmt.Printf("\nAlice: texto crifrado %s (%d bytes):\n", ciphertext, len(ciphertext))
	printBlockDump(ciphertext)

	if err := shared.SendMessage(*mode, metadata, hex.EncodeToString(ciphertext)); err != nil {
		panic(err)
	}

	fmt.Printf("\nAlice: arquivo %q escrito.\n", shared.TheChannel)
}

// sendSlowly appends the ciphertext to the channel one byte at a time,
// showing how each byte was produced. keystream is nil for ECB.
func sendSlowly(mode, metadata string, plaintext, ciphertext, keystream []byte, auto time.Duration) {
	f, err := shared.OpenChannel(mode, metadata)
	if err != nil {
		panic(err)
	}
	defer f.Close()

	fmt.Println("\nAlice: canal aberto")
	if auto == 0 {
		fmt.Println("Alice: pressione Enter para enviar o próximo byte.")
	}
	stdin := bufio.NewScanner(os.Stdin)

	for i, c := range ciphertext {
		if auto > 0 {
			time.Sleep(auto)
		} else {
			stdin.Scan()
		}

		if keystream != nil {
			fmt.Printf("byte %2d: %q %#02x ^ ks %#02x = %#02x\n", i, plaintext[i], plaintext[i], keystream[i], c)
		} else {
			// ECB: ciphertext is padded, so it may be longer than plaintext
			// and a byte on its own means nothing — only whole blocks do.
			fmt.Printf("byte %2d: %#02x", i, c)
			if (i+1)%16 == 0 {
				fmt.Printf("   <- bloco %d finalizado", i/16)
			}
			fmt.Println()
		}

		if _, err := fmt.Fprintf(f, "%02x", c); err != nil {
			panic(err)
		}
	}
	fmt.Fprintln(f)
	fmt.Println("\nAlice: terminou.")
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
			marker = fmt.Sprintf("  <-- igual ao bloco %d", first)
		} else {
			seen[block] = i
		}
		fmt.Printf("  block %d: %s%s\n", i, block, marker)
	}
}
