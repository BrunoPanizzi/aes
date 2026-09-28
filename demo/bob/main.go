// Bob receives the secret message Alice sent.
//
// Terminal 2:  go run ./demo/bob
//
// Bob reads the channel file, decrypts with the shared key, and
// prints the recovered plaintext. Run alice first in another terminal.
//
// With -follow Bob tails the channel and decrypts each byte as Alice
// (in -slow mode) sends it. Stream modes decrypt byte by byte; ECB has
// to buffer 16 bytes before a single one can be decrypted.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/BrunoPanizzi/aes-go/aes"
	"github.com/BrunoPanizzi/aes-go/demo/shared"
)

func main() {
	follow := flag.Bool("follow", false, "tail the channel, decrypting byte by byte (run alice with -slow)")
	flag.Parse()

	if *follow {
		receiveSlowly()
		return
	}

	mode, metadata, ciphertextHex, err := shared.ReceiveMessage()
	if err != nil {
		panic(err)
	}

	ciphertext, err := hex.DecodeString(ciphertextHex)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Bob: leu %d bytes de texto cifrado do arquivo %q (modo %s)\n\n", len(ciphertext), shared.TheChannel, mode)
	printBlockDump(ciphertext)

	var plaintext []byte
	switch mode {
	case "ecb":
		plaintext, err = aes.ECBDecrypt(ciphertext, shared.TheKey)
		if err != nil {
			panic(err)
		}
		fmt.Println("\nBob: modo ECB. Se o dump acima mostra blocos repetidos,")
		fmt.Println("     o texto claro tinha blocos repetidos: padrões vazam.")

	case "ctr":
		counterBlock, err := hex.DecodeString(metadata)
		if err != nil {
			panic(err)
		}
		plaintext, err = aes.CTRDecrypt(ciphertext, shared.TheKey, counterBlock)
		if err != nil {
			panic(err)
		}
		fmt.Println("\nBob: modo CTR. Todos os blocos cifrados parecem aleatórios:")
		fmt.Println("     mesmo texto claro, mesma chave, mas cada bloco recebeu um keystream diferente.")

	case "ofb":
		iv, err := hex.DecodeString(metadata)
		if err != nil {
			panic(err)
		}
		plaintext, err = aes.OFBDecrypt(ciphertext, shared.TheKey, iv)
		if err != nil {
			panic(err)
		}
		fmt.Println("\nBob: modo OFB. Como no CTR, sem padding e blocos parecem aleatórios.")
		fmt.Println("     Por baixo o keystream é encadeado: ks(i+1) = AES(ks(i)),")
		fmt.Println("     então precisa ser calculado em ordem. CTR poderia ser paralelo.")

	default:
		panic(fmt.Sprintf("unknown mode %q", mode))
	}

	fmt.Printf("\nBob: texto claro decifrado (%d bytes): `%s`\n", len(plaintext), plaintext)
}

// receiveSlowly decrypts the stream as it arrives on the Go channel
// that shared.Listen feeds from the file.
func receiveSlowly() {
	mode, metadata, bytes, err := shared.Listen()
	if err != nil {
		panic(err)
	}
	nonce, _ := hex.DecodeString(metadata) // "-" for ECB: no nonce, decode error ignored
	fmt.Printf("Bob: canal aberto, modo %s. Esperando bytes...\n\n", mode)

	var plaintext, block, all, keystream []byte
	i := 0
	for c := range bytes {
		all = append(all, c)

		if mode == "ecb" {
			block = append(block, c)
			fmt.Printf("byte %2d: %#02x   (guardado %2d/16, ainda não dá pra decifrar)\n", i, c, len(block))
			if len(block) == 16 {
				p := aes.AesDecrypt(block, shared.TheKey)
				fmt.Printf("   bloco %d finalizado -> AES⁻¹ -> %q\n", i/16, p)
				plaintext = append(plaintext, p...)
				block = nil
			}
		} else {
			if i%16 == 0 {
				// ponytail: keystream recomputed from the nonce at every
				// block boundary; O(n²) but messages here are a few blocks.
				keystream = shared.Keystream(mode, shared.TheKey, nonce, i+16)
				fmt.Printf("   keystream do bloco %d pronto: %x\n", i/16, keystream[i:])
			}
			p := c ^ keystream[i]
			plaintext = append(plaintext, p)
			fmt.Printf("byte %2d: %#02x ^ ks %#02x = %#02x %q   | %s\n", i, c, keystream[i], p, p, plaintext)
		}
		i++
	}

	if mode == "ecb" {
		// Now that the whole message is here, strip the PKCS#7 padding.
		plaintext, err = aes.ECBDecrypt(all, shared.TheKey)
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("\nBob: fim da mensagem. texto claro (%d bytes): `%s`\n", len(plaintext), plaintext)
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
		fmt.Printf("  bloco %d: %s%s\n", i, block, marker)
	}
}
