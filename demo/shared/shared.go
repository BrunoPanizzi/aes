// Package shared holds what Alice and Bob have in common: the key,
// the channel (a file both terminals can see), and the message format.
package shared

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// TheChannel is where ciphertext travels between the two terminals.
// A file is the simplest cross-process channel: Alice writes it,
// Bob reads it. (In the real world: a network socket.)
const TheChannel = "channel.txt"

// TheKey is the shared AES-128 key, 16 bytes.
//
// Teaching note: how Alice and Bob *agree* on a key without an
// eavesdropper seeing it is its own famous problem (key exchange,
// e.g. Diffie-Hellman). Here they simply both know it already.
var TheKey = []byte("0123456789abcdef") // 16 bytes = 128 bits

// SendMessage writes a framed message to the channel.
// Line 1: metadata — the mode, plus the counter block for CTR.
// Line 2: ciphertext, hex-encoded so students can `cat` the channel
// and inspect it with their own eyes.
func SendMessage(mode, metadata, ciphertextHex string) error {
	f, err := os.Create(TheChannel)
	if err != nil {
		return fmt.Errorf("opening channel: %w", err)
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%s %s\n%s\n", mode, metadata, ciphertextHex)
	return err
}

// ReceiveMessage reads a framed message from the channel.
// Returns the mode, the metadata (counter block hex for CTR),
// and the ciphertext.
func ReceiveMessage() (mode, metadata, ciphertextHex string, err error) {
	f, err := os.Open(TheChannel)
	if err != nil {
		return "", "", "", fmt.Errorf("opening channel: %w (has alice sent anything?)", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan()
	header := strings.Fields(scanner.Text())
	if len(header) < 1 {
		return "", "", "", fmt.Errorf("empty channel header")
	}
	mode = header[0]
	if len(header) > 1 {
		metadata = header[1]
	}

	scanner.Scan()
	ciphertextHex = scanner.Text()
	return mode, metadata, ciphertextHex, nil
}
