// Package shared holds what Alice and Bob have in common: the key,
// the channel (a file both terminals can see), and the message format.
package shared

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/BrunoPanizzi/aes-go/aes"
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

// pollInterval is how often Bob re-checks the file for new bytes.
const pollInterval = 50 * time.Millisecond

// Message format on the channel:
//
//	Line 1: metadata — the mode, plus the counter block / IV for stream modes.
//	Line 2: ciphertext, hex-encoded (2 chars per byte) so students can
//	        `cat` the channel and inspect it with their own eyes.
//	        The closing "\n" is the end-of-message marker.

// SendMessage writes a whole framed message to the channel at once.
func SendMessage(mode, metadata, ciphertextHex string) error {
	f, err := OpenChannel(mode, metadata)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = fmt.Fprintf(f, "%s\n", ciphertextHex)
	return err
}

// OpenChannel starts a transmission: it truncates the channel, writes
// the header line, and returns the file so the caller can append
// ciphertext one byte (2 hex chars) at a time. The caller must write
// the final "\n" — that is what tells Listen the message is over.
func OpenChannel(mode, metadata string) (*os.File, error) {
	f, err := os.Create(TheChannel)
	if err != nil {
		return nil, fmt.Errorf("opening channel: %w", err)
	}
	_, err = fmt.Fprintf(f, "%s %s\n", mode, metadata)
	return f, err
}

func parseHeader(line string) (mode, metadata string, err error) {
	fields := strings.Fields(line)
	if len(fields) < 1 {
		return "", "", fmt.Errorf("empty channel header")
	}
	mode = fields[0]
	if len(fields) > 1 {
		metadata = fields[1]
	}
	return mode, metadata, nil
}

// ReceiveMessage reads a complete framed message from the channel.
func ReceiveMessage() (mode, metadata, ciphertextHex string, err error) {
	f, err := os.Open(TheChannel)
	if err != nil {
		return "", "", "", fmt.Errorf("opening channel: %w (has alice sent anything?)", err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan()
	mode, metadata, err = parseHeader(scanner.Text())
	if err != nil {
		return "", "", "", err
	}

	scanner.Scan()
	ciphertextHex = scanner.Text()
	return mode, metadata, ciphertextHex, nil
}

// Listen tails the channel. It blocks until the header line has been
// written, then returns a Go channel that delivers ciphertext bytes as
// Alice appends them and is closed when the final "\n" arrives.
//
// Run alice first: she truncates the file, so a stale channel.txt from
// an earlier run is never mistaken for the new message.
func Listen() (mode, metadata string, bytes <-chan byte, err error) {
	var f *os.File
	for {
		f, err = os.Open(TheChannel)
		if err == nil {
			break
		}
		time.Sleep(pollInterval)
	}

	header := ""
	for c := nextChar(f); c != '\n'; c = nextChar(f) {
		header += string(c)
	}
	mode, metadata, err = parseHeader(header)
	if err != nil {
		f.Close()
		return "", "", nil, err
	}

	ch := make(chan byte)
	go func() {
		defer close(ch)
		defer f.Close()
		for {
			hi := nextChar(f)
			if hi == '\n' {
				return // end-of-message marker
			}
			lo := nextChar(f)
			b, err := hex.DecodeString(string([]byte{hi, lo}))
			if err != nil {
				return
			}
			ch <- b[0]
		}
	}()
	return mode, metadata, ch, nil
}

// nextChar reads one character from f, sleeping at EOF until the
// writer appends more. This is the blocking read a socket gives for free.
func nextChar(f *os.File) byte {
	var buf [1]byte
	for {
		if n, _ := f.Read(buf[:]); n == 1 {
			return buf[0]
		}
		time.Sleep(pollInterval)
	}
}

// Keystream returns the first n keystream bytes of a stream mode.
// Trick: since c = p XOR k, encrypting zeros yields the raw keystream.
// Returns nil for modes that have no keystream (ECB).
func Keystream(mode string, key, nonce []byte, n int) []byte {
	zeros := make([]byte, n)
	var ks []byte
	var err error
	switch mode {
	case "ctr":
		ks, err = aes.CTR(zeros, key, nonce)
	case "ofb":
		ks, err = aes.OFB(zeros, key, nonce)
	default:
		return nil
	}
	if err != nil {
		panic(err) // bad nonce length: the header on the channel is malformed
	}
	return ks
}
