package aes

import "fmt"

func Aes128(msg, key []byte) ([]byte, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("key must be 16 bytes long")
	}

	return msg, nil
}
