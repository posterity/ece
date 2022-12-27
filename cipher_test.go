package ece

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
)

func TestCipherUnmarshalJSON(t *testing.T) {
	c, err := EncodeString(AES256GCM.RandomKey(), "hello, world!")
	if err != nil {
		t.Fatal(err)
	}

	var dest = struct {
		Cipher Cipher `json:"cipher"`
	}{}

	suites := map[bool][]byte{
		true:  c,
		false: []byte("not a valid ECE cipher"),
	}

	for result, cipher := range suites {
		t.Run(fmt.Sprintf("expected result: %v", result), func(t *testing.T) {
			encoded := fmt.Sprintf(`{"cipher":"%s"}`, base64.StdEncoding.EncodeToString(cipher))
			err := json.Unmarshal([]byte(encoded), &dest)
			if result != (err == nil) {
				t.Fatal(err)
			}

			if result && !bytes.Equal(cipher, dest.Cipher) {
				t.Fatal("decoded value doesn't match the encoded one.")
			}
		})
	}
}

func TestCipherScan(t *testing.T) {
	c, err := EncodeString(AES256GCM.RandomKey(), "hello, world!")
	if err != nil {
		t.Fatal(err)
	}

	var dest = struct {
		Cipher Cipher
	}{}

	suites := map[bool][]byte{
		true:  c,
		false: []byte("not a valid ECE cipher"),
	}

	for result, cipher := range suites {
		t.Run(fmt.Sprintf("expected result: %v", result), func(t *testing.T) {
			err := dest.Cipher.Scan(cipher)
			if result != (err == nil) {
				t.Fatal(result, err)
			}

			if result && !bytes.Equal(cipher, dest.Cipher) {
				t.Fatal("decoded value doesn't match the encoded one.")
			}
		})
	}
}
