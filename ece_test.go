package ece

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"testing"
)

// MustDecodeB64 decodes str using base64.RawURLEncoding, or
// panics.
func MustDecodeB64(str string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(str)
	if err != nil {
		b, err = base64.RawStdEncoding.DecodeString(str)
		if err != nil {
			panic(err)
		}
	}
	return b
}

// assertEqual fails t if the bytes of wanted and got are not
// the same.
func assertEqual(t *testing.T, desc string, wanted, got []byte) {
	t.Helper()

	if !bytes.Equal(wanted, got) {
		t.Fatalf("%s → bytes are not equal", desc)
	}
}

// assertNotEqualssertEqual fails t if the bytes of wanted and got are not
// the same.
func assertNotEqual(t *testing.T, desc string, wanted, got []byte) {
	t.Helper()

	if bytes.Equal(wanted, got) {
		t.Fatalf("%s → bytes should not be equal", desc)
	}
}

const (
	nonceSize = 12
	keySize   = 16
)

// Test vectors from RFC8188 – Section 3
// https://datatracker.ietf.org/doc/html/rfc8188#section-3
var (
	plain          = []byte("I am the walrus")
	salt           = MustDecodeB64("I1BsxtFttlv3u_Oo94xnmw")
	prk            = MustDecodeB64("zyeH5phsIsgUyd4oiSEIy35x-gIi4aM7y0hCF8mwn9g")
	nonce          = MustDecodeB64("Bcs8gkIRKLI8GeI8")
	cek            = MustDecodeB64("_wniytB-ofscZDh4tbSjHw")
	key            = MustDecodeB64("yqdlZ-tYemfogSmv7Ws5PQ")
	encrypted      = MustDecodeB64("I1BsxtFttlv3u_Oo94xnmwAAEAAA-NAVub2qFgBEuQKRapoZu-IxkIva3MEB1PD-ly8Thjg")
	keyMulti       = MustDecodeB64("BO3ZVPxUlnLORbVGMpbT1Q")
	encryptedMulti = MustDecodeB64("uNCkWiNYzKTnBN9ji3-qWAAAABkCYTHOG8chz_gnvgOqdGYovxyjuqRyJFjEDyoF1Fvkj6hQPdPHI51OEUKEpgz3SsLWIqS_uA")
)

func TestComputePRK(t *testing.T) {
	got := computePRK(key, salt, keySize)
	assertEqual(t, "PRK", prk, got)
}

func TestDeriveCEK(t *testing.T) {
	got := deriveCEK(prk, keySize)
	assertEqual(t, "CEK", cek, got)
}

func TestDeriveNonce(t *testing.T) {
	got := deriveNonce(prk, bigZero, nonceSize)
	assertEqual(t, "Nonce", nonce, got)
}

func TestEncrypt(t *testing.T) {
	buf := new(bytes.Buffer)

	w, err := NewWriter(key, salt, 4096, "", buf)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	assertEqual(t, "cipher", encrypted, buf.Bytes())
}

func TestEncryptMultiRecord(t *testing.T) {
	buf := new(bytes.Buffer)

	w, err := NewWriter(MustDecodeB64("BO3ZVPxUlnLORbVGMpbT1Q"), MustDecodeB64("uNCkWiNYzKTnBN9ji3-qWA"), 25, "a1", buf)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}

	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r := NewReader(keyMulti, io.NopCloser(buf))
	got, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(t, "encrypt multi", plain, got)
}

func TestRead(t *testing.T) {
	r := bytes.NewReader(encrypted)
	dec := NewReader(key, io.NopCloser(r))

	got, err := io.ReadAll(dec)
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(t, "read", plain, got)
}

func TestReadMultiRecord(t *testing.T) {
	r := bytes.NewReader(encryptedMulti)
	dec := NewReader(keyMulti, io.NopCloser(r))

	got, err := io.ReadAll(dec)
	if err != nil {
		t.Fatal(err)
	}
	assertEqual(t, "read", plain, got)
}

// testEncryptDecrypt attempts to encrypt then decrypt
// the content of src.
func testEncryptDecrypt(t *testing.T, src []byte, rs int) {
	t.Helper()

	bufCipher := new(bytes.Buffer)
	w, err := NewWriter(key, salt, rs, "", bufCipher)
	if err != nil {
		t.Fatal(err)
	}

	io.Copy(w, bytes.NewReader(src))
	w.Flush()

	r := NewReader(key, io.NopCloser(bufCipher))
	plain, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(t, fmt.Sprintf("RS %d", rs), src, plain)
}

func TestLargeStream(t *testing.T) {
	randomBytes := make([]byte, 10240)
	if _, err := rand.Read(randomBytes); err != nil {
		t.Fatal(err)
	}

	t.Run("RS: 35", func(t *testing.T) {
		testEncryptDecrypt(t, randomBytes, 25)
	})
	t.Run("RS: 128", func(t *testing.T) {
		testEncryptDecrypt(t, randomBytes, 128)
	})
	t.Run("RS: 256", func(t *testing.T) {
		testEncryptDecrypt(t, randomBytes, 256)
	})
	t.Run("RS: 512", func(t *testing.T) {
		testEncryptDecrypt(t, randomBytes, 512)
	})
	t.Run("RS: 1024", func(t *testing.T) {
		testEncryptDecrypt(t, randomBytes, 1024)
	})
	t.Run("RS: 4096", func(t *testing.T) {
		testEncryptDecrypt(t, randomBytes, 4096)
	})
	t.Run("RS: 10240", func(t *testing.T) {
		testEncryptDecrypt(t, randomBytes, 10240)
	})
	t.Run("RS: 433", func(t *testing.T) {
		testEncryptDecrypt(t, randomBytes, 433)
	})
}

func ExampleReader() {
	var key []byte           // Main decryption key
	var cipher io.ReadCloser // AES-GCM encrypted data

	r := NewReader(key, cipher)
	plain, err := io.ReadAll(r)
	if err != nil {
		log.Fatalf("error during decryption: %v", err)
	}
	defer r.Close()

	fmt.Println(plain) // plain version of the content of cipher.
}

func ExampleWriter() {
	var key []byte     // Main decryption key
	var dest io.Writer // Where the encrypted data will be written

	var (
		salt       = NewRandomSalt()      // Must be random
		recordSize = 4096                 // Bytes per block in the cipher
		keyID      = "ID of the main key" // (Empty string to omit)
	)
	w, err := NewWriter(key, salt, recordSize, keyID, dest)
	if err != nil {
		log.Fatalf("error initializing writer: %v", err)
	}
	defer w.Close() // Cipher may be mis-formatted if omitted

	if _, err := io.WriteString(w, "Hello, World!"); err != nil {
		log.Fatalf("error writing cipher: %v", err)
	}

	log.Println("dest now contains encrypted data")
}
