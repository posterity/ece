package ece

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
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

func TestHeader(t *testing.T) {
	const (
		rs    = 621
		keyID = "Hello, World!"
	)
	h, err := NewHeader(salt, rs, keyID)
	if err != nil {
		t.Fatal(err)
	}

	data := make([]byte, 2048)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatal(err)
	}

	r := bytes.NewReader(append(h, data...))

	var got Header
	if _, err := got.ReadFrom(r); err != nil {
		t.Fatal(err)
	}

	assertEqual(t, "Salt", salt, h.Salt())

	if got := h.RecordSize(); rs != got {
		t.Fatal("rs doesn't match. Wanted:", rs, "Got:", got)
	}

	if got := h.idLength(); len(keyID) != got {
		t.Fatal("idLen doesn't match. Wanted:", len(keyID), "Got:", got)
	}

	if got := h.KeyID(); keyID != got {
		t.Fatal("keyID doesn't match. Wanted:", keyID, "Got:", got)
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

func TestReaderInvalidKey(t *testing.T) {
	data := make([]byte, 1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}

	var (
		k1  = AES256GCM.RandomKey()
		k2  = AES128GCM.RandomKey()
		buf = new(bytes.Buffer)
	)

	w, err := NewWriter(k1, salt, 4096, "", buf)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r := NewReader(k2, bytes.NewBuffer(buf.Bytes()))
	n, err := r.Read(make([]byte, 128))
	if err == nil {
		t.Fatal("expected an error")
	}
	if n > 0 {
		t.Fatal("expected bytes read to be zero")
	}
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

func ExamplePipe() {
	var plain io.ReadCloser

	r, err := Pipe(plain, key, 4096, "")
	if err != nil {
		log.Fatal(err)
	}

	http.Post("example.com", "application/octet/stream", r)

	// The HTTP POST request was sent with the content of plain
	// encrypted.
}
