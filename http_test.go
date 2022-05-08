package ece

import (
	"bytes"
	"crypto/rand"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestResponseWriter(t *testing.T) {
	fn := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write(plain)
	}

	encoding, ok := encodingFromKeySize(key)
	if !ok {
		t.Fatal("unsupported encoding")
	}

	h := Handler(key, 25, http.HandlerFunc(fn))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(plain))
	req.Header.Add("Content-Encoding", encoding.Name)
	req.Header.Add("Accept-Encoding", encoding.Name)
	h.ServeHTTP(rec, req)
	resp := rec.Result()

	sent, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// Ensure the data sent is not the same as the one passed.
	assertNotEqual(t, "sent data", plain, sent)

	// Try to decrypt it
	r := NewReader(key, io.NopCloser(bytes.NewReader(sent)))
	received, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	assertEqual(t, "received data", plain, received)
}

// TestRequestBody sends a request with encrypted data,
// and expects the middleware to decrypt it transparently
// before it hits the handler.
func TestRequestBody(t *testing.T) {
	fn := func(w http.ResponseWriter, r *http.Request) {
		received, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}

		assertEqual(t, "request payload", plain, received)
	}

	encoding, ok := encodingFromKeySize(key)
	if !ok {
		t.Fatal("unsupported encoding")
	}

	h := Handler(key, 25, http.HandlerFunc(fn))
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encrypted))
	req.Header.Add("Content-Encoding", encoding.Name)
	req.Header.Add("Accept-Encoding", encoding.Name)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
}

func TestUnsupportedEncoding(t *testing.T) {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		io.Copy(w, r.Body)
	}

	h := Handler(key, 25, http.HandlerFunc(fn))
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encrypted))
	req.Header.Add("Content-Encoding", "invalid string")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	if wanted := http.StatusUnsupportedMediaType; wanted != resp.StatusCode {
		t.Fatal("invalid status code. Wanted:", wanted, "Got:", resp.StatusCode)
	}
}

func TestInvalidKey(t *testing.T) {
	fn := func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		io.Copy(w, r.Body)
	}

	h := Handler(key, 25, http.HandlerFunc(fn))
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(encrypted))
	req.Header.Add("Content-Encoding", "aes128gcm")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	resp := rec.Result()
	if wanted := http.StatusUnsupportedMediaType; wanted != resp.StatusCode {
		t.Fatal("invalid status code. Wanted:", wanted, "Got:", resp.StatusCode)
	}
}

func TestClient(t *testing.T) {
	encoding, ok := encodingFromKeySize(key)
	if !ok {
		t.Fatal("unsupported encoding")
	}

	plainText := make([]byte, 10240)
	if _, err := rand.Read(plainText); err != nil {
		t.Fatal(err)
	}

	fn := func(w http.ResponseWriter, r *http.Request) {
		ce := r.Header.Get("Content-Encoding")
		assertEqual(t, "Content-Encoding", []byte(ce), []byte(encoding.Name))

		// Payload should be plainText
		payload, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		assertEqual(t, "payload received", plainText, payload)

		// // Write plainText, with the expectation that it will be
		// // transparently encrypted.
		w.WriteHeader(http.StatusOK)
		w.Write(plainText)
	}
	h := Handler(key, 25, http.HandlerFunc(fn))
	server := httptest.NewServer(h)
	t.Cleanup(server.Close)

	client, err := NewClient("", key)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Post(server.URL, "application/json", bytes.NewReader(plainText))
	if err != nil {
		t.Fatal(err)
	}

	ce := resp.Header.Get("Content-Encoding")
	assertEqual(t, "Content-Encoding", []byte(ce), []byte(encoding.Name))

	received, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assertEqual(t, "received", plainText, received)
}

func ExampleHandler() {
	h := http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			// r.Body now contains plain data if the client sent
			// encrypted request.

			// w.Write will encrypt the data before sending
			// it back.
		},
	)

	var (
		key = []byte("256-bit long key")
		rs  = 4096
	)
	http.ListenAndServe(":8000", Handler(key, rs, h))
}

func ExampleClient() {
	var (
		keyID   = "ID of the key below" // (Empty string to omit)
		key     = []byte("16 or 32 byte long key")
		payload = strings.NewReader(`{"key": "value"}`)
	)

	c, err := NewClient(keyID, key)
	if err != nil {
		log.Fatalf("error initializing the client: %v", err)
	}

	resp, err := c.Post("https://api.example.com", "application/json", payload)
	if err != nil {
		log.Fatalf("HTTP request failed: %v", err)
	}

	// payload was encrypted before it was sent
	// resp.Body is decrypted if the server returned an encrypted response.
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("error reading response: %v", err)
	}

	log.Println(data) // plain data
}
