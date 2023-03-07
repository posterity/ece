[![GoDoc reference](https://img.shields.io/badge/godoc-reference-blue.svg)](https://pkg.go.dev/code.posterity.life/ece)

# Encrypted-Content-Encoding for HTTP

This a Go implementation of
[RFC 8188](https://datatracker.ietf.org/doc/html/rfc8188), specifically the
draft published on June 2017.

ECE for HTTP defines a way to use standard HTTP content encoding to exchange
AES-GCM encrypted payloads between a client and server.

While the RFC only mentions 128-bit encryption with `AES-128-GCM`, this
library provides support for `AES-256-GCM` as well when a key sufficiently
long (32 bytes) is provided.

## Library

The library exposes 4 basic elements:

1. A `Reader` to decrypt;
2. A `Writer` to encrypt;
3. An HTTP middleware to handle server-side encryption/decryption;
4. An HTTP Client.

### Reader

`Reader` deciphers data from a reader (`io.Reader`) containing encrypted
data.

```go
var key []byte            // Main decryption key
var cipher io.ReadCloser  // AES-GCM encrypted data

r := ece.NewReader(key, cipher)
plain, err := io.ReadAll(r)
if err != nil {
  log.Fatalf("error during decryption: %v", err)
}
defer r.Close()

fmt.Println(plain) // plain version of the content of cipher.
```

### Writer

`Writer` writes encrypted data into another writer (`io.Writer`).

```go
var key = []byte("16 or 32 bytes long key")   // Main decryption key
var dest io.Writer                            // Where cipher will be written

var (
  salt        = ece.NewRandomSalt()     // Must be random
  recordSize  = 4096                    // Record size
  keyID       = "ID of the main key"    // (Empty string to omit)
)
w, err := ece.NewWriter(key, salt, recordSize, keyID, dest)
if err != nil {
  log.Fatalf("error initializing writer: %v", err)
}
defer w.Close()     // Cipher may be mis-formatted if omitted

if _, err := io.WriteString(w, "Hello, World!"); err != nil {
  log.Fatalf("error writing cipher: %v", err)
}

log.Println("dest now contains encrypted data")
```

### HTTP Handler

`Handler` is an HTTP middleware you can use to transparently
decrypt incoming requests and encrypt outgoing responses.

Incoming requests are decrypted if they come with a header `Content-Encoding`
set to either `aes128gcm` or `aes256gcm`. Similarly, responses are encrypted
if the request's `Accept-Encoding` or `X-Accept-Encoding` headers are set
to either value.

```go
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
http.ListenAndServe(":8000", ece.Handler(key, rs, h))
```

### HTTP Client

`Client` is a wrapper around `http.Client`, and handles the encryption of
outgoing requests, and the decryption of responses.

Requests are systematically encrypted, while responses are only decrypted if
the `Content-Encoding` header is set to `aes128gcm` or `aes256gcm`.

```go
var (
  keyID       = "ID of the key below"              // (Empty string to omit)
  key         = []byte("16 or 32 byte long key")
  payload     = strings.NewReader(`{"key": "value"}`)
)

c, err := ece.NewClient(keyID, key)
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
```

## Contributions

Contributions are welcome via Pull Requests.

## About us

What if you're hit by a bus tomorrow? [Posterity](https://posterity.life) helps
you make a plan in the event something happens to you.
