package ece

import (
	"errors"
	"io"
	"log"
	"net/http"
)

// encodingFromKeySize returns the name of the encoding
// based on length of k.
func encodingFromKeySize(k []byte) (*Encoding, bool) {
	switch size := len(k) * 8; size {
	case AES256GCM.Bits:
		return AES256GCM, true
	case AES128GCM.Bits:
		return AES128GCM, true
	default:
		return nil, false
	}
}

// getContentEncoding returns the name of the encoding
// the request's data is encoded with according
// to the Content-Encoding.
//
// If an empty or unknown value if found instead,
// the returned string is empty.
func getContentEncoding(h http.Header) (*Encoding, bool) {
	for _, v := range h.Values("Content-Encoding") {
		encoding, _ := EncodingFromString(v)
		if encoding != nil {
			return encoding, true
		}
	}

	return nil, false
}

// getAcceptedEncoding returns the name of the encoding
// the user-agent accepts according to the
// Accept-Encoding header.
//
// If X-Accept-Encoding exist, it will be considered
// first.
//
// If an empty or unknown value if found instead,
// the returned string is empty.
func getAcceptedEncoding(h http.Header) (*Encoding, bool) {
	values := h.Values("X-Accept-Encoding")
	if len(values) == 0 {
		values = h.Values("Accept-Encoding")
	}

	for _, v := range values {
		encoding, _ := EncodingFromString(v)
		if encoding != nil {
			return encoding, true
		}
	}
	return nil, false
}

// ResponseWriter wraps a pre-existing http.ResponseWriter
// to add supports for encryption using ECE.
type ResponseWriter struct {
	encoding *Encoding
	ew       *Writer
	http.ResponseWriter
}

// Flush implements http.Flusher.
//
// Flush must be called in order for the data written
// to the underlying ResponseWriter to be formatted
// correctly.
func (w *ResponseWriter) Flush() {
	w.ew.Flush()
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// See the documentation for http.ResponseWriter.
func (w *ResponseWriter) Write(p []byte) (int, error) {
	return w.ew.Write(p)
}

// NewResponseWriter upgrades w to write ECE-encoded
// data in HTTP responses.
func NewResponseWriter(key []byte, recordSize int, w http.ResponseWriter) (*ResponseWriter, error) {
	encoding, ok := encodingFromKeySize(key)
	if !ok {
		return nil, errors.New("invalid key size")
	}

	ew, err := NewWriter(key, NewRandomSalt(), recordSize, "", w)
	if err != nil {
		return nil, err
	}
	w.Header().Add("Accept-Encoding", encoding.Name)
	w.Header().Add("Content-Encoding", encoding.Name)
	w.Header().Add("Vary", "Content-Encoding")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Add("Vary", "Content-Type")
	return &ResponseWriter{encoding: encoding, ew: ew, ResponseWriter: w}, nil
}

// Handler is an HTTP middleware that can transparently decrypt
// incoming requests and encrypt outgoing responses.
//
// Incoming requests are decrypted if their Content-Encoding
// header is either "aes128gcm" or "aes256gcm". Similarly,
// responses are encrypted if the the Accept-Encoding
// (or X-Accept-Encoding) header is set to either value.
//
// If the configured key doesn't match the encoding scheme
// announced in a request, the server will responds with
// status code 415 Unsupported Media Type.
func Handler(key []byte, recordSize int, h http.Handler) http.Handler {
	fn := func(w http.ResponseWriter, r *http.Request) {
		contentEncoding, ok := getContentEncoding(r.Header)
		if ok {
			if contentEncoding.checkKey(key) {
				r.Body = NewReader(key, r.Body)
			} else {
				w.WriteHeader(http.StatusUnsupportedMediaType)
			}
		}

		acceptedEncoding, ok := getAcceptedEncoding(r.Header)
		if ok && acceptedEncoding.checkKey(key) {
			rw, err := NewResponseWriter(key, recordSize, w)
			if err != nil {
				log.Printf("ece: failed to create a ResponseWriter : %v\n", err)
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			defer rw.Flush()
			defer rw.ew.Close()
			w = rw
		}

		h.ServeHTTP(w, r)
	}

	return http.HandlerFunc(fn)
}

// Client is a wrapper around http.Client, and handles
// the encryption of outgoing requests, and the
// decryption of responses.
//
// Requests are systematically encrypted, while responses
// are only decrypted if the Content-Encoding header is
// set to "aes128gcm" or "aes256gcm".
type Client struct {
	Strict   bool
	key      []byte
	keyID    string
	encoding *Encoding

	*http.Client
}

// Get issues a GET to the specified URL.
func (c *Client) Get(url string) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

// Post issues a POST to the specified URL.
func (c *Client) Post(url, contentType string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, url, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", contentType)
	return c.Do(req)
}

// hijackRequest modified req.Body to use an encrypter.
func (c *Client) hijackRequest(req *http.Request) error {
	r, err := Pipe(req.Body, c.key, 4096, c.keyID)
	if err != nil {
		return err
	}

	req.ContentLength = 0
	req.Body = r
	req.Header.Set("Content-Encoding", c.encoding.Name)
	return nil
}

// hijackResponse modifies resp.Body to use a decrypter.
func (c *Client) hijackResponse(resp *http.Response) error {
	resp.Body = NewReader(c.key, resp.Body)
	resp.ContentLength = 0
	return nil
}

// Do encrypts the content of req.Body before it's sent, and decrypts the
// content of resp.Body before it's read.
func (c *Client) Do(req *http.Request) (*http.Response, error) {
	if req.Body != nil {
		if err := c.hijackRequest(req); err != nil {
			return nil, err
		}
	}
	req.Header.Set("Accept-Encoding", c.encoding.Name)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	encoding, ok := getContentEncoding(resp.Header)
	if ok && encoding.checkKey(c.key) {
		if err := c.hijackResponse(resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// NewClient returns a new HTTP client capable of encoding
// and decoding ECE.
func NewClient(keyID string, key []byte) (*Client, error) {
	encoding, ok := encodingFromKeySize(key)
	if !ok {
		return nil, errors.New("invalid key size")
	}

	c := &Client{
		Client:   http.DefaultClient,
		keyID:    keyID,
		key:      key,
		encoding: encoding,
	}
	return c, nil
}
