// Package ece provides support for reading and writing
// streams encoded using ECE (Encrypted-Content-Encoding) for HTTP,
// as defined in [RFC8188].
//
// Reader can read and decipher encrypted data, while Writer can be
// used to write a cipher into an underlying io.Writer.
//
// Client is an HTTP client capable of encrypting requests before they're sent,
// and decrypting responses as they're received.
//
// Handler is an HTTP middleware capable of transparently decrypting
// incoming requests and encrypting outgoing responses for clients that
// support it.
//
// # AES-GCM
//
// While [RFC8188] only mentions AES-128-GCM, this implementation extends it
// with support for 256-bit encryption (i.e. AES-256-GCM).
//
// Use 32-byte keys for AES-256-GCM, and 16-byte ones for AES-128-GCM.
//
//		key := ece.AES256GCM.RandomKey()
//		fmt.Println(len(key))
//
//	 -> 32
//
// # Record Size
//
// ECE encrypts data in chunks of predetermined length.
// The value can be anything above 17 characters,
// which corresponds to the AES-GCM tag length (16 bytes), plus a
// block-delimiter (1 byte).
//
// The ideal value depends on your use case. Smaller values create
// longer ciphers but require less memory to be
// decrypted, while larger values generate shorter ciphers, but
// require more memory for decryption.
//
// [RFC8188] recommends using multiples of 16.
//
// [RFC8188]: https://datatracker.ietf.org/doc/html/rfc8188
package ece // code.posterity.life/ece

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"strings"
	"unicode/utf8"
)

// Error represents an ECE-related error
// that occurred during decryption.
type Error struct {
	msg     string
	wrapped error
}

// Unwrap reveals the underlying error.
func (err *Error) Unwrap() error {
	return err.wrapped
}

// Error implements the error interface.
func (err *Error) Error() string {
	output := err.msg
	if err.wrapped != nil {
		output += ": " + err.wrapped.Error()
	}
	return output
}

// SaltLength as defined in RFC 8188.
const SaltLength int = 16

// Encoding represents a type of supported
// encoding.
type Encoding struct {
	Name string
	Bits int
}

// NewWriter returns a new writer for this encoding.
func (e *Encoding) NewWriter(key, salt []byte, recordSize int, keyID string, w io.Writer) (io.Writer, error) {
	if !e.checkKey(key) {
		return nil, errors.New("ece: invalid key size")
	}
	return NewWriter(key, salt, recordSize, keyID, w)
}

// NewReader returns a new reader for this encoding.
func (e *Encoding) NewReader(key []byte, r io.ReadCloser) (io.Reader, error) {
	if !e.checkKey(key) {
		return nil, errors.New("ece: invalid key size")
	}
	return NewReader(key, r), nil
}

// checkKey returns true if k is suitable for e.
func (e *Encoding) checkKey(k []byte) bool {
	return len(k) == (e.Bits / 8)
}

// RandomKey returns a random key suitable
// for this encoding. The function will panic
// if it can't generate random data using
// crypto/rand.
func (e *Encoding) RandomKey() []byte {
	k := make([]byte, e.Bits/8)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		panic(err)
	}
	return k
}

// String returns the name of e.
func (e *Encoding) String() string {
	return e.Name
}

// EncodingFromString returns the encoding that corresponds
// to the given string.
func EncodingFromString(encoding string) (*Encoding, bool) {
	switch strings.ToLower(encoding) {
	case AES128GCM.Name:
		return AES128GCM, true
	case AES256GCM.Name:
		return AES256GCM, true
	default:
		return nil, false
	}
}

// Supported encodings.
var (
	AES128GCM = &Encoding{"aes128gcm", 128}
	AES256GCM = &Encoding{"aes256gcm", 256}
)

// Constants defined in the RFC.
const (
	recordPadding        byte = 0x00
	recordDelimiter      byte = 0x01
	recordDelimiterFinal byte = 0x02
)

var (
	cekInfo   = append([]byte("Content-Encoding: aes128gcm"), 0x00, 0x01)
	nonceInfo = append([]byte("Content-Encoding: nonce"), 0x00, 0x01)
	bigZero   = new(big.Int).SetInt64(0)
	bigOne    = new(big.Int).SetInt64(1)
)

// NewRandomSalt returns a randomly generated salt
// (SaltLength bytes).
func NewRandomSalt() []byte {
	k := make([]byte, SaltLength)
	if _, err := rand.Read(k[:]); err != nil {
		panic(fmt.Errorf("unable to source random bytes: %v", err))
	}
	return k
}

// computePRK returns a pseudo-random key from the given
// key and salt.
//
// Formula:
//
//	HMAC-SHA-256 (salt, IKM)
func computePRK(key, salt []byte, length int) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(key)
	return h.Sum(nil)[:h.Size()]
}

// deriveCEK derives a content-encryption key
// from a master key.
//
// Formula:
//
//	CEK = HMAC-SHA-256(PRK, cek_info || 0x01)
func deriveCEK(prk []byte, length int) []byte {
	h := hmac.New(sha256.New, prk)
	h.Write(cekInfo)
	return h.Sum(nil)[:length]
}

// deriveNonce derives a nonce for a specific record in
// based on the PRK.
//
// Formula:
//
//	NONCE = HMAC-SHA-256(PRK, nonce_info || 0x01) XOR SEQ
func deriveNonce(prk []byte, sequence *big.Int, length int) []byte {
	h := hmac.New(sha256.New, prk)
	h.Write(nonceInfo)
	hashed := h.Sum(nil)[:length]

	seq := make([]byte, length)
	sequence.FillBytes(seq)

	nonce, err := xorBytes(hashed, seq)
	if err != nil {
		panic(err)
	}
	return nonce
}

const (
	rsLen = 4
	idLen = 1
)

var offsets = []int{
	SaltLength,
	SaltLength + rsLen,
	SaltLength + rsLen + idLen,
}

// Header represents the header of an encrypted
// message.
//
// Structure:
//
//	+-----------+--------+-----------+---------------+
//	| salt (16) | rs (4) | idLen (1) | keyID (idLen) |
//	+-----------+--------+-----------+---------------+
type Header []byte

// Salt returns the random salt in h.
func (h Header) Salt() []byte {
	return h[:offsets[0]]
}

// RecordSize returns the size of a single record
// in a message.
func (h Header) RecordSize() int {
	return int(binary.BigEndian.Uint32(h[offsets[0]:offsets[1]]))
}

// idLength returns the length of the KeyID
// string in the header.
func (h Header) idLength() int {
	return int(h[offsets[1]])
}

// KeyID returns the ID of the key used to
// encrypt a message.
func (h Header) KeyID() string {
	if h.idLength() == 0 {
		return ""
	}
	return string(h[offsets[2] : offsets[2]+h.idLength()])
}

// ReadFrom reads from r until the header h
// is fully formed.
//
// ReadFrom implements io.ReaderFrom.
func (h *Header) ReadFrom(r io.Reader) (n int64, err error) {
	const min = SaltLength + rsLen + idLen

	*h = make(Header, min)
	if read, err := io.ReadFull(r, *h); err != nil {
		n += int64(read)
		return n, err
	}

	if idLen := h.idLength(); idLen > 0 {
		keyID := make([]byte, idLen)
		if read, err := io.ReadFull(r, keyID); err != nil {
			n += int64(read)
			return n, err
		}
		*h = append(*h, keyID...)
	}

	return n, nil
}

// NewHeader returns a new encoding header with the given parameters.
func NewHeader(salt []byte, recordSize int, keyID string) (Header, error) {
	if len(salt) != SaltLength {
		return nil, fmt.Errorf("ece: salt length is %d bytes, but must be %d", len(salt), SaltLength)
	}
	if recordSize > math.MaxUint32 {
		return nil, fmt.Errorf("ece: record size cannot be larger than %d", math.MaxUint32)
	}
	if len(keyID) > math.MaxUint8 {
		return nil, fmt.Errorf("ece: keyID cannot be longer than %d bytes", math.MaxUint8)
	}

	rs := make([]byte, 4)
	binary.BigEndian.PutUint32(rs, uint32(recordSize))

	b := make([]byte, 0, len(salt)+4+1+len(keyID))
	b = append(b, salt...)
	b = append(b, rs...)

	b = append(b, uint8(utf8.RuneCount([]byte(keyID))))
	b = append(b, []byte(keyID)...)
	return b, nil
}

// Writer encrypts data before it's written to
// an underlying [io.Writer].
type Writer struct {
	gcm         cipher.AEAD
	prk         []byte
	header      Header
	w           io.Writer
	buf         []byte
	err         error
	contentSize int      // [record size] - [encryption overhead]
	seq         *big.Int // uint96
}

// ReadFrom copies the content of r into the writer using
// a buffer optimized for the configured record size.
func (e *Writer) ReadFrom(r io.Reader) (n int64, err error) {
	var (
		p  = make([]byte, e.contentSize)
		nn int
	)
	for {
		nn, err = r.Read(p[:])
		n += int64(nn)
		if err == nil {
			_, err = e.Write(p[:nn])
			if err != nil {
				break
			}
		} else if errors.Is(err, io.EOF) {
			err = nil
			break
		} else {
			break
		}
	}

	return
}

// encrypt returns the cipher of p.
func (e *Writer) encrypt(p []byte) ([]byte, error) {
	nonce := deriveNonce(e.prk, e.seq, e.gcm.NonceSize())
	return e.gcm.Seal(p[:0], nonce, p, nil), nil
}

// flush pushes data to the underlying writer.
func (e *Writer) flush(closing bool) (err error) {
	if e.err != nil {
		return e.err
	}
	defer func() {
		if err != nil {
			e.err = err
		}
	}()

	// Padding
	delimiter := recordDelimiter
	padding := e.header.RecordSize() - len(e.buf) - e.gcm.Overhead() - 1
	if closing {
		delimiter = recordDelimiterFinal
		padding = 0
	}
	e.buf = append(e.buf, delimiter)
	e.buf = append(e.buf, bytes.Repeat([]byte{recordPadding}, padding)...)

	// Record-size check
	if !closing && len(e.buf)+e.gcm.Overhead() != e.header.RecordSize() {
		return &Error{msg: "ece: invalid record length"}
	}

	e.buf, err = e.encrypt(e.buf)
	if err != nil {
		return
	}

	// Write the header if this is the first sequence.
	if e.seq.Cmp(bigZero) == 0 {
		if _, err = e.w.Write(e.header); err != nil {
			return
		}
	}

	if _, err = e.w.Write(e.buf); err != nil {
		return
	}

	e.buf = e.buf[:0]
	e.seq.Add(e.seq, bigOne)
	return
}

// Flush writes any currently buffered data to the
// underlying writer.
func (e *Writer) Flush() {
	e.err = e.flush(false)
}

// Write implements io.Writer.
func (e *Writer) Write(p []byte) (n int, err error) {
	if e.err != nil {
		err = e.err
		return
	}
	defer func() {
		if err != nil {
			e.err = err
		}
	}()

	left := len(p)
	for left > 0 {
		init := len(e.buf)
		avail := int(math.Min(float64(left), float64(e.contentSize-init)))

		pos := len(p) - left
		e.buf = append(e.buf, p[pos:pos+avail]...)
		left -= len(e.buf) - init

		if len(e.buf) == e.contentSize {
			err = e.flush(false)
			if err != nil {
				break
			}
		}
	}

	n = len(p) - left
	return
}

// Close Flushes any remaining data in the buffer, and tries
// to close the underlying writer if it implements io.Closer.
// It's an error to call Write() after calling Close().
func (e *Writer) Close() (err error) {
	if e.err != nil {
		return e.err
	}
	defer func() {
		if err != nil {
			e.err = err
		}
	}()

	err = e.flush(true)
	if err != nil {
		return
	}

	if c, ok := e.w.(io.Closer); ok {
		err = c.Close()
		if err != nil {
			return
		}
	}

	e.buf = nil
	e.header = nil
	e.err = errors.New("writer is closed")
	return
}

// NewWriter writes encrypted data into w.
func NewWriter(key, salt []byte, recordSize int, keyID string, w io.Writer) (*Writer, error) {
	header, err := NewHeader(salt, recordSize, keyID)
	if err != nil {
		return nil, err
	}

	prk := computePRK(key, header.Salt(), len(key))
	cek := deriveCEK(prk, len(key))

	ci, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(ci)
	if err != nil {
		return nil, err
	}

	contentSize := header.RecordSize() - gcm.Overhead() - 1 // delimiter
	if contentSize < 0 {
		return nil, &Error{msg: "record size cannot be smaller than the encryption and delimitation overhead"}
	}

	e := &Writer{
		gcm:         gcm,
		prk:         prk,
		header:      header,
		contentSize: contentSize,
		w:           w,
		seq:         new(big.Int),
		buf:         make([]byte, 0, header.RecordSize()),
	}
	return e, nil
}

// Reader decrypts data form an underlying
// [io.Reader].
type Reader struct {
	Header Header // nil until enough bytes are read

	gcm cipher.AEAD
	prk []byte
	key []byte
	r   io.Reader
	buf []byte
	seq *big.Int // uint96
	err error
}

// decrypt decrypts p using d.gcm.
func (d *Reader) decrypt(p []byte) ([]byte, error) {
	nonce := deriveNonce(d.prk, d.seq, d.gcm.NonceSize())
	return d.gcm.Open(p[:0], nonce, p, nil)
}

// readHeader performs multiple reads on r until the header is
// assembled.
func (d *Reader) readHeader() error {
	if _, err := d.Header.ReadFrom(d.r); err != nil {
		return err
	}

	prk := computePRK(d.key, d.Header.Salt(), len(d.key))
	cek := deriveCEK(prk, len(d.key))

	ci, err := aes.NewCipher(cek)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(ci)
	if err != nil {
		return err
	}

	d.prk = prk
	d.gcm = gcm
	d.seq = new(big.Int)
	d.buf = make([]byte, 0, d.Header.RecordSize())
	return nil
}

// read reads and decrypts one record from the underlying
// reader, and fill p with the deciphered data.
func (d *Reader) read(p []byte) (n int, err error) {
	if len(d.buf) > 0 {
		n = copy(p, d.buf)
		d.buf = d.buf[n:]
		return
	}

	if d.err != nil {
		return 0, d.err
	}
	defer func() {
		if err != nil {
			d.err = err
		}
	}()

	if d.Header == nil {
		if err := d.readHeader(); err != nil {
			err = &Error{msg: "ece: failed to read header", wrapped: err}
			return 0, err
		}
	}

	d.buf = make([]byte, d.Header.RecordSize())

	var nn int
	nn, err = io.ReadFull(d.r, d.buf)
	if err == io.ErrUnexpectedEOF {
		d.err = io.EOF
	} else if err != nil {
		return
	}

	// Decrypt
	d.buf, err = d.decrypt(d.buf[:nn])
	if err != nil {
		return
	}

	// Trim padding
	d.buf = bytes.TrimRight(d.buf, string(recordPadding))

	// Find and trim delimiter
	delimiter := d.buf[len(d.buf)-1]
	if delimiter == recordDelimiterFinal {
		d.err = io.EOF
	} else if delimiter != recordDelimiter {
		err = &Error{msg: "ece: missing record delimiter", wrapped: err}
		return
	}
	d.buf = d.buf[:len(d.buf)-1]

	n = copy(p, d.buf)
	d.buf = d.buf[n:]
	d.seq.Add(d.seq, bigOne)
	return
}

// Read implements io.Reader.
func (d *Reader) Read(p []byte) (n int, err error) {
	for n < len(p) && err == nil {
		var nn int
		nn, err = d.read(p[n:])
		n += nn
	}
	return
}

// WriteTo copies the content of d into dst using a buffer optimized
// for the record size declared in the header of the ECE cipher.
func (d *Reader) WriteTo(dst io.Writer) (n int64, err error) {
	if d.Header != nil {
		return 0, errors.New("invalid state")
	}
	if err = d.readHeader(); err != nil {
		return
	}

	var (
		p  = make([]byte, d.Header.RecordSize()-d.gcm.Overhead())
		nr int
	)
	for {
		nr, err = d.Read(p[:])
		if err != nil && !errors.Is(err, io.EOF) {
			break
		}

		nw, wErr := dst.Write(p[:nr])
		n += int64(nw)
		if wErr != nil {
			break
		}

		if errors.Is(err, io.EOF) {
			err = nil
			break
		}
	}

	return
}

// Close closes the underlying reader
// if it implements [io.Closer].
func (d *Reader) Close() error {
	if closer, ok := d.r.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

// NewReader deciphers data read from r.
func NewReader(key []byte, r io.Reader) *Reader {
	return &Reader{
		r:   r,
		key: key,
	}
}

// xorBytes returns an array containing
// the result of of a[i] XOR b[i].
func xorBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("ece: slices must be of equal length")
	}
	output := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		output[i] = a[i] ^ b[i]
	}
	return output, nil
}

// Pipe returns a reader from which the encrypted content in src
// can be read in clear.
//
// Pipe will read src until EOF is reached.
func Pipe(src io.Reader, key []byte, recordSize int, keyID string) (io.ReadCloser, error) {
	r, w := io.Pipe()
	ew, err := NewWriter(key, NewRandomSalt(), recordSize, keyID, w)
	if err != nil {
		return nil, err
	}

	go func() {
		if _, err := io.Copy(ew, src); err != nil {
			w.CloseWithError(err)
			return
		}
		w.CloseWithError(ew.Close())
	}()

	return r, nil
}

// EncodeString encodes the given string using the given key,
// and a random salt.
func EncodeString(key []byte, content string) ([]byte, error) {
	b := &bytes.Buffer{}
	w, err := NewWriter(key, NewRandomSalt(), 1024, "", b)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(w, content); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}
