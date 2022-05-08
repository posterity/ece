// Package ece provides support for reading and writing
// streams encoded using ECE (Encrypted-Content-Encoding) for HTTP,
// as defined in RFC 8188.
//
// Reader can read and decipher encrypted data, while Writer can be
// used to write a cipher into an underlying io.Writer.
//
// Client is an HTTP client capable of encryption requests before they're sent,
// and decrypting responses before they're read.
//
// Handler is an HTTP middleware capable of transparently decrypting
// incoming requests, and encryption outgoing responses.
//
//
// AES-GCM
//
// RFC 8188 only mentions AES-128-GCM as the encryption algorithm of
// choice. However, this implementation extends it by supporting 256-bit
// encryption as well. The only difference from a developer experience is
// the length of the key you must provide.
//
// For AES-256-GCM, the key must be 32 bytes long.
//
// For AES-128-GCM, the key must be 16 bytes long.
//
//
// Record Size
//
// ECE encrypts data in chunks of predetermined length.
// The value can be anything above 17 characters,
// which corresponds to the AES GCM tag length, plus a
// block-delimiter.
//
// The ideal value depends on your use case. Smaller values are
// create larger ciphers but require very little memory to be
// decrypted. Larger values are more efficient, but require more
// memory.
//
// Multiples of 16 are recommended.
package ece

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

// Error represents a ECE-related error
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
// encodings
type Encoding struct {
	Name string
	Bits int
}

// checkKey returns true if k is suitable
// for e.
func (e *Encoding) checkKey(k []byte) bool {
	return len(k) == (e.Bits / 8)
}

// RandomKey returns a random key suitable
// for this encoding. The method will panic
// if it can't generate random data.
func (e *Encoding) RandomKey() []byte {
	k := make([]byte, e.Bits/8)
	if _, err := rand.Read(k); err != nil {
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
	rand.Read(k[:])
	return k
}

// computePRK returns a pseudo-random key from the given
// key and salt.
//
// Formula:
// 	HMAC-SHA-256 (salt, IKM)
func computePRK(key, salt []byte, length int) []byte {
	h := hmac.New(sha256.New, salt)
	h.Write(key)
	return h.Sum(nil)[:h.Size()]
}

// deriveCEK derives a content-encryption key
// from a master key.
//
// Formula:
// 	CEK = HMAC-SHA-256(PRK, cek_info || 0x01)
func deriveCEK(prk []byte, length int) []byte {
	h := hmac.New(sha256.New, prk)
	h.Write(cekInfo)
	return h.Sum(nil)[:length]
}

// deriveNonce derives a nonce for a specific record in
// based on the PRK.
//
// Formula:
// 	NONCE = HMAC-SHA-256(PRK, nonce_info || 0x01) XOR SEQ
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

// Header represents the header of an encrypted
// message.
//
// Structure:
// 	+-----------+--------+-----------+---------------+
// 	| salt (16) | rs (4) | idlen (1) | keyid (idlen) |
// 	+-----------+--------+-----------+---------------+
type Header []byte

// Salt returns the random salt in h.
func (h Header) Salt() []byte {
	return h[0:SaltLength]
}

// RecordSize returns the size of a single record
// in a message.
func (h Header) RecordSize() int {
	return int(binary.BigEndian.Uint32(h[SaltLength : SaltLength+4]))
}

// IDLength returns the length of the KeyID
// string in the header.
func (h Header) IDLength() int {
	return int(h[SaltLength+4])
}

// KeyID returns the ID of the key used to
// encrypt a message.
func (h Header) KeyID() string {
	if h.IDLength() == 0 {
		return ""
	}
	return string(h[SaltLength+5 : SaltLength+5+h.IDLength()])
}

// NewHeader returns a new encoding header with the given parameters.
func NewHeader(salt []byte, recordSize int, keyID string) (Header, error) {
	if len(salt) != SaltLength {
		return nil, fmt.Errorf("ece: salt length is %d, but should be %d", len(salt), SaltLength)
	}
	if recordSize > math.MaxUint32 {
		return nil, fmt.Errorf("ece: record size cannot be larger than %d", math.MaxUint32)
	}
	if len(keyID) > math.MaxUint8 {
		return nil, fmt.Errorf("ece: keyID cannot be longer than larger than %d bytes", math.MaxUint8)
	}

	rb := make([]byte, 4)
	binary.BigEndian.PutUint32(rb, uint32(recordSize))

	b := make([]byte, 0, len(salt)+4+1+len(keyID))
	b = append(b, salt...)
	b = append(b, rb...)

	b = append(b, uint8(utf8.RuneCount([]byte(keyID))))
	b = append(b, []byte(keyID)...)
	return b, nil
}

// Writer implements a io.Writer that can
// write ECE-formatted encrypted content to
// an underlying writer.
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

	if len(e.buf) == 0 {
		return nil
	}

	// Padding
	delimiter := recordDelimiter
	padding := e.header.RecordSize() - len(e.buf) - e.gcm.Overhead() - 1
	if closing {
		delimiter = recordDelimiterFinal
		padding = 0
	}
	e.buf = append(e.buf, delimiter)
	e.buf = append(e.buf, bytes.Repeat([]byte{recordPadding}, padding)...)

	// Padding check
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

// Flush writes the data currently in the buffer to the
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

// Reader implements an io.Reader that can
// decipher ECE data from an underlying reader.
type Reader struct {
	// Only available after enough
	// data has been read (minimum 21 bytes)
	Header Header

	gcm                cipher.AEAD
	prk                []byte
	key                []byte
	r                  io.ReadCloser
	buf                []byte
	seq                *big.Int // uint96
	reachedFinalRecord bool
	err                error
}

// decrypt decrypts p using d.gcm.
func (d *Reader) decrypt(p []byte) ([]byte, error) {
	nonce := deriveNonce(d.prk, d.seq, d.gcm.NonceSize())
	return d.gcm.Open(p[:0], nonce, p, nil)
}

// readHeader performs multiple reads on r until the header is
// assembled.
func (d *Reader) readHeader() error {
	// Read Salt, RecordSize and IDLength
	fixed := SaltLength + 4 + 1
	d.Header = make(Header, fixed)
	if _, err := io.ReadFull(d.r, d.Header); err != nil {
		return err
	}

	// Read KeyID
	if d.Header.IDLength() > 0 {
		keyID := make([]byte, d.Header.IDLength())
		_, err := io.ReadFull(d.r, keyID)
		if err != nil {
			return err
		}
		d.Header = append(d.Header, keyID...)
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

	if d.reachedFinalRecord {
		err = io.EOF
		return
	}

	if d.gcm == nil {
		if err := d.readHeader(); err != nil {
			err = &Error{msg: "ece: failed to read header", wrapped: err}
			return 0, err
		}
	}

	d.buf = make([]byte, d.Header.RecordSize())
	n, err = io.ReadFull(d.r, d.buf)
	if err == io.ErrUnexpectedEOF {
		d.err = io.EOF
		d.reachedFinalRecord = true
	} else if err != nil {
		return
	}

	// Decrypt
	d.buf, err = d.decrypt(d.buf[:n])
	if err != nil {
		return
	}

	// Trim padding
	d.buf = bytes.TrimRight(d.buf, string(recordPadding))

	// Find and trim delimiter
	delimiter := d.buf[len(d.buf)-1]
	if delimiter == recordDelimiterFinal {
		d.reachedFinalRecord = true
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

// Close closes the underlying reader if it implements
// http.
func (d *Reader) Close() error {
	return d.r.Close()
}

// NewReader deciphers data from r.
func NewReader(key []byte, r io.ReadCloser) *Reader {
	return &Reader{
		r:                  r,
		key:                key,
		reachedFinalRecord: false,
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
