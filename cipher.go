package ece

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
)

// Cipher represents an ECE-encoded cipher.
//
// Cipher is useful to validate a value parsed
// from using [json.Unmarshaler], or read
// from a database with [sql.Scanner].
type Cipher []byte

// UnmarshalJSON implements [json.Unmarshaler], and
// returns an error if b does not start with a valid
// ECE header.
func (c *Cipher) UnmarshalJSON(b []byte) error {
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	n, err := base64.StdEncoding.Decode(raw, bytes.Trim(b, `"`))
	if err != nil {
		return fmt.Errorf("value is not a valid quoted base64 string: %v", err)
	}
	raw = raw[:n]

	h := Header{}
	if _, err := h.ReadFrom(bytes.NewReader(raw)); err != nil {
		return fmt.Errorf("unable to read header: %v", err)
	}

	*c = raw
	return nil
}

// Scan implements [sql.Scanner] and returns an error
// if v is not a []byte that starts with a valid ECE header.
func (c *Cipher) Scan(src any) error {
	b, ok := src.([]byte)
	if !ok {
		return errors.New("value is not a valid []byte")
	}

	h := Header{}
	if _, err := h.ReadFrom(bytes.NewReader(b)); err != nil {
		return fmt.Errorf("unable to read header: %v", err)
	}

	*c = b
	return nil
}
