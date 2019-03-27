// Package deoxysii implements the Deoxys-II-256-128 MRAE algorithm.
//
// See: https://competitions.cr.yp.to/round3/deoxysv141.pdf
package deoxysii

import (
	"crypto/cipher"
	"errors"

	"github.com/oasislabs/deoxysii/internal/api"
	"github.com/oasislabs/deoxysii/internal/ct64"
	"github.com/oasislabs/deoxysii/internal/hardware"
)

const (
	// KeySize is Deoxys-II-256-128 key size in bytes.
	KeySize = 32

	// NonceSize is the Deoxys-II-256-128 nonce size in bytes.
	NonceSize = 15

	// TagSize is the Deoxys-II-256-128 authentication tag size
	// in bytes.
	TagSize = 16
)

var (
	// ErrOpen is the error returned when the message authentication
	// fails durring an Open call.
	ErrOpen = errors.New("deoxysii: message authentication failure")

	errInvalidKeySize   = errors.New("deoxysii: invalid key size")
	errInvalidNonceSize = errors.New("deoxysii: invalid nonce size")

	impl api.Impl = ct64.Impl
)

type deoxysII struct {
	derivedKs [api.STKCount][api.STKSize]byte
}

// NonceSize returns the size of the nonce that must be passed to Seal
// and Open.
func (aead *deoxysII) NonceSize() int {
	return NonceSize
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (aead *deoxysII) Overhead() int {
	return TagSize
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and should be unique
// for all time, for a given key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
func (aead *deoxysII) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic(errInvalidNonceSize)
	}

	ret, out := sliceForAppend(dst, len(plaintext)+TagSize)
	impl.E(&aead.derivedKs, nonce, out, additionalData, plaintext)

	return ret
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (aead *deoxysII) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		return nil, errInvalidNonceSize
	}
	if len(ciphertext) < TagSize {
		return nil, ErrOpen
	}

	ret, out := sliceForAppend(dst, len(ciphertext)-TagSize)
	ok := impl.D(&aead.derivedKs, nonce, out, additionalData, ciphertext)
	if !ok {
		// Do not release unauthenticated plaintext.
		for i := range out {
			out[i] = 0
		}
		return nil, ErrOpen
	}

	return ret, nil
}

// Reset clears the AEAD instance such that no sensitive keying material
// remains in memory.
func (aead *deoxysII) Reset() {
	for i := range aead.derivedKs {
		for j := range aead.derivedKs[i] {
			aead.derivedKs[i][j] = 0
		}
	}
}

// New creates a new cipher.AEAD instance backed by Deoxys-II-256-128
// with the provided key.
func New(key []byte) cipher.AEAD {
	if len(key) != KeySize {
		panic(errInvalidKeySize)
	}

	aead := &deoxysII{}
	impl.STKDeriveK(key, &aead.derivedKs)

	return aead
}

var _ cipher.AEAD = (*deoxysII)(nil)

func init() {
	if hardware.Impl != nil {
		impl = hardware.Impl
	}
}
