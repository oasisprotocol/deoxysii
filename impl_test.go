// Copyright (c) 2019 Oasis Labs Inc. <info@oasislabs.com>
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
//
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
// BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
// CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

package deoxysii

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/oasisprotocol/deoxysii/internal/api"
	"github.com/oasisprotocol/deoxysii/internal/ct32"
	"github.com/oasisprotocol/deoxysii/internal/ct64"
	"github.com/oasisprotocol/deoxysii/internal/hardware"
	"github.com/oasisprotocol/deoxysii/internal/vartime"
)

var testFactories = []api.Factory{
	ct64.Factory,
	ct32.Factory,
	vartime.Factory,
}

func TestImpl(t *testing.T) {
	oldFactory := factory
	defer func() {
		factory = oldFactory
	}()

	for _, testFactory := range testFactories {
		t.Run("Implementation_"+testFactory.Name(), func(t *testing.T) {
			factory = testFactory
			doTestImpl(t)
		})
	}
}

func doTestImpl(t *testing.T) {
	require := require.New(t)

	// New with a invalid key size should fail.
	var key [KeySize]byte
	aead, err := New(key[:KeySize-1])
	require.Nil(aead, "aead.New(): Truncated Key")
	require.Equal(ErrInvalidKeySize, err, "aead.New(): Truncated key")

	aead, err = New(key[:])
	require.NoError(err, "aead.New()")
	require.NotNil(aead, "aead.New()")

	// Seal with an invalid nonce size should panic.
	var nonce [NonceSize]byte
	require.Panics(func() {
		aead.Seal(nil, nonce[:NonceSize-1], nil, nil)
	}, "aead.Seal(): Truncated nonce")

	// Open with a invalid nonce size should fail.
	var ct [TagSize]byte
	b, err := aead.Open(nil, nonce[:NonceSize-1], ct[:], nil)
	require.Equal(ErrInvalidNonceSize, err, "aead.Open(): Truncated nonce")
	require.Nil(b, "aead.Open(): Truncated nonce")

	// Open with a invalid ciphertext || tag should fail.
	b, err = aead.Open(nil, nonce[:], ct[:TagSize-1], nil)
	require.Equal(ErrOpen, err, "aead.Open(): Truncated ciphertext")
	require.Nil(b, "aead.Open(): Truncated ciphertext")
}

func BenchmarkDeoxysII(b *testing.B) {
	oldFactory := factory
	defer func() {
		factory = oldFactory
	}()

	for _, testFactory := range testFactories {
		factory = testFactory
		doBenchmarkDeoxysII(b)
	}
}

func doBenchmarkDeoxysII(b *testing.B) {
	benchSizes := []int{8, 32, 64, 576, 1536, 4096, 1024768}

	for _, sz := range benchSizes {
		bn := "DeoxysII_" + factory.Name() + "_"
		sn := fmt.Sprintf("_%d", sz)
		b.Run(bn+"Encrypt"+sn, func(b *testing.B) { doBenchmarkAEADEncrypt(b, sz) })
		b.Run(bn+"Decrypt"+sn, func(b *testing.B) { doBenchmarkAEADDecrypt(b, sz) })
	}
}

func doBenchmarkAEADEncrypt(b *testing.B, sz int) {
	b.StopTimer()
	b.SetBytes(int64(sz))

	nonce, key := make([]byte, NonceSize), make([]byte, KeySize)
	m, c := make([]byte, sz), make([]byte, 0, sz+TagSize)
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(key)
	_, _ = rand.Read(m)
	aead, _ := New(key)

	b.StartTimer()
	for i := 0; i < b.N; i++ {
		c = c[:0]

		c = aead.Seal(c, nonce, m, nil)
		if len(c) != sz+TagSize {
			b.Fatalf("Seal failed")
		}
	}
}

func doBenchmarkAEADDecrypt(b *testing.B, sz int) {
	b.StopTimer()
	b.SetBytes(int64(sz))

	nonce, key := make([]byte, NonceSize), make([]byte, KeySize)
	m, c, d := make([]byte, sz), make([]byte, 0, sz+TagSize), make([]byte, 0, sz)
	_, _ = rand.Read(nonce)
	_, _ = rand.Read(key)
	_, _ = rand.Read(m)
	aead, _ := New(key)

	c = aead.Seal(c, nonce, m, nil)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		d = d[:0]

		var err error
		d, err = aead.Open(d, nonce, c, nil)
		if err != nil {
			b.Fatalf("Open failed")
		}
	}
	b.StopTimer()

	if !bytes.Equal(m, d) {
		b.Fatalf("Open output mismatch")
	}
}

func init() {
	if hardware.Factory != nil {
		testFactories = append([]api.Factory{hardware.Factory}, testFactories...)
	}
}
