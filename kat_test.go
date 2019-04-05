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
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type knownAnswerTests struct {
	Name         string
	Key          []byte
	Nonce        []byte
	MsgData      []byte
	AADData      []byte
	KnownAnswers []*testVector
}

type testVector struct {
	Ciphertext []byte
	Tag        []byte
	Length     int
}

func mustDecodeHexString(s string) []byte {
	s = strings.Join(strings.Fields(s), "")
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestVectors(t *testing.T) {
	oldFactory := factory
	defer func() {
		factory = oldFactory
	}()

	// Known Answer Tests.
	for _, testFactory := range testFactories {
		t.Run("OfficialVectors_"+testFactory.Name(), func(t *testing.T) {
			factory = testFactory
			doTestOfficialVectors(t)
		})
		t.Run("KnownAnswerTest_"+testFactory.Name(), func(t *testing.T) {
			factory = testFactory
			validateTestVectorJSON(t, "./testdata/Deoxys-II-256-128.json")
		})
	}
}

func doTestOfficialVectors(t *testing.T) {
	require := require.New(t)
	for _, tc := range officialTestVectors {
		aead, err := New(tc.Key)
		require.NoError(err, "aead.New()")
		c := aead.Seal(nil, tc.Nonce, tc.Message, tc.AssociatedData)
		require.Equal(tc.Sealed, c, "%s", tc.Name)
	}
}

func validateTestVectorJSON(t *testing.T, fn string) {
	require := require.New(t)

	raw, err := ioutil.ReadFile(fn) //nolint:gosec
	require.NoError(err, "Read test vector JSON")

	var kats knownAnswerTests
	err = json.Unmarshal(raw, &kats)
	require.NoError(err, "Parse test vector JSON")

	aead, err := New(kats.Key)
	require.NoError(err, "aead.New()")
	require.Equal(NonceSize, aead.NonceSize(), "aead.NonceSize()")
	require.Equal(TagSize, aead.Overhead(), "aead.Overhead()")

	msg, aad := kats.MsgData, kats.AADData

	var (
		dst, expectedDst []byte
		off              int
	)
	for _, v := range kats.KnownAnswers {
		ptLen := v.Length
		m, a := msg[:ptLen], aad[:ptLen]

		expectedDst = append(expectedDst, v.Ciphertext...)
		expectedDst = append(expectedDst, v.Tag...)
		expectedC := expectedDst[off:]

		dst = aead.Seal(dst, kats.Nonce, m, a) // Append to dst
		c := dst[off:]
		require.Len(c, ptLen+TagSize, "Seal(): len(c) %d", ptLen)
		require.Equal(expectedC, c, "Seal(): %d", ptLen)

		p, err := aead.Open(nil, kats.Nonce, c, a)
		require.NoError(err, "Open(): %d", ptLen)
		require.Len(m, ptLen, "Open(): len(p) %d", ptLen)
		if len(p) != 0 {
			require.Equal(m, p, "Open(): p %d", ptLen)
		}

		// Test malformed ciphertext (or tag).
		badC := append([]byte{}, c...)
		badC[ptLen] ^= 0x23
		p, err = aead.Open(nil, kats.Nonce, badC, a)
		require.Error(err, "Open(Bad c): %d", ptLen)
		require.Nil(p, "Open(Bad c): len(p) %d", ptLen)

		// Test malformed AD.
		if ptLen > 0 {
			badA := append([]byte{}, a...)
			badA[ptLen-1] ^= 0x23
			p, err = aead.Open(nil, kats.Nonce, c, badA)
			require.Error(err, "Open(Bad a): %d", ptLen)
			require.Nil(p, "Open(Bad a): len(p) %d", ptLen)
		}

		off += len(c)
	}

	require.Equal(expectedDst, dst, "Final concatenated ciphertexts")
}

// Official test vectors, adapted to have the final form of ciphertext || tag.
//
// Taken from: https://sites.google.com/view/deoxyscipher/
var officialTestVectors = []struct {
	Name           string
	Key            []byte
	Nonce          []byte
	AssociatedData []byte
	Message        []byte
	Sealed         []byte
}{
	{
		Name:           "Test vector 1",
		Key:            mustDecodeHexString("0704010e0b0815121f1c192623202d2a3734313e3b3845424f4c495653505d5a"),
		Nonce:          mustDecodeHexString("100f0e0d0c0b0a0908070605040302"),
		AssociatedData: nil,
		Message:        nil,
		Sealed:         mustDecodeHexString("634bee5902050f86b0db27e0f65b0f57"),
	},
	{
		Name:           "Test vector 2",
		Key:            mustDecodeHexString("0704010e0b0815121f1c192623202d2a3734313e3b3845424f4c495653505d5a"),
		Nonce:          mustDecodeHexString("100f0e0d0c0b0a0908070605040302"),
		AssociatedData: mustDecodeHexString("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f"),
		Message:        nil,
		Sealed:         mustDecodeHexString("64e34124a47b44c7d8e877ad113d6299"),
	},
	{
		Name:           "Test vector 3",
		Key:            mustDecodeHexString("0704010e0b0815121f1c192623202d2a3734313e3b3845424f4c495653505d5a"),
		Nonce:          mustDecodeHexString("100f0e0d0c0b0a0908070605040302"),
		AssociatedData: mustDecodeHexString("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f 20"),
		Message:        nil,
		Sealed:         mustDecodeHexString("979e012954ccf163837137f3eeb405be"),
	},
	{
		Name:           "Test vector 4",
		Key:            mustDecodeHexString("0704010e0b0815121f1c192623202d2a3734313e3b3845424f4c495653505d5a"),
		Nonce:          mustDecodeHexString("100f0e0d0c0b0a0908070605040302"),
		AssociatedData: nil,
		Message:        mustDecodeHexString("101112131415161718191a1b1c1d1e1f 202122232425262728292a2b2c2d2e2f"),
		Sealed:         mustDecodeHexString("99bdd0382c1f2af08bef2636279c3c9b 747c7eaea80d87f2f5437f068cdc1165 fc85f698fb1d058c18c78d7f9097ec14"),
	},
	{
		Name:           "Test vector 5",
		Key:            mustDecodeHexString("0704010e0b0815121f1c192623202d2a3734313e3b3845424f4c495653505d5a"),
		Nonce:          mustDecodeHexString("100f0e0d0c0b0a0908070605040302"),
		AssociatedData: nil,
		Message:        mustDecodeHexString("101112131415161718191a1b1c1d1e1f 202122232425262728292a2b2c2d2e2f 30"),
		Sealed:         mustDecodeHexString("11b83586b6d988f83069adfc4291af24 3910c095657e4bb4340b95b77b1ed7a9 8d 6ab5e48c403623193b3e40dbf12616c5"),
	},
	{
		Name:           "Test vector 6",
		Key:            mustDecodeHexString("0704010e0b0815121f1c192623202d2a3734313e3b3845424f4c495653505d5a"),
		Nonce:          mustDecodeHexString("100f0e0d0c0b0a0908070605040302"),
		AssociatedData: mustDecodeHexString("000102030405060708090a0b0c0d0e0f"),
		Message:        mustDecodeHexString("101112131415161718191a1b1c1d1e1f 202122232425262728292a2b2c2d2e2f"),
		Sealed:         mustDecodeHexString("8c8de55536ac17ab4f9f06778f291f67 d2dafc679374049f06950ff065db4cc5 fe958f9e761478a462d7d89c64716cde"),
	},
	{
		Name:           "Test vector 7",
		Key:            mustDecodeHexString("0704010e0b0815121f1c192623202d2a3734313e3b3845424f4c495653505d5a"),
		Nonce:          mustDecodeHexString("100f0e0d0c0b0a0908070605040302"),
		AssociatedData: mustDecodeHexString("000102030405060708090a0b0c0d0e0f 10"),
		Message:        mustDecodeHexString("101112131415161718191a1b1c1d1e1f 202122232425262728292a2b2c2d2e2f 30"),
		Sealed:         mustDecodeHexString("2717f4821993ffe06ac8ef3e09b285c2 2500a9bb2bcc0672fcd5a1c46cff676d 2c c83f2f53fe04ced2849bffb471b206d6"),
	},
}
