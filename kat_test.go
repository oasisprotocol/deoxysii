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
	"os"
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

func katInputs() (msg, aad []byte) {
	msg = make([]byte, 256)
	aad = make([]byte, 256)

	for i := range msg {
		msg[i] = byte(255 & (i*197 + 123))
	}
	for i := range aad {
		aad[i] = byte(255 & (i*193 + 123))
	}

	return
}

func ctorInputs() (key, nonce []byte) {
	key = make([]byte, KeySize)
	nonce = make([]byte, NonceSize)

	for i := range key {
		key[i] = byte(255 & (i*191 + 123))
	}
	for i := range nonce {
		nonce[i] = byte(255 & (i*181 + 123))
	}

	return
}

func generateKAT(t *testing.T, fn string) {
	require := require.New(t)

	msg, aad := katInputs()
	key, nonce := ctorInputs()

	katOut := &knownAnswerTests{
		Name:    "Deoxys-II-256-128",
		MsgData: msg,
		AADData: aad,
		Key:     key,
		Nonce:   nonce,
	}

	aead, err := New(katOut.Key)
	require.NoError(err, "aead.New()")

	for i := range msg {
		ct := aead.Seal(nil, nonce, msg[:i], aad[:i])

		// Assume that ct = ciphertext | tag.
		tag := ct[i:]
		ct = ct[:i]

		vec := &testVector{
			Ciphertext: ct,
			Tag:        tag,
			Length:     i,
		}

		katOut.KnownAnswers = append(katOut.KnownAnswers, vec)
	}

	jsonOut, _ := json.Marshal(&katOut)
	err = ioutil.WriteFile(fn, jsonOut, 0o600)
	require.NoError(err, "ioutil.WriteFile()")
}

func TestVectors(t *testing.T) {
	const testDataFile = "./testdata/Deoxys-II-256-128.json"

	oldFactory := factory
	defer func() {
		factory = oldFactory
	}()

	doRegenerate := os.Getenv("DEOXYSII_REGENERATE_KAT") != ""

	// Known Answer Tests.
	for idx, testFactory := range testFactories {
		t.Run("OfficialVectors_"+testFactory.Name(), func(t *testing.T) {
			factory = testFactory
			doTestOfficialVectors(t)
		})
		t.Run("KnownAnswerTest_"+testFactory.Name(), func(t *testing.T) {
			if doRegenerate {
				t.Skip("regenerate mode")
			}
			factory = testFactory
			validateTestVectorJSON(t, testDataFile)
		})
		if doRegenerate && idx == 0 {
			t.Run("KnownAnswerTest-REGENERATE_"+testFactory.Name(), func(t *testing.T) {
				factory = testFactory
				generateKAT(t, testDataFile)
			})
		}
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
//
// Note: The official vectors (dated 2019/06/08) list 128 bit nonces, the final
// byte of which has no impact on the output.  As this implementation strictly
// enforces nonce length, the nonces have been trucated as appropriate.
type officialTestVector struct {
	Name           string
	Key            string
	Nonce          string
	AssociatedData string
	Message        string
	Sealed         string
}

func doTestOfficialVectors(t *testing.T) {
	require := require.New(t)

	raw, err := ioutil.ReadFile("testdata/Deoxys-II-256-128-official-20190608.json")
	require.NoError(err, "Read test vector JSON")

	var vectors []officialTestVector
	err = json.Unmarshal(raw, &vectors)
	require.NoError(err, "Parse test vector JSON")

	hexToByte := func(s string) []byte {
		b, hexErr := hex.DecodeString(s)
		require.NoError(hexErr, "Decode hex encoded test data")
		if len(b) == 0 {
			return nil
		}
		return b
	}

	for _, tc := range vectors {
		aead, err := New(hexToByte(tc.Key))
		require.NoError(err, "aead.New()")

		nonce := hexToByte(tc.Nonce)
		msg := hexToByte(tc.Message)
		aad := hexToByte(tc.AssociatedData)
		sealed := hexToByte(tc.Sealed)

		c := aead.Seal(nil, nonce, msg, aad)
		require.Equal(sealed, c, "%s - Seal", tc.Name)

		p, err := aead.Open(nil, nonce, sealed, aad)
		require.NoError(err, "%s - Open", tc.Name)
		require.Equal(msg, p, "%s - Open", tc.Name)
	}
}
