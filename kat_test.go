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
	err = ioutil.WriteFile(fn, jsonOut, 0600)
	require.NoError(err, "ioutil.WriteFile()")
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
//
// Note: The official vectors (dated 2019/06/08) list 128 bit nonces, the final
// byte of which has no impact on the output.  As this implementation strictly
// enforces nonce length, the nonces have been trucated as appropriate.
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
		Key:            mustDecodeHexString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
		Nonce:          mustDecodeHexString("202122232425262728292a2b2c2d2e"), // 2f
		AssociatedData: nil,
		Message:        nil,
		Sealed:         mustDecodeHexString("2b97bd77712f0cde975309959dfe1d7c"),
	},
	{
		Name:           "Test vector 2",
		Key:            mustDecodeHexString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
		Nonce:          mustDecodeHexString("202122232425262728292a2b2c2d2e"), // 2f
		AssociatedData: mustDecodeHexString("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f"),
		Message:        nil,
		Sealed:         mustDecodeHexString("54708ae5565a71f147bdb94d7ba3aed7"),
	},
	{
		Name:           "Test vector 3",
		Key:            mustDecodeHexString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
		Nonce:          mustDecodeHexString("202122232425262728292a2b2c2d2e"), // 2f
		AssociatedData: mustDecodeHexString("f495c9c03d29989695d98ff5d4306501 25805c1e0576d06f26cbda42b1f82238 b8"),
		Message:        nil,
		Sealed:         mustDecodeHexString("3277689dc4208cc1ff59d15434a1baf1"),
	},
	{
		Name:           "Test vector 4",
		Key:            mustDecodeHexString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
		Nonce:          mustDecodeHexString("202122232425262728292a2b2c2d2e"), // 2f
		AssociatedData: nil,
		Message:        mustDecodeHexString("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f"),
		Sealed:         mustDecodeHexString("9da20db1c2781f6669257d87e2a4d9be 1970f7581bef2c995e1149331e5e8cc1 92ce3aec3a4b72ff9eab71c2a93492fa"),
	},
	{
		Name:           "Test vector 5",
		Key:            mustDecodeHexString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
		Nonce:          mustDecodeHexString("202122232425262728292a2b2c2d2e"), // 2f
		AssociatedData: nil,
		Message:        mustDecodeHexString("15cd77732f9d0c4c6e581ef400876ad9 188c5b8850ebd38224da95d7cdc99f7a cc"),
		Sealed:         mustDecodeHexString("e5ffd2abc5b459a73667756eda6443ed e86c0883fc51dd75d22bb14992c68461 8c 5fa78d57308f19d0252072ee39df5ecc"),
	},
	{
		Name:           "Test vector 6",
		Key:            mustDecodeHexString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
		Nonce:          mustDecodeHexString("202122232425262728292a2b2c2d2e"), // 2f
		AssociatedData: mustDecodeHexString("000102030405060708090a0b0c0d0e0f"),
		Message:        mustDecodeHexString("000102030405060708090a0b0c0d0e0f 101112131415161718191a1b1c1d1e1f"),
		Sealed:         mustDecodeHexString("109f8a168b36dfade02628a9e129d525 7f03cc7912aefa79729b67b186a2b08f 6549f9bf10acba0a451dbb2484a60d90"),
	},
	{
		Name:           "Test vector 7",
		Key:            mustDecodeHexString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
		Nonce:          mustDecodeHexString("202122232425262728292a2b2c2d2e"), // 2f
		AssociatedData: mustDecodeHexString("000102030405060708090a0b0c0d0e0f 10"),
		Message:        mustDecodeHexString("422857fb165af0a35c03199fb895604d ca9cea6d788954962c419e0d5c225c03 27"),
		Sealed:         mustDecodeHexString("7d772203fa38be296d8d20d805163130 c69aba8cb16ed845c2296c61a8f34b39 4e 0b3f10e3933c78190b24b33008bf80e9"),
	},
	{
		Name:           "Test vector 8",
		Key:            mustDecodeHexString("101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"),
		Nonce:          mustDecodeHexString("202122232425262728292a2b2c2d2e"), // 2f
		AssociatedData: mustDecodeHexString("3290bb8441279dc6083a43e9048c3dc0 8966ab30d7a6b35759e7a13339f12491 8f3b5ab1affa65e6c0e3680eb33a6ec8 2424ab1ce5a40b8654e13d845c29b138 96a1466a75fc875acba4527ded37ed00 c600a357c9a6e586c74cf3d85cd3258c 813218f319d12b82480e5124ff19ec00 bda1fbb8bd25eeb3de9fcbf3296deba2 50caf7e9f4ef0be1918e24221dd0be88 8c59c166ad761d7b58462a1b1d44b042 65b45827172c133dd5b6c870b9af7b21 368d12a88f4efa1751047543d584382d 9ec22e7550d50ecddba27d1f65453f1f 3398de54ee8c1f4ac8e16f5523d89641 e99a632380af0f0b1e6b0e192ec29bf1 d8714978ff9fbfb93604142393e9a82c 3aaebbbe15e3b4e5cfd18bdfe309315c 9f9f830deebe2edcdc24f8eca90fda49 f6646e789c5041fb5be933fa843278e9 5f3a54f8eb41f14777ea949d5ea442b0 1249e64816151a325769e264ed4acd5c 3f21700ca755d5bc0c2c5f9453419510 bc74f2d71621dcecb9efc9c24791b4bb 560fb70a8231521d6560af89d8d50144 d9c080863f043781153bcd59030e60bd 17a6d7aa083211b67b581fa4f74cce4d 030d1e8f9429fd725c110040d41eb698 9ffb1595c72cbe3c9b78a8ab80d71a6a 5283da77b89cae295bb13c14fbe466b6 17f4da8ad60b085e2ea153f6713ae004 6aa31e0ba44e43ef36a111bf05c073a4 e3624cd35f63a546f9142b35aa81b882 6d"),
		Message:        mustDecodeHexString("83dab23b1379e090755c99079cfe918c b737e989f2d720ccaff493a744927644 fec3653211fa75306a83486e5c34ecfe 63870c97251a73e4b9033ae374809711 b211ed5d293a592e466a81170f1d8575 0b5ca025ccd4579947edbae9ec132bfb 1a7233ad79fae30006a6699f14389386 1b975226ed9d3cfb8a240be232fbf4e8 3755d59d20bc2faa2ea5e5b042842748 5cca5e76a89fe32bdd59ab4177ad7cb1 899c101e3c4f7535129591390ebdf301 40846078b13867bbb2efd6cf434afe35 6eb18d716b21fd664c26c908496534bf 2cde6d6b897799016594fb6d9f830ae5 f44ccec26d42ff0d1a21b80cdbe8c8c1 70a5f766fad884abcc781b5b8ebc0f55 9bfeaa4557b04d977d51411a7f47bf43 7d0280cf9f92bc4f9cd6226337a49232 0851955adae2cafea22a89c3132dd252 e4728328eda05555dff3241404341b8a a502d45c456113af42a8e91a85e4b4e9 555028982ec3d144722af0eb04a6d3b8 127c3040629de53f5fd187048198e8f8 e8cc857afcbae45c693fec12fc2149d5 e7587d0121b1717d0147f6979f75e8f0 85293f705c3399a6cc8df7057bf481e6 c374edf0a0af7479f858045357b7fe21 021c3fabdaf012652bf2e5db257bd949 0ce637a81477bd3f9814a2198fdb9afa 9344321f2393798670e588c47a1924d5 92cda3eb5a96754dfd92d87ee1ffa9d4 ee586c85d7518c5d2db57d0451c33de0"),
		Sealed:         mustDecodeHexString("88294fcef65a1bdfd7baaa472816c64e f5bef2622b88c1ec5a739396157ef493 5f3aa76449e391c32da28ee2857f399a c3dd95aed30cfb26cc0063cd4cd8f743 1108176fbf370123856662b000a8348e 5925fbb97c9ec0c737758330a7983f06 b51590c1d2f5e5faaf0eb58e34e19e5f c85cec03d3926dd46a79ba7026e83dec 24e07484c9103dd0cdb0edb505500cac a5e1d5dbc71348cf00648821488ebaab 7f9d84bbbf91b3c521dbef30110e7bd9 4f8dad5ab8e0cc5411ca9682d210d5d8 0c0c4bdbba8181789a4273d6deb80899 fdcd976ca6f3a9770b54305f586a0425 6cfbeb4c11254e88559f294db3b9a94b 80ab9f9a02cb4c0748de0af781868552 1691dba5738be546dba13a56016fb863 5af9dff50f25d1b17ad21707db2640a7 6a741e65e559b2afaaec0f37e18436bf 02008f84dbd7b2698687a22376b65dc7 524fca8a28709eee3f3caee3b28ed117 3d1e08ee849e2ca63d2c90d555755c8f bafd5d2f4b37f06a1dbd6852ee2ffcfe 79d510152e98fc4f3094f740a4aede9e e378b606d34576776bf5f1269f5385a8 4b3928433bfca177550ccfcd22cd0331 bbc595e38c2758b2662476fa66354c4e 84c7b360405aa3f5b2a48621bdca1a90 c69b21789c91b5b8c568e3c741d99e22 f6d7e26f2abed045f1d578b782ab4a5c f2af636d842b3012e180e4b045d8d15b 057b69c92398a517053daf9be7c2935e a616f0c218e18b526cf2a3f8c115e262"),
	},
}
