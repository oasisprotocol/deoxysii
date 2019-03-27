// +build amd64,!noasm

package hardware

import (
	"crypto/subtle"

	"github.com/oasislabs/deoxysii/internal/api"
)

//
// AMD64 SSSE3 + AES-NI implementation.
//
// The assembly uses the following instructions over SSE2:
//  * PSHUFB (SSSE3)
//  * AESENC (AES-NI)
//

//go:noescape
func cpuid(params *uint32)

//go:noescape
func stkDeriveK(key *byte, derivedKs *[api.STKCount][api.STKSize]byte)

//go:noescape
func bcEncrypt(ciphertext *[api.BlockSize]byte, derivedKs *[api.STKCount][api.STKSize]byte, tweak *[api.TweakSize]byte, plaintext *[api.BlockSize]byte)

//go:noescape
func bcTag(tag *[16]byte, derivedKs *[api.STKCount][api.STKSize]byte, prefix byte, blockNr int, plaintext *byte, n int)

//go:noescape
func bcXOR(ciphertext *byte, derivedKs *[api.STKCount][api.STKSize]byte, tag *[16]byte, blockNr int, nonce *[16]byte, plaintext *byte, n int)

type aesniImpl struct{}

func (impl *aesniImpl) Name() string {
	return "aesni"
}

func (impl *aesniImpl) STKDeriveK(key []byte, derivedKs *[api.STKCount][api.STKSize]byte) {
	stkDeriveK(&key[0], derivedKs)
}

func (impl *aesniImpl) E(derivedKs *[api.STKCount][api.STKSize]byte, nonce, dst, ad, msg []byte) {
	var (
		auth [api.TagSize]byte
		i    int
	)

	// Associated data
	adLen := len(ad)
	if fullBlocks := adLen / api.BlockSize; fullBlocks > 0 {
		bcTag(&auth, derivedKs, api.PrefixADBlock, 0, &ad[0], fullBlocks)
		i += fullBlocks
		adLen -= fullBlocks * api.BlockSize
	}
	if adLen > 0 {
		var aStar [16]byte
		copy(aStar[:], ad[len(ad)-adLen:])
		aStar[adLen] = 0x80

		bcTag(&auth, derivedKs, api.PrefixADFinal, i, &aStar[0], 1)
	}

	// Message authentication and tag generation
	msgLen := len(msg)
	i = 0
	if fullBlocks := msgLen / api.BlockSize; fullBlocks > 0 {
		bcTag(&auth, derivedKs, api.PrefixMsgBlock, 0, &msg[0], fullBlocks)
		i += fullBlocks
		msgLen -= fullBlocks * api.BlockSize
	}
	if msgLen > 0 {
		var mStar [16]byte
		copy(mStar[:], msg[len(msg)-msgLen:])
		mStar[msgLen] = 0x80

		bcTag(&auth, derivedKs, api.PrefixMsgFinal, i, &mStar[0], 1)
	}

	// 20. tag <- Ek(0001||0000||N, tag)
	var encNonce [api.BlockSize]byte
	copy(encNonce[1:], nonce)
	encNonce[0] = api.PrefixTag << api.PrefixShift
	bcEncrypt(&auth, derivedKs, &encNonce, &auth)

	// Message encryption
	var encTag [api.TagSize]byte
	copy(encTag[:], auth[:])
	encTag[0] |= 0x80
	encNonce[0] = 0 // 0x00 || nonce

	msgLen, i = len(msg), 0
	if fullBlocks := msgLen / api.BlockSize; fullBlocks > 0 {
		bcXOR(&dst[0], derivedKs, &encTag, 0, &encNonce, &msg[0], fullBlocks)
		i += fullBlocks
		msgLen -= fullBlocks * api.BlockSize
	}
	if msgLen > 0 {
		var tmp [api.BlockSize]byte

		copy(tmp[:], msg[i*16:])
		bcXOR(&tmp[0], derivedKs, &encTag, i, &encNonce, &tmp[0], 1)
		copy(dst[i*16:], tmp[:])
	}

	// Append the tag.
	copy(dst[len(dst)-api.TagSize:], auth[:])
}

func (impl *aesniImpl) D(derivedKs *[api.STKCount][api.STKSize]byte, nonce, dst, ad, ct []byte) bool {
	// Split out ct into ciphertext and tag.
	ctLen := len(ct) - api.TagSize
	ciphertext, tag := ct[:ctLen], ct[ctLen:]

	// Message decryption.
	var (
		i        int
		decNonce [api.BlockSize]byte
		decTag   [api.TagSize]byte
	)
	copy(decNonce[1:], nonce)
	copy(decTag[:], tag)
	decTag[0] |= 0x80
	if fullBlocks := ctLen / api.BlockSize; fullBlocks > 0 {
		bcXOR(&dst[0], derivedKs, &decTag, 0, &decNonce, &ciphertext[0], fullBlocks)
		i += fullBlocks
		ctLen -= fullBlocks * api.BlockSize
	}
	if ctLen > 0 {
		var tmp [api.BlockSize]byte

		copy(tmp[:], ciphertext[i*16:])
		bcXOR(&tmp[0], derivedKs, &decTag, i, &decNonce, &tmp[0], 1)
		copy(dst[i*16:], tmp[:])
	}

	// Associated data.
	var auth [api.TagSize]byte
	adLen := len(ad)
	i = 0
	if fullBlocks := adLen / api.BlockSize; fullBlocks > 0 {
		bcTag(&auth, derivedKs, api.PrefixADBlock, i, &ad[0], fullBlocks)
		i += fullBlocks
		adLen -= fullBlocks * api.BlockSize
	}
	if adLen > 0 {
		var aStar [16]byte
		copy(aStar[:], ad[len(ad)-adLen:])
		aStar[adLen] = 0x80

		bcTag(&auth, derivedKs, api.PrefixADFinal, i, &aStar[0], 1)
	}

	// Message authentication and tag generation.
	msgLen := len(dst)
	i = 0
	if fullBlocks := msgLen / api.BlockSize; fullBlocks > 0 {
		bcTag(&auth, derivedKs, api.PrefixMsgBlock, i, &dst[0], fullBlocks)
		i += fullBlocks
		msgLen -= fullBlocks * api.BlockSize
	}
	if msgLen > 0 {
		var mStar [16]byte
		copy(mStar[:], dst[len(dst)-msgLen:])
		mStar[msgLen] = 0x80

		bcTag(&auth, derivedKs, api.PrefixMsgFinal, i, &mStar[0], 1)
	}

	// 29. tag' <- Ek(0001||0000||N, tag')
	decNonce[0] = api.PrefixTag << api.PrefixShift
	bcEncrypt(&auth, derivedKs, &decNonce, &auth)

	// Tag verification.
	return subtle.ConstantTimeCompare(tag, auth[:]) == 1
}

func cpuIsSupported() bool {
	const (
		ssse3Bit = 1 << 9
		aesBit   = 1 << 25
	)

	regs := [4]uint32{0x01}
	cpuid(&regs[0])
	if regs[2]&ssse3Bit == 0 {
		return false
	}
	if regs[2]&aesBit == 0 {
		return false
	}

	return true
}

func init() {
	if cpuIsSupported() {
		// Set the hardware impl.
		Impl = &aesniImpl{}
	}
}
