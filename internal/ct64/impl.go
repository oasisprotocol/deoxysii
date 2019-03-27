// Package ct64 provides a portable constant time Deoxys-II-256-128 implementation
// intended for 64 bit processors.
//
// Performance is likely to be attrocious, as not much effort has been spent on
// optimization, under the view that it's unlikely to ever actually be really
// good without hardware accelerated AES.
package ct64

import (
	"crypto/subtle"

	"github.com/oasislabs/deoxysii/internal/api"
)

var Impl api.Impl = &ct64Impl{}

type ct64Impl struct{}

func (impl *ct64Impl) Name() string {
	return "ct64"
}

func (impl *ct64Impl) STKDeriveK(key []byte, derivedKs *[api.STKCount][api.STKSize]byte) {
	api.STKDeriveK(key, derivedKs)
}

func (impl *ct64Impl) E(derivedKs *[api.STKCount][api.STKSize]byte, nonce, dst, ad, msg []byte) {
	var (
		tweaks [4][api.TweakSize]byte
		i, j   int
	)

	// Associated data.
	adLen := len(ad)
	var auth [api.TagSize]byte
	for i = 0; adLen >= 4*api.BlockSize; i += 4 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADBlock, i)
		api.EncodeTagTweak(&tweaks[1], api.PrefixADBlock, i+1)
		api.EncodeTagTweak(&tweaks[2], api.PrefixADBlock, i+2)
		api.EncodeTagTweak(&tweaks[3], api.PrefixADBlock, i+3)

		bcTagx4(auth[:], derivedKs, &tweaks, ad[i*api.BlockSize:])
		adLen -= 4 * api.BlockSize
	}
	for ; adLen >= api.BlockSize; i++ {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADBlock, i)

		bcTagx1(auth[:], derivedKs, &tweaks[0], ad[i*api.BlockSize:])
		adLen -= api.BlockSize
	}
	if adLen > 0 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADFinal, i)

		var aStar [api.BlockSize]byte
		copy(aStar[:], ad[len(ad)-adLen:])
		aStar[adLen] = 0x80

		bcTagx1(auth[:], derivedKs, &tweaks[0], aStar[:])
	}

	// Message authentication and tag generation.
	msgLen := len(msg)
	tag := auth[:]
	for j = 0; msgLen >= 4*api.BlockSize; j += 4 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgBlock, j)
		api.EncodeTagTweak(&tweaks[1], api.PrefixMsgBlock, j+1)
		api.EncodeTagTweak(&tweaks[2], api.PrefixMsgBlock, j+2)
		api.EncodeTagTweak(&tweaks[3], api.PrefixMsgBlock, j+3)

		bcTagx4(tag, derivedKs, &tweaks, msg[j*api.BlockSize:])
		msgLen -= 4 * api.BlockSize
	}
	for ; msgLen >= api.BlockSize; j++ {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgBlock, j)

		bcTagx1(tag, derivedKs, &tweaks[0], msg[j*api.BlockSize:])
		msgLen -= api.BlockSize
	}
	if msgLen > 0 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgFinal, j)

		var mStar [api.BlockSize]byte
		copy(mStar[:], msg[len(msg)-msgLen:])
		mStar[msgLen] = 0x80

		bcTagx1(tag, derivedKs, &tweaks[0], mStar[:])
	}

	// Generate the tag.
	var encNonce [api.BlockSize]byte
	copy(encNonce[1:], nonce)
	encNonce[0] = api.PrefixTag << api.PrefixShift
	bcEncrypt(tag, derivedKs, &encNonce, tag)

	// Message encryption.
	encNonce[0] = 0 // 0x00 || nonce

	var encBlks [4 * api.BlockSize]byte
	c := dst[0:]
	msgLen = len(msg)
	for j = 0; msgLen >= 4*api.BlockSize; j += 4 {
		api.EncodeEncTweak(&tweaks[0], tag, j)
		api.EncodeEncTweak(&tweaks[1], tag, j+1)
		api.EncodeEncTweak(&tweaks[2], tag, j+2)
		api.EncodeEncTweak(&tweaks[3], tag, j+3)

		bcKeystreamx4(encBlks[:], derivedKs, &tweaks, &encNonce)
		api.XORBytes(c[j*api.BlockSize:], msg[j*api.BlockSize:], encBlks[:], len(encBlks))
		msgLen -= 4 * api.BlockSize
	}
	for ; msgLen >= api.BlockSize; j++ {
		api.EncodeEncTweak(&tweaks[0], tag, j)

		bcEncrypt(encBlks[:api.BlockSize], derivedKs, &tweaks[0], encNonce[:])
		api.XORBytes(c[j*api.BlockSize:], msg[j*api.BlockSize:], encBlks[:api.BlockSize], api.BlockSize)
		msgLen -= api.BlockSize
	}
	if msgLen > 0 {
		api.EncodeEncTweak(&tweaks[0], tag, j)

		bcEncrypt(encBlks[:api.BlockSize], derivedKs, &tweaks[0], encNonce[:])
		api.XORBytes(c[j*api.BlockSize:], msg[j*api.BlockSize:], encBlks[:api.BlockSize], msgLen)
	}

	// Append the tag.
	copy(dst[len(dst)-api.TagSize:], tag)
}

func (impl *ct64Impl) D(derivedKs *[api.STKCount][api.STKSize]byte, nonce, dst, ad, ct []byte) bool {
	// Split out ct into ciphertext and tag.
	ctLen := len(ct) - api.TagSize
	ciphertext, tag := ct[:ctLen], ct[ctLen:]

	var (
		tweaks   [4][api.TweakSize]byte
		decNonce [api.BlockSize]byte
		j        int
	)

	// Message decryption.
	copy(decNonce[1:], nonce)
	var decTweaks [4][api.TweakSize]byte
	var decBlks [4 * api.BlockSize]byte
	for j = 0; ctLen >= 4*api.BlockSize; j += 4 {
		api.EncodeEncTweak(&decTweaks[0], tag, j)
		api.EncodeEncTweak(&decTweaks[1], tag, j+1)
		api.EncodeEncTweak(&decTweaks[2], tag, j+2)
		api.EncodeEncTweak(&decTweaks[3], tag, j+3)

		bcKeystreamx4(decBlks[:], derivedKs, &decTweaks, &decNonce)
		api.XORBytes(dst[j*api.BlockSize:], ciphertext[j*api.BlockSize:], decBlks[:], len(decBlks))
		ctLen -= 4 * api.BlockSize
	}
	for ; ctLen >= api.BlockSize; j++ {
		api.EncodeEncTweak(&decTweaks[0], tag, j)

		bcEncrypt(decBlks[:api.BlockSize], derivedKs, &decTweaks[0], decNonce[:])
		api.XORBytes(dst[j*api.BlockSize:], ciphertext[j*api.BlockSize:], decBlks[:api.BlockSize], api.BlockSize)
		ctLen -= api.BlockSize
	}
	if ctLen > 0 {
		api.EncodeEncTweak(&decTweaks[0], tag, j)
		bcEncrypt(decBlks[:api.BlockSize], derivedKs, &decTweaks[0], decNonce[:])
		api.XORBytes(dst[j*api.BlockSize:], ciphertext[j*api.BlockSize:], decBlks[:api.BlockSize], ctLen)
	}

	// Associated data.
	adLen := len(ad)
	var (
		auth [api.TagSize]byte
		i    int
	)
	for i = 0; adLen >= 4*api.BlockSize; i += 4 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADBlock, i)
		api.EncodeTagTweak(&tweaks[1], api.PrefixADBlock, i+1)
		api.EncodeTagTweak(&tweaks[2], api.PrefixADBlock, i+2)
		api.EncodeTagTweak(&tweaks[3], api.PrefixADBlock, i+3)

		bcTagx4(auth[:], derivedKs, &tweaks, ad[i*api.BlockSize:])
		adLen -= 4 * api.BlockSize
	}
	for ; adLen >= api.BlockSize; i++ {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADBlock, i)

		bcTagx1(auth[:], derivedKs, &tweaks[0], ad[i*api.BlockSize:])
		adLen -= api.BlockSize
	}
	if adLen > 0 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixADFinal, i)

		var aStar [api.BlockSize]byte
		copy(aStar[:], ad[len(ad)-adLen:])
		aStar[adLen] = 0x80

		bcTagx1(auth[:], derivedKs, &tweaks[0], aStar[:])
	}

	// Message authentication and tag generation.
	msgLen := len(dst)
	tagP := auth[:]
	for j = 0; msgLen >= 4*api.BlockSize; j += 4 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgBlock, j)
		api.EncodeTagTweak(&tweaks[1], api.PrefixMsgBlock, j+1)
		api.EncodeTagTweak(&tweaks[2], api.PrefixMsgBlock, j+2)
		api.EncodeTagTweak(&tweaks[3], api.PrefixMsgBlock, j+3)

		bcTagx4(tagP, derivedKs, &tweaks, dst[j*api.BlockSize:])
		msgLen -= 4 * api.BlockSize
	}
	for ; msgLen >= api.BlockSize; j++ {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgBlock, j)

		bcTagx1(tagP, derivedKs, &tweaks[0], dst[j*api.BlockSize:])
		msgLen -= api.BlockSize
	}
	if msgLen > 0 {
		api.EncodeTagTweak(&tweaks[0], api.PrefixMsgFinal, j)

		var mStar [api.BlockSize]byte
		copy(mStar[:], dst[len(dst)-msgLen:])
		mStar[msgLen] = 0x80

		bcTagx1(tagP, derivedKs, &tweaks[0], mStar[:])
	}

	// Generate the re-calculated tag.
	decNonce[0] = api.PrefixTag << api.PrefixShift
	bcEncrypt(tagP, derivedKs, &decNonce, tagP)

	// Tag verification.
	return subtle.ConstantTimeCompare(tag, tagP) == 1
}
