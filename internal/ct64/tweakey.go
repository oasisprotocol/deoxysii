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

package ct64

import (
	aes "git.schwanenlied.me/yawning/bsaes.git/ct64"

	"github.com/oasislabs/deoxysii/internal/api"
)

// Note: This is trivial to accelerate with vector ops.  Performance
// will likely be horrific without such things.  At the point where
// there's a vector unit, it's worth doing a vectorized AES
// implementation too.

func deriveSubTweakKeysx1(stks *[api.STKCount][8]uint64, derivedKs *[api.STKCount][api.STKSize]byte, t *[api.TweakSize]byte) {
	var tk1, tmp [api.STKSize]byte

	copy(tk1[:], t[:])
	api.XORBytes(tmp[:], derivedKs[0][:], tk1[:], api.STKSize)
	aes.Load4xU32(&stks[0], tmp[:])

	for i := 1; i <= api.Rounds; i++ {
		api.H(&tk1)
		api.XORBytes(tmp[:], derivedKs[i][:], tk1[:], api.STKSize)
		aes.Load4xU32(&stks[i], tmp[:])
	}

	api.Bzero(tk1[:])
	api.Bzero(tmp[:])
}

func deriveSubTweakKeysx4(stks *[api.STKCount][8]uint64, derivedKs *[api.STKCount][api.STKSize]byte, t *[4][api.TweakSize]byte) {
	var tk1, tmp [4][api.STKSize]byte

	for i := range t {
		copy(tk1[i][:], t[i][:])
		api.XORBytes(tmp[i][:], derivedKs[0][:], tk1[i][:], api.STKSize)
	}
	aes.Load16xU32(&stks[0], tmp[0][:], tmp[1][:], tmp[2][:], tmp[3][:])

	for i := 1; i <= api.Rounds; i++ {
		for j := range t {
			api.H(&tk1[j])
			api.XORBytes(tmp[j][:], derivedKs[i][:], tk1[j][:], api.STKSize)
		}
		aes.Load16xU32(&stks[i], tmp[0][:], tmp[1][:], tmp[2][:], tmp[3][:])
	}

	for i := range t {
		api.Bzero(tk1[i][:])
		api.Bzero(tmp[i][:])
	}
}
