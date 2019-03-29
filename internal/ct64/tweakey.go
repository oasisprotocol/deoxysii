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

import "github.com/oasislabs/deoxysii/internal/api"

// Note: This is trivial to accelerate with vector ops.  Performance
// will likely be horrific without such things.  At the point where
// there's a vector unit, it's worth doing a vectorized AES
// implementation too.

func deriveSubTweakKeys(stks *[api.STKCount][api.STKSize]byte, derivedKs *[api.STKCount][api.STKSize]byte, t *[api.TweakSize]byte) {
	var tk1 [api.STKSize]byte

	copy(tk1[:], t[:]) // Tk1 = W1

	// i == 0
	api.XORBytes(stks[0][:], derivedKs[0][:], tk1[:], api.STKSize)

	// i == 1 ... i == 16
	for i := 1; i <= api.Rounds; i++ {
		// Tk1(i+1) = h(Tk1(i))
		api.H(&tk1)

		api.XORBytes(stks[i][:], derivedKs[i][:], tk1[:], api.STKSize)
	}
}
