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
