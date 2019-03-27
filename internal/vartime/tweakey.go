package vartime

import (
	"encoding/binary"

	"github.com/oasislabs/deoxysii/internal/api"
)

func deriveSubTweakKeys(stks *[api.STKCount][4]uint32, derivedKs *[api.STKCount][api.STKSize]byte, t *[api.TweakSize]byte) {
	var tk1, stk [api.STKSize]byte

	writeStk := func(idx int) {
		// Convert stk to a format that is easier to use with the
		// table driven AES round function.
		//
		// Note: Other implementations can just return each
		// Sub-Tweak Key as a 16 byte value.
		stks[idx][0] = binary.BigEndian.Uint32(stk[0:])
		stks[idx][1] = binary.BigEndian.Uint32(stk[4:])
		stks[idx][2] = binary.BigEndian.Uint32(stk[8:])
		stks[idx][3] = binary.BigEndian.Uint32(stk[12:])
	}

	copy(tk1[:], t[:]) // Tk1 = W1

	// i == 0
	api.XORBytes(stk[:], derivedKs[0][:], tk1[:], api.STKSize)
	writeStk(0)

	// i == 1 ... i == 16
	for i := 1; i <= api.Rounds; i++ {
		// Tk1(i+1) = h(Tk1(i))
		api.H(&tk1)

		api.XORBytes(stk[:], derivedKs[i][:], tk1[:], api.STKSize)
		writeStk(i)
	}
}
