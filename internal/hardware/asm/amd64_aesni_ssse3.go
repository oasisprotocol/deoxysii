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

package main

import (
	"encoding/binary"
	"fmt"
	"os"

	. "github.com/mmcloughlin/avo/build"
	"github.com/mmcloughlin/avo/buildtags"
	. "github.com/mmcloughlin/avo/operand"

	"github.com/oasisprotocol/deoxysii/internal/api"
)

//
// SSSE3 + AES-NI implementation.
//
// While I much prefer using AVX, the primary consumer of this needs to run
// on everything that is capable of running SGX, which includes a range of
// potato-tier Pentium processors that do not support it.
//

var (
	// In order to keep this from being an unreadable mess, use uint64s
	// to hold the various constants.  This isn't avo's fault, Go's
	// assembler is just... "special".

	// Key schedule round constants table ([api.STKCount][api.STKSize]byte)
	rcons = func() Mem {
		ref := GLOBL("rcons", RODATA|NOPTR)
		for i, rcon := range api.Rcons {
			rc := [api.STKSize]byte{
				1, 2, 4, 8,
				rcon, rcon, rcon, rcon,
				0, 0, 0, 0,
				0, 0, 0, 0,
			}
			lo := binary.LittleEndian.Uint64(rc[0:])
			hi := binary.LittleEndian.Uint64(rc[8:])
			DATA(i*8*2, U64(lo))
			DATA(i*8*2+8, U64(hi))
		}
		return ref
	}()

	// lfsr masks
	x0mask    = splatU8x16("x0mask", 0x01)
	invx0mask = splatU8x16("invx0mask", 0xfe)
	x7mask    = splatU8x16("x7mask", 0x80)
	invx7mask = splatU8x16("invx7mask", 0x7f)

	// h shuffle
	hshuf = func() Mem {
		shuf := [api.STKSize]byte{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
		}
		api.H(&shuf)
		return newU8x16("hshuf", shuf)
	}()

	// endian byteswap + move to high double quad word
	beshuf = func() Mem {
		shuf := [api.STKSize]byte{
			0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80,
			0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
		}
		return newU8x16("beshuf", shuf)
	}()

	// uint128_t(1)
	one = func() Mem {
		return newU64x2("one", [2]uint64{1, 0})
	}()
)

func newU8x16(name string, values [16]uint8) Mem {
	ref := GLOBL(name, RODATA|NOPTR)
	lo := binary.LittleEndian.Uint64(values[0:])
	hi := binary.LittleEndian.Uint64(values[8:])
	DATA(0, U64(lo))
	DATA(8, U64(hi))
	return ref
}

func splatU8x16(name string, value uint8) Mem {
	var v64 uint64
	for i := 0; i < 8; i++ {
		v64 <<= 8
		v64 |= uint64(value)
	}
	return newU64x2(name, [2]uint64{v64, v64})
}

func newU64x2(name string, values [2]uint64) Mem {
	ref := GLOBL(name, RODATA|NOPTR)
	for i, v := range values {
		DATA(i*8, U64(v))
	}
	return ref
}

func InitPackage() error {
	// Use our stub types instead of having AVO do it.
	Package(".")

	c, err := buildtags.ParseConstraint("amd64,!purego")
	if err != nil {
		return fmt.Errorf("internal/hardware/asm: failed to parse build constraint: %w", err)
	}
	Constraints(c)

	return nil
}

// func stkDeriveK(key *byte, derivedKs *[api.STKCount][api.STKSize]byte)
func StkDeriveK() error {
	TEXT(
		"stkDeriveK",
		NOSPLIT|NOFRAME,
		"func(key *byte, derivedKs *[16+1][16]byte)",
	)

	Comment("Derive the Sub-Tweak Key 'K' component for each round from the key")

	key := Mem{Base: Load(Param("key"), GP64())}
	derivedKs := Mem{Base: Load(Param("derivedKs"), GP64())}

	Comment("Load the various constants")

	x0maskReg, invx0maskReg, x7maskReg, invx7maskReg, hshufReg := XMM(), XMM(), XMM(), XMM(), XMM()
	rconsReg := GP64()
	LEAQ(rcons, rconsReg) // rcon
	rconsMem := Mem{Base: rconsReg}
	MOVO(x0mask, x0maskReg)       // x0 mask
	MOVO(invx0mask, invx0maskReg) // ~x0 mask
	MOVO(x7mask, x7maskReg)       // x7 mask
	MOVO(invx7mask, invx7maskReg) // ~x7 mask
	MOVO(hshuf, hshufReg)         // PSHUFB constant for h

	Comment("Load tk2/tk3")

	tk2, tk3 := XMM(), XMM()
	MOVOU(key.Offset(16), tk2)
	MOVOU(key.Offset(0), tk3)

	Comment("i == 0")

	t0, t1 := XMM(), XMM()
	MOVO(tk2, t0)      // k = tk2
	PXOR(tk3, t0)      // k ^= tk3
	PXOR(rconsMem, t0) // k ^= rcon[0]
	MOVOU(t0, derivedKs)

	Comment("i == 1 -> i == 16")

	indexReg := GP64()
	MOVQ(U64(16), indexReg)
	rconsMem = rconsMem.Idx(indexReg, 1)
	derivedKs = derivedKs.Idx(indexReg, 1)

	loopReg := GP64()
	MOVQ(U64(16), loopReg) // Loop counter

	Label("derive_stk_loop")

	Comment("lfsr2(tk2)")

	MOVO(tk2, t0)
	MOVO(tk2, t1)
	PSRLQ(Imm(7), t0)       // t0 = tk2 >> 7
	PSRLQ(Imm(5), t1)       // t1 = tk2 >> 5
	PSLLQ(Imm(1), tk2)      // tk2 = tk2 << 1
	PAND(invx0maskReg, tk2) // tk2 &= 0xfefefefe...
	PXOR(t1, t0)            // t0 ^= t1
	PAND(x0maskReg, t0)     // t0 &= 0x01010101...
	POR(t0, tk2)            // tk2 &= t0

	Comment("lfsr3(tk)")

	MOVO(tk3, t0)
	MOVO(tk3, t1)
	PSLLQ(Imm(7), t0)       // t0 = tk3 << 7
	PSLLQ(Imm(1), t1)       // t1 = tk3 << 1
	PSRLQ(Imm(1), tk3)      // tk3 = tk3 >> 1
	PAND(invx7maskReg, tk3) // tk3 &= 0x7f7f7f7f...
	PXOR(t1, t0)            // t0 ^= t1
	PAND(x7maskReg, t0)     // t0 &= 0x80808080...
	POR(t0, tk3)            // tk3 &= t0

	Comment("h(tk2), h(tk3)")

	PSHUFB(hshuf, tk2)
	PSHUFB(hshuf, tk3)

	Comment(
		"stk = tk1 ^ tk2 ^ tk3 ^ rcon[i]",
		"",
		"Note: tk1 is h(tk1), where tk1 is initialized to the tweak.",
		"This (the permutation and XOR to derive the actual STK) is handled",
		"in bcEncrypt.",
	)
	MOVO(tk2, t0)      // t0 = tk2
	PXOR(tk3, t0)      // t0 ^= tk3
	PXOR(rconsMem, t0) // t0 ^= rcons[i]
	MOVOU(t0, derivedKs)

	Comment("Offset bookkeeping, and the loop")

	ADDQ(Imm(16), indexReg)
	DECQ(loopReg)
	JNZ(LabelRef("derive_stk_loop"))

	Comment("Sanitize registers of key material, return")

	PXOR(t0, t0)
	PXOR(t1, t1)
	PXOR(tk2, tk2)
	PXOR(tk3, tk3)
	RET()

	return nil
}

// func bcEncrypt(ciphertext *byte, derivedKs *[api.STKCount][api.STKSize]byte, tweak *[api.TweakSize]byte, plaintext *byte)
func BcEncrypt() error {
	TEXT(
		"bcEncrypt",
		NOSPLIT|NOFRAME,
		"func(ciphertext *byte, derivedKs *[16+1][16]byte, tweak *[16]byte, plaintext *byte)",
	)

	Comment(
		"Encrypt 1 block of plaintext with derivedKs/tweak, store output in",
		"ciphertext",
	)

	ciphertext := Mem{Base: Load(Param("ciphertext"), GP64())}
	derivedKs := Mem{Base: Load(Param("derivedKs"), GP64())}
	tweak := Mem{Base: Load(Param("tweak"), GP64())}
	plaintext := Mem{Base: Load(Param("plaintext"), GP64())}

	hshufReg := XMM()
	MOVO(hshuf, hshufReg) // PSHUFB constant for h

	Comment("i == 0")

	t0, t1, tk1 := XMM(), XMM(), XMM()
	MOVOU(plaintext, t0) // t0 = plaintext
	MOVOU(derivedKs, t1) // t1 = tk2[0] ^ tk3[0] ^ rcon[0]
	MOVOU(tweak, tk1)    // tk1 = tweak
	PXOR(tk1, t1)        // t1 ^= tk1 (complete subtweakkey)
	PXOR(t1, t0)         // t0 ^= t1

	Comment("i == 1 -> i == 16")

	for i := 1; i <= 16; i++ {
		PSHUFB(hshufReg, tk1)             // tk1 = h(tk1)
		MOVOU(derivedKs.Offset(i*16), t1) // t1 = tk2[i] ^ tk3[i] ^ rcon[i]
		PXOR(tk1, t1)                     // t1 ^= tk1 (complete subtweakkey)
		AESENC(t1, t0)                    // t0 = AESENC(t1, t0)
	}

	Comment("Write ciphertext, sanitize key material, return")

	MOVOU(t0, ciphertext)
	PXOR(tk1, tk1) // tk1
	PXOR(t1, t1)   // subtweakkey
	RET()

	return nil
}

// func bcTag(tag *[16]byte, derivedKs *[api.STKCount][api.STKSize]byte, prefix byte, blockNr int, plaintext *byte, n int)
func BcTag() error {
	TEXT(
		"bcTag",
		NOSPLIT|NOFRAME,
		"func(tag *[16]byte, derivedKs *[16+1][16]byte, prefix byte, blockNr int, plaintext *byte, n int)",
	)

	Comment(
		"Accumulate n blocks of plaintext with derivedKs/prefix/blockNr into",
		"tag",
	)

	tag := Mem{Base: Load(Param("tag"), GP64())}
	derivedKs := Mem{Base: Load(Param("derivedKs"), GP64())}
	prefix := Load(Param("prefix"), GP64())
	blockNr := Load(Param("blockNr"), GP64())
	plaintext := Mem{Base: Load(Param("plaintext"), GP64())}
	n := Load(Param("n"), GP64())

	beshufReg, prefixReg, hshufReg, tagReg := XMM(), XMM(), XMM(), XMM()
	SHLQ(Imm(4), prefix) // prefix = prefix << 4
	MOVO(beshuf, beshufReg)
	MOVQ(prefix, prefixReg) // prefix << 4
	MOVO(hshuf, hshufReg)   // PSHUFB constant for h
	MOVOU(tag, tagReg)

	// Note: Too lazy to comment this.  It is "block_x1_loop", but unrolled 4x.
	Comment("4 blocks at a time")

	CMPQ(n, Imm(4))
	JL(LabelRef("block_x4_loop_skip"))

	Label("block_x4_loop")

	t0, t1, t2, t3, t4, t5, t6, t7, t8, oneReg := XMM(), XMM(), XMM(), XMM(), XMM(), XMM(), XMM(), XMM(), XMM(), XMM()
	MOVO(one, oneReg)
	MOVQ(blockNr, t0)
	MOVO(t0, t1)
	PADDQ(oneReg, t1)
	MOVO(t1, t2)
	PADDQ(oneReg, t2)
	MOVO(t2, t3)
	PADDQ(oneReg, t3)
	PSHUFB(beshufReg, t0)
	PSHUFB(beshufReg, t1)
	PSHUFB(beshufReg, t2)
	PSHUFB(beshufReg, t3)
	POR(prefixReg, t0)
	POR(prefixReg, t1)
	POR(prefixReg, t2)
	POR(prefixReg, t3)
	ADDQ(Imm(4), blockNr)

	MOVOU(derivedKs, t8)
	MOVOU(plaintext, t4)
	MOVOU(plaintext.Offset(16), t5)
	MOVOU(plaintext.Offset(32), t6)
	MOVOU(plaintext.Offset(48), t7)
	PXOR(t0, t4)
	PXOR(t1, t5)
	PXOR(t2, t6)
	PXOR(t3, t7)
	PXOR(t8, t4)
	PXOR(t8, t5)
	PXOR(t8, t6)
	PXOR(t8, t7)
	ADDQ(Imm(64), plaintext.Base)

	t9, t10, t11 := XMM(), XMM(), oneReg
	for i := 1; i <= 16; i++ {
		MOVOU(derivedKs.Offset(i*16), t8)
		MOVO(t8, t9)
		MOVO(t8, t10)
		MOVO(t8, t11)
		PSHUFB(hshufReg, t0)
		PSHUFB(hshufReg, t1)
		PSHUFB(hshufReg, t2)
		PSHUFB(hshufReg, t3)
		PXOR(t0, t8)
		PXOR(t1, t9)
		PXOR(t2, t10)
		PXOR(t3, t11)
		AESENC(t8, t4)
		AESENC(t9, t5)
		AESENC(t10, t6)
		AESENC(t11, t7)
	}

	PXOR(t4, tagReg)
	PXOR(t5, tagReg)
	PXOR(t6, tagReg)
	PXOR(t7, tagReg)

	SUBQ(Imm(4), n)
	CMPQ(n, Imm(4))
	JG(LabelRef("block_x4_loop"))

	MOVOU(tagReg, tag)

	Comment("Sanitize registers of key material (block 0 handled prior to return)")

	PXOR(t1, t1)   // tk1 (block 1)
	PXOR(t2, t2)   // tk1 (block 2)
	PXOR(t3, t3)   // tk1 (block 3)
	PXOR(t9, t9)   // AES round key (block 1)
	PXOR(t10, t10) // AES round key (block 2)
	PXOR(t11, t11) // AES round key (block 3)

	Label("block_x4_loop_skip")

	Comment("1 block at a time")

	TESTQ(n, n)
	JZ(LabelRef("out"))

	Label("block_x1_loop")
	MOVQ(blockNr, t0)
	PSHUFB(beshufReg, t0)
	POR(prefixReg, t0) // t0 = prefix || blockNr
	INCQ(blockNr)

	MOVOU(derivedKs, t8) // t8 = tk2[0] ^ tk3[0] ^ rcon[0]
	MOVOU(plaintext, t4) // t4 = plaintext
	PXOR(t0, t8)         // t8 ^= tk1 (complete subtweakkey)
	PXOR(t8, t4)         // t4 ^= t8
	ADDQ(Imm(16), plaintext.Base)

	for i := 1; i <= 16; i++ {
		MOVOU(derivedKs.Offset(i*16), t8) // t8 = tk2[i] ^ tk3[i] ^ rcon[i]
		PSHUFB(hshufReg, t0)              // t0 = h(tk1)
		PXOR(t0, t8)                      // t8 ^= tk1 (complete subtweakkey)
		AESENC(t8, t4)
	}

	PXOR(t4, tagReg) // tag ^= t4
	DECQ(n)
	JNZ(LabelRef("block_x1_loop"))

	MOVOU(tagReg, tag)

	Label("out")

	Comment("Sanitize remaining registers of key material and return")

	PXOR(t0, t0) // tk1 (block 0)
	PXOR(t8, t8) // AES round key (block 0)
	RET()

	return nil
}

// func bcXOR(ciphertext *byte, derivedKs *[api.STKCount][api.STKSize]byte, tag *[16]byte, blockNr int, nonce *[16]byte, plaintext *byte, n int)
func BcXOR() error {
	TEXT(
		"bcXOR",
		NOSPLIT|NOFRAME,
		"func(ciphertext *byte, derivedKs *[16+1][16]byte, tag *[16]byte, blockNr int, nonce *[16]byte, plaintext *byte, n int)",
	)

	Comment(
		"XOR n blocks of keystream generated with key/tag/blockNr/nonce with",
		"plaintext and save to ciphertext.",
	)

	ciphertext := Mem{Base: Load(Param("ciphertext"), GP64())}
	derivedKs := Mem{Base: Load(Param("derivedKs"), GP64())}
	tag := Mem{Base: Load(Param("tag"), GP64())}
	blockNr := Load(Param("blockNr"), GP64())
	nonce := Mem{Base: Load(Param("nonce"), GP64())}
	plaintext := Mem{Base: Load(Param("plaintext"), GP64())}
	n := Load(Param("n"), GP64())

	hshufReg, tagReg, nonceReg := XMM(), XMM(), XMM()
	MOVO(hshuf, hshufReg)  // PSHUFB constant for h
	MOVOU(tag, tagReg)     // tag
	MOVOU(nonce, nonceReg) // nonce

	Comment("4 blocks at a time")

	CMPQ(n, Imm(4))
	JL(LabelRef("block_x4_loop_skip"))

	Label("block_x4_loop")

	t0, t1, t2, t3, t4, t5, t6, t7, t8, beshufReg, oneReg := XMM(), XMM(), XMM(), XMM(), XMM(), XMM(), XMM(), XMM(), XMM(), XMM(), XMM()
	MOVO(beshuf, beshufReg)
	MOVO(one, oneReg)
	MOVQ(blockNr, t0)
	MOVO(t0, t1)
	PADDQ(oneReg, t1)
	MOVO(t1, t2)
	PADDQ(oneReg, t2)
	MOVO(t2, t3)
	PADDQ(oneReg, t3)
	PSHUFB(beshufReg, t0)
	PSHUFB(beshufReg, t1)
	PSHUFB(beshufReg, t2)
	PSHUFB(beshufReg, t3)
	PXOR(tagReg, t0)
	PXOR(tagReg, t1)
	PXOR(tagReg, t2)
	PXOR(tagReg, t3)
	ADDQ(Imm(4), blockNr)

	MOVOU(derivedKs, t8)
	MOVO(nonceReg, t4)
	MOVO(nonceReg, t5)
	MOVO(nonceReg, t6)
	MOVO(nonceReg, t7)
	PXOR(t0, t4)
	PXOR(t1, t5)
	PXOR(t2, t6)
	PXOR(t3, t7)
	PXOR(t8, t4)
	PXOR(t8, t5)
	PXOR(t8, t6)
	PXOR(t8, t7)

	t9, t10, t11 := XMM(), beshufReg, oneReg
	for i := 1; i <= 16; i++ {
		MOVOU(derivedKs.Offset(i*16), t8)
		MOVO(t8, t9)
		MOVO(t8, t10)
		MOVO(t8, t11)
		PSHUFB(hshuf, t0)
		PSHUFB(hshuf, t1)
		PSHUFB(hshuf, t2)
		PSHUFB(hshuf, t3)
		PXOR(t0, t8)
		PXOR(t1, t9)
		PXOR(t2, t10)
		PXOR(t3, t11)
		AESENC(t8, t4)
		AESENC(t9, t5)
		AESENC(t10, t6)
		AESENC(t11, t7)
	}

	MOVOU(plaintext, t8)
	MOVOU(plaintext.Offset(16), t9)
	MOVOU(plaintext.Offset(32), t10)
	MOVOU(plaintext.Offset(48), t11)
	PXOR(t4, t8)
	PXOR(t5, t9)
	PXOR(t6, t10)
	PXOR(t7, t11)
	MOVOU(t8, ciphertext)
	MOVOU(t9, ciphertext.Offset(16))
	MOVOU(t10, ciphertext.Offset(32))
	MOVOU(t11, ciphertext.Offset(48))
	ADDQ(Imm(64), plaintext.Base)
	ADDQ(Imm(64), ciphertext.Base)

	SUBQ(Imm(4), n)
	CMPQ(n, Imm(4))
	JG(LabelRef("block_x4_loop"))

	Comment("Sanitize registers of key material (block 0 handled prior to return)")

	PXOR(t1, t1) // tk1 (block 1)
	PXOR(t2, t2) // tk1 (block 2)
	PXOR(t3, t3) // tk1 (block 3)
	PXOR(t5, t5) // keystream (block 1)
	PXOR(t6, t6) // keystream (block 2)
	PXOR(t7, t7) // keystream (block 3)

	Label("block_x4_loop_skip")

	Comment("1 block at a time")

	TESTQ(n, n)
	JZ(LabelRef("out"))

	MOVO(beshuf, beshufReg) // PSHUFB constant for byteswap

	Label("block_x1_loop")

	MOVQ(blockNr, t0)
	PSHUFB(beshufReg, t0) // t0 = 0x0000000000000000 || blockNr
	PXOR(tagReg, t0)      // t0 ^= tag(tk)
	INCQ(blockNr)

	MOVOU(derivedKs, t8) // t8 = tk2[0] ^ tk3[0] ^ rcon[0]
	MOVO(nonceReg, t4)   // t4 = nonce
	PXOR(t0, t8)         // t8 ^= tk1
	PXOR(t8, t4)         // t4 ^= t8

	for i := 1; i <= 16; i++ {
		PSHUFB(hshufReg, t0)              // t0 = h(tk1)
		MOVOU(derivedKs.Offset(i*16), t8) // t8 = tk2[i] ^ tk3[i] ^ rcon[i]
		PXOR(t0, t8)                      // t8 ^= tk1 (complete subtweakkey)
		AESENC(t8, t4)
	}

	MOVOU(plaintext, t8) // t8 = plaintext
	PXOR(t4, t8)         // t8 ^= t4
	MOVOU(t8, ciphertext)
	ADDQ(Imm(16), plaintext.Base)
	ADDQ(Imm(16), ciphertext.Base)

	DECQ(n)
	JNZ(LabelRef("block_x1_loop"))

	Label("out")

	Comment("Sanitize remaining registers of key material and return")

	PXOR(t0, t0) // tk1 (block 0)
	PXOR(t4, t4) // keystream (block 0)

	RET()

	return nil
}

func main() {
	for i, step := range []func() error{
		InitPackage,
		StkDeriveK,
		BcEncrypt,
		BcTag,
		BcXOR,
	} {
		if err := step(); err != nil {
			fmt.Printf("step %d failed: %v", i, err)
			os.Exit(1)
		}
	}

	Generate()
}
