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

// +build !noasm

#include "textflag.h"

//
// SSSE3 + AES-NI implementation.
//

//
// Constants, masks, etc.
//
// WARNING: The Go assembler makes it so that the easiest way to represent
// these is as uint64 literals in native byte order, instead of doing the
// sensible thing and allowing arbitrary length binary literals.
//

// rcon
DATA ·rcon<>+0x00(SB)/8, $0x2f2f2f2f08040201
DATA ·rcon<>+0x08(SB)/8, $0x0000000000000000
DATA ·rcon<>+0x10(SB)/8, $0x5e5e5e5e08040201
DATA ·rcon<>+0x18(SB)/8, $0x0000000000000000
DATA ·rcon<>+0x20(SB)/8, $0xbcbcbcbc08040201
DATA ·rcon<>+0x28(SB)/8, $0x0000000000000000
DATA ·rcon<>+0x30(SB)/8, $0x6363636308040201
DATA ·rcon<>+0x38(SB)/8, $0x0000000000000000
DATA ·rcon<>+0x40(SB)/8, $0xc6c6c6c608040201
DATA ·rcon<>+0x48(SB)/8, $0x0000000000000000
DATA ·rcon<>+0x50(SB)/8, $0x9797979708040201
DATA ·rcon<>+0x58(SB)/8, $0x0000000000000000
DATA ·rcon<>+0x60(SB)/8, $0x3535353508040201
DATA ·rcon<>+0x68(SB)/8, $0x0000000000000000
DATA ·rcon<>+0x70(SB)/8, $0x6a6a6a6a08040201
DATA ·rcon<>+0x78(SB)/8, $0x0000000000000000
DATA ·rcon<>+0x80(SB)/8, $0xd4d4d4d408040201
DATA ·rcon<>+0x88(SB)/8, $0x0000000000000000
DATA ·rcon<>+0x90(SB)/8, $0xb3b3b3b308040201
DATA ·rcon<>+0x98(SB)/8, $0x0000000000000000
DATA ·rcon<>+0xa0(SB)/8, $0x7d7d7d7d08040201
DATA ·rcon<>+0xa8(SB)/8, $0x0000000000000000
DATA ·rcon<>+0xb0(SB)/8, $0xfafafafa08040201
DATA ·rcon<>+0xb8(SB)/8, $0x0000000000000000
DATA ·rcon<>+0xc0(SB)/8, $0xefefefef08040201
DATA ·rcon<>+0xc8(SB)/8, $0x0000000000000000
DATA ·rcon<>+0xd0(SB)/8, $0xc5c5c5c508040201
DATA ·rcon<>+0xd8(SB)/8, $0x0000000000000000
DATA ·rcon<>+0xe0(SB)/8, $0x9191919108040201
DATA ·rcon<>+0xe8(SB)/8, $0x0000000000000000
DATA ·rcon<>+0xf0(SB)/8, $0x3939393908040201
DATA ·rcon<>+0xf8(SB)/8, $0x0000000000000000
DATA ·rcon<>+0x100(SB)/8, $0x7272727208040201
DATA ·rcon<>+0x108(SB)/8, $0x0000000000000000
GLOBL ·rcon<>(SB), (NOPTR+RODATA), $272

// lfsr masks
DATA ·x0mask<>+0x00(SB)/8, $0x0101010101010101
DATA ·x0mask<>+0x08(SB)/8, $0x0101010101010101
GLOBL ·x0mask<>(SB), (NOPTR+RODATA), $16

DATA ·invx0mask<>+0x00(SB)/8, $0xfefefefefefefefe
DATA ·invx0mask<>+0x08(SB)/8, $0xfefefefefefefefe
GLOBL ·invx0mask<>(SB), (NOPTR+RODATA), $16

DATA ·x7mask<>+0x00(SB)/8, $0x8080808080808080
DATA ·x7mask<>+0x08(SB)/8, $0x8080808080808080
GLOBL ·x7mask<>(SB), (NOPTR+RODATA), $16

DATA ·invx7mask<>+0x00(SB)/8, $0x7f7f7f7f7f7f7f7f
DATA ·invx7mask<>+0x08(SB)/8, $0x7f7f7f7f7f7f7f7f
GLOBL ·invx7mask<>(SB), (NOPTR+RODATA), $16

// h shuffle
DATA ·hshuf<>+0x00(SB)/8, $0x000f0a050c0b0601
DATA ·hshuf<>+0x08(SB)/8, $0x0807020d04030e09
GLOBL ·hshuf<>(SB), (NOPTR+RODATA), $16

// endian byteswap + move to high double quad word
DATA ·beshuf<>+0x00(SB)/8, $0x8080808080808080
DATA ·beshuf<>+0x08(SB)/8, $0x0001020304050607
GLOBL ·beshuf<>(SB), (NOPTR+RODATA), $16

// uint128_t(1)
DATA ·one<>+0x00(SB)/8, $0x0000000000000001
DATA ·one<>+0x08(SB)/8, $0x0000000000000000
GLOBL ·one<>(SB), (NOPTR+RODATA), $16

// Derive the Sub-Tweak Key 'K' component for each round from the key.
//
// func stkDeriveK(key *byte, derivedKs *[api.STKCount][api.STKSize]byte)
TEXT ·stkDeriveK(SB), NOSPLIT|NOFRAME, $0-16
	MOVQ key+0(FP), R15       // key
	MOVQ derivedKs+8(FP), R14 // derivedKs

	// Load the various constants.
	LEAQ ·rcon<>(SB), R12      // rcon
	MOVO ·x0mask<>(SB), X15    // x0 mask
	MOVO ·invx0mask<>(SB), X14 // ~x0 mask
	MOVO ·x7mask<>(SB), X13    // x7 mask
	MOVO ·invx7mask<>(SB), X12 // ~x7 mask
	MOVO ·hshuf<>(SB), X11     // PSHUFB constant for h

	MOVOU 16(R15), X1 // tk2
	MOVOU 0(R15), X2  // tk3

	// i == 0
	MOVO  X1, X6    // k = tk2
	PXOR  X2, X6    // k ^= tk3
	PXOR  (R12), X6 // k ^= rcon[0]
	MOVOU X6, (R14)

	ADDQ $16, R12
	ADDQ $16, R14

	// i == 1 ... i == 16
	MOVQ $16, AX

derive_stk_loop:
	// lfsr2(tk2)
	MOVO  X1, X6
	MOVO  X1, X7
	PSRLQ $7, X6  // X6 = X1 >> 7
	PSRLQ $5, X7  // X7 = X1 >> 5
	PSLLQ $1, X1  // X1 = X1 << 1
	PAND  X14, X1 // X1 &= 0xfefefefe...
	PXOR  X7, X6  // X6 ^= X7
	PAND  X15, X6 // X6 &= 0x01010101...
	POR   X6, X1  // X1 |= X6

	// lfsr3(tk)
	MOVO  X2, X6
	MOVO  X2, X7
	PSLLQ $7, X6  // X6 = X2 << 7
	PSLLQ $1, X7  // X7 = X2 << 1
	PSRLQ $1, X2  // X2 = X2 >> 1
	PAND  X12, X2 // X2 &= 0x7f7f7f7f...
	PXOR  X7, X6  // X6 ^= X7
	PAND  X13, X6 // X6 &= 0x80808080...
	POR   X6, X2  // X2 |= X6

	// h(tk2), h(tk3)
	PSHUFB X11, X1 // X1 = h(tk2)
	PSHUFB X11, X2 // X2 = h(tk3)

	// stk = tk1 ^ tk2 ^ tk3 ^ rcon[i]
	MOVO  X1, X6    // k = tk2
	PXOR  X2, X6    // k ^= tk3
	PXOR  (R12), X6 // k ^= rcon[i]
	MOVOU X6, (R14)

	ADDQ $16, R12
	ADDQ $16, R14

	SUBQ $1, AX
	JNZ  derive_stk_loop

	// Sanitize registers of key material.
	PXOR X1, X1
	PXOR X2, X2
	PXOR X6, X6
	PXOR X7, X7

	RET

// Encrypt 1 block of plaintext with derivedKs/tweak, store output in ciphertext.
//
// func bcEncrypt(ciphertext *byte, derivedKs *[api.STKCount][api.STKSize]byte, tweak *[api.TweakSize]byte, plaintext *byte)
TEXT ·bcEncrypt(SB), NOSPLIT|NOFRAME, $0-32
	MOVQ ciphertext+0(FP), R15 // ciphertext
	MOVQ derivedKs+8(FP), R14  // derivedKs
	MOVQ tweak+16(FP), R13     // tweak
	MOVQ plaintext+24(FP), R12 // plaintext

	MOVO ·hshuf<>(SB), X13 // X14 = PSHUFB constant for h

	// i == 0
	MOVOU (R12), X15 // X15 = plaintext
	MOVOU (R14), X14 // X14 = tk2 ^ tk3 ^ rcon[0]
	MOVOU (R13), X0  // X0 = tk1
	PXOR  X0, X14    // X14 ^= tk1
	PXOR  X14, X15   // X15 ^= X14

	// i == 1 ... i == 16
#define block_x1_round(N) \
	PSHUFB X13, X0     \ // X0 = h(tk1)
	MOVOU  N(R14), X14 \ // X14 = tk2 ^ tk3 ^ rcon[i]
	PXOR   X0, X14     \ // X14 ^= tk1
	AESENC X14, X15

block_x1_round(16)
block_x1_round(32)
block_x1_round(48)
block_x1_round(64)
block_x1_round(80)
block_x1_round(96)
block_x1_round(112)
block_x1_round(128)
block_x1_round(144)
block_x1_round(160)
block_x1_round(176)
block_x1_round(192)
block_x1_round(208)
block_x1_round(224)
block_x1_round(240)
block_x1_round(256)

#undef block_x1_round

	MOVOU X15, (R15)

	// Sanitize registers of key material.
	PXOR X0, X0   // tk1
	PXOR X14, X14 // AES round key

	RET

// Accumulate n blocks of plaintext with derivedKs/prefix/blockNr into tag.
//
// func bcTag(tag *[16]byte, derivedKs *[api.STKCount][api.STKSize]byte, prefix byte, blockNr int, plaintext *byte, n int)
TEXT ·bcTag(SB), NOSPLIT|NOFRAME, $0-48
	MOVQ    tag+0(FP), R15        // tag
	MOVQ    derivedKs+8(FP), R14  // derivedKs
	MOVBQZX prefix+16(FP), R13    // prefix
	MOVQ    blockNr+24(FP), R12   // blockNr
	MOVQ    plaintext+32(FP), R11 // plaintext
	MOVQ    n+40(FP), R10         // n

	SHLQ  $4, R13            // prefix = prefix << 4
	MOVO  ·beshuf<>(SB), X12 // X12 = PSHUFB constant for byteswap + move to high
	MOVQ  R13, X13           // X13 = prefix << 4
	MOVO  ·hshuf<>(SB), X14  // X14 = PSHUFB constant for h
	MOVOU (R15), X15         // X15 = tag

	//
	// 4 blocks at a time.
	//

	CMPQ R10, $4
	JL   block_x4_loop_skip

block_x4_loop:
	MOVO   ·one<>(SB), X11
	MOVQ   R12, X0
	MOVO   X0, X1
	PADDQ  X11, X1
	MOVO   X1, X2
	PADDQ  X11, X2
	MOVO   X2, X3
	PADDQ  X11, X3
	PSHUFB X12, X0
	PSHUFB X12, X1
	PSHUFB X12, X2
	PSHUFB X12, X3
	POR    X13, X0
	POR    X13, X1
	POR    X13, X2
	POR    X13, X3
	ADDQ   $4, R12

	MOVOU (R14), X8
	MOVOU (R11), X4
	MOVOU 16(R11), X5
	MOVOU 32(R11), X6
	MOVOU 48(R11), X7
	PXOR  X0, X4
	PXOR  X1, X5
	PXOR  X2, X6
	PXOR  X3, X7
	PXOR  X8, X4
	PXOR  X8, X5
	PXOR  X8, X6
	PXOR  X8, X7
	ADDQ  $64, R11

#define block_x4_round(N) \
	MOVOU  N(R14), X8 \
	MOVO   X8, X9     \
	MOVO   X8, X10    \
	MOVO   X8, X11    \
	PSHUFB X14, X0    \
	PSHUFB X14, X1    \
	PSHUFB X14, X2    \
	PSHUFB X14, X3    \
	PXOR   X0, X8     \
	PXOR   X1, X9     \
	PXOR   X2, X10    \
	PXOR   X3, X11    \
	AESENC X8, X4     \
	AESENC X9, X5     \
	AESENC X10, X6    \
	AESENC X11, X7

block_x4_round(16)
block_x4_round(32)
block_x4_round(48)
block_x4_round(64)
block_x4_round(80)
block_x4_round(96)
block_x4_round(112)
block_x4_round(128)
block_x4_round(144)
block_x4_round(160)
block_x4_round(176)
block_x4_round(192)
block_x4_round(208)
block_x4_round(224)
block_x4_round(240)
block_x4_round(256)

#undef block_x4_round

	PXOR X4, X15
	PXOR X5, X15
	PXOR X6, X15
	PXOR X7, X15

	SUBQ $4, R10
	CMPQ R10, $4
	JG   block_x4_loop

	MOVOU X15, (R15)

	// Sanitize registers of key material (block 0 handled prior to return)
	PXOR X1, X1   // tk1 (block 1)
	PXOR X2, X2   // tk1 (block 2)
	PXOR X3, X3   // tk1 (block 3)
	PXOR X9, X9   // AES round key (block 1)
	PXOR X10, X10 // AES round key (block 2)
	PXOR X11, X11 // AES round key (block 3)

block_x4_loop_skip:

	//
	// 1 block at a time.
	//

	TESTQ R10, R10
	JZ    out

block_x1_loop:
	MOVQ   R12, X0
	PSHUFB X12, X0
	POR    X13, X0 // X0 = prefix || blockNr
	ADDQ   $1, R12

	MOVOU (R14), X8 // X8 = tk2 ^ tk3 ^ rcon[0]
	MOVOU (R11), X4 // X4 = plaintext
	PXOR  X0, X8    // X8 ^= tk1
	PXOR  X8, X4    // X4 ^= X8
	ADDQ  $16, R11

#define block_x1_round(N) \
	MOVOU  N(R14), X8 \ // X8 = tk2 ^ tk3 ^ rcon[i]
	PSHUFB X14, X0    \ // X0 = h(tk1)
	PXOR   X0, X8     \ // X8 ^= tk1
	AESENC X8, X4

block_x1_round(16)
block_x1_round(32)
block_x1_round(48)
block_x1_round(64)
block_x1_round(80)
block_x1_round(96)
block_x1_round(112)
block_x1_round(128)
block_x1_round(144)
block_x1_round(160)
block_x1_round(176)
block_x1_round(192)
block_x1_round(208)
block_x1_round(224)
block_x1_round(240)
block_x1_round(256)

#undef block_x1_round

	PXOR X4, X15 // X15 ^= X4

	SUBQ $1, R10
	JNZ  block_x1_loop

	MOVOU X15, (R15) // tag = X15

out:
	// Sanitize remaining registers of key material.
	PXOR X0, X0 // tk1 (block 0)
	PXOR X8, X8 // AES round key (block 0)

	RET

// XOR n block of keystream generated with key/tag/blockNr/nonce with plaintext
// and save to ciphertext.
//
// func bcXOR(ciphertext *byte, derivedKs *[api.STKCount][api.STKSize]byte, tag *[16]byte, blockNr int, nonce *[16]byte, plaintext *byte, n int)
TEXT ·bcXOR(SB), NOSPLIT|NOFRAME, $0-56
	MOVQ ciphertext+0(FP), R15 // ciphertext
	MOVQ derivedKs+8(FP), R14  // derivedKs
	MOVQ tag+16(FP), R13       // tag
	MOVQ blockNr+24(FP), R12   // blockNr
	MOVQ nonce+32(FP), R11     // nonce
	MOVQ plaintext+40(FP), R10 // plaintext
	MOVQ n+48(FP), R9          // n

	MOVO  ·hshuf<>(SB), X14 // X14 = PSHUFB constant for h
	MOVOU (R13), X15        // X15 = tag
	MOVOU (R11), X12        // X12 = nonce

	//
	// 4 blocks at a time.
	//

	CMPQ R9, $4
	JL   block_x4_loop_skip

block_x4_loop:
	MOVO   ·beshuf<>(SB), X11
	MOVO   ·one<>(SB), X10
	MOVQ   R12, X0
	MOVO   X0, X1
	PADDQ  X10, X1
	MOVO   X1, X2
	PADDQ  X10, X2
	MOVO   X2, X3
	PADDQ  X10, X3
	PSHUFB X11, X0
	PSHUFB X11, X1
	PSHUFB X11, X2
	PSHUFB X11, X3
	PXOR   X15, X0
	PXOR   X15, X1
	PXOR   X15, X2
	PXOR   X15, X3
	ADDQ   $4, R12

	MOVOU (R14), X8
	MOVO  X12, X4
	MOVO  X12, X5
	MOVO  X12, X6
	MOVO  X12, X7
	PXOR  X0, X4
	PXOR  X1, X5
	PXOR  X2, X6
	PXOR  X3, X7
	PXOR  X8, X4
	PXOR  X8, X5
	PXOR  X8, X6
	PXOR  X8, X7

#define block_x4_round(N) \
	MOVOU  N(R14), X8 \
	MOVO   X8, X9     \
	MOVO   X8, X10    \
	MOVO   X8, X11    \
	PSHUFB X14, X0    \
	PSHUFB X14, X1    \
	PSHUFB X14, X2    \
	PSHUFB X14, X3    \
	PXOR   X0, X8     \
	PXOR   X1, X9     \
	PXOR   X2, X10    \
	PXOR   X3, X11    \
	AESENC X8, X4     \
	AESENC X9, X5     \
	AESENC X10, X6    \
	AESENC X11, X7    \

block_x4_round(16)
block_x4_round(32)
block_x4_round(48)
block_x4_round(64)
block_x4_round(80)
block_x4_round(96)
block_x4_round(112)
block_x4_round(128)
block_x4_round(144)
block_x4_round(160)
block_x4_round(176)
block_x4_round(192)
block_x4_round(208)
block_x4_round(224)
block_x4_round(240)
block_x4_round(256)

#undef block_x4_round

	MOVOU (R10), X8
	MOVOU 16(R10), X9
	MOVOU 32(R10), X10
	MOVOU 48(R10), X11
	PXOR  X4, X8
	PXOR  X5, X9
	PXOR  X6, X10
	PXOR  X7, X11
	MOVOU X8, (R15)
	MOVOU X9, 16(R15)
	MOVOU X10, 32(R15)
	MOVOU X11, 48(R15)
	ADDQ  $64, R10
	ADDQ  $64, R15

	SUBQ $4, R9
	CMPQ R9, $4
	JG   block_x4_loop

	// Sanitize registers of key material (block 0 handled prior to return)
	PXOR X1, X1 // tk1 (block 1)
	PXOR X2, X2 // tk1 (block 2)
	PXOR X3, X3 // tk1 (block 3)

block_x4_loop_skip:

	//
	// 1 block at a time.
	//

	TESTQ R9, R9
	JZ    out

	MOVO ·beshuf<>(SB), X11 // PSHUFB constant for byteswap

block_x1_loop:
	MOVQ   R12, X0
	PSHUFB X11, X0 // X0 = 0x0000000000000000 || blockNr
	PXOR   X15, X0 // X0 ^= tag(tk)
	ADDQ   $1, R12

	MOVOU (R14), X8 // X8 = tk2 ^ tk3 ^ rcon[0]
	MOVO  X12, X4   // X4 = nonce
	PXOR  X0, X8    // X8 ^= tk1
	PXOR  X8, X4    // X4 ^= X8

#define block_x1_round(N) \
	PSHUFB X14, X0    \ // X0 = h(tk1)
	MOVOU  N(R14), X8 \ // X8 = tk2 ^ tk3 ^ rcon[i]
	PXOR   X0, X8     \ // X8 ^= tk1
	AESENC X8, X4

block_x1_round(16)
block_x1_round(32)
block_x1_round(48)
block_x1_round(64)
block_x1_round(80)
block_x1_round(96)
block_x1_round(112)
block_x1_round(128)
block_x1_round(144)
block_x1_round(160)
block_x1_round(176)
block_x1_round(192)
block_x1_round(208)
block_x1_round(224)
block_x1_round(240)
block_x1_round(256)

#undef block_x1_round

	MOVOU (R10), X8 // X8 = plaintext
	PXOR  X4, X8    // X8 ^= X4
	MOVOU X8, (R15)
	ADDQ  $16, R10
	ADDQ  $16, R15

	SUBQ $1, R9
	JNZ  block_x1_loop

out:
	// Sanitize remaining registers of key material.
	PXOR X0, X0 // tk1 (block 0)

	RET
