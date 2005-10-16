C FIXME: Do we need an OFFSET macro? Or is it fine to use expressions such as [%i1 + 0]

C FIXME: How much can we rely on the assembler to be able to
C understand arithmetic expressions? Mayby we don't need to use m4
C eval.

C Used as temporaries by the AES macros
define(<TMP1>, <%g1>)
define(<TMP2>, <%g2>)

C Loop invariants used by AES_ROUND
define(<T0>,	<%o0>)
define(<T1>,	<%o1>)
define(<T2>,	<%o2>)
define(<T3>,	<%o3>)

C AES_LOAD(i, src, key, res)
define(<AES_LOAD>, <
	ldub	[$2 + eval(4*$1)], $4
	ldub	[$2 + eval(4*$1 + 1)], TMP1
	ldub	[$2 + eval(4*$1 + 2)], TMP2
	sll	TMP1, 8, TMP1
	
	or	$4, TMP1, $4
	ldub	[$2 + eval(4*$1+3)], TMP1
	sll	TMP2, 16, TMP2
	or	$4, TMP2, $4
	
	sll	TMP1, 24, TMP1
	C	Get subkey
	ld	[$3 + eval(4*$1)], TMP2
	or	$4, TMP1, $4
	xor	$4, TMP2, $4>)dnl

C AES_ROUND(i, T, a, b, c, d, key, res)
C Computes one word of the AES round
C FIXME: Could use registers pointing directly to the four tables
C FIXME: Needs better instruction scheduling, and perhaps more temporaries
C Alternatively, we can use a single table and some rotations
define(<AES_ROUND>, <
	and	$3, 0xff, TMP1		C  0
	srl	$4, 6, TMP2		C  1
	sll	TMP1, 2, TMP1		C  0
	and	TMP2, 0x3fc, TMP2	C  1
	ld	[T0 + TMP1], $8		C  0	E0
	srl	$5, 14, TMP1		C  2
	ld	[T1 + TMP2], TMP2	C  1
	and	TMP1, 0x3fc, TMP1	C  2
	xor	$8, TMP2, $8		C  1	E1
	srl	$6, 22, TMP2		C  3
	ld	[T2 + TMP1], TMP1	C  2
	and	TMP2, 0x3fc, TMP2	C  3
	xor	$8, TMP1, $8		C  2	E2
	ld	[$7 + eval(4*$1)], TMP1	C  4
	ld	[T3 + TMP2], TMP2	C  3
	xor	$8, TMP1, $8		C  4	E4
	xor	$8, TMP2, $8		C  3	E3
>)dnl

C AES_FINAL_ROUND(i, T, a, b, c, d, key, dst)
C Compute one word in the final round function. Output is converted to
C octets and stored at dst. Relies on AES_SBOX being zero.
define(<AES_FINAL_ROUND>, <
	C	Load subkey
	ld	[$7 + eval(4*$1)], TMP1

	and	$3, 0xff, TMP2
	ldub	[T + TMP2], TMP2
	nop
	xor	TMP1, TMP2, TMP2
	stb	TMP2, [$8 + eval(4*$1)]
	
	srl	$4, 8, TMP2
	and	TMP2, 0xff, TMP2
	ldub	[T + TMP2], TMP2
	srl	TMP1, 8, TMP1
	xor	TMP1, TMP2, TMP2
	stb	TMP2, [$8 + eval(4*$1 + 1)]

	srl	$5, 16, TMP2
	and	TMP2, 0xff, TMP2
	ldub	[T + TMP2], TMP2
	srl	TMP1, 8, TMP1
	xor	TMP1, TMP2, TMP2
	stb	TMP2, [$8 + eval(4*$1 + 2)]

	srl	$6, 24, TMP2
	ldub	[T + TMP2], TMP2
	srl	TMP1, 8, TMP1
	xor	TMP1, TMP2, TMP2
	stb	TMP2, [$8 + eval(4*$1 + 3)]>)

