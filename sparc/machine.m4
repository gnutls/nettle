C FIXME: Do we need an OFFSET macro? Or is it fine to use expressions such as [%i1 + 0]

C FIXME: How much can we rely on the assembler to be able to
C understand arithmetic expressions? Mayby we don't need to use m4
C eval.

C Used as temporaries by the AES macros
define(<TMP1>, <%o0>)
define(<TMP2>, <%o1>)

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
	and	$3, 0xff, TMP1
	sll	TMP1, 2, TMP1
	add	TMP1, AES_TABLE0, TMP1
	ld	[$2 + TMP1], $8

	srl	$4, 6, TMP1
	and	TMP1, 0x3fc, TMP1
	add	TMP1, AES_TABLE1, TMP1
	ld	[$2 + TMP1], TMP1
	nop
	xor	$8, TMP1, $8

	srl	$5, 14, TMP1
	and	TMP1, 0x3fc, TMP1
	add	TMP1, AES_TABLE2, TMP1
	ld	[$2 + TMP1], TMP1
	nop
	xor	$8, TMP1, $8

	srl	$6, 22, TMP1
	and	TMP1, 0x3fc, TMP1
	add	TMP1, AES_TABLE3, TMP1
	ld	[$2 + TMP1], TMP1
	nop
	xor	$8, TMP1, $8

	ld	[$7 + eval(4*$1)], TMP1
	nop
	xor	$8, TMP1, $8>)dnl

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

