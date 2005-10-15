C FIXME: Do we need an OFFSET macro? Or is it fine to use expressions such as [%i1 + 0]

C FIXME: How much can we rely on the assembler to be able to
C understand arithmetic expressions? Mayby we don't need to use m4
C eval.

C AES_LOAD(i, src, key, res, t1, t2)
define(<AES_LOAD>, <
	ldub	[$2 + eval(4*$1)], $4
	ldub	[$2 + eval(4*$1 + 1)], $5
	ldub	[$2 + eval(4*$1 + 2)], $6
	sll	$5, 8, $5
	
	or	$4, $5, $4	! U
	ldub	[$2 + eval(4*$1+3)], $5
	sll	$6, 16, $6
	or	$4, $6, $4
	
	sll	$5, 24, $5
	! Get subkey
	ld	[$3 + eval(4*$1)], $6
	or	$4, $5, $4
	xor	$4, $6, $4>)dnl

C AES_ROUND(i, T, a, b, c, d, key, res, t)
C Computes one word of the AES round
C FIXME: Could use registers pointing directly to the four tables
C FIXME: Needs better instruction scheduling, and perhaps more temporaries
C Alternatively, we can use a single table and some rotations
define(<AES_ROUND>, <
	and	$3, 0xff, $9
	sll	$9, 2, $9
	add	$9, AES_TABLE0, $9
	ld	[$2 + $9], $8

	srl	$4, 6, $9
	and	$9, 0x3fc, $9
	add	$9, AES_TABLE1, $9
	ld	[$2 + $9], $9
	xor	$9, $8

	srl	$5, 14, $9
	and	$9, 0x3fc, $9
	add	$9, AES_TABLE2, $9
	ld	[$2 + $9], $9
	xor	$9, $8

	srl	$4, 22, $9
	and	$9, 0x3fc, $9
	add	$9, AES_TABLE3, $9
	ld	[$2 + $9], $9
	xor	$9, $8

	ld	[$7 + eval(4*$1)], $9
	xor	$9, $8>)dnl

