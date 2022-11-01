C Threshold of processing multiple blocks in parallel
C of a multiple of 4
define(`POLY1305_BLOCK_THRESHOLD', `12')

C Argments
define(`CTX', `r3')
define(`DATA', `r4')
define(`PADBYTE', `r5') C Padding byte register
define(`LEN', `r6')

define(`DEFINES_BLOCK_R64', `
	define(`T0', `r9')
	define(`T1', `r10')
	define(`T2', `r8')
	define(`T2A', `r9')
	define(`T2S', `r10')
	define(`RZ', `r6')
	define(`IDX', `r10')

	define(`ZERO', `v0')
	define(`F0S', `v3')
	define(`F11', `v4')
	define(`T', `v5')

	define(`R', `v6')
	define(`S', `v7')

	define(`T00', `v8')
	define(`T10', `v9')
	define(`T11', `v10')
	define(`MU0', `v11')
	define(`MU1', `v12')
	')

C Inputs H0, H1, H2 are general-puropse registers of previous state radix 2^64
C Outputs F0, F1 are vector registers of result state radix 2^64 sorted as follows
C (low 64-bit of F0) + (low 64-bit of F1) + (high 64-bit of F1)
C BLOCK_R64(F0, F1, H0, H1, H2)
define(`BLOCK_R64', `
	DEFINES_BLOCK_R64()
	C Load 128-bit input block
IF_LE(`
	ld			T0, 0(DATA)
	ld			T1, 8(DATA)
')
IF_BE(`
	li			IDX, 8
	ldbrx		T1, IDX, DATA
	ldbrx		T0, 0, DATA
')
	C Combine state with input block, latter is padded to 17-bytes 
	C by low-order byte of PADBYTE register
	addc		T0, T0, $3
	adde		T1, T1, $4
	adde		T2, PADBYTE, $5

	mtvsrdd		VSR(T), T0, T1

	C Load key and pre-computed values
	li			IDX, 16
	lxvd2x		VSR(R), 0, CTX
	lxvd2x		VSR(S), IDX, CTX

	andi.		T2A, T2, 3
	srdi		T2S, T2, 2

	li			RZ, 0
	vxor		ZERO, ZERO, ZERO

	xxpermdi	VSR(MU0), VSR(R), VSR(S), 0b01
	xxswapd		VSR(MU1), VSR(R)

	mtvsrdd		VSR(T11), 0, T2A
	mtvsrdd		VSR(T00), T2S, RZ
	mtvsrdd		VSR(T10), 0, T2

	C Mutiplicate key by combined state and block
	vmsumudm	$1, T, MU0, ZERO
	vmsumudm	$2, T, MU1, ZERO
	vmsumudm	F11, T11, MU1, ZERO

	vmsumudm	$1, T00, S, $1
	vmsumudm	$2, T10, MU0, $2

	C Product addition
	xxmrgld		VSR(F11), VSR(F11), VSR(ZERO)
	vadduqm		$2, $2, F11

	xxmrghd		VSR(F0S), VSR(ZERO), VSR($1)
	vadduqm		$2, $2, F0S
	')
