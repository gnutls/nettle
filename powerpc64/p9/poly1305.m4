C Threshold of processing multiple blocks in parallel
C of a multiple of 4
define(`POLY1305_BLOCK_THRESHOLD', `12')

C DEFINES_BLOCK_R64(GPR0, VR0)
define(`DEFINES_BLOCK_R64', `
	define(`H0', `eval(0+$1)')
	define(`H1', `eval(1+$1)')
	define(`H2', `eval(2+$1)')
	
	define(`T0', `eval(3+$1)')
	define(`T1', `eval(4+$1)')
	define(`T2', `eval(2+$1)')
	define(`T2A', `eval(3+$1)')
	define(`T2S', `eval(4+$1)')
	define(`RZ', `eval(0+$1)')
	define(`IDX', `eval(4+$1)')

	define(`F0', `eval(0+$2)')
	define(`F1', `eval(1+$2)')
	
	define(`ZERO', `eval(2+$2)')
	define(`F0S', `eval(3+$2)')
	define(`F11', `eval(4+$2)')
	define(`T', `eval(5+$2)')

	define(`R', `eval(6+$2)')
	define(`S', `eval(7+$2)')

	define(`T00', `eval(8+$2)')
	define(`T10', `eval(9+$2)')
	define(`T11', `eval(10+$2)')
	define(`MU0', `eval(11+$2)')
	define(`MU1', `eval(12+$2)')
	')

C CTX is the address of context where key and pre-computed values are stored
C DATA is the address of input block
C PADBYTE is padding byte for input block
C GPR0 is the starting register of sequential general-purpose registers 
C used in the macro of following layout
C GPR0, GPR1, GPR2 are inputs representing the previous state radix 2^64
C GPR3, GPR4 are temporary registers
C VR0 is the starting register of sequential vector resigers used in
C the macro of following layout
C VR0, VR1 are outputs representing the result state radix 2^64 sorted as follows
C (low 64-bit of VR0) + (low 64-bit of VR1) + (high 64-bit of VR1)
C VR2..VR12 are temporary registers
C BLOCK_R64(CTX, DATA, PADBYTE, GPR0, VR0)
define(`BLOCK_R64', `
	DEFINES_BLOCK_R64($4,$5)
	C Load 128-bit input block
IF_LE(`
	ld			T0, 0($2)
	ld			T1, 8($2)
')
IF_BE(`
	li			IDX, 8
	ldbrx		T1, IDX, $2
	ldbrx		T0, 0, $2
')
	C Combine state with input block, latter is padded to 17-bytes 
	C by low-order byte of PADBYTE register
	addc		T0, T0, H0
	adde		T1, T1, H1
	adde		T2, $3, H2

	mtvsrdd		VSR(T), T0, T1

	C Load key and pre-computed values
	li			IDX, 16
	lxvd2x		VSR(R), 0, $1
	lxvd2x		VSR(S), IDX, $1

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
	vmsumudm	F0, T, MU0, ZERO
	vmsumudm	F1, T, MU1, ZERO
	vmsumudm	F11, T11, MU1, ZERO

	vmsumudm	F0, T00, S, F0
	vmsumudm	F1, T10, MU0, F1

	C Product addition
	xxmrgld		VSR(F11), VSR(F11), VSR(ZERO)
	vadduqm		F1, F1, F11

	xxmrghd		VSR(F0S), VSR(ZERO), VSR(F0)
	vadduqm		F1, F1, F0S
	')
