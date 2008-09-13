dnl AES_LOAD(a, b, c, d, src, key)
dnl Loads the next block of data from src, and add the subkey pointed
dnl to by key.
dnl Note that x86 allows unaligned accesses.
dnl Would it be preferable to interleave the loads and stores?
define(<AES_LOAD>, <
	movl	($5),$1
	movl	4($5),$2
	movl	8($5),$3
	movl	12($5),$4
	
	xorl	($6),$1
	xorl	4($6),$2
	xorl	8($6),$3
	xorl	12($6),$4>)dnl

dnl AES_STORE(a, b, c, d, key, dst)
dnl Adds the subkey to a, b, c, d,
dnl and stores the result in the area pointed to by dst.
dnl Note that x86 allows unaligned accesses.
dnl Would it be preferable to interleave the loads and stores?
define(<AES_STORE>, <
	xorl	($5),$1
	xorl	4($5),$2
	xorl	8($5),$3
	xorl	12($5),$4

	movl	$1,($6)
	movl	$2,4($6)
	movl	$3,8($6)
	movl	$4,12($6)>)dnl

dnl AES_ROUND(table,a,b,c,d,out,tmp)
dnl Computes one word of the AES round. Leaves result in $6.
define(<AES_ROUND>, <
	movl	$2, $7
	andl	<$>0xff, $7
	movl	AES_TABLE0 ($1, $7,4),$6
	movl	$3, $7
	shrl	<$>8,$7
	andl	<$>0xff,$7
	xorl	AES_TABLE1 ($1, $7, 4),$6
	movl	$4,$7			C  third one
	shrl	<$>16,$7
	andl	<$>0xff,$7
	xorl	AES_TABLE2 ($1, $7, 4),$6
	movl	$5,$7			C  fourth one
	shrl	<$>24,$7
	andl	<$>0xff,$7
	xorl	AES_TABLE3 ($1, $7, 4),$6>)dnl

dnl AES_FINAL_ROUND(a, b, c, d, out, tmp)
dnl Computes one word of the final round. Leaves result in %edi.
dnl Note that we have to quote $ in constants.
define(<AES_FINAL_ROUND>, <
	C FIXME: Perform substitution on least significant byte here,
	C to save work later.
	movl	$1,$5
	andl	<$>0x000000ff,$5
	movl	$2,$6
	andl	<$>0x0000ff00,$6
	orl	$6, $5
	movl	$3,$6
	andl	<$>0x00ff0000,$6
	orl	$6, $5
	movl	$4,$6
	andl	<$>0xff000000,$6
	orl	$6, $5>)dnl

dnl BYTEREG(reg) gives the 8-bit register corresponding to the given 32-bit register.
dnl Use in AES_SUBST_BYTE below, and is used by both the x86 and the x86_64 assembler.
define(<BYTEREG>,<ifelse(
	$1, %eax, %al,
	$1, %ebx, %bl,
	$1, %ecx, %cl,
	$1, %edx, %dl,
	dnl The rest are x86_64 only	
	$1, %esi, %sil,
	$1, %edi, %dil,
	$1, %ebp, %bpl,
	$1, %esp, %spl,
	$1, %r8d, %r8b,
	$1, %r9d, %r9b,
	$1, %r10d, %r10b,
	$1, %r11d, %r11b,
	$1, %r12d, %r12b,
	$1, %r13d, %r13b,
	$1, %r14d, %r14b,
	$1, %r15d, %r15b)>)dnl

dnl AES_SUBST_BYTE(A, B, C, D, table, tmp)
dnl Substitutes the least significant byte of
dnl each of eax, ebx, ecx and edx, and also rotates
dnl the words one byte to the left.
dnl Uses that AES_SBOX == 0
define(<AES_SUBST_BYTE>, <
	movl	$1,$6
	andl	<$>0x000000ff,$6
	movb	($5, $6),BYTEREG($1)
	roll	<$>8,$1

	movl	$2,$6
	andl	<$>0x000000ff,$6
	movb	($5, $6),BYTEREG($2)
	roll	<$>8,$2

	movl	$3,$6
	andl	<$>0x000000ff,$6
	movb	($5, $6),BYTEREG($3)
	roll	<$>8,$3

	movl	$4,$6
	andl	<$>0x000000ff,$6
	movb	($5, $6),BYTEREG($4)
	roll	<$>8,$4>)dnl
