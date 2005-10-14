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
	shrl	<$>6,$7
	andl	<$>0x000003fc,$7	C  clear all but offset bytes
	xorl	AES_TABLE1 ($1, $7),$6
	movl	$4,$7			C  third one
	shrl	<$>14,$7
	andl	<$>0x000003fc,$7
	xorl	AES_TABLE2 ($1, $7),$6
	movl	$5,$7			C  fourth one
	shrl	<$>22,$7
	andl	<$>0x000003fc,$7
	xorl	AES_TABLE3 ($1, $7),$6>)dnl

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

dnl AES_SUBST_BYTE(table, tmp)
dnl Substitutes the least significant byte of
dnl each of eax, ebx, ecx and edx, and also rotates
dnl the words one byte to the left.
dnl FIXME: AES_SBOX is zero. Any win by deleting the offset?
define(<AES_SUBST_BYTE>, <
	movl	%eax,$2
	andl	<$>0x000000ff,$2
	movb	AES_SBOX ($1, $2),%al
	roll	<$>8,%eax

	movl	%ebx,$2
	andl	<$>0x000000ff,$2
	movb	AES_SBOX ($1, $2),%bl
	roll	<$>8,%ebx

	movl	%ecx,$2
	andl	<$>0x000000ff,$2
	movb	AES_SBOX ($1, $2),%cl
	roll	<$>8,%ecx

	movl	%edx,$2
	andl	<$>0x000000ff,$2
	movb	AES_SBOX ($1, $2),%dl
	roll	<$>8,%edx>)dnl

C OFFSET(i)
C Expands to 4*i, or to the empty string if i is zero
define(<OFFSET>, <ifelse($1,0,,eval(4*$1))>)
