dnl AES_LAST_ROUND(a, b, c, d)
dnl Leaves result in %edi
dnl Note that we have to quote $ in constants.
define(<AES_LAST_ROUND>, <
	movl	%e<>$1<>x,%edi
	andl	<$>0x000000ff,%edi
	movl	%e<>$2<>x,%ebp
	andl	<$>0x0000ff00,%ebp
	orl	%ebp,%edi
	movl	%e<>$3<>x,%ebp
	andl	<$>0x00ff0000,%ebp
	orl	%ebp,%edi
	movl	%e<>$4<>x,%ebp
	andl	<$>0xff000000,%ebp
	orl	%ebp,%edi>)dnl

dnl AES_LOAD(key, src)
dnl Loads the next block of data from src, and add the subkey pointed
dnl to by key.
dnl Note that x86 allows unaligned accesses.
dnl Would it be preferable to interleave the loads and stores?
define(<AES_LOAD>, <
	movl	($2),%eax
	movl	4($2),%ebx
	movl	8($2),%ecx
	movl	12($2),%edx
	
	xorl	($1),%eax
	xorl	4($1),%ebx
	xorl	8($1),%ecx
	xorl	12($1),%edx>)dnl

dnl AES_STORE(key, dst)
dnl Adds the subkey pointed to by %esi to %eax-%edx,
dnl and stores the result in the area pointed to by %edi.
dnl Note that x86 allows unaligned accesses.
dnl Would it be preferable to interleave the loads and stores?
define(<AES_STORE>, <
	xorl	($1),%eax
	xorl	4($1),%ebx
	xorl	8($1),%ecx
	xorl	12($1),%edx

	movl	%eax,($2)
	movl	%ebx,4($2)
	movl	%ecx,8($2)
	movl	%edx,12($2)>)dnl
