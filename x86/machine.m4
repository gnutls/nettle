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
