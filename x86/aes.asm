	.file	"rijndael.s"

	.data

#include "rijndaeltbls.S"

	.text

.globl	print_word

	//// rijndael_encrypt(RIJNDAEL_context *ctx, const UINT8 *plaintext
	////		    UINT8 *ciphertext)
	.align 16
.globl rijndael_encrypt
	.type	rijndael_encrypt,@function
rijndael_encrypt:
	//// save all registers that need to be saved
	pushl	%ebx		// 16(%esp)
	pushl	%ebp		// 12(%esp)
	pushl	%esi		// 8(%esp)
	pushl	%edi		// 4(%esp)
	movl	24(%esp),%esi	// address of plaintext
	movl	(%esi),%eax	// load plaintext into registers
	movl	4(%esi),%ebx
	movl	8(%esi),%ecx
	movl	12(%esi),%edx
	movl	20(%esp),%esi	// address of context struct ctx
	xorl	(%esi),%eax	// add first key to plaintext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx
	movl	20(%esp),%ebp	// address of context struct
	movl	480(%ebp),%ebp	// get number of rounds to do from struct

	subl	$1,%ebp
	addl	$16,%esi	// point to next key
.encrypt_loop:
	pushl	%esi		// save this first: we'll clobber it later

	//// First column
	shll	$2,%esi		// index in dtbl1
	movl	dtbl1(%esi),%edi
	shrl	$6,%esi
	andl	$0x000003fc,%esi // clear all but offset bytes
	xorl	dtbl2(%esi),%edi
	movl	%ecx,%esi	// third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl3(%esi),%edi
	movl	%edx,%esi	// fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl4(%esi),%edi
	pushl	%edi		// save first on stack

	//// Second column
	movl	%ebx,%esi	// copy first in
	andl	$0x000000ff,%esi // clear all but offset
	shll	$2,%esi		// index in dtbl1
	movl	dtbl1(%esi),%edi
	movl	%ecx,%esi	// second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi // clear all but offset bytes
	xorl	dtbl2(%esi),%edi
	movl	%edx,%esi	// third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl3(%esi),%edi
	movl	%eax,%esi	// fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl4(%esi),%edi
	pushl	%edi		// save first on stack

	//// Third column
	movl	%ecx,%esi	// copy first in
	andl	$0x000000ff,%esi // clear all but offset
	shll	$2,%esi		// index in dtbl1
	movl	dtbl1(%esi),%edi
	movl	%edx,%esi	// second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi // clear all but offset bytes
	xorl	dtbl2(%esi),%edi
	movl	%eax,%esi	// third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl3(%esi),%edi
	movl	%ebx,%esi	// fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl4(%esi),%edi
	pushl	%edi		// save first on stack

	//// Fourth column
	movl	%edx,%esi	// copy first in
	andl	$0x000000ff,%esi // clear all but offset
	shll	$2,%esi		// index in dtbl1
	movl	dtbl1(%esi),%edi
	movl	%eax,%esi	// second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi // clear all but offset bytes
	xorl	dtbl2(%esi),%edi
	movl	%ebx,%esi	// third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl3(%esi),%edi
	movl	%ecx,%esi	// fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	dtbl4(%esi),%edi

	movl	%edi,%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	popl	%esi
	xorl	(%esi),%eax	// add current session key to plaintext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx
	addl	$16,%esi	// point to next key
	decl	%ebp
	jnz	.encrypt_loop

	//// last round
	//// first column
	movl	%eax,%edi
	andl	$0x000000ff,%edi
	movl	%ebx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	pushl	%edi

	//// second column
	movl	%eax,%edi
	andl	$0x0000ff00,%edi
	movl	%ebx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	pushl	%edi

	//// third column
	movl	%eax,%edi
	andl	$0x00ff0000,%edi
	movl	%ebx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	pushl	%edi

	//// fourth column
	movl	%eax,%edi
	andl	$0xff000000,%edi
	movl	%ebx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	movl	%edi,%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	xchgl	%ebx,%edx

	//// S-box substitution
	mov	$4,%edi
.sb_sub:
	movl	%eax,%ebp
	andl	$0x000000ff,%ebp
	movb	sbox(%ebp),%al
	roll	$8,%eax

	movl	%ebx,%ebp
	andl	$0x000000ff,%ebp
	movb	sbox(%ebp),%bl
	roll	$8,%ebx

	movl	%ecx,%ebp
	andl	$0x000000ff,%ebp
	movb	sbox(%ebp),%cl
	roll	$8,%ecx

	movl	%edx,%ebp
	andl	$0x000000ff,%ebp
	movb	sbox(%ebp),%dl
	roll	$8,%edx

	decl	%edi
	jnz	.sb_sub

	xorl	(%esi),%eax	// add last key to plaintext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx

	//// store encrypted data back to caller's buffer
	movl	28(%esp),%edi
	movl	%eax,(%edi)
	movl	%ebx,4(%edi)
	movl	%ecx,8(%edi)
	movl	%edx,12(%edi)
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
.eore:
	.size	rijndael_encrypt,.eore-rijndael_encrypt


	//// rijndael_decrypt(RIJNDAEL_context *ctx, const UINT8 *ciphertext
	////		    UINT8 *plaintext)
	.align 16
.globl rijndael_decrypt
	.type	rijndael_decrypt,@function
rijndael_decrypt:
	//// save all registers that need to be saved
	pushl	%ebx		// 16(%esp)
	pushl	%ebp		// 12(%esp)
	pushl	%esi		// 8(%esp)
	pushl	%edi		// 4(%esp)
	movl	24(%esp),%esi	// address of ciphertext
	movl	(%esi),%eax	// load ciphertext into registers
	movl	4(%esi),%ebx
	movl	8(%esi),%ecx
	movl	12(%esi),%edx
	movl	20(%esp),%esi	// address of context struct ctx
	movl	480(%esi),%ebp	// get number of rounds to do from struct
	shll	$4,%ebp
	leal	240(%esi, %ebp),%esi
	shrl	$4,%ebp
	xorl	(%esi),%eax	// add last key to ciphertext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx

	subl	$1,%ebp		// one round is complete
	subl	$16,%esi	// point to previous key
.decrypt_loop:
	pushl	%esi		// save this first: we'll clobber it later
	xchgl	%ebx,%edx

	//// First column
	movl	%eax,%esi	// copy first in
	andl	$0x000000ff,%esi // clear all but offset
	shll	$2,%esi		// index in itbl1
	movl	itbl1(%esi),%edi
	movl	%ebx,%esi	// second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi // clear all but offset bytes
	xorl	itbl2(%esi),%edi
	movl	%ecx,%esi	// third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	itbl3(%esi),%edi
	movl	%edx,%esi	// fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	itbl4(%esi),%edi
	pushl	%edi		// save first on stack

	//// Second column
	movl	%edx,%esi	// copy first in
	andl	$0x000000ff,%esi // clear all but offset
	shll	$2,%esi		// index in itbl1
	movl	itbl1(%esi),%edi
	movl	%eax,%esi	// second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi // clear all but offset bytes
	xorl	itbl2(%esi),%edi
	movl	%ebx,%esi	// third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	itbl3(%esi),%edi
	movl	%ecx,%esi	// fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	itbl4(%esi),%edi
	pushl	%edi

	//// Third column
	movl	%ecx,%esi	// copy first in
	andl	$0x000000ff,%esi // clear all but offset
	shll	$2,%esi		// index in itbl1
	movl	itbl1(%esi),%edi
	movl	%edx,%esi	// second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi // clear all but offset bytes
	xorl	itbl2(%esi),%edi
	movl	%eax,%esi	// third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	itbl3(%esi),%edi
	movl	%ebx,%esi	// fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	itbl4(%esi),%edi
	pushl	%edi		// save first on stack

	//// Fourth column
	movl	%ebx,%esi	// copy first in
	andl	$0x000000ff,%esi // clear all but offset
	shll	$2,%esi		// index in itbl1
	movl	itbl1(%esi),%edi
	movl	%ecx,%esi	// second one
	shrl	$6,%esi
	andl	$0x000003fc,%esi // clear all but offset bytes
	xorl	itbl2(%esi),%edi
	movl	%edx,%esi	// third one
	shrl	$14,%esi
	andl	$0x000003fc,%esi
	xorl	itbl3(%esi),%edi
	movl	%eax,%esi	// fourth one
	shrl	$22,%esi
	andl	$0x000003fc,%esi
	xorl	itbl4(%esi),%edi
	movl	%edi,%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	popl	%esi
	xorl	(%esi),%eax	// add current session key to plaintext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx
	subl	$16,%esi	// point to previous key
	decl	%ebp
	jnz	.decrypt_loop

	xchgl	%ebx,%edx

	//// last round
	//// first column
	movl	%eax,%edi
	andl	$0x000000ff,%edi
	movl	%ebx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	pushl	%edi

	//// second column
	movl	%eax,%edi
	andl	$0xff000000,%edi
	movl	%ebx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	pushl	%edi

	//// third column
	movl	%eax,%edi
	andl	$0x00ff0000,%edi
	movl	%ebx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x0000ff00,%ebp
	orl	%ebp,%edi
	pushl	%edi

	//// second column
	movl	%eax,%edi
	andl	$0x0000ff00,%edi
	movl	%ebx,%ebp
	andl	$0x00ff0000,%ebp
	orl	%ebp,%edi
	movl	%ecx,%ebp
	andl	$0xff000000,%ebp
	orl	%ebp,%edi
	movl	%edx,%ebp
	andl	$0x000000ff,%ebp
	orl	%ebp,%edi
	movl	%edi,%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	xchgl	%ebx,%edx

	//// inverse S-box substitution
	mov	$4,%edi
.isb_sub:
	movl	%eax,%ebp
	andl	$0x000000ff,%ebp
	movb	isbox(%ebp),%al
	roll	$8,%eax

	movl	%ebx,%ebp
	andl	$0x000000ff,%ebp
	movb	isbox(%ebp),%bl
	roll	$8,%ebx

	movl	%ecx,%ebp
	andl	$0x000000ff,%ebp
	movb	isbox(%ebp),%cl
	roll	$8,%ecx

	movl	%edx,%ebp
	andl	$0x000000ff,%ebp
	movb	isbox(%ebp),%dl
	roll	$8,%edx

	decl	%edi
	jnz	.isb_sub

	xorl	(%esi),%eax	// add first key to plaintext
	xorl	4(%esi),%ebx
	xorl	8(%esi),%ecx
	xorl	12(%esi),%edx

	//// store decrypted data back to caller's buffer
	movl	28(%esp),%edi
	movl	%eax,(%edi)
	movl	%ebx,4(%edi)
	movl	%ecx,8(%edi)
	movl	%edx,12(%edi)
	popl	%edi
	popl	%esi
	popl	%ebp
	popl	%ebx
	ret
.eord:
	.size	rijndael_decrypt,.eord-rijndael_decrypt

	.align 16
.globl rijndael_setup
	.type	rijndael_setup,@function
rijndael_decrypt:
	//// save all registers that need to be saved
	pushl	%ebx		// 16(%esp)
	pushl	%ebp		// 12(%esp)
	pushl	%esi		// 8(%esp)
	pushl	%edi		// 4(%esp)
	movl	20(%esp),%esi	/* context structure */
	movl	24(%esp),%ecx	/* key size */
	movl	28(%esp),%edi	/* original key */
	/* This code assumes that the key length given is greater than
	   or equal to 4 words (128 bits).  BAD THINGS WILL HAPPEN
	   OTHERWISE! */
	shrl	$2,%ecx		/* divide by 4 to get total key length */
	movl	%ecx,%edx	/* calculate the number of rounds */
	addl	$6,%edx		/* key length in words + 6 = num. rounds */
	/* copy the initial key into the context structure */
	pushl	%ecx
.key_copy_loop:	
	movl	(%edi),%eax
	addl	$4,%edi
	movl	%eax,(%esi)
	addl	$4,%esi
	decl	%ecx
	jnz	.key_copy_loop
	popl	%ecx
	incl	%edx		/* number of rounds + 1 */
	shll	$2,%edx		/* times rijndael blk size 4words */
	subl	%ecx,%edx	/* # of other keys to make */
	movl	%ecx,%ebp
	decl	%ecx		/* turn ecx into a mask */
	movl	$1,%ebx		/* round constant */
.keygen_loop:
	movl	-4(%esi),%eax	/* previous key */
	testl	%ecx,%ebp
	jnz	.testnk
	/* rotate and substitute */
	roll	$8,%eax
	movl	%eax,%edi
	andl	$0xff,%eax
