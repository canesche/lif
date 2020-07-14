	.text
	.file	"llvm-link"
	.globl	main                    # -- Begin function main
	.p2align	4, 0x90
	.type	main,@function
main:                                   # @main
	.cfi_startproc
# %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	subq	$48, %rsp
	movq	%fs:40, %rax
	movq	%rax, -8(%rbp)
	movaps	.L__const.main.input_data(%rip), %xmm0
	movaps	%xmm0, -48(%rbp)
	movaps	.L__const.main.input_data+16(%rip), %xmm0
	movaps	%xmm0, -32(%rbp)
	leaq	-48(%rbp), %rdi
	movl	$32, %esi
	callq	do_one_computation
	movzbl	%al, %esi
	movl	$.L.str, %edi
	xorl	%eax, %eax
	callq	printf
	movq	%fs:40, %rax
	cmpq	-8(%rbp), %rax
	jne	.LBB0_2
# %bb.1:                                # %SP_return
	xorl	%eax, %eax
	addq	$48, %rsp
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.LBB0_2:                                # %CallStackCheckFailBlk
	.cfi_def_cfa %rbp, 16
	callq	__stack_chk_fail
.Lfunc_end0:
	.size	main, .Lfunc_end0-main
	.cfi_endproc
                                        # -- End function
	.globl	do_one_computation      # -- Begin function do_one_computation
	.p2align	4, 0x90
	.type	do_one_computation,@function
do_one_computation:                     # @do_one_computation
# %bb.0:
	pushq	%r15
	pushq	%r14
	pushq	%rbx
	subq	$64, %rsp
	movq	%rdi, %rbx
	xorps	%xmm0, %xmm0
	movaps	%xmm0, 16(%rsp)
	movaps	%xmm0, (%rsp)
	movaps	.L__const.do_one_computation.basepoint(%rip), %xmm0
	movaps	%xmm0, 32(%rsp)
	movaps	.L__const.do_one_computation.basepoint+16(%rip), %xmm0
	movaps	%xmm0, 48(%rsp)
	movq	%rsp, %r14
	leaq	32(%rsp), %r15
	movl	$32, %esi
	movl	$32, %r9d
	movq	%r14, %rdi
	movq	%rbx, %rdx
	movq	%r15, %r8
	callq	curve25519_donna
	movq	(%rsp), %rax
	movq	8(%rsp), %rcx
	movq	%rax, (%rbx)
	movq	%rcx, 8(%rbx)
	movq	16(%rsp), %rax
	movq	%rax, 16(%rbx)
	movq	24(%rsp), %rax
	movq	%rax, 24(%rbx)
	movl	$32, %esi
	movl	$32, %r9d
	movq	%r14, %rdi
	movq	%rbx, %rdx
	movq	%r15, %r8
	callq	curve25519_donna
	movq	(%rsp), %rax
	movq	8(%rsp), %rcx
	movq	%rax, (%rbx)
	movq	%rcx, 8(%rbx)
	movq	16(%rsp), %rax
	movq	%rax, 16(%rbx)
	movq	24(%rsp), %rax
	movq	%rax, 24(%rbx)
	movl	$32, %esi
	movl	$32, %r9d
	movq	%r14, %rdi
	movq	%rbx, %rdx
	movq	%r15, %r8
	callq	curve25519_donna
	movq	(%rsp), %rax
	movq	8(%rsp), %rcx
	movq	%rax, (%rbx)
	movq	%rcx, 8(%rbx)
	movq	16(%rsp), %rax
	movq	%rax, 16(%rbx)
	movq	24(%rsp), %rax
	movq	%rax, 24(%rbx)
	movl	$32, %esi
	movl	$32, %r9d
	movq	%r14, %rdi
	movq	%rbx, %rdx
	movq	%r15, %r8
	callq	curve25519_donna
	movq	(%rsp), %rax
	movq	8(%rsp), %rcx
	movq	%rax, (%rbx)
	movq	%rcx, 8(%rbx)
	movq	16(%rsp), %rax
	movq	%rax, 16(%rbx)
	movq	24(%rsp), %rax
	movq	%rax, 24(%rbx)
	movl	$32, %esi
	movl	$32, %r9d
	movq	%r14, %rdi
	movq	%rbx, %rdx
	movq	%r15, %r8
	callq	curve25519_donna
	movq	(%rsp), %rax
	movq	8(%rsp), %rcx
	movq	%rax, (%rbx)
	movq	%rcx, 8(%rbx)
	movq	16(%rsp), %rax
	movq	%rax, 16(%rbx)
	movq	24(%rsp), %rax
	movq	%rax, 24(%rbx)
	movl	$32, %esi
	movl	$32, %r9d
	movq	%r14, %rdi
	movq	%rbx, %rdx
	movq	%r15, %r8
	callq	curve25519_donna
	movq	(%rsp), %rax
	movq	8(%rsp), %rcx
	movq	%rax, (%rbx)
	movq	%rcx, 8(%rbx)
	movq	16(%rsp), %rax
	movq	%rax, 16(%rbx)
	movq	24(%rsp), %rax
	movq	%rax, 24(%rbx)
	movl	$32, %esi
	movl	$32, %r9d
	movq	%r14, %rdi
	movq	%rbx, %rdx
	movq	%r15, %r8
	callq	curve25519_donna
	movq	(%rsp), %rax
	movq	8(%rsp), %rcx
	movq	%rax, (%rbx)
	movq	%rcx, 8(%rbx)
	movq	16(%rsp), %rax
	movq	%rax, 16(%rbx)
	movq	24(%rsp), %rax
	movq	%rax, 24(%rbx)
	movl	$32, %esi
	movl	$32, %r9d
	movq	%r14, %rdi
	movq	%rbx, %rdx
	movq	%r15, %r8
	callq	curve25519_donna
	movq	(%rsp), %rax
	movq	8(%rsp), %rcx
	movq	%rax, (%rbx)
	movq	%rcx, 8(%rbx)
	movq	16(%rsp), %rax
	movq	%rax, 16(%rbx)
	movq	24(%rsp), %rax
	movq	%rax, 24(%rbx)
	movl	$32, %esi
	movl	$32, %r9d
	movq	%r14, %rdi
	movq	%rbx, %rdx
	movq	%r15, %r8
	callq	curve25519_donna
	movq	24(%rsp), %rax
	movq	%rax, 24(%rbx)
	movq	16(%rsp), %rax
	movq	%rax, 16(%rbx)
	movq	(%rsp), %rax
	movq	8(%rsp), %rcx
	movq	%rcx, 8(%rbx)
	movq	%rax, (%rbx)
	movb	(%rsp), %al
	addq	$64, %rsp
	popq	%rbx
	popq	%r14
	popq	%r15
	retq
.Lfunc_end1:
	.size	do_one_computation, .Lfunc_end1-do_one_computation
                                        # -- End function
	.globl	init_dut                # -- Begin function init_dut
	.p2align	4, 0x90
	.type	init_dut,@function
init_dut:                               # @init_dut
	.cfi_startproc
# %bb.0:
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset %rbp, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register %rbp
	popq	%rbp
	.cfi_def_cfa %rsp, 8
	retq
.Lfunc_end2:
	.size	init_dut, .Lfunc_end2-init_dut
	.cfi_endproc
                                        # -- End function
	.globl	prepare_inputs          # -- Begin function prepare_inputs
	.p2align	4, 0x90
	.type	prepare_inputs,@function
prepare_inputs:                         # @prepare_inputs
	.cfi_startproc
# %bb.0:
	pushq	%r14
	.cfi_def_cfa_offset 16
	pushq	%rbx
	.cfi_def_cfa_offset 24
	pushq	%rax
	.cfi_def_cfa_offset 32
	.cfi_offset %rbx, -24
	.cfi_offset %r14, -16
	movq	%rdx, %r14
	movq	%rdi, %rbx
	movl	$32, %edx
	callq	randombytes
	callq	randombit
	movb	%al, (%r14)
	testb	%al, %al
	jne	.LBB3_2
# %bb.1:
	movq	$0, 24(%rbx)
	movq	$0, 16(%rbx)
	movq	$0, 8(%rbx)
	movq	$0, (%rbx)
.LBB3_2:
	addq	$8, %rsp
	.cfi_def_cfa_offset 24
	popq	%rbx
	.cfi_def_cfa_offset 16
	popq	%r14
	.cfi_def_cfa_offset 8
	retq
.Lfunc_end3:
	.size	prepare_inputs, .Lfunc_end3-prepare_inputs
	.cfi_endproc
                                        # -- End function
	.globl	curve25519_donna        # -- Begin function curve25519_donna
	.p2align	4, 0x90
	.type	curve25519_donna,@function
curve25519_donna:                       # @curve25519_donna
# %bb.0:
	pushq	%rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	subq	$1224, %rsp             # imm = 0x4C8
	movq	%rdi, 72(%rsp)          # 8-byte Spill
	movb	(%rdx), %al
	movb	%al, (%rsp)
	movb	1(%rdx), %al
	movb	%al, 1(%rsp)
	movb	2(%rdx), %al
	movb	%al, 2(%rsp)
	movb	3(%rdx), %al
	movb	%al, 3(%rsp)
	movb	4(%rdx), %al
	movb	%al, 4(%rsp)
	movb	5(%rdx), %al
	movb	%al, 5(%rsp)
	movb	6(%rdx), %al
	movb	%al, 6(%rsp)
	movb	7(%rdx), %al
	movb	%al, 7(%rsp)
	movb	8(%rdx), %al
	movb	%al, 8(%rsp)
	movb	9(%rdx), %al
	movb	%al, 9(%rsp)
	movb	10(%rdx), %al
	movb	%al, 10(%rsp)
	movb	11(%rdx), %al
	movb	%al, 11(%rsp)
	movb	12(%rdx), %al
	movb	%al, 12(%rsp)
	movb	13(%rdx), %al
	movb	%al, 13(%rsp)
	movb	14(%rdx), %al
	movb	%al, 14(%rsp)
	movb	15(%rdx), %al
	movb	%al, 15(%rsp)
	movb	16(%rdx), %al
	movb	%al, 16(%rsp)
	movb	17(%rdx), %al
	movb	%al, 17(%rsp)
	movb	18(%rdx), %al
	movb	%al, 18(%rsp)
	movb	19(%rdx), %al
	movb	%al, 19(%rsp)
	movb	20(%rdx), %al
	movb	%al, 20(%rsp)
	movb	21(%rdx), %al
	movb	%al, 21(%rsp)
	movb	22(%rdx), %al
	movb	%al, 22(%rsp)
	movb	23(%rdx), %al
	movb	%al, 23(%rsp)
	movb	24(%rdx), %al
	movb	%al, 24(%rsp)
	movb	25(%rdx), %al
	movb	%al, 25(%rsp)
	movb	26(%rdx), %al
	movb	%al, 26(%rsp)
	movb	27(%rdx), %al
	movb	%al, 27(%rsp)
	movb	28(%rdx), %al
	movb	%al, 28(%rsp)
	movb	29(%rdx), %al
	movb	%al, 29(%rsp)
	movb	30(%rdx), %al
	movb	%al, 30(%rsp)
	movb	31(%rdx), %al
	movb	%al, 31(%rsp)
	andb	$-8, (%rsp)
	andb	$63, %al
	orb	$64, %al
	movb	%al, 31(%rsp)
	movzwl	(%r8), %eax
	movzbl	2(%r8), %ecx
	shlq	$16, %rcx
	orq	%rax, %rcx
	movzbl	3(%r8), %eax
	andl	$3, %eax
	shlq	$24, %rax
	orq	%rcx, %rax
	movq	%rax, 80(%rsp)
	movl	3(%r8), %eax
	shrl	$2, %eax
	andl	$33554431, %eax         # imm = 0x1FFFFFF
	movq	%rax, 88(%rsp)
	movl	6(%r8), %eax
	shrl	$3, %eax
	andl	$67108863, %eax         # imm = 0x3FFFFFF
	movq	%rax, 96(%rsp)
	movl	9(%r8), %eax
	shrl	$5, %eax
	andl	$33554431, %eax         # imm = 0x1FFFFFF
	movq	%rax, 104(%rsp)
	movl	12(%r8), %eax
	shrl	$6, %eax
	movq	%rax, 112(%rsp)
	movzwl	16(%r8), %eax
	movzbl	18(%r8), %ecx
	shlq	$16, %rcx
	orq	%rax, %rcx
	movzbl	19(%r8), %eax
	andl	$1, %eax
	shlq	$24, %rax
	orq	%rcx, %rax
	movq	%rax, 120(%rsp)
	movl	19(%r8), %eax
	shrl	%eax
	andl	$67108863, %eax         # imm = 0x3FFFFFF
	movq	%rax, 128(%rsp)
	movl	22(%r8), %eax
	shrl	$3, %eax
	andl	$33554431, %eax         # imm = 0x1FFFFFF
	movq	%rax, 136(%rsp)
	movl	25(%r8), %eax
	shrl	$4, %eax
	andl	$67108863, %eax         # imm = 0x3FFFFFF
	movq	%rax, 144(%rsp)
	movl	28(%r8), %eax
	shrl	$6, %eax
	andl	$33554431, %eax         # imm = 0x1FFFFFF
	movq	%rax, 152(%rsp)
	leaq	256(%rsp), %rdi
	leaq	160(%rsp), %r15
	movq	%rsp, %rdx
	leaq	80(%rsp), %rcx
	movq	%r15, %rsi
	callq	cmult
	leaq	1136(%rsp), %r14
	movl	$11, %edx
	movq	%r14, %rdi
	movq	%r15, %rsi
	callq	fsquare
	leaq	496(%rsp), %rbx
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%r14, %rsi
	callq	fsquare
	leaq	576(%rsp), %rbp
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	leaq	1056(%rsp), %r12
	movl	$11, %ecx
	movq	%r12, %rdi
	movq	%rbp, %rsi
	movq	%r15, %rdx
	callq	fmul
	leaq	336(%rsp), %r13
	movl	$10, %ecx
	movq	%r13, %rdi
	movq	%r12, %rsi
	movq	%r14, %rdx
	callq	fmul
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%r13, %rsi
	callq	fsquare
	leaq	976(%rsp), %r13
	movl	$10, %ecx
	movq	%r13, %rdi
	movq	%rbp, %rsi
	movq	%r12, %rdx
	callq	fmul
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%r13, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	leaq	896(%rsp), %r14
	movl	$10, %ecx
	movq	%r14, %rdi
	movq	%rbp, %rsi
	movq	%r13, %rdx
	callq	fmul
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%r14, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	leaq	816(%rsp), %r13
	movl	$10, %ecx
	movq	%r13, %rdi
	movq	%rbx, %rsi
	movq	%r14, %rdx
	callq	fmul
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%r13, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %ecx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	movq	%r13, %rdx
	callq	fmul
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	leaq	736(%rsp), %r13
	movl	$10, %ecx
	movq	%r13, %rdi
	movq	%rbp, %rsi
	movq	%r14, %rdx
	callq	fmul
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%r13, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	leaq	656(%rsp), %r14
	movl	$10, %ecx
	movq	%r14, %rdi
	movq	%rbx, %rsi
	movq	%r13, %rdx
	callq	fmul
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%r14, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %ecx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	movq	%r14, %rdx
	callq	fmul
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %ecx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	movq	%r13, %rdx
	callq	fmul
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	callq	fsquare
	movl	$10, %edx
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	callq	fsquare
	leaq	416(%rsp), %rbp
	movl	$10, %ecx
	movq	%rbp, %rdi
	movq	%rbx, %rsi
	leaq	336(%rsp), %rdx
	callq	fmul
	movl	$10, %ecx
	movq	%r15, %rdi
	leaq	256(%rsp), %rsi
	movq	%rbp, %rdx
	callq	fmul
	movl	160(%rsp), %r10d
	movl	%r10d, %ecx
	sarl	$31, %ecx
	andl	%r10d, %ecx
	movl	%ecx, %r14d
	sarl	$26, %r14d
	andl	$-67108864, %ecx        # imm = 0xFC000000
	subl	%ecx, %r10d
	addl	168(%rsp), %r14d
	movl	%r14d, %edx
	sarl	$31, %edx
	andl	%r14d, %edx
	movl	%edx, %ecx
	sarl	$25, %ecx
	andl	$-33554432, %edx        # imm = 0xFE000000
	subl	%edx, %r14d
	addl	176(%rsp), %ecx
	movl	%ecx, %esi
	sarl	$31, %esi
	andl	%ecx, %esi
	movl	%esi, %edx
	sarl	$26, %edx
	andl	$-67108864, %esi        # imm = 0xFC000000
	subl	%esi, %ecx
	addl	184(%rsp), %edx
	movl	%edx, %edi
	sarl	$31, %edi
	andl	%edx, %edi
	movl	%edi, %r9d
	sarl	$25, %r9d
	andl	$-33554432, %edi        # imm = 0xFE000000
	subl	%edi, %edx
	addl	192(%rsp), %r9d
	movl	%r9d, %esi
	sarl	$31, %esi
	andl	%r9d, %esi
	movl	%esi, %edi
	sarl	$26, %edi
	andl	$-67108864, %esi        # imm = 0xFC000000
	subl	%esi, %r9d
	addl	200(%rsp), %edi
	movl	%edi, %esi
	sarl	$31, %esi
	andl	%edi, %esi
	movl	%esi, %ebp
	sarl	$25, %ebp
	andl	$-33554432, %esi        # imm = 0xFE000000
	subl	%esi, %edi
	addl	208(%rsp), %ebp
	movl	%ebp, %esi
	sarl	$31, %esi
	andl	%ebp, %esi
	movl	%esi, %ebx
	sarl	$26, %ebx
	andl	$-67108864, %esi        # imm = 0xFC000000
	subl	%esi, %ebp
	addl	216(%rsp), %ebx
	movl	%ebx, %esi
	sarl	$31, %esi
	andl	%ebx, %esi
	movl	%esi, %r8d
	sarl	$25, %r8d
	andl	$-33554432, %esi        # imm = 0xFE000000
	subl	%esi, %ebx
	addl	224(%rsp), %r8d
	movl	%r8d, %esi
	sarl	$31, %esi
	andl	%r8d, %esi
	movl	%esi, %r11d
	sarl	$26, %r11d
	andl	$-67108864, %esi        # imm = 0xFC000000
	subl	%esi, %r8d
	addl	232(%rsp), %r11d
	movl	%r11d, %esi
	sarl	$31, %esi
	andl	%r11d, %esi
	movl	%esi, %eax
	sarl	$25, %eax
	andl	$-33554432, %esi        # imm = 0xFE000000
	subl	%esi, %r11d
	leal	(%rax,%rax,8), %esi
	leal	(%rax,%rsi,2), %r13d
	addl	%r10d, %r13d
	movl	%r13d, %eax
	sarl	$31, %eax
	andl	%r13d, %eax
	movl	%eax, %r10d
	sarl	$26, %r10d
	addl	%r14d, %r10d
	andl	$-67108864, %eax        # imm = 0xFC000000
	subl	%eax, %r13d
	movl	%r10d, %eax
	sarl	$31, %eax
	andl	%r10d, %eax
	movl	%eax, %r14d
	sarl	$25, %r14d
	addl	%ecx, %r14d
	andl	$-33554432, %eax        # imm = 0xFE000000
	subl	%eax, %r10d
	movl	%r14d, %eax
	sarl	$31, %eax
	andl	%r14d, %eax
	movl	%eax, %r15d
	sarl	$26, %r15d
	addl	%edx, %r15d
	andl	$-67108864, %eax        # imm = 0xFC000000
	subl	%eax, %r14d
	movl	%r15d, %eax
	sarl	$31, %eax
	andl	%r15d, %eax
	movl	%eax, %r12d
	sarl	$25, %r12d
	addl	%r9d, %r12d
	andl	$-33554432, %eax        # imm = 0xFE000000
	subl	%eax, %r15d
	movl	%r12d, %eax
	sarl	$31, %eax
	andl	%r12d, %eax
	movl	%eax, %edx
	sarl	$26, %edx
	addl	%edi, %edx
	andl	$-67108864, %eax        # imm = 0xFC000000
	subl	%eax, %r12d
	movl	%edx, %eax
	sarl	$31, %eax
	andl	%edx, %eax
	movl	%eax, %r9d
	sarl	$25, %r9d
	addl	%ebp, %r9d
	andl	$-33554432, %eax        # imm = 0xFE000000
	subl	%eax, %edx
	movl	%r9d, %eax
	sarl	$31, %eax
	andl	%r9d, %eax
	movl	%eax, %ebp
	sarl	$26, %ebp
	addl	%ebx, %ebp
	andl	$-67108864, %eax        # imm = 0xFC000000
	subl	%eax, %r9d
	movl	%ebp, %eax
	sarl	$31, %eax
	andl	%ebp, %eax
	movl	%eax, %ebx
	sarl	$25, %ebx
	addl	%r8d, %ebx
	andl	$-33554432, %eax        # imm = 0xFE000000
	subl	%eax, %ebp
	movl	%ebx, %eax
	sarl	$31, %eax
	andl	%ebx, %eax
	movl	%eax, %esi
	sarl	$26, %esi
	addl	%r11d, %esi
	andl	$-67108864, %eax        # imm = 0xFC000000
	subl	%eax, %ebx
	movl	%esi, %eax
	sarl	$31, %eax
	andl	%esi, %eax
	movl	%eax, %ecx
	sarl	$25, %ecx
	andl	$-33554432, %eax        # imm = 0xFE000000
	subl	%eax, %esi
	leal	(%rcx,%rcx,8), %eax
	leal	(%rcx,%rax,2), %ecx
	addl	%r13d, %ecx
	movl	%ecx, %eax
	sarl	$31, %eax
	andl	%ecx, %eax
	movl	%eax, %edi
	sarl	$26, %edi
	addl	%r10d, %edi
	andl	$-67108864, %eax        # imm = 0xFC000000
	subl	%eax, %ecx
	movl	%ecx, %r13d
	sarl	$26, %r13d
	addl	%edi, %r13d
	andl	$67108863, %ecx         # imm = 0x3FFFFFF
	movl	%r13d, %edi
	sarl	$25, %edi
	addl	%r14d, %edi
	andl	$33554431, %r13d        # imm = 0x1FFFFFF
	movl	%edi, %r10d
	sarl	$26, %r10d
	addl	%r15d, %r10d
	andl	$67108863, %edi         # imm = 0x3FFFFFF
	movl	%r10d, %r14d
	sarl	$25, %r14d
	addl	%r12d, %r14d
	andl	$33554431, %r10d        # imm = 0x1FFFFFF
	movl	%r14d, %r8d
	sarl	$26, %r8d
	addl	%edx, %r8d
	andl	$67108863, %r14d        # imm = 0x3FFFFFF
	movl	%r8d, %r12d
	sarl	$25, %r12d
	addl	%r9d, %r12d
	andl	$33554431, %r8d         # imm = 0x1FFFFFF
	movl	%r12d, %eax
	sarl	$26, %eax
	addl	%ebp, %eax
	andl	$67108863, %r12d        # imm = 0x3FFFFFF
	movl	%eax, %ebp
	sarl	$25, %ebp
	addl	%ebx, %ebp
	andl	$33554431, %eax         # imm = 0x1FFFFFF
	movl	%ebp, %ebx
	sarl	$26, %ebx
	addl	%esi, %ebx
	andl	$67108863, %ebp         # imm = 0x3FFFFFF
	movl	%ebx, %esi
	sarl	$25, %esi
	andl	$33554431, %ebx         # imm = 0x1FFFFFF
	leal	(%rsi,%rsi,8), %edx
	leal	(%rsi,%rdx,2), %r11d
	addl	%ecx, %r11d
	movl	%r11d, %esi
	sarl	$26, %esi
	addl	%r13d, %esi
	andl	$67108863, %r11d        # imm = 0x3FFFFFF
	movl	%esi, %ecx
	sarl	$25, %ecx
	addl	%edi, %ecx
	movl	%esi, %r9d
	movl	%ecx, %edi
	sarl	$26, %edi
	addl	%r10d, %edi
	movl	%ecx, %r13d
	movl	%edi, %r10d
	sarl	$25, %r10d
	addl	%r14d, %r10d
	movl	%r10d, %r15d
	sarl	$26, %r15d
	addl	%r8d, %r15d
	movl	%r15d, %edx
	sarl	$25, %edx
	addl	%r12d, %edx
	movl	%edx, %r14d
	sarl	$26, %r14d
	addl	%eax, %r14d
	movl	%r14d, %r12d
	sarl	$25, %r12d
	addl	%ebp, %r12d
	movl	%r12d, %r8d
	sarl	$26, %r8d
	addl	%ebx, %r8d
	movl	%r8d, %ebx
	sarl	$25, %ebx
	leal	(%rbx,%rbx,8), %ebp
	leal	(%rbx,%rbp,2), %ebx
	leal	-67108845(%r11,%rbx), %eax
                                        # kill: def $ebx killed $ebx killed $rbx
	addl	%r11d, %ebx
	movl	%ebx, 44(%rsp)          # 4-byte Spill
	movl	%esi, %ebp
	orl	$-33554432, %ebp        # imm = 0xFE000000
	shll	$16, %esi
	andl	%ebp, %esi
	movl	%esi, %ebp
	shll	$8, %ebp
	andl	%esi, %ebp
	movl	%ebp, %esi
	shll	$4, %esi
	andl	%ebp, %esi
	leal	(,%rsi,4), %ebp
	andl	%esi, %ebp
	movq	%rbp, 64(%rsp)          # 8-byte Spill
	movl	%ecx, %esi
	orl	$-67108864, %esi        # imm = 0xFC000000
	shll	$16, %ecx
	andl	%esi, %ecx
	movl	%ecx, %esi
	shll	$8, %esi
	andl	%ecx, %esi
	movl	%esi, %ecx
	shll	$4, %ecx
	andl	%esi, %ecx
	leal	(,%rcx,4), %esi
	andl	%ecx, %esi
	movl	%edi, %ecx
	orl	$-33554432, %ecx        # imm = 0xFE000000
	movl	%edi, %r11d
	shll	$16, %edi
	andl	%ecx, %edi
	movl	%edi, %ecx
	shll	$8, %ecx
	andl	%edi, %ecx
	movl	%ecx, %edi
	shll	$4, %edi
	andl	%ecx, %edi
	leal	(,%rdi,4), %ecx
	andl	%edi, %ecx
	movq	%rcx, 56(%rsp)          # 8-byte Spill
	movl	%r10d, %ecx
	orl	$-67108864, %ecx        # imm = 0xFC000000
	movl	%r10d, %edi
	shll	$16, %edi
	andl	%ecx, %edi
	movl	%edi, %ecx
	shll	$8, %ecx
	andl	%edi, %ecx
	movl	%ecx, %edi
	shll	$4, %edi
	andl	%ecx, %edi
	leal	(,%rdi,4), %ecx
	andl	%edi, %ecx
	movq	%rcx, 48(%rsp)          # 8-byte Spill
	movl	%r15d, %edi
	orl	$-33554432, %edi        # imm = 0xFE000000
	movl	%r15d, %ebx
	shll	$16, %r15d
	andl	%edi, %r15d
	movl	%r15d, %edi
	shll	$8, %edi
	andl	%r15d, %edi
	movl	%edi, %ebp
	shll	$4, %ebp
	andl	%edi, %ebp
	leal	(,%rbp,4), %r15d
	andl	%ebp, %r15d
	movl	%edx, %edi
	orl	$-67108864, %edi        # imm = 0xFC000000
	movl	%edx, %ebp
	shll	$16, %edx
	andl	%edi, %edx
	movl	%edx, %edi
	shll	$8, %edi
	andl	%edx, %edi
	movl	%edi, %edx
	shll	$4, %edx
	andl	%edi, %edx
	leal	(,%rdx,4), %edi
	andl	%edx, %edi
	leal	(%rdi,%rdi), %edx
	andl	%edi, %edx
	sarl	$31, %eax
	notl	%eax
	sarl	$31, %edx
	andl	%eax, %edx
	movl	%r14d, %edi
	orl	$-33554432, %edi        # imm = 0xFE000000
	movl	%r14d, %ecx
	shll	$16, %r14d
	andl	%edi, %r14d
	movl	%r14d, %edi
	shll	$8, %edi
	andl	%r14d, %edi
	movl	%edi, %r14d
	shll	$4, %r14d
	andl	%edi, %r14d
	leal	(,%r14,4), %eax
	andl	%r14d, %eax
	leal	(%rax,%rax), %r14d
	andl	%eax, %r14d
	sarl	$31, %r14d
	andl	%edx, %r14d
	movl	%r12d, %eax
	orl	$-67108864, %eax        # imm = 0xFC000000
	movl	%r12d, %edx
	shll	$16, %r12d
	andl	%eax, %r12d
	movl	%r12d, %eax
	shll	$8, %eax
	andl	%r12d, %eax
	movl	%eax, %edi
	shll	$4, %edi
	andl	%eax, %edi
	leal	(,%rdi,4), %eax
	andl	%edi, %eax
	leal	(%rax,%rax), %r12d
	andl	%eax, %r12d
	sarl	$31, %r12d
	andl	%r14d, %r12d
	movl	%r8d, %eax
	orl	$-33554432, %eax        # imm = 0xFE000000
	movl	%r8d, %r14d
	shll	$16, %r8d
	andl	%eax, %r8d
	movl	%r8d, %eax
	shll	$8, %eax
	andl	%r8d, %eax
	movl	%eax, %edi
	shll	$4, %edi
	andl	%eax, %edi
	leal	(,%rdi,4), %eax
	andl	%edi, %eax
	leal	(%rax,%rax), %edi
	andl	%eax, %edi
	sarl	$31, %edi
	andl	%r12d, %edi
	leal	(%rsi,%rsi), %eax
	movq	64(%rsp), %r8           # 8-byte Reload
	andl	%r8d, %esi
	andl	%eax, %esi
	movq	56(%rsp), %rax          # 8-byte Reload
	andl	%eax, %esi
	addl	%eax, %eax
	andl	%eax, %esi
	movq	48(%rsp), %rax          # 8-byte Reload
	andl	%eax, %esi
	addl	%eax, %eax
	andl	%eax, %esi
	andl	%r15d, %esi
	leal	(%r15,%r15), %eax
	andl	%eax, %esi
	leal	(%r8,%r8), %eax
	andl	%eax, %esi
	andl	$67108863, %r13d        # imm = 0x3FFFFFF
	andl	$67108863, %ebp         # imm = 0x3FFFFFF
	andl	$67108863, %edx         # imm = 0x3FFFFFF
	sarl	$31, %esi
	andl	%edi, %esi
	movl	%esi, %eax
	andl	$67108845, %eax         # imm = 0x3FFFFED
	movl	44(%rsp), %edi          # 4-byte Reload
	subl	%eax, %edi
	movl	%esi, %eax
	subl	%esi, %r10d
	andl	$67108863, %esi         # imm = 0x3FFFFFF
	subl	%esi, %r13d
	subl	%esi, %ebp
	subl	%esi, %edx
	andl	$33554431, %r9d         # imm = 0x1FFFFFF
	andl	$33554431, %r11d        # imm = 0x1FFFFFF
	andl	$33554431, %ebx         # imm = 0x1FFFFFF
	andl	$33554431, %ecx         # imm = 0x1FFFFFF
	andl	$33554431, %r14d        # imm = 0x1FFFFFF
	andl	$33554431, %eax         # imm = 0x1FFFFFF
	subl	%eax, %r9d
	subl	%eax, %r11d
	subl	%eax, %ebx
	subl	%eax, %ecx
	subl	%eax, %r14d
	movq	72(%rsp), %rsi          # 8-byte Reload
	movb	$0, 16(%rsi)
	movl	%edi, %eax
	movb	%al, (%rsi)
	movb	%ah, 1(%rsi)
	shrl	$16, %eax
	movb	%al, 2(%rsi)
	leal	(,%r9,4), %eax
	shrl	$24, %edi
	orl	%eax, %edi
	movb	%dil, 3(%rsi)
	movl	%r9d, %eax
	shrl	$6, %eax
	movb	%al, 4(%rsi)
	movl	%r9d, %eax
	shrl	$14, %eax
	movb	%al, 5(%rsi)
	leal	(,%r13,8), %eax
	shrl	$22, %r9d
	orl	%eax, %r9d
	movb	%r9b, 6(%rsi)
	movl	%r13d, %eax
	shrl	$5, %eax
	movb	%al, 7(%rsi)
	movl	%r13d, %eax
	shrl	$13, %eax
	movb	%al, 8(%rsi)
	movl	%r11d, %eax
	shll	$5, %eax
	shrl	$21, %r13d
	orl	%eax, %r13d
	movb	%r13b, 9(%rsi)
	movl	%r11d, %eax
	shrl	$3, %eax
	movb	%al, 10(%rsi)
	movl	%r11d, %eax
	shrl	$11, %eax
	movb	%al, 11(%rsi)
	movl	%r10d, %eax
	shll	$6, %eax
	shrl	$19, %r11d
	orl	%eax, %r11d
	movb	%r11b, 12(%rsi)
	movl	%r10d, %eax
	shrl	$2, %eax
	movb	%al, 13(%rsi)
	movl	%r10d, %eax
	shrl	$10, %eax
	movb	%al, 14(%rsi)
	shrl	$18, %r10d
	movb	%r10b, 15(%rsi)
	movb	%bl, 16(%rsi)
	movb	%bh, 17(%rsi)
	movl	%ebx, %eax
	shrl	$16, %eax
	movb	%al, 18(%rsi)
	leal	(%rbp,%rbp), %eax
	shrl	$24, %ebx
	orl	%eax, %ebx
	movb	%bl, 19(%rsi)
	movl	%ebp, %eax
	shrl	$7, %eax
	movb	%al, 20(%rsi)
	movl	%ebp, %eax
	shrl	$15, %eax
	movb	%al, 21(%rsi)
	leal	(,%rcx,8), %eax
	shrl	$23, %ebp
	orl	%eax, %ebp
	movb	%bpl, 22(%rsi)
	movl	%ecx, %eax
	shrl	$5, %eax
	movb	%al, 23(%rsi)
	movl	%ecx, %eax
	shrl	$13, %eax
	movb	%al, 24(%rsi)
	movl	%edx, %eax
	shll	$4, %eax
	shrl	$21, %ecx
	orl	%eax, %ecx
	movb	%cl, 25(%rsi)
	movl	%edx, %eax
	shrl	$4, %eax
	movb	%al, 26(%rsi)
	movl	%edx, %eax
	shrl	$12, %eax
	movb	%al, 27(%rsi)
	movl	%r14d, %eax
	shll	$6, %eax
	shrl	$20, %edx
	orl	%eax, %edx
	movb	%dl, 28(%rsi)
	movl	%r14d, %eax
	shrl	$2, %eax
	movb	%al, 29(%rsi)
	movl	%r14d, %eax
	shrl	$10, %eax
	movb	%al, 30(%rsi)
	shrl	$18, %r14d
	movb	%r14b, 31(%rsi)
	xorl	%eax, %eax
	addq	$1224, %rsp             # imm = 0x4C8
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	retq
.Lfunc_end4:
	.size	curve25519_donna, .Lfunc_end4-curve25519_donna
                                        # -- End function
	.p2align	4, 0x90         # -- Begin function cmult
	.type	cmult,@function
cmult:                                  # @cmult
# %bb.0:
	pushq	%rbp
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	subq	$1304, %rsp             # imm = 0x518
	movq	%rcx, %r12
	movq	%rdx, 1280(%rsp)        # 8-byte Spill
	movq	%rsi, 1296(%rsp)        # 8-byte Spill
	movq	%rdi, 1288(%rsp)        # 8-byte Spill
	xorps	%xmm0, %xmm0
	movaps	%xmm0, 608(%rsp)
	movaps	%xmm0, 592(%rsp)
	movaps	%xmm0, 576(%rsp)
	movaps	%xmm0, 560(%rsp)
	movaps	%xmm0, 544(%rsp)
	movaps	%xmm0, 528(%rsp)
	movaps	%xmm0, 512(%rsp)
	movaps	%xmm0, 496(%rsp)
	movaps	%xmm0, 480(%rsp)
	movq	$0, 624(%rsp)
	movaps	%xmm0, 160(%rsp)
	movaps	%xmm0, 176(%rsp)
	movaps	%xmm0, 192(%rsp)
	movaps	%xmm0, 208(%rsp)
	movaps	%xmm0, 224(%rsp)
	movaps	%xmm0, 240(%rsp)
	movaps	%xmm0, 256(%rsp)
	movaps	%xmm0, 272(%rsp)
	movaps	%xmm0, 288(%rsp)
	movq	$0, 304(%rsp)
	movq	$1, 160(%rsp)
	movaps	%xmm0, 960(%rsp)
	movaps	%xmm0, 1088(%rsp)
	movaps	%xmm0, 1072(%rsp)
	movaps	%xmm0, 1056(%rsp)
	movaps	%xmm0, 1040(%rsp)
	movaps	%xmm0, 1024(%rsp)
	movaps	%xmm0, 1008(%rsp)
	movaps	%xmm0, 992(%rsp)
	movaps	%xmm0, 976(%rsp)
	movq	$0, 1104(%rsp)
	movq	$1, 960(%rsp)
	movaps	%xmm0, 1120(%rsp)
	movaps	%xmm0, 1136(%rsp)
	movaps	%xmm0, 1152(%rsp)
	movaps	%xmm0, 1168(%rsp)
	movaps	%xmm0, 1184(%rsp)
	movaps	%xmm0, 1200(%rsp)
	movaps	%xmm0, 1216(%rsp)
	movaps	%xmm0, 1232(%rsp)
	movaps	%xmm0, 1248(%rsp)
	movq	$0, 1264(%rsp)
	movaps	%xmm0, 448(%rsp)
	movaps	%xmm0, 432(%rsp)
	movaps	%xmm0, 416(%rsp)
	movaps	%xmm0, 400(%rsp)
	movaps	%xmm0, 384(%rsp)
	movaps	%xmm0, 368(%rsp)
	movaps	%xmm0, 352(%rsp)
	movaps	%xmm0, 336(%rsp)
	movaps	%xmm0, 320(%rsp)
	movq	$0, 464(%rsp)
	movaps	%xmm0, 128(%rsp)
	movaps	%xmm0, 112(%rsp)
	movaps	%xmm0, 96(%rsp)
	movaps	%xmm0, 80(%rsp)
	movaps	%xmm0, 64(%rsp)
	movaps	%xmm0, 48(%rsp)
	movaps	%xmm0, 32(%rsp)
	movaps	%xmm0, 16(%rsp)
	movaps	%xmm0, (%rsp)
	movq	$0, 144(%rsp)
	movq	$1, (%rsp)
	movaps	%xmm0, 928(%rsp)
	movaps	%xmm0, 912(%rsp)
	movaps	%xmm0, 896(%rsp)
	movaps	%xmm0, 880(%rsp)
	movaps	%xmm0, 864(%rsp)
	movaps	%xmm0, 848(%rsp)
	movaps	%xmm0, 832(%rsp)
	movaps	%xmm0, 816(%rsp)
	movaps	%xmm0, 800(%rsp)
	movq	$0, 944(%rsp)
	movaps	%xmm0, 768(%rsp)
	movaps	%xmm0, 752(%rsp)
	movaps	%xmm0, 736(%rsp)
	movaps	%xmm0, 720(%rsp)
	movaps	%xmm0, 704(%rsp)
	movaps	%xmm0, 688(%rsp)
	movaps	%xmm0, 672(%rsp)
	movaps	%xmm0, 656(%rsp)
	movaps	%xmm0, 640(%rsp)
	movq	$0, 784(%rsp)
	movq	$1, 640(%rsp)
	leaq	480(%rsp), %rdi
	movl	$10, %ecx
	movq	%rdi, %rbx
	movq	%r12, %rsi
	rep;movsq (%rsi), %es:(%rdi)
	movb	31(%rdx), %r14b
	testb	%r14b, %r14b
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	leaq	168(%rsp), %rax
	leaq	808(%rsp), %rdi
	leaq	648(%rsp), %rsi
	leaq	328(%rsp), %rdx
	leaq	8(%rsp), %rcx
	leaq	968(%rsp), %r15
	leaq	1128(%rsp), %r13
	movq	%r15, %r8
	movq	%r13, %r9
	pushq	%r12
	pushq	%rax
	movq	%rax, %rbp
	pushq	%rbx
	callq	fmonty
	addq	$32, %rsp
	testb	%r14b, %r14b
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %r14b
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r15, %rdi
	movq	%r13, %rsi
	movq	%rbx, %rdx
	movq	%rbp, %r15
	movq	%rbp, %rcx
	leaq	808(%rsp), %rbp
	movq	%rbp, %r8
	leaq	648(%rsp), %r13
	movq	%r13, %r9
	pushq	%r12
	leaq	16(%rsp), %rbx
	pushq	%rbx
	leaq	344(%rsp), %rax
	pushq	%rax
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %r14b
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %r14b
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%rbp, %rdi
	movq	%r13, %rsi
	leaq	328(%rsp), %rdx
	movq	%rbx, %rcx
	leaq	968(%rsp), %rbx
	movq	%rbx, %r8
	leaq	1128(%rsp), %rbp
	movq	%rbp, %r9
	pushq	%r12
	pushq	%r15
	movq	%r15, %r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %r14b
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %r14b
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%rbx, %rdi
	movq	%rbp, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %rbp
	movq	%rbp, %r8
	leaq	648(%rsp), %r13
	movq	%r13, %r9
	pushq	%r12
	leaq	16(%rsp), %rax
	pushq	%rax
	leaq	344(%rsp), %rbx
	pushq	%rbx
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %r14b
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %r14b
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%rbp, %rdi
	movq	%r13, %rsi
	movq	%rbx, %rdx
	leaq	8(%rsp), %rcx
	leaq	968(%rsp), %rbx
	movq	%rbx, %r8
	leaq	1128(%rsp), %r13
	movq	%r13, %r9
	movq	%r12, %rbp
	pushq	%r12
	leaq	176(%rsp), %r12
	pushq	%r12
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %r14b
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %r14b
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%rbx, %rdi
	movq	%r13, %rsi
	movq	%r15, %rdx
	movq	%r12, %rcx
	leaq	808(%rsp), %r15
	movq	%r15, %r8
	leaq	648(%rsp), %r12
	movq	%r12, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %rbx
	pushq	%rbx
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %r14b
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %r14b
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r15, %rdi
	movq	%r12, %rsi
	movq	%rbx, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r13
	movq	%r13, %r8
	leaq	1128(%rsp), %r15
	movq	%r15, %r9
	pushq	%rbp
	leaq	176(%rsp), %r12
	pushq	%r12
	leaq	504(%rsp), %rbx
	pushq	%rbx
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %r14b
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %r14b
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r13, %rdi
	movq	%r15, %rsi
	movq	%rbx, %rdx
	movq	%r12, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r13
	movq	%r13, %r9
	pushq	%rbp
	leaq	16(%rsp), %rax
	pushq	%rax
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %r14b
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	30(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r13, %rsi
	movq	%r15, %rdx
	leaq	8(%rsp), %rcx
	leaq	968(%rsp), %r15
	movq	%r15, %r8
	leaq	1128(%rsp), %r13
	movq	%r13, %r9
	pushq	%rbp
	leaq	176(%rsp), %r14
	pushq	%r14
	leaq	504(%rsp), %r12
	pushq	%r12
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r15, %rdi
	movq	%r13, %rsi
	movq	%r13, %r15
	movq	%r12, %rdx
	movq	%r14, %rcx
	leaq	808(%rsp), %r13
	movq	%r13, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %rax
	pushq	%rax
	leaq	344(%rsp), %r12
	pushq	%r12
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r13, %rdi
	movq	%r14, %rsi
	movq	%r12, %rdx
	leaq	8(%rsp), %rcx
	leaq	968(%rsp), %r13
	movq	%r13, %r8
	movq	%r15, %r14
	movq	%r15, %r9
	pushq	%rbp
	leaq	176(%rsp), %r15
	pushq	%r15
	leaq	504(%rsp), %r12
	pushq	%r12
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r13, %rdi
	movq	%r14, %rsi
	movq	%r12, %rdx
	movq	%r15, %rcx
	leaq	808(%rsp), %r13
	movq	%r13, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r12
	pushq	%r12
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r13, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r12, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	29(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	28(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	27(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r15
	pushq	%r15
	leaq	504(%rsp), %r13
	pushq	%r13
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r13, %rdx
	movq	%r15, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	26(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	25(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	24(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r15
	pushq	%r15
	leaq	504(%rsp), %r13
	pushq	%r13
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r13, %rdx
	movq	%r15, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	23(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	22(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	21(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r15
	pushq	%r15
	leaq	504(%rsp), %r13
	pushq	%r13
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r13, %rdx
	movq	%r15, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	20(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	19(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	18(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r15
	pushq	%r15
	leaq	504(%rsp), %r13
	pushq	%r13
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r13, %rdx
	movq	%r15, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	17(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	16(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	15(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r15
	pushq	%r15
	leaq	504(%rsp), %r13
	pushq	%r13
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r13, %rdx
	movq	%r15, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	14(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	13(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	12(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r15
	pushq	%r15
	leaq	504(%rsp), %r13
	pushq	%r13
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r13, %rdx
	movq	%r15, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$16, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$8, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$8, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$4, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$4, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$2, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$2, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$1, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$1, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	1280(%rsp), %rax        # 8-byte Reload
	movb	11(%rax), %bl
	testb	%bl, %bl
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmovnsq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmovnsq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmovnsq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmovnsq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmovnsq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmovnsq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmovnsq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmovnsq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmovnsq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmovnsq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmovnsq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmovnsq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmovnsq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmovnsq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmovnsq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmovnsq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmovnsq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmovnsq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	%bl, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovsq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmovnsq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovsq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmovnsq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmovnsq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmovnsq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmovnsq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmovnsq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmovnsq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmovnsq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovsq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmovnsq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmovnsq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmovnsq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmovnsq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmovnsq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmovnsq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmovnsq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmovnsq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmovnsq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmovnsq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmovnsq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$64, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	16(%rsp), %r13
	pushq	%r13
	leaq	344(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$64, %bl
	movq	960(%rsp), %rax
	movq	968(%rsp), %rcx
	movq	480(%rsp), %rdx
	movq	488(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 480(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 968(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 976(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 984(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	movq	960(%rsp), %rax
	movq	480(%rsp), %rcx
	testb	$32, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 960(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 480(%rsp)
	movq	968(%rsp), %rax
	movq	488(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 968(%rsp)
	cltq
	cmoveq	488(%rsp), %rax
	movq	%rax, 488(%rsp)
	movq	976(%rsp), %rax
	movq	496(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 976(%rsp)
	cltq
	cmoveq	496(%rsp), %rax
	movq	%rax, 496(%rsp)
	movq	984(%rsp), %rax
	movq	504(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 984(%rsp)
	cltq
	cmoveq	504(%rsp), %rax
	movq	%rax, 504(%rsp)
	movq	992(%rsp), %rax
	movq	512(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 992(%rsp)
	cltq
	cmoveq	512(%rsp), %rax
	movq	%rax, 512(%rsp)
	movq	1000(%rsp), %rax
	movq	520(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1000(%rsp)
	cltq
	cmoveq	520(%rsp), %rax
	movq	%rax, 520(%rsp)
	movq	1008(%rsp), %rax
	movq	528(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1008(%rsp)
	cltq
	cmoveq	528(%rsp), %rax
	movq	%rax, 528(%rsp)
	movq	1016(%rsp), %rax
	movq	536(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1016(%rsp)
	cltq
	cmoveq	536(%rsp), %rax
	movq	%rax, 536(%rsp)
	movq	1024(%rsp), %rax
	movq	544(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1024(%rsp)
	cltq
	cmoveq	544(%rsp), %rax
	movq	%rax, 544(%rsp)
	movq	1032(%rsp), %rax
	movq	552(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1032(%rsp)
	cltq
	cmoveq	552(%rsp), %rax
	movq	%rax, 552(%rsp)
	movq	1120(%rsp), %rax
	movq	160(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 1120(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 160(%rsp)
	movq	1128(%rsp), %rax
	movq	168(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1128(%rsp)
	cltq
	cmoveq	168(%rsp), %rax
	movq	%rax, 168(%rsp)
	movq	1136(%rsp), %rax
	movq	176(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1136(%rsp)
	cltq
	cmoveq	176(%rsp), %rax
	movq	%rax, 176(%rsp)
	movq	1144(%rsp), %rax
	movq	184(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1144(%rsp)
	cltq
	cmoveq	184(%rsp), %rax
	movq	%rax, 184(%rsp)
	movq	1152(%rsp), %rax
	movq	192(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1152(%rsp)
	cltq
	cmoveq	192(%rsp), %rax
	movq	%rax, 192(%rsp)
	movq	1160(%rsp), %rax
	movq	200(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1160(%rsp)
	cltq
	cmoveq	200(%rsp), %rax
	movq	%rax, 200(%rsp)
	movq	1168(%rsp), %rax
	movq	208(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1168(%rsp)
	cltq
	cmoveq	208(%rsp), %rax
	movq	%rax, 208(%rsp)
	movq	1176(%rsp), %rax
	movq	216(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1176(%rsp)
	cltq
	cmoveq	216(%rsp), %rax
	movq	%rax, 216(%rsp)
	movq	1184(%rsp), %rax
	movq	224(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1184(%rsp)
	cltq
	cmoveq	224(%rsp), %rax
	movq	%rax, 224(%rsp)
	movq	1192(%rsp), %rax
	movq	232(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 1192(%rsp)
	cltq
	cmoveq	232(%rsp), %rax
	movq	%rax, 232(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	968(%rsp), %r12
	movq	%r12, %r8
	leaq	1128(%rsp), %r14
	movq	%r14, %r9
	pushq	%rbp
	leaq	176(%rsp), %r13
	pushq	%r13
	leaq	504(%rsp), %r15
	pushq	%r15
	callq	fmonty
	addq	$32, %rsp
	testb	$32, %bl
	movq	800(%rsp), %rax
	movq	808(%rsp), %rcx
	movq	320(%rsp), %rdx
	movq	328(%rsp), %rsi
	movslq	%eax, %rdi
	cmovneq	%rdx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rdx, %rdi
	movq	%rdi, 320(%rsp)
	movslq	%ecx, %rax
	cmovneq	%rsi, %rcx
	movq	%rcx, 808(%rsp)
	cmoveq	%rsi, %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 816(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 824(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	movq	800(%rsp), %rax
	movq	320(%rsp), %rcx
	testb	$16, %bl
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 800(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, 320(%rsp)
	movq	808(%rsp), %rax
	movq	328(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 808(%rsp)
	cltq
	cmoveq	328(%rsp), %rax
	movq	%rax, 328(%rsp)
	movq	816(%rsp), %rax
	movq	336(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 816(%rsp)
	cltq
	cmoveq	336(%rsp), %rax
	movq	%rax, 336(%rsp)
	movq	824(%rsp), %rax
	movq	344(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 824(%rsp)
	cltq
	cmoveq	344(%rsp), %rax
	movq	%rax, 344(%rsp)
	movq	832(%rsp), %rax
	movq	352(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 832(%rsp)
	cltq
	cmoveq	352(%rsp), %rax
	movq	%rax, 352(%rsp)
	movq	840(%rsp), %rax
	movq	360(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 840(%rsp)
	cltq
	cmoveq	360(%rsp), %rax
	movq	%rax, 360(%rsp)
	movq	848(%rsp), %rax
	movq	368(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 848(%rsp)
	cltq
	cmoveq	368(%rsp), %rax
	movq	%rax, 368(%rsp)
	movq	856(%rsp), %rax
	movq	376(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 856(%rsp)
	cltq
	cmoveq	376(%rsp), %rax
	movq	%rax, 376(%rsp)
	movq	864(%rsp), %rax
	movq	384(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 864(%rsp)
	cltq
	cmoveq	384(%rsp), %rax
	movq	%rax, 384(%rsp)
	movq	872(%rsp), %rax
	movq	392(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 872(%rsp)
	cltq
	cmoveq	392(%rsp), %rax
	movq	%rax, 392(%rsp)
	movq	640(%rsp), %rax
	movq	(%rsp), %rcx
	movslq	%eax, %rdx
	cmovneq	%rcx, %rax
	movq	%rax, 640(%rsp)
	cmoveq	%rcx, %rdx
	movq	%rdx, (%rsp)
	movq	648(%rsp), %rax
	movq	8(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 648(%rsp)
	cltq
	cmoveq	8(%rsp), %rax
	movq	%rax, 8(%rsp)
	movq	656(%rsp), %rax
	movq	16(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 656(%rsp)
	cltq
	cmoveq	16(%rsp), %rax
	movq	%rax, 16(%rsp)
	movq	664(%rsp), %rax
	movq	24(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 664(%rsp)
	cltq
	cmoveq	24(%rsp), %rax
	movq	%rax, 24(%rsp)
	movq	672(%rsp), %rax
	movq	32(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 672(%rsp)
	cltq
	cmoveq	32(%rsp), %rax
	movq	%rax, 32(%rsp)
	movq	680(%rsp), %rax
	movq	40(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 680(%rsp)
	cltq
	cmoveq	40(%rsp), %rax
	movq	%rax, 40(%rsp)
	movq	688(%rsp), %rax
	movq	48(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 688(%rsp)
	cltq
	cmoveq	48(%rsp), %rax
	movq	%rax, 48(%rsp)
	movq	696(%rsp), %rax
	movq	56(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 696(%rsp)
	cltq
	cmoveq	56(%rsp), %rax
	movq	%rax, 56(%rsp)
	movq	704(%rsp), %rax
	movq	64(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 704(%rsp)
	cltq
	cmoveq	64(%rsp), %rax
	movq	%rax, 64(%rsp)
	movq	712(%rsp), %rax
	movq	72(%rsp), %rcx
	cmoveq	%rax, %rcx
	movq	%rcx, 712(%rsp)
	cltq
	cmoveq	72(%rsp), %rax
	movq	%rax, 72(%rsp)
	subq	$8, %rsp
	movq	%r12, %rdi
	movq	%r14, %rsi
	movq	%r15, %rdx
	movq	%r13, %rcx
	leaq	808(%rsp), %r12
	movq	%r12, %r8
	leaq	648(%rsp), %r14
	movq	%r14, %r9
