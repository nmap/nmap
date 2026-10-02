/*-
 * Copyright (c) 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from the Stanford/CMU enet packet filter,
 * (net/enet.c) distributed as part of 4.3BSD, and code contributed
 * to Berkeley by Steven McCanne and Van Jacobson both of Lawrence
 * Berkeley Laboratory.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)bpf.c	7.5 (Berkeley) 7/15/91
 */

#include <config.h>

#include <pcap/pcap-inttypes.h>
#include "pcap-types.h"
#include "extract.h"
#include "diag-control.h"

#define EXTRACT_SHORT	EXTRACT_BE_U_2
#define EXTRACT_LONG	EXTRACT_BE_U_4

#ifndef _WIN32
#include <sys/param.h>
#include <sys/types.h>
#include <sys/time.h>
#endif /* _WIN32 */

#include <pcap-int.h>

#include <stdlib.h>

#ifdef __linux__
#include <linux/types.h>
#include <linux/if_packet.h>
#include <linux/filter.h>
#endif

#define MAX_BACKWARD_JUMPS 64U

/*
 * Kernel BPF implementations tend to define BPF_MAXINSNS to 512 or 4096, the
 * userland interpreter in libpcap is meant to support much longer filter
 * programs.  In the latter case it is important that BPF_MAXINSNS does not
 * interfere with the safety checks in the validator and the interpreter:
 *   (BPF_MAXINSNS + UINT8_MAX) * sizeof(struct bpf_insn) < UINT32_MAX
 * It makes the most sense to be able to interpret as many instructions as
 * pcap_compile() can produce, without optimization, for a valid filter
 * expression before it consumes as much memory as the current definitions of
 * NCHUNKS and CHUNKSIZE() allow.  For some expressions this can be almost
 * 1.53 million instructions on a 64-bit machine and twice as many on a 32-bit
 * machine.
 */
#ifdef BPF_MAXINSNS
#undef BPF_MAXINSNS
#endif
#define BPF_MAXINSNS 3060000U

/*
 * Execute the filter program starting at pc on the packet p
 * wirelen is the length of the original packet
 * buflen is the amount of data present
 * aux_data is auxiliary data, currently used only when interpreting
 * filters intended for the Linux kernel in cases where the kernel
 * rejects the filter; it contains VLAN tag information
 * For the kernel, p is assumed to be a pointer to an mbuf if buflen is 0,
 * in all other cases, p is a pointer to a buffer and buflen is its size.
 *
 * Thanks to Ani Sinha <ani@arista.com> for providing initial implementation
 */
#if defined(SKF_AD_VLAN_TAG_PRESENT)
u_int
pcapint_filter_with_aux_data(const struct bpf_insn *pc, const u_int proglen,
    const u_char *p, const u_int wirelen, const u_int buflen,
    const struct pcap_bpf_aux_data *aux_data)
#else
u_int
pcapint_filter_with_aux_data(const struct bpf_insn *pc, const u_int proglen,
    const u_char *p, const u_int wirelen, const u_int buflen,
    const struct pcap_bpf_aux_data *aux_data _U_)
#endif
{
	register uint32_t A, X;
	register bpf_u_int32 k;

	if (pc == 0)
		/*
		 * No filter means accept all.
		 * In this case the value of 'proglen' is irrelevant.
		 */
		return (u_int)-1;
	if (proglen < 1 || proglen > BPF_MAXINSNS)
		return 0;

	/*
	 * Require the current instruction pointer not to overflow for both the
	 * filter program (where the pointer will be dereferenced) and an
	 * immediately following margin (where it will be not).  So long as the
	 * margin is large enough to represent the destination of any single
	 * conditional [forward] jump from within the filter program, a single
	 * guard prevents all filter program over-read attempts that result
	 * from the program running out of instructions before a BPF_RET or a
	 * conditional jump directing the interpreter beyond the program end.
	 * Unconditional jumps mean a larger problem space, which the BPF_JA
	 * case below addresses separately.
	 */
	const struct bpf_insn *pcend = pc + proglen;
	if (pcend + UINT8_MAX < pc)
		return 0;

	A = 0;
	X = 0;
	uint32_t mem[BPF_MEMWORDS] = {0};
	const struct bpf_insn *pc0 = pc;
	unsigned backward_jumps = 0;
	--pc;
	for (;;) {
		++pc;
		if (pc >= pcend)
			return 0;
		switch (pc->code) {

		default:
			return 0;
		case BPF_RET|BPF_K:
			return (u_int)pc->k;

		case BPF_RET|BPF_A:
			return (u_int)A;

		case BPF_LD|BPF_W|BPF_ABS:
			k = pc->k;
			if (k > buflen || sizeof(int32_t) > buflen - k) {
				return 0;
			}
			A = EXTRACT_LONG(&p[k]);
			continue;

		case BPF_LD|BPF_H|BPF_ABS:
			k = pc->k;
			if (k > buflen || sizeof(int16_t) > buflen - k) {
				return 0;
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case BPF_LD|BPF_B|BPF_ABS:
			/*
			 * Yes, we know, this switch doesn't do
			 * anything unless we're building for
			 * a Linux kernel with removed VLAN
			 * tags available as meta-data.
			 */
DIAG_OFF_DEFAULT_ONLY_SWITCH
			switch (pc->k) {

#if defined(SKF_AD_VLAN_TAG_PRESENT)
			case SKF_AD_OFF + SKF_AD_VLAN_TAG:
				if (!aux_data)
					return 0;
				A = aux_data->vlan_tag;
				break;

			case SKF_AD_OFF + SKF_AD_VLAN_TAG_PRESENT:
				if (!aux_data)
					return 0;
				A = aux_data->vlan_tag_present;
				break;
#endif
			default:
				k = pc->k;
				if (k >= buflen) {
					return 0;
				}
				A = p[k];
				break;
			}
DIAG_ON_DEFAULT_ONLY_SWITCH
			continue;

		case BPF_LD|BPF_W|BPF_LEN:
			A = wirelen;
			continue;

		case BPF_LDX|BPF_W|BPF_LEN:
			X = wirelen;
			continue;

		case BPF_LD|BPF_W|BPF_IND:
			k = X + pc->k;
			if (pc->k > buflen || X > buflen - pc->k ||
			    sizeof(int32_t) > buflen - k) {
				return 0;
			}
			A = EXTRACT_LONG(&p[k]);
			continue;

		case BPF_LD|BPF_H|BPF_IND:
			k = X + pc->k;
			if (X > buflen || pc->k > buflen - X ||
			    sizeof(int16_t) > buflen - k) {
				return 0;
			}
			A = EXTRACT_SHORT(&p[k]);
			continue;

		case BPF_LD|BPF_B|BPF_IND:
			k = X + pc->k;
			if (pc->k >= buflen || X >= buflen - pc->k) {
				return 0;
			}
			A = p[k];
			continue;

		case BPF_LDX|BPF_MSH|BPF_B:
			k = pc->k;
			if (k >= buflen) {
				return 0;
			}
			X = (p[pc->k] & 0xf) << 2;
			continue;

		case BPF_LD|BPF_IMM:
			A = pc->k;
			continue;

		case BPF_LDX|BPF_IMM:
			X = pc->k;
			continue;

		case BPF_LD|BPF_MEM:
			if (pc->k >= BPF_MEMWORDS)
				return 0;
			A = mem[pc->k];
			continue;

		case BPF_LDX|BPF_MEM:
			if (pc->k >= BPF_MEMWORDS)
				return 0;
			X = mem[pc->k];
			continue;

		case BPF_ST:
			if (pc->k >= BPF_MEMWORDS)
				return 0;
			mem[pc->k] = A;
			continue;

		case BPF_STX:
			if (pc->k >= BPF_MEMWORDS)
				return 0;
			mem[pc->k] = X;
			continue;

		case BPF_JMP|BPF_JA:
			/*
			 * The pointer (pc) decrements and increments in units
			 * of sizeof(struct bpf_insn) == 8 bytes.  The number
			 * of units is in the [INT32_MIN, INT32_MAX] interval,
			 * hence the result can point before the beginning or
			 * beyond the end of the filter program and can under-
			 * or overflow; also on 32-bit architectures it can
			 * under- or overflow more than once and can test
			 * negative for underflow, overflow and out-of-range
			 * conditions after under- or overflowing at least
			 * once.
			 *
			 * However, it has been verified above that the program
			 * length is sufficiently small and the pointer does
			 * not wrap within the bounds of the filter program, so
			 * there is a one-to-one correspondence between BPF
			 * program counter values [0, proglen) and all valid
			 * values of the pointer.  In other words, after this
			 * unconditional jump the pointer arithmetic result
			 * will be valid iff BPF program counter value will be
			 * valid.  For the latter problem the solution is
			 * almost the same as in the validator.
			 *
			 * The main difference is that here the current value
			 * of BPF program counter is not a 32-bit unsigned
			 * variable, but a ptrdiff_t expression, which is
			 * 64-bit signed on 64-bit architectures and 32-bit
			 * signed on 32-bit architectures.  However, the cast
			 * to 32-bit unsigned is safe in both cases because:
			 * pc0 <= pc < pc0 + proglen, therefore:
			 * 0 <= pc - pc0 < proglen <= BPF_MAXINSNS < INT32_MAX
			 */
			if ((bpf_u_int32)(pc - pc0) + 1 + pc->k >= proglen)
				return 0;
			/*
			 * Terminate the program if this is a non-forward jump
			 * and is:
			 * - a guaranteed infinite loop because it jumps to
			 *   itself (exactly the same as in the validator), or
			 * - a backward jump after many enough backward jumps
			 *   already made for this packet.
			 */
			if ((bpf_int32)pc->k < 0 && ((bpf_int32)pc->k == -1 ||
			    backward_jumps++ >= MAX_BACKWARD_JUMPS))
				return 0;
			/*
			 * XXX - we currently implement "ip6 protochain"
			 * with backward jumps, so sign-extend pc->k.
			 */
			pc += (bpf_int32)pc->k;
			continue;

		case BPF_JMP|BPF_JGT|BPF_K:
			pc += (A > pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_K:
			pc += (A >= pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_K:
			pc += (A == pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_K:
			pc += (A & pc->k) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGT|BPF_X:
			pc += (A > X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JGE|BPF_X:
			pc += (A >= X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JEQ|BPF_X:
			pc += (A == X) ? pc->jt : pc->jf;
			continue;

		case BPF_JMP|BPF_JSET|BPF_X:
			pc += (A & X) ? pc->jt : pc->jf;
			continue;

		case BPF_ALU|BPF_ADD|BPF_X:
			A += X;
			continue;

		case BPF_ALU|BPF_SUB|BPF_X:
			A -= X;
			continue;

		case BPF_ALU|BPF_MUL|BPF_X:
			A *= X;
			continue;

		case BPF_ALU|BPF_DIV|BPF_X:
			if (X == 0)
				return 0;
			A /= X;
			continue;

		case BPF_ALU|BPF_MOD|BPF_X:
			if (X == 0)
				return 0;
			A %= X;
			continue;

		case BPF_ALU|BPF_AND|BPF_X:
			A &= X;
			continue;

		case BPF_ALU|BPF_OR|BPF_X:
			A |= X;
			continue;

		case BPF_ALU|BPF_XOR|BPF_X:
			A ^= X;
			continue;

		case BPF_ALU|BPF_LSH|BPF_X:
			if (X < 32)
				A <<= X;
			else
				A = 0;
			continue;

		case BPF_ALU|BPF_RSH|BPF_X:
			if (X < 32)
				A >>= X;
			else
				A = 0;
			continue;

		case BPF_ALU|BPF_ADD|BPF_K:
			A += pc->k;
			continue;

		case BPF_ALU|BPF_SUB|BPF_K:
			A -= pc->k;
			continue;

		case BPF_ALU|BPF_MUL|BPF_K:
			A *= pc->k;
			continue;

		case BPF_ALU|BPF_DIV|BPF_K:
			if (pc->k == 0)
				return 0;
			A /= pc->k;
			continue;

		case BPF_ALU|BPF_MOD|BPF_K:
			if (pc->k == 0)
				return 0;
			A %= pc->k;
			continue;

		case BPF_ALU|BPF_AND|BPF_K:
			A &= pc->k;
			continue;

		case BPF_ALU|BPF_OR|BPF_K:
			A |= pc->k;
			continue;

		case BPF_ALU|BPF_XOR|BPF_K:
			A ^= pc->k;
			continue;

		case BPF_ALU|BPF_LSH|BPF_K:
			A = (pc->k < 32) ? A << pc->k : 0;
			continue;

		case BPF_ALU|BPF_RSH|BPF_K:
			A = (pc->k < 32) ? A >> pc->k : 0;
			continue;

		case BPF_ALU|BPF_NEG:
			/*
			 * Most BPF arithmetic is unsigned, but negation
			 * can't be unsigned; respecify it as subtracting
			 * the accumulator from 0U, so that 1) we don't
			 * get compiler warnings about negating an unsigned
			 * value and 2) don't get UBSan warnings about
			 * the result of negating 0x80000000 being undefined.
			 */
			A = (0U - A);
			continue;

		case BPF_MISC|BPF_TAX:
			X = A;
			continue;

		case BPF_MISC|BPF_TXA:
			A = X;
			continue;
		}
	}
}

u_int
pcapint_filter(const struct bpf_insn *pc, const u_int proglen, const u_char *p,
    u_int wirelen, u_int buflen)
{
	return pcapint_filter_with_aux_data(pc, proglen, p, wirelen, buflen, NULL);
}

/*
 * Return true if the instruction is valid, as far as is possible to tell
 * without knowing what the rest of the filter program is.
 */
uint8_t
pcapint_valid_insn(const struct bpf_insn *insn)
{
	/*
	 * Require the opcode to be valid, for particular opcodes also require
	 * the value of k to be valid.  The list of opcodes below is exactly
	 * the same as in bpf_filter() to make it easier to cross-reference.
	 */
	switch (insn->code) {
	case BPF_RET|BPF_K:
	case BPF_RET|BPF_A:
	case BPF_LD|BPF_W|BPF_ABS:
	case BPF_LD|BPF_H|BPF_ABS:
	case BPF_LD|BPF_B|BPF_ABS:
	case BPF_LD|BPF_W|BPF_LEN:
	case BPF_LDX|BPF_W|BPF_LEN:
	case BPF_LD|BPF_W|BPF_IND:
	case BPF_LD|BPF_H|BPF_IND:
	case BPF_LD|BPF_B|BPF_IND:
	case BPF_LDX|BPF_MSH|BPF_B:
	case BPF_LD|BPF_IMM:
	case BPF_LDX|BPF_IMM:
		return 1;
	case BPF_LD|BPF_MEM:
	case BPF_LDX|BPF_MEM:
	case BPF_ST:
	case BPF_STX:
		// Reject a non-existent scratch memory register.
		return insn->k < BPF_MEMWORDS;
	case BPF_JMP|BPF_JA:
	case BPF_JMP|BPF_JGT|BPF_K:
	case BPF_JMP|BPF_JGE|BPF_K:
	case BPF_JMP|BPF_JEQ|BPF_K:
	case BPF_JMP|BPF_JSET|BPF_K:
	case BPF_JMP|BPF_JGT|BPF_X:
	case BPF_JMP|BPF_JGE|BPF_X:
	case BPF_JMP|BPF_JEQ|BPF_X:
	case BPF_JMP|BPF_JSET|BPF_X:
	case BPF_ALU|BPF_ADD|BPF_X:
	case BPF_ALU|BPF_SUB|BPF_X:
	case BPF_ALU|BPF_MUL|BPF_X:
	case BPF_ALU|BPF_DIV|BPF_X:
	case BPF_ALU|BPF_MOD|BPF_X:
	case BPF_ALU|BPF_AND|BPF_X:
	case BPF_ALU|BPF_OR|BPF_X:
	case BPF_ALU|BPF_XOR|BPF_X:
	case BPF_ALU|BPF_LSH|BPF_X:
	case BPF_ALU|BPF_RSH|BPF_X:
	case BPF_ALU|BPF_ADD|BPF_K:
	case BPF_ALU|BPF_SUB|BPF_K:
	case BPF_ALU|BPF_MUL|BPF_K:
		return 1;
	case BPF_ALU|BPF_DIV|BPF_K:
	case BPF_ALU|BPF_MOD|BPF_K:
		// Reject a constant division or modulo by 0.
		return insn->k != 0;
	case BPF_ALU|BPF_AND|BPF_K:
	case BPF_ALU|BPF_OR|BPF_K:
	case BPF_ALU|BPF_XOR|BPF_K:
		return 1;
	case BPF_ALU|BPF_LSH|BPF_K:
	case BPF_ALU|BPF_RSH|BPF_K:
		// Reject a constant shift by more than 31 bits.
		return insn->k < 32;
	case BPF_ALU|BPF_NEG:
	case BPF_MISC|BPF_TAX:
	case BPF_MISC|BPF_TXA:
		return 1;
	}
	// Reject an invalid opcode.
	return 0;
}

/*
 * Return true if the 'fcode' is a valid filter program.
 * The constraints are that each jump be forward and to a valid
 * code and that the code terminates with either an accept or reject.
 *
 * The kernel needs to be able to verify an application's filter code.
 * Otherwise, a bogus program could easily crash the system.
 */
int
pcapint_validate_filter(const struct bpf_insn *f, int len)
{
	u_int i, from;
	const struct bpf_insn *p;

	if (len < 1 || (u_int)len > BPF_MAXINSNS || f + len < f)
		return 0;

	for (i = 0; i < (u_int)len; ++i) {
		p = &f[i];
		if (! pcapint_valid_insn(p))
			return 0;
		switch (BPF_CLASS(p->code)) {
		case BPF_JMP:
			/*
			 * Check that jumps are within the code block,
			 * regardless of the direction.  libpcap uses
			 * backward jumps to implement the "protochain"
			 * primitive.  All offsets that mean a backward
			 * jump in libpcap (whether in-range or not) in
			 * kernel BPF implementations mean out-of-range
			 * or overflow forward jumps -- kernel
			 * implementations must reject that.
			 *
			 * Unconditional branches have a 32-bit offset,
			 * so they could overflow; we check to make
			 * sure they don't.  Conditional branches have
			 * an 8-bit offset, and the from address is <=
			 * BPF_MAXINSNS, and we know that BPF_MAXINSNS
			 * is sufficiently small that adding 255 to it
			 * won't overflow.
			 *
			 * We know that len is <= BPF_MAXINSNS, and we
			 * know that BPF_MAXINSNS is < the maximum value
			 * of a u_int, so that i + 1 doesn't overflow.
			 */
			from = i + 1;
			switch (BPF_OP(p->code)) {
			case BPF_JA:
				/*
				 * So long as both 'from' and bpf_insn.k are
				 * 32-bit unsigned, this check rejects any jump
				 * offset that points outside of the valid BPF
				 * address space of the filter program no
				 * matter whether signed interpretation of the
				 * offset is positive or negative.
				 *
				 * Note that this condition is necessary, but
				 * not sufficient to get correct results from
				 * respective pointer arithmetic in the process
				 * address space.  Other necessary conditions
				 * are that BPF_MAXINSNS is correctly defined
				 * and enforced, and that the pointer does not
				 * overflow.
				 */
				if (from + p->k >= (u_int)len)
					return 0;
				/*
				 * The only type of infinite loop that can be
				 * detected in this function is a "ja L" that
				 * jumps to itself.  For this only k == -1
				 * needs to be tested because the check above
				 * has already rejected all other values that
				 * would wrap the pointer equivalently on
				 * 32-bit architectures.
				 */
				if ((bpf_int32)p->k == -1)
					return 0;
				break;
			case BPF_JEQ:
			case BPF_JGT:
			case BPF_JGE:
			case BPF_JSET:
				if (from + p->jt >= (u_int)len || from + p->jf >= (u_int)len)
					return 0;
				break;
			}
		}
	}
	return BPF_CLASS(f[len - 1].code) == BPF_RET;
}

/*
 * Exported because older versions of libpcap exported them.
 * This function is deprecated and unsafe, use pcap_offline_filter() instead.
 */
u_int
bpf_filter(const struct bpf_insn *pc, const u_char *p, u_int wirelen,
    u_int buflen)
{
	// The actual length of the filter program is not known.
	return pcapint_filter(pc, BPF_MAXINSNS, p, wirelen, buflen);
}

int
bpf_validate(const struct bpf_insn *f, int len)
{
	return pcapint_validate_filter(f, len);
}
