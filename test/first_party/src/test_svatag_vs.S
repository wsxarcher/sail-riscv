#include "common/encoding.h"

// Svatag (v0.2, DRAFT): a VS-mode access to svitts and svittu uses the state
// of vsvitts and vsvittu ("The CSR access from VS mode, if allowed, uses the
// state of vsvitts and vsvittu CSRs, respectively"). Tag table bases are
// 4 KiB aligned: bits 11:0 read 0.
//
// NOTE: the CSR addresses are PLACEHOLDERS; the draft specification has not
// allocated CSR addresses yet (see model/extensions/Zimt/zimt_regs.sail).

#define CSR_SVITTS  0x5C2
#define CSR_SVITTU  0x5C3
#define CSR_VSVITTS 0x6C2
#define CSR_VSVITTU 0x6C3

#define SVITTS_BASE  0x80001000
#define SVITTU_BASE  0x80002000
#define VSVITTS_BASE 0x80003000
#define VSVITTU_BASE 0x80004000
// Written from VS-mode: not 4 KiB aligned, so bits 11:0 are dropped
#define VS_WRITE_S   0x80005fff
#define VS_WRITE_U   0x80006001

.global main
main:
#if __riscv_xlen == 64
  mv s11, ra

  // Without Svatag (e.g. experimental extensions disabled) the CSRs do not
  // exist: pass trivially.
  la t0, pass
  csrw mtvec, t0
  li t0, SVITTS_BASE
  csrw CSR_SVITTS, t0
  la t0, vs_return
  csrw mtvec, t0

  li t0, SVITTU_BASE
  csrw CSR_SVITTU, t0
  li t0, VSVITTS_BASE
  csrw CSR_VSVITTS, t0
  li t0, VSVITTU_BASE
  csrw CSR_VSVITTU, t0

  // Enter VS-mode (MPP = S, MPV = 1) at guest; it ends with an ecall to M-mode.
  li t0, MSTATUS_MPP
  csrc mstatus, t0
  li t0, MSTATUS_MPP & (MSTATUS_MPP >> 1)
  csrs mstatus, t0
  li t0, MSTATUS_MPV
  csrs mstatus, t0
  la t0, guest
  csrw mepc, t0
  mret

.align 4
guest:
  // Reads see vsvitts and vsvittu.
  csrr s1, CSR_SVITTS
  csrr s2, CSR_SVITTU
  // Writes go to vsvitts and vsvittu.
  li t0, VS_WRITE_S
  csrw CSR_SVITTS, t0
  li t0, VS_WRITE_U
  csrw CSR_SVITTU, t0
  ecall

.align 6
vs_return:
  csrr t0, mcause
  li t1, CAUSE_VIRTUAL_SUPERVISOR_ECALL
  bne t0, t1, fail

  li t1, VSVITTS_BASE
  bne s1, t1, fail
  li t1, VSVITTU_BASE
  bne s2, t1, fail

  // svitts and svittu keep their bases.
  csrr t0, CSR_SVITTS
  li t1, SVITTS_BASE
  bne t0, t1, fail
  csrr t0, CSR_SVITTU
  li t1, SVITTU_BASE
  bne t0, t1, fail
  // vsvitts and vsvittu hold the aligned bases written from VS-mode.
  csrr t0, CSR_VSVITTS
  li t1, VS_WRITE_S & ~0xfff
  bne t0, t1, fail
  csrr t0, CSR_VSVITTU
  li t1, VS_WRITE_U & ~0xfff
  bne t0, t1, fail

.align 2
pass:
  mv ra, s11
  li a0, 0
  ret
fail:
  mv ra, s11
  li a0, 1
  ret
#else
  // Svatag is RV64-only; pass trivially on RV32.
  li a0, 0
  ret
#endif
