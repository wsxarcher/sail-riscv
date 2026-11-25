#include "common/encoding.h"

// Zimt and Svatag (v0.2, DRAFT): Smstateen and Ssstateen gate the S-level and
// H-level memory tagging CSRs. "CSR access to senvmtagexclude0,
// senvmtagexclude1, henvmtagexclude0, and henvmtagexclude1 [svittu, svitts,
// vsvitts, and vsvittu] from modes less privileged than M causes illegal
// instruction exception if Smstateen is implemented and mstateen0.MT=0", and
// the access to the S-level ones from VS-mode "causes virtual instruction
// exception if Ssstateen is implemented, hstateen0.MT=0, and mstateen0.MT=1 or
// Smstateen is not implemented". The H-level ones raise a virtual instruction
// exception from VS-mode and VU-mode whenever HS-mode may access them, so
// with mstateen0.MT = 1, and so do the S-level ones from VU-mode.
//
// 1. mstateen0.MT is writable; hstateen0.MT is writable while mstateen0.MT =
//    1, and reads 0 while it is 0.
// 2. Each gated CSR, read and written from M, HS, U, VS and VU-mode, with
//    mstateen0.MT = 0 (and hstateen0.MT written 1 before, and 0 before),
//    with mstateen0.MT = 1 and hstateen0.MT = 0, and with both 1. A read that
//    does not trap returns the value of its CSR (in VS-mode, svitts and
//    svittu return vsvitts and vsvittu), one that traps leaves its register;
//    the writes write the value that the mode reads, so that the CSRs keep
//    their values.
// 3. The writes that do not trap reach their CSR (from HS-mode each of the
//    eight; from VS-mode, svitts and svittu reach vsvitts and vsvittu, and
//    senvmtagexclude0/1, which have no VS-level copy, themselves); those that
//    trap change nothing (also from U-mode, VU-mode, and VS-mode to the
//    H-level CSRs with both bits set).
// 4. The M-level CSRs are not gated.
// senvmtagexclude1 and henvmtagexclude1 hold what M-mode reads back (they
// are hardwired to zero without 7-bit tags).
//
// NOTE: the CSR addresses and the position of the MT bit (53) are
// PLACEHOLDERS; the draft specification has not allocated them yet (see
// model/extensions/Zimt/zimt_regs.sail and Stateen/stateen_regs.sail).

#define CSR_MENVMTAGEXCLUDE0 0x7C2
#define CSR_MVITT            0x7C4
#define CSR_SENVMTAGEXCLUDE0 0x5C0
#define CSR_SENVMTAGEXCLUDE1 0x5C1
#define CSR_SVITTS           0x5C2
#define CSR_SVITTU           0x5C3
#define CSR_HENVMTAGEXCLUDE0 0x6C0
#define CSR_HENVMTAGEXCLUDE1 0x6C1
#define CSR_VSVITTS          0x6C2
#define CSR_VSVITTU          0x6C3
#define STATEEN0_MT          (1 << 53)
#define STATEEN0H_MT         (1 << (53 - 32))
#define MT_MODE_SHIFT        34
#define MT_MODE_TAG4         2

#define CAUSE_ILLEGAL        CAUSE_ILLEGAL_INSTRUCTION
#define CAUSE_VIRTUAL        CAUSE_VIRTUAL_INSTRUCTION

// What a read that traps leaves in its register (s3).
#define SENTINEL             0x0123456789abcdef

#define M_MODE  PRV_M, 0
#define HS_MODE PRV_S, 0
#define U_MODE  PRV_U, 0
#define VS_MODE PRV_S, 1
#define VU_MODE PRV_U, 1

// Run the code at label in privilege mpp with V = mpv; its ebreak returns to
// M-mode here. record_trap records the cause of an illegal or virtual
// instruction exception in s2 (0: none), and skips the instruction. Neither
// touches s3, which the reads write, or s4, which the writes write.
.macro in_mode mpp, mpv, label
    li s2, 0
    la s5, 91f
    li t0, MSTATUS_MPP | MSTATUS_MPV
    csrc mstatus, t0
    li t0, ((\mpp) << 11) | ((\mpv) * MSTATUS_MPV)
    csrs mstatus, t0
    la t0, \label
    csrw mepc, t0
    mret
91:
.endm

// Run the code at label in privilege mpp with V = mpv: it must raise
// exception cause (0: none).
.macro check_csr mpp, mpv, label, cause
    in_mode \mpp, \mpv, \label
    li t0, \cause
    bne s2, t0, fail
.endm

// Read the CSR at label (read_s<n> or read_h<n>) into s3: entry n of table
// without an exception, SENTINEL with one. Then write entry n of table to it
// from the code at wlabel (write_s<n> or write_h<n>).
.macro check_rw mpp, mpv, label, wlabel, cause, table, n
    li s3, SENTINEL
    check_csr \mpp, \mpv, \label, \cause
    .if \cause
    li t0, SENTINEL
    .else
    la t0, \table
    ld t0, (8 * \n)(t0)
    .endif
    bne s3, t0, fail
    la t0, \table
    ld s4, (8 * \n)(t0)
    check_csr \mpp, \mpv, \wlabel, \cause
.endm

// Read and write each CSR of level (s or h) in privilege mpp with V = mpv,
// with the values of table.
.macro check_level mpp, mpv, level, cause, table
    check_rw \mpp, \mpv, read_\level\()0, write_\level\()0, \cause, \table, 0
    check_rw \mpp, \mpv, read_\level\()1, write_\level\()1, \cause, \table, 1
    check_rw \mpp, \mpv, read_\level\()2, write_\level\()2, \cause, \table, 2
    check_rw \mpp, \mpv, read_\level\()3, write_\level\()3, \cause, \table, 3
.endm

// Both levels from each mode.
.macro check_modes hs_s, hs_h, vs_s, vs_h, vu
    check_level M_MODE, s, 0, known_s
    check_level M_MODE, h, 0, known_h
    check_level HS_MODE, s, \hs_s, known_s
    check_level HS_MODE, h, \hs_h, known_h
    check_level U_MODE, s, CAUSE_ILLEGAL, known_s
    check_level U_MODE, h, CAUSE_ILLEGAL, known_h
    check_level VS_MODE, s, \vs_s, known_vs
    check_level VS_MODE, h, \vs_h, known_h
    check_level VU_MODE, s, \vu, known_vs
    check_level VU_MODE, h, \vu, known_h
.endm

// Write the value in t2 to csr from privilege mpp with V = mpv.
.macro write_from mpp, mpv, csr, cause
    check_csr \mpp, \mpv, write_csr_\csr, \cause
.endm

// Fail unless csr holds value; expect_high: value as kept by a high
// exclusion mask (s6: its writable bits).
.macro expect csr, value
    csrr t0, \csr
    li t1, \value
    bne t0, t1, fail
.endm
.macro expect_high csr, value
    csrr t0, \csr
    li t1, \value
    and t1, t1, s6
    bne t0, t1, fail
.endm

// Write value to csr from M-mode, and record what M-mode reads back in entry
// n of table.
.macro set_known csr, value, table, n
    li t0, \value
    csrw \csr, t0
    csrr t0, \csr
    la t1, \table
    sd t0, (8 * \n)(t1)
.endm

.global main
main:
#if __riscv_xlen == 64
    mv s11, ra

    // Without Zimt (e.g. experimental extensions disabled) mseccfg.MT_MODE
    // reads back 0: pass trivially. With Zimt, mstateen0.MT must be
    // writable, as the configuration makes it.
    li t0, MT_MODE_TAG4 << MT_MODE_SHIFT
    csrs CSR_MSECCFG, t0
    csrr t1, CSR_MSECCFG
    csrc CSR_MSECCFG, t0
    and t1, t1, t0
    beqz t1, pass_early
    li s9, STATEEN0_MT
    csrs CSR_MSTATEEN0, s9
    csrr t0, CSR_MSTATEEN0
    and t0, t0, s9
    beqz t0, fail_early
    csrr s10, mtvec
    la t0, record_trap
    csrw mtvec, t0
    csrw vsatp, zero
    csrw hgatp, zero
    csrw hstatus, zero

    // s6: the writable bits of the high exclusion masks.
    li t0, -1
    csrw CSR_SENVMTAGEXCLUDE1, t0
    csrr s6, CSR_SENVMTAGEXCLUDE1
    // Recognizable values, kept by the writes that trap.
    set_known CSR_SENVMTAGEXCLUDE0, 0x1, known_s, 0
    set_known CSR_SENVMTAGEXCLUDE1, 0x00000f00000000f0, known_s, 1
    set_known CSR_SVITTS, 0x81000000, known_s, 2
    set_known CSR_SVITTU, 0x82000000, known_s, 3
    set_known CSR_HENVMTAGEXCLUDE0, 0x2, known_h, 0
    set_known CSR_HENVMTAGEXCLUDE1, 0x00003c0000000c00, known_h, 1
    set_known CSR_VSVITTS, 0x83000000, known_h, 2
    set_known CSR_VSVITTU, 0x84000000, known_h, 3
    // VS-mode reads senvmtagexclude0/1 themselves, and vsvitts and vsvittu
    // through svitts and svittu.
    la t0, known_s
    la t1, known_vs
    ld t2, 0(t0)
    sd t2, 0(t1)
    ld t2, 8(t0)
    sd t2, 8(t1)
    la t0, known_h
    ld t2, 16(t0)
    sd t2, 16(t1)
    ld t2, 24(t0)
    sd t2, 24(t1)

    // ------------------------------------------------------------------
    // 1. mstateen0.MT is writable; hstateen0.MT reads 0 while mstateen0.MT
    //    = 0, and is writable while it is 1.
    csrw CSR_MSTATEEN0, zero
    csrr t0, CSR_MSTATEEN0
    bnez t0, fail
    csrw CSR_HSTATEEN0, s9
    csrr t0, CSR_HSTATEEN0
    bnez t0, fail
    csrw CSR_MSTATEEN0, s9
    csrr t0, CSR_MSTATEEN0
    bne t0, s9, fail
    csrw CSR_HSTATEEN0, s9
    csrr t0, CSR_HSTATEEN0
    bne t0, s9, fail
    csrw CSR_MSTATEEN0, zero
    csrr t0, CSR_HSTATEEN0
    bnez t0, fail
    csrw CSR_MSTATEEN0, s9
    csrw CSR_HSTATEEN0, zero
    csrr t0, CSR_HSTATEEN0
    bnez t0, fail

    // ------------------------------------------------------------------
    // 2. a. mstateen0.MT = 0, after hstateen0.MT = 1: illegal instruction
    //       below M-mode,
    csrw CSR_HSTATEEN0, s9
    csrw CSR_MSTATEEN0, zero
    check_modes CAUSE_ILLEGAL, CAUSE_ILLEGAL, CAUSE_ILLEGAL, CAUSE_ILLEGAL, CAUSE_ILLEGAL
    //    b. and after hstateen0.MT = 0, in VS-mode and VU-mode too,
    csrw CSR_MSTATEEN0, s9
    csrw CSR_HSTATEEN0, zero
    csrw CSR_MSTATEEN0, zero
    check_modes CAUSE_ILLEGAL, CAUSE_ILLEGAL, CAUSE_ILLEGAL, CAUSE_ILLEGAL, CAUSE_ILLEGAL
    //    c. mstateen0.MT = 1, hstateen0.MT = 0: HS-mode accesses them, VS-mode
    //       and VU-mode raise virtual instruction,
    csrw CSR_MSTATEEN0, s9
    csrw CSR_HSTATEEN0, zero
    check_modes 0, 0, CAUSE_VIRTUAL, CAUSE_VIRTUAL, CAUSE_VIRTUAL
    //    d. mstateen0.MT = 1, hstateen0.MT = 1: VS-mode accesses the S-level
    //       ones too.
    csrw CSR_HSTATEEN0, s9
    check_modes 0, 0, 0, CAUSE_VIRTUAL, CAUSE_VIRTUAL

    // The writes of 2 wrote the values that their mode reads, so the CSRs
    // keep the known ones.
    expect CSR_SVITTS, 0x81000000
    expect CSR_VSVITTU, 0x84000000

    // ------------------------------------------------------------------
    // 3. a. The writes reach their CSR (mstateen0.MT = hstateen0.MT = 1),
    li t2, 0x91000000
    write_from VS_MODE, CSR_SVITTS, 0
    expect CSR_VSVITTS, 0x91000000
    expect CSR_SVITTS, 0x81000000
    li t2, 0x92000000
    write_from VS_MODE, CSR_SVITTU, 0
    expect CSR_VSVITTU, 0x92000000
    expect CSR_SVITTU, 0x82000000
    li t2, 0x30
    write_from VS_MODE, CSR_SENVMTAGEXCLUDE0, 0
    expect CSR_SENVMTAGEXCLUDE0, 0x30
    li t2, 0x0000500000000050
    write_from VS_MODE, CSR_SENVMTAGEXCLUDE1, 0
    expect_high CSR_SENVMTAGEXCLUDE1, 0x0000500000000050
    li t2, 0xa1000000
    write_from HS_MODE, CSR_SVITTS, 0
    expect CSR_SVITTS, 0xa1000000
    li t2, 0xa2000000
    write_from HS_MODE, CSR_SVITTU, 0
    expect CSR_SVITTU, 0xa2000000
    li t2, 0xa3000000
    write_from HS_MODE, CSR_VSVITTS, 0
    expect CSR_VSVITTS, 0xa3000000
    li t2, 0xa4000000
    write_from HS_MODE, CSR_VSVITTU, 0
    expect CSR_VSVITTU, 0xa4000000
    li t2, 0x40
    write_from HS_MODE, CSR_SENVMTAGEXCLUDE0, 0
    expect CSR_SENVMTAGEXCLUDE0, 0x40
    li t2, 0x0000600000000060
    write_from HS_MODE, CSR_SENVMTAGEXCLUDE1, 0
    expect_high CSR_SENVMTAGEXCLUDE1, 0x0000600000000060
    li t2, 0x50
    write_from HS_MODE, CSR_HENVMTAGEXCLUDE0, 0
    expect CSR_HENVMTAGEXCLUDE0, 0x50
    li t2, 0x0000700000000070
    write_from HS_MODE, CSR_HENVMTAGEXCLUDE1, 0
    expect_high CSR_HENVMTAGEXCLUDE1, 0x0000700000000070
    //    b. a write that traps changes nothing: from VS-mode to the H-level
    //       CSRs, and from VU-mode and U-mode (virtual and illegal
    //       instruction),
    li t2, 0xb0000000
    write_from VS_MODE, CSR_VSVITTS, CAUSE_VIRTUAL
    write_from VS_MODE, CSR_HENVMTAGEXCLUDE1, CAUSE_VIRTUAL
    write_from VU_MODE, CSR_SVITTS, CAUSE_VIRTUAL
    write_from VU_MODE, CSR_SENVMTAGEXCLUDE1, CAUSE_VIRTUAL
    write_from VU_MODE, CSR_VSVITTU, CAUSE_VIRTUAL
    write_from U_MODE, CSR_SVITTU, CAUSE_ILLEGAL
    write_from U_MODE, CSR_SENVMTAGEXCLUDE0, CAUSE_ILLEGAL
    write_from U_MODE, CSR_HENVMTAGEXCLUDE1, CAUSE_ILLEGAL
    expect CSR_VSVITTS, 0xa3000000
    expect CSR_SVITTS, 0xa1000000
    expect CSR_VSVITTU, 0xa4000000
    expect CSR_SVITTU, 0xa2000000
    expect CSR_SENVMTAGEXCLUDE0, 0x40
    expect_high CSR_SENVMTAGEXCLUDE1, 0x0000600000000060
    expect_high CSR_HENVMTAGEXCLUDE1, 0x0000700000000070
    //       from VS-mode with hstateen0.MT = 0 (virtual instruction),
    csrw CSR_HSTATEEN0, zero
    li t2, 0xb1000000
    write_from VS_MODE, CSR_SVITTS, CAUSE_VIRTUAL
    write_from VS_MODE, CSR_VSVITTU, CAUSE_VIRTUAL
    expect CSR_VSVITTS, 0xa3000000
    expect CSR_SVITTS, 0xa1000000
    expect CSR_VSVITTU, 0xa4000000
    li t2, 0x60
    write_from VS_MODE, CSR_SENVMTAGEXCLUDE0, CAUSE_VIRTUAL
    write_from VS_MODE, CSR_SENVMTAGEXCLUDE1, CAUSE_VIRTUAL
    expect CSR_SENVMTAGEXCLUDE0, 0x40
    expect_high CSR_SENVMTAGEXCLUDE1, 0x0000600000000060
    //       and from HS-mode and VS-mode with mstateen0.MT = 0 (illegal
    //       instruction).
    csrw CSR_MSTATEEN0, zero
    li t2, 0xb2000000
    write_from HS_MODE, CSR_SVITTU, CAUSE_ILLEGAL
    write_from HS_MODE, CSR_VSVITTS, CAUSE_ILLEGAL
    write_from VS_MODE, CSR_SVITTS, CAUSE_ILLEGAL
    expect CSR_SVITTU, 0xa2000000
    expect CSR_VSVITTS, 0xa3000000
    expect CSR_SVITTS, 0xa1000000
    li t2, 0x70
    write_from HS_MODE, CSR_SENVMTAGEXCLUDE0, CAUSE_ILLEGAL
    write_from HS_MODE, CSR_SENVMTAGEXCLUDE1, CAUSE_ILLEGAL
    write_from HS_MODE, CSR_HENVMTAGEXCLUDE0, CAUSE_ILLEGAL
    write_from HS_MODE, CSR_HENVMTAGEXCLUDE1, CAUSE_ILLEGAL
    expect CSR_SENVMTAGEXCLUDE0, 0x40
    expect_high CSR_SENVMTAGEXCLUDE1, 0x0000600000000060
    expect CSR_HENVMTAGEXCLUDE0, 0x50
    expect_high CSR_HENVMTAGEXCLUDE1, 0x0000700000000070

    // ------------------------------------------------------------------
    // 4. The M-level CSRs: M-mode accesses them whatever mstateen0.MT (0
    //    here), HS-mode never.
    li t2, 0x80
    write_from M_MODE, CSR_MENVMTAGEXCLUDE0, 0
    expect CSR_MENVMTAGEXCLUDE0, 0x80
    li t2, 0xc1000000
    write_from M_MODE, CSR_MVITT, 0
    expect CSR_MVITT, 0xc1000000
    csrw CSR_MSTATEEN0, s9
    csrw CSR_HSTATEEN0, s9
    li t2, 0x90
    write_from HS_MODE, CSR_MENVMTAGEXCLUDE0, CAUSE_ILLEGAL
    write_from HS_MODE, CSR_MVITT, CAUSE_ILLEGAL
    expect CSR_MENVMTAGEXCLUDE0, 0x80
    expect CSR_MVITT, 0xc1000000

    csrw mtvec, s10
pass:
    csrw CSR_MSTATEEN0, zero
pass_early:
    mv ra, s11
    li a0, 0
    ret
fail:
    csrw mtvec, s10
fail_early:
    csrw CSR_MSTATEEN0, zero
    mv ra, s11
    li a0, 1
    ret

// The code that in_mode runs: an access, then an ebreak back to M-mode.
.irp n, 0, 1, 2, 3
read_s\n:
    csrr s3, 0x5C0 + \n
    ebreak
write_s\n:
    csrw 0x5C0 + \n, s4
    ebreak
read_h\n:
    csrr s3, 0x6C0 + \n
    ebreak
write_h\n:
    csrw 0x6C0 + \n, s4
    ebreak
.endr
.irp csr, CSR_SVITTS, CSR_SVITTU, CSR_VSVITTS, CSR_VSVITTU, CSR_SENVMTAGEXCLUDE0, CSR_SENVMTAGEXCLUDE1, CSR_HENVMTAGEXCLUDE0, CSR_HENVMTAGEXCLUDE1, CSR_MENVMTAGEXCLUDE0, CSR_MVITT
write_csr_\csr:
    csrw \csr, t2
    ebreak
.endr

// Trap handler: record an illegal or virtual instruction exception in s2
// and skip the instruction, in the same mode; return to M-mode at s5 after
// an ebreak; fail on any other trap.
.p2align 6
record_trap:
    csrr t0, mcause
    li t1, CAUSE_BREAKPOINT
    beq t0, t1, 1f
    li t1, CAUSE_ILLEGAL
    beq t0, t1, 2f
    li t1, CAUSE_VIRTUAL
    bne t0, t1, 3f
2:
    bnez s2, 3f
    mv s2, t0
    csrr t0, mepc
    addi t0, t0, 4
    csrw mepc, t0
    mret
1:
    li t0, MSTATUS_MPP
    csrs mstatus, t0
    li t0, MSTATUS_MPV
    csrc mstatus, t0
    csrw mepc, s5
    mret
// An unexpected trap, in any mode: fail in M-mode.
3:
    li t0, MSTATUS_MPP
    csrs mstatus, t0
    li t0, MSTATUS_MPV
    csrc mstatus, t0
    la t0, fail
    csrw mepc, t0
    mret
#else
    // Zimt is RV64-only: on RV32 the MT bit (bit 53, bit 21 of mstateen0h
    // and hstateen0h) is read-only zero (with Smstateen and, for
    // hstateen0h, H, which the first-party configurations have).
    li t0, STATEEN0H_MT
    csrs CSR_MSTATEEN0H, t0
    csrr t1, CSR_MSTATEEN0H
    and t1, t1, t0
    bnez t1, 1f
    csrs CSR_HSTATEEN0H, t0
    csrr t1, CSR_HSTATEEN0H
    and t1, t1, t0
    bnez t1, 1f
    li a0, 0
    ret
1:
    li a0, 1
    ret
#endif

#if __riscv_xlen == 64
.section .data
// The values of the CSRs that the setup writes, as M-mode reads them back:
// senvmtagexclude0/1, svitts and svittu (known_s); henvmtagexclude0/1,
// vsvitts and vsvittu (known_h); and those that VS-mode reads through the
// S-level addresses: senvmtagexclude0/1, vsvitts and vsvittu (known_vs).
.p2align 3
known_s:
    .dword 0, 0, 0, 0
known_h:
    .dword 0, 0, 0, 0
known_vs:
    .dword 0, 0, 0, 0
#endif
