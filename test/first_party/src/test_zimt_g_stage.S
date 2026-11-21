#include "common/encoding.h"

// Self-checking test for the implicit tag checks of the Zimt memory
// tagging extension (v0.2, DRAFT) at a virtual privilege whose
// first-stage address translation is Bare while the G stage translates.
// Tagged-data pages are defined by the MTAG bit "in first stage page
// tables", and "If paging is disabled and memory tagging is enabled for
// execution environment, then all data pages are tagged-data page", so
// with vsatp = Bare the loads and stores are checked whatever hgatp is,
// and the G stage translates their tag loads.
//
// Runs in M-mode. The accesses run at effective privilege VS through
// MPRV (MPV = 1, MPP = S), with henvcfg.MT_MODE enabling 4-bit tags,
// henvcfg.PMM pointer masking (PMLEN = 7) and vsvitts as the tag table,
// vsatp = Bare and hgatp = Sv39x4, which maps the guest physical
// gigapage 0x80000000 (the test image) to the same addresses.
//
// NOTE: the CSR address of vsvitts is a PLACEHOLDER; the draft
// specification has not allocated CSR addresses yet (see
// model/extensions/Zimt/zimt_regs.sail).

#define CSR_VSVITTS      0x6C2

// henvcfg.MT_MODE: bits 35:34; henvcfg.PMM: bits 33:32.
#define MT_MODE_SHIFT    34
#define MT_MODE_TAG4     2
#define PMM_SHIFT        32
#define PMM_PMLEN_7      2

#define CAUSE_SOFTWARE_CHECK 18
#define SWCHECK_TVAL_MEM_TAG 4
#define MSTATUS_MPP_S    (1 << 11)

// A guest physical gigapage that the G stage does not map.
#define UNMAPPED_GPA     0x40000000

// Each trap sets MPP = M and MPV = 0, and its mret then MPP = U, so this
// selects effective privilege VS again before each access.
.macro mprv_vs
    li t5, MSTATUS_MPP
    csrc mstatus, t5
    li t5, MSTATUS_MPRV | MSTATUS_MPV | MSTATUS_MPP_S
    csrs mstatus, t5
.endm

// Check the trap that record_trap recorded: mcause in s2, mtval in s3,
// mtinst in s4, mstatus.GVA in s5, mtval2 in s8.
.macro expect_trap cause, tval, tval2, gva
    li t5, \cause
    bne s2, t5, fail
    bne s3, \tval, fail
    bne s8, \tval2, fail
    li t5, \gva
    bne s5, t5, fail
    bnez s4, fail
.endm

.global main
main:
#if __riscv_xlen == 64
    // record_trap resumes at mepc + 4.
    .option push
    .option norvc
    mv s11, ra
    la t0, record_trap
    csrw mtvec, t0

    // ------------------------------------------------------------------
    // 1. Memory tagging with 4-bit tags and pointer masking for VS-mode.
    //    If MT_MODE reads back 0, Zimt is not present (e.g. experimental
    //    extensions disabled): pass trivially.
    li t0, (MT_MODE_TAG4 << MT_MODE_SHIFT) | (PMM_PMLEN_7 << PMM_SHIFT)
    csrs CSR_HENVCFG, t0
    csrr t1, CSR_HENVCFG
    srli t1, t1, MT_MODE_SHIFT
    andi t1, t1, 3
    li t2, MT_MODE_TAG4
    bne t1, t2, pass

    // ------------------------------------------------------------------
    // 2. vsvitts puts the tag byte of data_buf in tag_region (see
    //    test_zimt.S), and chunk 0 of data_buf, an even chunk (lower
    //    nibble), gets tag 5. M-mode does not check the store.
    la t0, tag_region
    li t1, 4096
    add t0, t0, t1         // tag_anchor = tag_region + 4096
    la t2, data_buf
    srli t3, t2, 5
    sub t0, t0, t3
    csrw CSR_VSVITTS, t0
    csrr t0, CSR_VSVITTS
    add t0, t0, t3         // tag byte of chunk 0 of data_buf
    li t1, 5
    sb t1, 0(t0)

    // ------------------------------------------------------------------
    // 3. Guest translation: vsatp = Bare, and hgatp = Sv39x4 with the
    //    gigapage 0x80000000 (index 2 of the root table) mapped to the
    //    same addresses, with U set, as G-stage leaves need.
    li t0, 0x80000000
    srli t0, t0, RISCV_PGSHIFT - PTE_PPN_SHIFT
    ori t0, t0, PTE_V | PTE_R | PTE_W | PTE_X | PTE_U | PTE_A | PTE_D
    la t1, gpt
    sd t0, 16(t1)
    srli t1, t1, RISCV_PGSHIFT
    li t0, (HGATP64_MODE & ~(HGATP64_MODE << 1)) * HGATP_MODE_SV39X4
    or t0, t0, t1
    csrw hgatp, t0
    csrw vsatp, zero
    hfence.gvma

    // ------------------------------------------------------------------
    // 4. Loads and stores at effective privilege VS:
    la t2, data_buf
    li t0, 5
    slli t0, t0, 60
    or t0, t0, t2          // t0 = data_buf tagged with 5
    li t1, 6
    slli t1, t1, 60
    or t1, t1, t2          // t1 = data_buf tagged with 6
    li s2, 0
    //    a. through a matching pointer: no exception,
    mprv_vs
    ld t4, 0(t0)
    sd t4, 8(t0)
    bnez s2, fail
    //    b. a load through a mismatching pointer: software-check
    //       exception with mtval = 4 and GVA = 0 (mtval is not a guest
    //       virtual address),
    li t3, SWCHECK_TVAL_MEM_TAG
    li s8, 0
    mprv_vs
    ld t4, 0(t1)
    expect_trap CAUSE_SOFTWARE_CHECK, t3, zero, 0
    //    c. a store through a mismatching pointer as well, which leaves
    //       memory unchanged,
    li t4, -1
    li s2, 0
    li s8, 0
    mprv_vs
    sd t4, 16(t1)
    expect_trap CAUSE_SOFTWARE_CHECK, t3, zero, 0
    li t5, MSTATUS_MPRV
    csrc mstatus, t5
    ld t4, 16(t2)
    bnez t4, fail
    //    d. with the tag table in a guest physical gigapage that the G
    //       stage does not map, the tag load of a load, and of a store,
    //       raises a load guest-page fault: mtval = the guest virtual
    //       address of the tag byte, mtval2 = its guest physical
    //       address (the same, as vsatp = Bare) >> 2, GVA = 1, and
    //       mtinst = 0, since the fault is not one of the access of the
    //       instruction.
    li t3, UNMAPPED_GPA
    csrw CSR_VSVITTS, t3
    srli t4, t2, 5
    add t3, t3, t4         // guest virtual address of the tag byte
    srli t6, t3, 2
    li s2, 0
    li s4, -1
    mprv_vs
    ld t4, 0(t0)
    expect_trap CAUSE_LOAD_GUEST_PAGE_FAULT, t3, t6, 1
    li s2, 0
    li s4, -1
    mprv_vs
    sd t4, 0(t0)
    expect_trap CAUSE_LOAD_GUEST_PAGE_FAULT, t3, t6, 1

    li t0, MSTATUS_MPRV
    csrc mstatus, t0

pass:
    call cleanup
    mv ra, s11
    li a0, 0
    ret
fail:
    call cleanup
    mv ra, s11
    li a0, 1
    ret

cleanup:
    li t0, MSTATUS_MPRV
    csrc mstatus, t0
    csrw hgatp, zero
    hfence.gvma
    li t0, (3 << MT_MODE_SHIFT) | (3 << PMM_SHIFT)
    csrc CSR_HENVCFG, t0
    csrw CSR_VSVITTS, zero
    ret

// Record mcause in s2, mtval in s3, mtinst in s4, mstatus.GVA in s5 and
// mtval2 in s8, and resume at mepc + 4.
.p2align 6
record_trap:
    csrr s2, mcause
    csrr s3, mtval
    csrr s4, CSR_MTINST
    csrr s5, mstatus
    srli s5, s5, 38
    andi s5, s5, 1
    csrr s8, CSR_MTVAL2
    csrr t5, mepc
    addi t5, t5, 4
    csrw mepc, t5
    mret
    .option pop
#else
    // Zimt is RV64-only; pass trivially on RV32.
    li a0, 0
    ret
#endif

#if __riscv_xlen == 64
.section .data
.p2align 14
gpt:                       // Sv39x4 root table
    .fill 16384, 1, 0
.p2align 12
tag_region:
    .fill 8192, 1, 0
data_buf:
    .fill 64, 1, 0
#endif
