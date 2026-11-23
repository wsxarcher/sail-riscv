#include "common/encoding.h"

// Self-checking test for the implicit tag checks of the Zimt memory
// tagging extension (v0.2, DRAFT) with first-stage paging: PTE.MTAG,
// tagged-data and tagcheck-exempt code pages, the straddle rules,
// supervisor accesses to user pages, mstatus.MTAG_I and hstatus.MTAG_I,
// HLV*/HSV*/HLVX*, and the AMOs, LR/SC, cbo.zero and vector accesses
// (an AMO over two pages, which is never split, is not checked).
//
// Runs in M-mode, and in S, U, HS, HU and VS-mode for what MPRV cannot
// do (instruction fetches, HLV* in HS/HU-mode). Memory tagging uses
// 4-bit tags with pointer masking (PMLEN = 7) for S, U, VS and VU-mode
// (menvcfg, senvcfg, henvcfg, hstatus.HUPMM). satp, and vsatp with
// hgatp = Bare, use the same Sv39 tables: the gigapage 0x80000000 (the
// test image) mapped to itself, and the 4 KiB pages of test_pages below
// from VA 0xC0000000. Memory tags are 0 except where a test sets them,
// so pointer tag 0 matches and pointer tag 5 mismatches.
//
// NOTE: the CSR addresses of the tag table bases and the position of
// PTE.MTAG (bit 58) are PLACEHOLDERS; the draft specification has not
// allocated them yet (see model/extensions/Zimt/zimt_regs.sail and
// model/sys/vmem_pte.sail).

#define CSR_SVITTS       0x5C2
#define CSR_SVITTU       0x5C3
#define CSR_VSVITTS      0x6C2
#define CSR_VSVITTU      0x6C3

// [mhs]envcfg.MT_MODE: bits 35:34; [mhs]envcfg.PMM: bits 33:32.
#define MT_MODE_SHIFT    34
#define MT_MODE_TAG4     2
#define PMM_SHIFT        32
#define PMM_PMLEN_7      2
#define ENVCFG_MT_PMM    ((MT_MODE_TAG4 << MT_MODE_SHIFT) | (PMM_PMLEN_7 << PMM_SHIFT))
#define ENVCFG_MT        (3 << MT_MODE_SHIFT)
#define HSTATUS_VUMT     (MT_MODE_TAG4 << 50)
#define HSTATUS_HUPMM    (PMM_PMLEN_7 << 48)
#define HSTATUS_MTAG_I   (1 << 10)
#define MSTATUS_MTAG_I   (1 << 40)
#define MSTATUS_MPP_S    (1 << 11)

#define PTE_MTAG         (1 << 58)
#define PTE_LEAF         (PTE_V | PTE_A | PTE_D)
#define DATA_S           (PTE_LEAF | PTE_R | PTE_W)
#define DATA_U           (DATA_S | PTE_U)
#define CODE_S           (PTE_LEAF | PTE_R | PTE_X)
#define CODE_U           (CODE_S | PTE_U)

#define CAUSE_SOFTWARE_CHECK 18
#define SWCHECK_TVAL_MEM_TAG 4

// Test pages, from VA 0xC0000000 (index 3 of the root table).
#define TVA              0xC0000000
#define VA_A             (TVA + 0x0000)  // S tagged-data page
#define VA_B             (TVA + 0x1000)  // S data page without MTAG
#define VA_D             (TVA + 0x2000)  // U tagged-data page
#define VA_A2            (TVA + 0x3000)  // S tagged-data page
#define VA_C             (TVA + 0x4000)  // S RWX page with MTAG: not a tagged-data page
#define VA_TS            (TVA + 0x5000)  // S-mode tag table page
#define VA_TU            (TVA + 0x6000)  // U-mode tag table page
#define VA_UXC           (TVA + 0x7000)  // code_page, user and tagcheck-exempt
#define VA_XC            (TVA + 0x8000)  // code_page, tagcheck-exempt
#define VA_NC            (TVA + 0x9000)  // code_page, normal
#define VA_SX            (TVA + 0xA000)  // straddle_p0, exempt
#define VA_SN            (TVA + 0xB000)  // straddle_p1, normal
#define VA_SXX           (TVA + 0xC000)  // straddle_p0, exempt
#define VA_SXX1          (TVA + 0xD000)  // straddle_p1, exempt
#define VA_UC            (TVA + 0xE000)  // code_page, user
#define VA_UNM           (TVA + 0xF000)  // not mapped
#define VA_N             (TVA + 0x10000) // page_b: S data page without MTAG, before VA_T
#define VA_T             (TVA + 0x11000) // page_a2: S tagged-data page
// The tag byte of VA v (4-bit tags) is at VITT + (v >> 5), here
// VA_TS or VA_TU + ((v - TVA) >> 5).
#define VITT_S           (VA_TS - (TVA >> 5))
#define VITT_U           (VA_TU - (TVA >> 5))
#define TAG_OFF(v)       (((v) - TVA) >> 5)
// Section 9: the tag of the last chunk of the address space
// (0x0FFFFFFFFFFFFFFF) in the last byte of tag_s (at VA_TS), so that of
// chunk 0 at this non-canonical address.
#define VITT_WRAP        0xF8000000C0006000
// Sections 11 and 12: root[4] points VA_IMP to a VS-stage level-1 table at
// the guest physical address IMP_L1, which the G stage does not map, at
// its entry 5; vsvitts = VITT_IMP puts the tag of VA_A at VA_IMP.
#define IMP_L1           0x40000000
#define VA_IMP           0x100A00000
#define IMP_HTVAL        ((IMP_L1 + 5 * 8) >> 2)
#define VITT_IMP         (VA_IMP - (TVA >> 5))
#define TINST_VS_PTE_READ 0x3000  // 64-bit read for VS-stage address translation

// Entry points of code_page.
#define CODE_LD          0x00  // ld t4, 0(t1)
#define CODE_CHECKTAG    0x08  // checktag t1, 0
#define CODE_HLV         0x10  // hlv.d t4, (t1)
#define CODE_JR          0x18  // jr t1
#define CODE_SD          0x20  // sd t4, 0(t1)
#define CODE_SETTAG      0x28  // settag t1, 0

.macro checktag rs1, imm4
  .4byte ((0x43 << 25) | (\imm4 << 20) | (\rs1 << 15) | (0x4 << 12) | 0x73)
.endm
.macro settag rs1, imm4
  .4byte ((0x41 << 25) | (\imm4 << 20) | (\rs1 << 15) | (0x4 << 12) | 0x73)
.endm
.macro cbo_zero rs1
  .4byte ((4 << 20) | (\rs1 << 15) | (2 << 12) | 0x0F)
.endm

// reg = va with pointer tag `tag`
.macro ptr reg, va, tag
    li \reg, \va
    li t5, \tag
    slli t5, t5, 60
    or \reg, \reg, t5
.endm

// Map test page index `idx` to physical address `t0` with PTE flags.
.macro map_page idx, flags
    srli t0, t0, RISCV_PGSHIFT
    slli t0, t0, PTE_PPN_SHIFT
    li t2, \flags
    or t0, t0, t2
    la t2, l0_table
    sd t0, (\idx * 8)(t2)
.endm

// Set the 4-bit memory tag of the chunk of `va` in the tag page `page`.
.macro set_tag page, va, tag
    la t0, \page
    li t2, TAG_OFF(\va)
    add t0, t0, t2
    lbu t2, 0(t0)
    .if ((\va >> 4) & 1)
    andi t2, t2, 0x0F
    ori t2, t2, (\tag << 4)
    .else
    andi t2, t2, 0xF0
    ori t2, t2, \tag
    .endif
    sb t2, 0(t0)
.endm

// Each trap sets MPP = M, and its mret then MPP = U, so these select the
// effective privilege again before each access.
.macro mprv mpp
    li t5, MSTATUS_MPP | MSTATUS_MPV
    csrc mstatus, t5
    li t5, MSTATUS_MPRV | \mpp
    csrs mstatus, t5
.endm
.macro mprv_off
    li t5, MSTATUS_MPRV
    csrc mstatus, t5
.endm

// Run code at virtual address `entry` in the mode that `mpp`/`mpv` (MPP
// and MPV bits) select, with t1 as its argument, until its ecall.
.macro run entry, mpp
    la s10, 1f
    li t5, MSTATUS_MPP | MSTATUS_MPV | MSTATUS_MPRV
    csrc mstatus, t5
    li t5, \mpp
    csrs mstatus, t5
    li t5, \entry
    csrw mepc, t5
    mret
1:
.endm

.macro expect_none
    bnez s2, fail
.endm
.macro expect_trap cause, tval
    li t5, \cause
    bne s2, t5, fail
    li t5, \tval
    bne s3, t5, fail
.endm
.macro expect_swcheck gva
    expect_trap CAUSE_SOFTWARE_CHECK, SWCHECK_TVAL_MEM_TAG
    li t5, \gva
    bne s5, t5, fail
.endm
// A guest-page fault (cause) at tval in an implicit access of a VS-stage
// walk, taken to M-mode: mtinst = the pseudoinstruction, mtval2 =
// IMP_HTVAL, GVA = 1, and mstatus.MTAG_I = mtag_i (the deposit).
.macro expect_implicit cause, tval, mtag_i
    expect_trap \cause, \tval
    li t5, TINST_VS_PTE_READ
    bne s4, t5, fail
    li t5, IMP_HTVAL
    bne s8, t5, fail
    li t5, 1
    bne s5, t5, fail
    srli t5, s6, 40
    andi t5, t5, 1
    li t6, \mtag_i
    bne t5, t6, fail
.endm
// The same, taken to HS-mode: htinst, htval, hstatus.GVA = 1 and
// hstatus.MTAG_I = mtag_i.
.macro expect_implicit_hs cause, tval, mtag_i
    expect_trap \cause, \tval
    li t5, TINST_VS_PTE_READ
    bne s4, t5, fail
    li t5, IMP_HTVAL
    bne s8, t5, fail
    srli t5, s7, 6
    andi t5, t5, 1
    li t6, 1
    bne t5, t6, fail
    srli t5, s7, 10
    andi t5, t5, 1
    li t6, \mtag_i
    bne t5, t6, fail
.endm

.global main
main:
#if __riscv_xlen == 64
    .option push
    .option norvc
    mv s11, ra
    la t0, m_trap
    csrw mtvec, t0

    // ------------------------------------------------------------------
    // 1. Setup. If MT_MODE reads back 0, Zimt is not present (e.g.
    //    experimental extensions disabled): pass trivially.
    li t0, ENVCFG_MT_PMM
    csrs CSR_MENVCFG, t0
    csrr t1, CSR_MENVCFG
    srli t1, t1, MT_MODE_SHIFT
    andi t1, t1, 3
    li t2, MT_MODE_TAG4
    bne t1, t2, pass
    csrs CSR_SENVCFG, t0
    li t0, VITT_S
    csrw CSR_SVITTS, t0
    li t0, VITT_U
    csrw CSR_SVITTU, t0

    //    Page tables: root[2] maps the test image, root[3] -> l1_table,
    //    l1_table[0] -> l0_table, which maps the test pages.
    la t1, root_table
    li t0, 0x80000000
    srli t0, t0, RISCV_PGSHIFT
    slli t0, t0, PTE_PPN_SHIFT
    ori t0, t0, PTE_LEAF | PTE_R | PTE_W | PTE_X
    sd t0, 16(t1)
    la t0, l1_table
    srli t0, t0, RISCV_PGSHIFT
    slli t0, t0, PTE_PPN_SHIFT
    ori t0, t0, PTE_V
    sd t0, 24(t1)
    la t1, l1_table
    la t0, l0_table
    srli t0, t0, RISCV_PGSHIFT
    slli t0, t0, PTE_PPN_SHIFT
    ori t0, t0, PTE_V
    sd t0, 0(t1)
    la t0, page_a
    map_page 0, DATA_S | PTE_MTAG
    la t0, page_b
    map_page 1, DATA_S
    la t0, page_d
    map_page 2, DATA_U | PTE_MTAG
    la t0, page_a2
    map_page 3, DATA_S | PTE_MTAG
    la t0, page_c
    map_page 4, DATA_S | PTE_X | PTE_MTAG
    la t0, tag_s
    map_page 5, DATA_S
    la t0, tag_u
    map_page 6, DATA_U
    la t0, code_page
    map_page 7, CODE_U | PTE_MTAG
    la t0, code_page
    map_page 8, CODE_S | PTE_MTAG
    la t0, code_page
    map_page 9, CODE_S
    la t0, straddle_p0
    map_page 10, CODE_S | PTE_MTAG
    la t0, straddle_p1
    map_page 11, CODE_S
    la t0, straddle_p0
    map_page 12, CODE_S | PTE_MTAG
    la t0, straddle_p1
    map_page 13, CODE_S | PTE_MTAG
    la t0, code_page
    map_page 14, CODE_U
    la t0, page_b
    map_page 16, DATA_S
    la t0, page_a2
    map_page 17, DATA_S | PTE_MTAG
    la t0, root_table
    srli t0, t0, RISCV_PGSHIFT
    li t1, SATP_MODE_SV39
    slli t1, t1, 60
    or t0, t0, t1
    csrw satp, t0
    sfence.vma

    // ------------------------------------------------------------------
    // 2. Loads and stores at effective privilege S (MPRV, MPP = S):
    //    a. in a tagged-data page (MTAG = 1, X = 0): a matching pointer
    //       passes, a mismatching one raises a software-check exception
    //       (mtval = 4, GVA = 0),
    ptr t1, VA_A, 0
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_none
    ptr t1, VA_A, 5
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_swcheck 0
    //    b. a mismatching store leaves memory unchanged,
    li t4, -1
    li s2, 0
    mprv MSTATUS_MPP_S
    sd t4, 8(t1)
    mprv_off
    expect_swcheck 0
    la t0, page_a
    ld t4, 8(t0)
    bnez t4, fail
    //    c. a page without MTAG, and an RWX page with MTAG (not a
    //       tagged-data page), are not checked,
    ptr t1, VA_B, 5
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_none
    ptr t1, VA_C, 5
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_none
    //    d. stack pointer based accesses are not checked,
    mv s9, sp
    ptr sp, VA_A, 5
    mprv MSTATUS_MPP_S
    ld t4, 0(sp)
    mprv_off
    mv sp, s9
    expect_none
    //    e. an access straddling a tagged-data page and a page without
    //       MTAG is checked in both: the last chunk of A matches, the
    //       first chunk of B does not, then does,
    set_tag tag_s, (VA_A + 0xFF0), 5
    ptr t1, (VA_A + 0xFFC), 5
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_swcheck 0
    set_tag tag_s, VA_B, 5
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_none
    //    f. a fault of a tag load reports the tag address, with mtinst =
    //       0; a page fault of the access itself comes first, and reports
    //       its address,
    li t0, VA_UNM - (TVA >> 5)
    csrw CSR_SVITTS, t0
    ptr t1, VA_A, 5
    li s4, -1
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_trap CAUSE_LOAD_PAGE_FAULT, VA_UNM
    bnez s4, fail
    li t0, VITT_S
    csrw CSR_SVITTS, t0
    ptr t1, VA_UNM, 5
    li s2, 0
    mprv MSTATUS_MPP_S
    sd t4, 0(t1)
    mprv_off
    expect_trap CAUSE_STORE_PAGE_FAULT, VA_UNM
    //    g. without memory tagging, MTAG is ignored.
    li t0, ENVCFG_MT
    csrc CSR_MENVCFG, t0
    ptr t1, VA_A, 5
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_none
    li t0, ENVCFG_MT_PMM
    csrs CSR_MENVCFG, t0

    // ------------------------------------------------------------------
    // 3. Supervisor accesses to user pages are not checked, and the MTAG
    //    bits of user pages are ignored for them (SUM = 1):
    li t0, MSTATUS_SUM
    csrs mstatus, t0
    //    a. a user tagged-data page: unchecked at effective privilege S,
    //       checked at U (with the U-mode tag table),
    ptr t1, VA_D, 5
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_none
    mprv 0
    ld t4, 0(t1)
    mprv_off
    expect_swcheck 0
    //    b. user tagged-data page D then supervisor tagged-data page A2:
    //       the chunk in A2 is checked, the one in D is not,
    ptr t1, (VA_D + 0xFFC), 5
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_swcheck 0
    set_tag tag_s, VA_A2, 5
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_none
    //    c. supervisor page B without MTAG then user tagged-data page D:
    //       neither counts as a tagged-data page, so neither is checked.
    ptr t1, (VA_B + 0xFFC), 5
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_none
    li t0, MSTATUS_SUM
    csrc mstatus, t0

    // ------------------------------------------------------------------
    // 4. mstatus.MTAG_I:
    //    a. it is writable, and not part of sstatus,
    li t0, MSTATUS_MTAG_I
    csrs mstatus, t0
    csrr t1, mstatus
    and t1, t1, t0
    beqz t1, fail
    csrr t1, sstatus
    and t1, t1, t0
    bnez t1, fail
    //    b. with MPRV = 1, MTAG_I = 1 makes loads and stores unchecked,
    ptr t1, VA_A, 5
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_none
    li t0, MSTATUS_MTAG_I
    csrc mstatus, t0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_swcheck 0
    //    c. a trap that writes a nonzero mtinst (the transformed load of a
    //       load page fault) deposits the MTAG bit of the code page of the
    //       trapping instruction: 1 from a tagcheck-exempt code page, 0
    //       from another one,
    li t1, VA_UNM
    li s2, 0
    run (VA_XC + CODE_LD), MSTATUS_MPP_S
    expect_trap CAUSE_LOAD_PAGE_FAULT, VA_UNM
    beqz s4, fail
    li t0, MSTATUS_MTAG_I
    and t1, s6, t0
    beqz t1, fail
    li t1, VA_UNM
    run (VA_NC + CODE_LD), MSTATUS_MPP_S
    li t0, MSTATUS_MTAG_I
    and t1, s6, t0
    bnez t1, fail
    //    d. one that writes mtinst = 0 (ecall) leaves it unchanged.
    li t0, MSTATUS_MTAG_I
    csrs mstatus, t0
    ptr t1, VA_B, 0
    li s2, 0
    run (VA_NC + CODE_LD), MSTATUS_MPP_S
    expect_none
    csrr t1, mstatus
    li t0, MSTATUS_MTAG_I
    and t1, t1, t0
    beqz t1, fail
    csrc mstatus, t0

    // ------------------------------------------------------------------
    // 5. Tagcheck-exempt code pages (MTAG = 1, X = 1), in S-mode:
    //    a. a load from one is not checked, from another one it is,
    ptr t1, VA_A, 5
    li s2, 0
    run (VA_XC + CODE_LD), MSTATUS_MPP_S
    expect_none
    run (VA_NC + CODE_LD), MSTATUS_MPP_S
    expect_swcheck 0
    //    b. checktag checks from one too,
    li s2, 0
    run (VA_XC + CODE_CHECKTAG), MSTATUS_MPP_S
    expect_swcheck 0
    //    c. an instruction straddling an exempt and a normal code page is
    //       fetched from a normal one, so it is checked; between two
    //       exempt code pages it is not.
    li s2, 0
    run (VA_SX + 0xFFE), MSTATUS_MPP_S
    expect_swcheck 0
    li s2, 0
    run (VA_SXX + 0xFFE), MSTATUS_MPP_S
    expect_none

    // ------------------------------------------------------------------
    // 6. MTAG is reserved in non-leaf PTEs and G-stage PTEs:
    //    a. a non-leaf PTE with MTAG gives a page fault,
    la t2, root_table
    ld t3, 24(t2)
    li t0, PTE_MTAG
    or t0, t0, t3
    sd t0, 24(t2)
    sfence.vma
    ptr t1, VA_A, 0
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_trap CAUSE_LOAD_PAGE_FAULT, VA_A
    sd t3, 24(t2)
    sfence.vma
    //    b. a G-stage leaf with MTAG gives a guest-page fault (effective
    //       privilege VS with vsatp = Bare and hgatp = Sv39x4 mapping the
    //       test image; henvcfg.MT_MODE is 0 still).
    la t1, g_table
    li t0, 0x80000000
    srli t0, t0, RISCV_PGSHIFT
    slli t0, t0, PTE_PPN_SHIFT
    ori t0, t0, PTE_LEAF | PTE_R | PTE_W | PTE_X | PTE_U
    li t2, PTE_MTAG
    or t0, t0, t2
    sd t0, 16(t1)
    srli t1, t1, RISCV_PGSHIFT
    li t0, (HGATP64_MODE & ~(HGATP64_MODE << 1)) * HGATP_MODE_SV39X4
    or t0, t0, t1
    csrw hgatp, t0
    csrw vsatp, zero
    hfence.gvma
    la t1, page_b
    srli t3, t1, 2
    li s2, 0
    mprv MSTATUS_MPP_S | MSTATUS_MPV
    ld t4, 0(t1)
    mprv_off
    li t5, CAUSE_LOAD_GUEST_PAGE_FAULT
    bne s2, t5, fail
    bne s3, t1, fail
    bne s8, t3, fail
    csrw hgatp, zero
    hfence.gvma

    // ------------------------------------------------------------------
    // 7. HLV*/HSV*, with vsatp using the same tables (hgatp = Bare) and
    //    henvcfg, hstatus.VUMT_MODE and senvcfg for the MT_MODE. The tag
    //    table of the other guest mode has the pointer tag (5) of the
    //    accesses at their chunk, so that only the tag table of their
    //    guest mode gives the expected outcome:
    set_tag tag_u, VA_A, 5
    set_tag tag_s, VA_D, 5
    li t0, ENVCFG_MT_PMM
    csrs CSR_HENVCFG, t0
    li t0, HSTATUS_HUPMM
    csrs hstatus, t0
    li t0, VITT_S
    csrw CSR_VSVITTS, t0
    li t0, VITT_U
    csrw CSR_VSVITTU, t0
    la t0, root_table
    srli t0, t0, RISCV_PGSHIFT
    li t1, SATP_MODE_SV39
    slli t1, t1, 60
    or t0, t0, t1
    csrw vsatp, t0
    hfence.vvma
    //    a. in M-mode with SPVP = 1 (henvcfg): a VS tagged-data page is
    //       checked, and a mismatch sets GVA; a page without MTAG is not,
    li t0, HSTATUS_SPVP
    csrs hstatus, t0
    ptr t1, VA_A, 0
    li s2, 0
    hlv.d t4, (t1)
    expect_none
    ptr t1, VA_A, 5
    li s8, -1
    hlv.d t4, (t1)
    expect_swcheck 1
    bnez s8, fail
    li t4, -1
    li s2, 0
    hsv.d t4, (t1)
    expect_swcheck 1
    la t0, page_a
    ld t4, 0(t0)
    bnez t4, fail
    ptr t1, VA_B, 5
    li s2, 0
    hlv.d t4, (t1)
    expect_none
    //    b. hstatus.MTAG_I is writable, and makes HLV*/HSV* unchecked,
    li t0, HSTATUS_MTAG_I
    csrs hstatus, t0
    csrr t1, hstatus
    and t1, t1, t0
    beqz t1, fail
    ptr t1, VA_A, 5
    hlv.d t4, (t1)
    hsv.d t4, (t1)
    expect_none
    li t0, HSTATUS_MTAG_I
    csrc hstatus, t0
    //    c. in M-mode with SPVP = 0: senvcfg, not hstatus.VUMT_MODE,
    li t0, HSTATUS_SPVP
    csrc hstatus, t0
    ptr t1, VA_D, 5
    hlv.d t4, (t1)
    expect_swcheck 1
    li t0, ENVCFG_MT
    csrc CSR_SENVCFG, t0
    li t0, HSTATUS_VUMT
    csrs hstatus, t0
    li s2, 0
    hlv.d t4, (t1)
    expect_none
    //    d. in HU-mode with SPVP = 0: hstatus.VUMT_MODE, not senvcfg,
    li t0, HSTATUS_HU
    csrs hstatus, t0
    run (VA_UC + CODE_HLV), 0
    expect_swcheck 1
    li t0, HSTATUS_VUMT
    csrc hstatus, t0
    li t0, ENVCFG_MT_PMM
    csrs CSR_SENVCFG, t0
    li s2, 0
    run (VA_UC + CODE_HLV), 0
    expect_none
    //    e. in HU-mode with SPVP = 1: henvcfg,
    li t0, HSTATUS_SPVP
    csrs hstatus, t0
    ptr t1, VA_A, 5
    run (VA_UC + CODE_HLV), 0
    expect_swcheck 1
    //    f. in HS-mode with SPVP = 0: senvcfg, not hstatus.VUMT_MODE,
    li t0, HSTATUS_SPVP
    csrc hstatus, t0
    ptr t1, VA_D, 5
    li s2, 0
    run (VA_NC + CODE_HLV), MSTATUS_MPP_S
    expect_swcheck 1
    li t0, ENVCFG_MT
    csrc CSR_SENVCFG, t0
    li t0, HSTATUS_VUMT
    csrs hstatus, t0
    li s2, 0
    run (VA_NC + CODE_HLV), MSTATUS_MPP_S
    expect_none
    li t0, ENVCFG_MT_PMM
    csrs CSR_SENVCFG, t0
    //    g. not from a tagcheck-exempt code page,
    li t0, HSTATUS_SPVP
    csrs hstatus, t0
    ptr t1, VA_A, 5
    run (VA_XC + CODE_HLV), MSTATUS_MPP_S
    expect_none
    set_tag tag_u, VA_A, 0
    set_tag tag_s, VA_D, 0
    //    h. HLVX* is never checked: with vsatp = Bare every page is a
    //       tagged-data page, so HLV* is checked; vsvitts puts the tag byte
    //       of the first chunk of code_page (tag 5) in tag_s.
    csrw vsatp, zero
    hfence.vvma
    la t0, tag_s
    li t1, 4096
    add t0, t0, t1
    la t2, code_page
    srli t2, t2, 5
    sub t0, t0, t2
    csrw CSR_VSVITTS, t0
    csrr t0, CSR_VSVITTS
    add t0, t0, t2
    li t1, 5
    sb t1, 0(t0)
    la t1, code_page
    li s2, 0
    hlv.wu t4, (t1)
    expect_swcheck 1
    li s2, 0
    hlvx.wu t4, (t1)
    expect_none
    li t1, 0
    sb t1, 0(t0)
    li t0, VITT_S
    csrw CSR_VSVITTS, t0

    // ------------------------------------------------------------------
    // 8. A trap to HS-mode that writes a nonzero htinst (the transformed
    //    load of a load page fault in VS-mode) deposits the VS-stage MTAG
    //    bit of the code page of the trapping instruction in
    //    hstatus.MTAG_I: 1 from a tagcheck-exempt code page, 0 from
    //    another one.
    la t0, root_table
    srli t0, t0, RISCV_PGSHIFT
    li t1, SATP_MODE_SV39
    slli t1, t1, 60
    or t0, t0, t1
    csrw vsatp, t0
    hfence.vvma
    la t0, hs_trap
    csrw stvec, t0
    li t0, (1 << CAUSE_LOAD_PAGE_FAULT)
    csrs medeleg, t0
    li t1, VA_UNM
    li s7, 0
    run (VA_XC + CODE_LD), MSTATUS_MPP_S | MSTATUS_MPV
    li t0, CAUSE_LOAD_PAGE_FAULT
    bne s2, t0, fail
    li t0, HSTATUS_MTAG_I
    and t1, s7, t0
    beqz t1, fail
    li t1, VA_UNM
    li s7, -1
    run (VA_NC + CODE_LD), MSTATUS_MPP_S | MSTATUS_MPV
    li t0, HSTATUS_MTAG_I
    and t1, s7, t0
    bnez t1, fail
    li t0, (1 << CAUSE_LOAD_PAGE_FAULT)
    csrc medeleg, t0

    // ------------------------------------------------------------------
    // 9. An access over the last page of the address space (a
    //    tagged-data page) and page 0 is checked in the last chunk
    //    (0x0FFFFFFFFFFFFFFF), whose tag VITT_WRAP puts in the last byte
    //    of tag_s, and then in chunk 0, as chunk indexes wrap around like
    //    addresses: its tag address, VITT_WRAP, is not canonical, so a
    //    load page fault, also for a store. root[0] maps the gigapage of
    //    the test image at VA 0, root[511] -> l1_top, whose last entry
    //    maps its first megapage with MTAG at VA 0xFFFFFFFFFFE00000.
    li t0, MSTATUS_MTAG_I | MSTATUS_SUM
    csrc mstatus, t0
    la t0, root_table
    srli t0, t0, RISCV_PGSHIFT
    li t1, SATP_MODE_SV39
    slli t1, t1, 60
    or t0, t0, t1
    csrw satp, t0
    la t1, root_table
    li t0, 0x80000000
    srli t0, t0, RISCV_PGSHIFT
    slli t0, t0, PTE_PPN_SHIFT
    ori t0, t0, DATA_S
    sd t0, 0(t1)
    la t0, l1_top
    srli t0, t0, RISCV_PGSHIFT
    slli t0, t0, PTE_PPN_SHIFT
    ori t0, t0, PTE_V
    li t2, 511 * 8
    add t2, t1, t2
    sd t0, 0(t2)
    la t1, l1_top
    li t0, 0x80000000
    srli t0, t0, RISCV_PGSHIFT
    slli t0, t0, PTE_PPN_SHIFT
    li t2, DATA_S | PTE_MTAG
    or t0, t0, t2
    li t2, 511 * 8
    add t2, t1, t2
    sd t0, 0(t2)
    sfence.vma
    la t0, tag_s
    li t1, 0xFFF
    add t0, t0, t1
    li t1, 0x50
    sb t1, 0(t0)
    li t0, VITT_WRAP
    csrw CSR_SVITTS, t0
    ptr t1, 0x01FFFFFFFFFFFFFC, 5
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_trap CAUSE_LOAD_PAGE_FAULT, VITT_WRAP
    li s2, 0
    mprv MSTATUS_MPP_S
    sd t4, 0(t1)
    mprv_off
    expect_trap CAUSE_LOAD_PAGE_FAULT, VITT_WRAP

    // ------------------------------------------------------------------
    // 10. A load from a tagcheck-exempt code page is not checked in
    //     U-mode, VS-mode (with vsatp) and VU-mode either, and from a code
    //     page without PTE.MTAG it is: of the user tagged-data page VA_D
    //     from U-mode and VU-mode (svittu, vsvittu: tag_u), of the
    //     tagged-data page VA_A from VS-mode (vsvitts: tag_s), with pointer
    //     tag 5.
    li t0, HSTATUS_MTAG_I
    csrc hstatus, t0
    ptr t1, VA_D, 5
    li s2, 0
    run (VA_UXC + CODE_LD), 0
    expect_none
    run (VA_UC + CODE_LD), 0
    expect_swcheck 0
    ptr t1, VA_A, 5
    li s2, 0
    run (VA_XC + CODE_LD), MSTATUS_MPP_S | MSTATUS_MPV
    expect_none
    run (VA_NC + CODE_LD), MSTATUS_MPP_S | MSTATUS_MPV
    expect_swcheck 0
    ptr t1, VA_D, 5
    li s2, 0
    run (VA_UXC + CODE_LD), MSTATUS_MPV
    expect_none
    run (VA_UC + CODE_LD), MSTATUS_MPV
    expect_swcheck 0

    // ------------------------------------------------------------------
    // 11. A fetch guest-page fault of an implicit access of the VS-stage
    //     walk writes the pseudoinstruction to htinst and the guest
    //     physical address of the PTE >> 2 to htval, and deposits in
    //     hstatus.MTAG_I the MTAG bit of the code page of the trapping
    //     instruction: 0, as its fetch failed, also right after a jump from
    //     a tagcheck-exempt code page. The G stage maps the test image to
    //     itself, and root[4] points VA_IMP to a VS-stage table at a guest
    //     physical address (IMP_L1) that it does not map.
    la t1, g_table
    li t0, 0x80000000
    srli t0, t0, RISCV_PGSHIFT
    slli t0, t0, PTE_PPN_SHIFT
    ori t0, t0, PTE_LEAF | PTE_R | PTE_W | PTE_X | PTE_U
    sd t0, 16(t1)
    srli t1, t1, RISCV_PGSHIFT
    li t0, (HGATP64_MODE & ~(HGATP64_MODE << 1)) * HGATP_MODE_SV39X4
    or t0, t0, t1
    csrw hgatp, t0
    la t1, root_table
    li t0, IMP_L1
    srli t0, t0, RISCV_PGSHIFT
    slli t0, t0, PTE_PPN_SHIFT
    ori t0, t0, PTE_V
    sd t0, 32(t1)
    hfence.gvma
    hfence.vvma
    la t0, hs_trap
    csrw stvec, t0
    li t0, (1 << CAUSE_FETCH_GUEST_PAGE_FAULT)
    csrs medeleg, t0
    li t0, HSTATUS_MTAG_I
    csrs hstatus, t0
    li t1, VA_IMP
    li s2, 0
    li s7, -1
    run (VA_XC + CODE_JR), MSTATUS_MPP_S | MSTATUS_MPV
    expect_implicit_hs CAUSE_FETCH_GUEST_PAGE_FAULT, VA_IMP, 0
    li t0, (1 << CAUSE_FETCH_GUEST_PAGE_FAULT)
    csrc medeleg, t0

    // ------------------------------------------------------------------
    // 12. The same for a load, a store, the tag accesses of checktag,
    //     settag and an implicit check (vsvitts = VITT_IMP puts the tag of
    //     VA_A at VA_IMP), and an HLV in HS-mode: the trap deposits the
    //     MTAG bit of the trapping instruction's code page in
    //     mstatus.MTAG_I (taken to M-mode) or in hstatus.MTAG_I (taken to
    //     HS-mode, 0 from V = 0): 1 from a tagcheck-exempt code page, 0
    //     from another one, so for the tag load of an implicit check.
    //   a. Taken to M-mode, from VS-mode,
    li t0, HSTATUS_SPVP
    csrs hstatus, t0
    li t0, HSTATUS_MTAG_I
    csrc hstatus, t0
    li t0, MSTATUS_MTAG_I
    csrc mstatus, t0
    li t1, VA_IMP
    li s2, 0
    run (VA_XC + CODE_LD), MSTATUS_MPP_S | MSTATUS_MPV
    expect_implicit CAUSE_LOAD_GUEST_PAGE_FAULT, VA_IMP, 1
    li t1, VA_IMP
    li s2, 0
    run (VA_NC + CODE_LD), MSTATUS_MPP_S | MSTATUS_MPV
    expect_implicit CAUSE_LOAD_GUEST_PAGE_FAULT, VA_IMP, 0
    li t1, VA_IMP
    li s2, 0
    run (VA_XC + CODE_SD), MSTATUS_MPP_S | MSTATUS_MPV
    expect_implicit CAUSE_STORE_GUEST_PAGE_FAULT, VA_IMP, 1
    li t0, VITT_IMP
    csrw CSR_VSVITTS, t0
    li t1, VA_A
    li s2, 0
    run (VA_NC + CODE_CHECKTAG), MSTATUS_MPP_S | MSTATUS_MPV
    expect_implicit CAUSE_LOAD_GUEST_PAGE_FAULT, VA_IMP, 0
    li t1, VA_A
    li s2, 0
    run (VA_XC + CODE_CHECKTAG), MSTATUS_MPP_S | MSTATUS_MPV
    expect_implicit CAUSE_LOAD_GUEST_PAGE_FAULT, VA_IMP, 1
    li t0, MSTATUS_MTAG_I
    csrc mstatus, t0
    li t1, VA_A
    li s2, 0
    run (VA_XC + CODE_SETTAG), MSTATUS_MPP_S | MSTATUS_MPV
    expect_implicit CAUSE_STORE_GUEST_PAGE_FAULT, VA_IMP, 1
    ptr t1, VA_A, 5
    li s2, 0
    run (VA_NC + CODE_LD), MSTATUS_MPP_S | MSTATUS_MPV
    expect_implicit CAUSE_LOAD_GUEST_PAGE_FAULT, VA_IMP, 0
    li t0, VITT_S
    csrw CSR_VSVITTS, t0
    //   b. taken to M-mode, from HS-mode (HLV, tagcheck-exempt code page),
    li t0, MSTATUS_MTAG_I
    csrc mstatus, t0
    li t1, VA_IMP
    li s2, 0
    run (VA_XC + CODE_HLV), MSTATUS_MPP_S
    expect_implicit CAUSE_LOAD_GUEST_PAGE_FAULT, VA_IMP, 1
    li t0, MSTATUS_MTAG_I
    csrc mstatus, t0
    //   c. taken to HS-mode.
    li t0, (1 << CAUSE_LOAD_GUEST_PAGE_FAULT) | (1 << CAUSE_STORE_GUEST_PAGE_FAULT)
    csrs medeleg, t0
    li t1, VA_IMP
    li s2, 0
    run (VA_XC + CODE_LD), MSTATUS_MPP_S | MSTATUS_MPV
    expect_implicit_hs CAUSE_LOAD_GUEST_PAGE_FAULT, VA_IMP, 1
    li t1, VA_IMP
    li s2, 0
    run (VA_NC + CODE_LD), MSTATUS_MPP_S | MSTATUS_MPV
    expect_implicit_hs CAUSE_LOAD_GUEST_PAGE_FAULT, VA_IMP, 0
    li t0, HSTATUS_MTAG_I
    csrs hstatus, t0
    li t1, VA_IMP
    li s2, 0
    run (VA_XC + CODE_HLV), MSTATUS_MPP_S
    expect_implicit_hs CAUSE_LOAD_GUEST_PAGE_FAULT, VA_IMP, 0
    li t0, (1 << CAUSE_LOAD_GUEST_PAGE_FAULT) | (1 << CAUSE_STORE_GUEST_PAGE_FAULT)
    csrc medeleg, t0
    la t1, root_table
    sd zero, 32(t1)
    csrw hgatp, zero
    hfence.gvma
    hfence.vvma

    // ------------------------------------------------------------------
    // 13. A load and a store over a page without MTAG and a tagged-data
    //     page, with the chunk in the first page mismatching, are checked
    //     there too (the straddle rule): a software-check exception, no
    //     byte stored; then matching.
    li t0, VITT_S
    csrw CSR_SVITTS, t0
    set_tag tag_s, VA_T, 5
    ptr t1, (VA_N + 0xFFC), 5
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_swcheck 0
    li t4, -1
    li s2, 0
    mprv MSTATUS_MPP_S
    sd t4, 0(t1)
    mprv_off
    expect_swcheck 0
    la t0, page_b
    li t2, 0xFFC
    add t0, t0, t2
    lwu t4, 0(t0)
    bnez t4, fail
    la t0, page_a2
    lwu t4, 0(t0)
    bnez t4, fail
    set_tag tag_s, (VA_N + 0xFF0), 5
    li s2, 0
    mprv MSTATUS_MPP_S
    ld t4, 0(t1)
    mprv_off
    expect_none
    set_tag tag_s, (VA_N + 0xFF0), 0
    set_tag tag_s, VA_T, 0

    // ------------------------------------------------------------------
    // 14. AMOs, LR/SC, cbo.zero and vector loads and stores at effective
    //     privilege S: through a mismatching pointer, in a tagged-data
    //     page each raises a software-check exception and is not
    //     performed; in a page without MTAG none is checked.
    li t0, MSTATUS_VS
    csrs mstatus, t0
    vsetivli t0, 2, e64, m1, ta, ma
    la t0, page_a
    li t4, -1
    sd t4, 0(t0)
    ptr t1, VA_A, 5
    li t2, 7
    li s2, 0
    mprv MSTATUS_MPP_S
    amoadd.d t4, t2, (t1)
    mprv_off
    expect_swcheck 0
    li s2, 0
    mprv MSTATUS_MPP_S
    lr.d t4, (t1)
    mprv_off
    expect_swcheck 0
    li s2, 0
    mprv MSTATUS_MPP_S
    sc.d t4, t2, (t1)
    mprv_off
    expect_swcheck 0
    li s2, 0
    mprv MSTATUS_MPP_S
    cbo_zero 6
    mprv_off
    expect_swcheck 0
    li s2, 0
    mprv MSTATUS_MPP_S
    vle64.v v2, (t1)
    mprv_off
    expect_swcheck 0
    vmv.v.i v2, 0
    li s2, 0
    mprv MSTATUS_MPP_S
    vse64.v v2, (t1)
    mprv_off
    expect_swcheck 0
    la t0, page_a
    ld t4, 0(t0)
    li t5, -1
    bne t4, t5, fail
    sd zero, 0(t0)
    ptr t1, VA_B, 5
    li s2, 0
    mprv MSTATUS_MPP_S
    amoadd.d t4, t2, (t1)
    lr.d t4, (t1)
    sc.d t4, t2, (t1)
    cbo_zero 6
    vle64.v v2, (t1)
    vse64.v v2, (t1)
    mprv_off
    expect_none

    // ------------------------------------------------------------------
    // 15. LR/SC and AMOs are never split: an AMO over the page without
    //     MTAG and the tagged-data page translates its first page only
    //     and raises its misaligned exception (a store/AMO access fault,
    //     as it is outside its 16-byte misaligned atomicity granule). It
    //     is not checked, though the first chunk of the next page has a
    //     mismatching tag, and stores no byte.
    li t0, VITT_S
    csrw CSR_SVITTS, t0
    set_tag tag_s, (VA_N + 0xFF0), 5
    set_tag tag_s, VA_T, 0
    la t0, page_b
    li t2, 0xFF8
    add t0, t0, t2
    sd zero, 0(t0)
    la t0, page_a2
    sd zero, 0(t0)
    ptr t1, (VA_N + 0xFFC), 5
    li t2, 7
    li s2, 0
    mprv MSTATUS_MPP_S
    amoadd.d t4, t2, (t1)
    mprv_off
    expect_trap CAUSE_STORE_ACCESS, (VA_N + 0xFFC)
    la t0, page_b
    li t2, 0xFF8
    add t0, t0, t2
    ld t4, 0(t0)
    bnez t4, fail
    la t0, page_a2
    ld t4, 0(t0)
    bnez t4, fail
    set_tag tag_s, (VA_N + 0xFF0), 0

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
    li t0, MSTATUS_MPRV | MSTATUS_SUM | MSTATUS_MTAG_I
    csrc mstatus, t0
    csrw satp, zero
    csrw vsatp, zero
    csrw hgatp, zero
    sfence.vma
    hfence.gvma
    hfence.vvma
    li t0, (3 << MT_MODE_SHIFT) | (3 << PMM_SHIFT)
    csrc CSR_MENVCFG, t0
    csrc CSR_SENVCFG, t0
    csrc CSR_HENVCFG, t0
    li t0, HSTATUS_SPVP | HSTATUS_HU | HSTATUS_MTAG_I | (3 << 50) | (3 << 48)
    csrc hstatus, t0
    li t0, (1 << CAUSE_LOAD_PAGE_FAULT) | (1 << CAUSE_FETCH_GUEST_PAGE_FAULT) | (1 << CAUSE_LOAD_GUEST_PAGE_FAULT) | (1 << CAUSE_STORE_GUEST_PAGE_FAULT)
    csrc medeleg, t0
    csrw CSR_SVITTU, zero
    csrw CSR_VSVITTS, zero
    csrw CSR_VSVITTU, zero
    ret

// M-mode trap handler. An ecall returns to the M-mode code at s10.
// Any other trap records mcause in s2, mtval in s3, mtinst in s4,
// mstatus.GVA in s5, mstatus in s6 and mtval2 in s8, and resumes at
// mepc + 4.
.p2align 6
m_trap:
    csrr t5, mcause
    li t6, CAUSE_USER_ECALL
    beq t5, t6, 1f
    li t6, CAUSE_SUPERVISOR_ECALL
    beq t5, t6, 1f
    li t6, CAUSE_VIRTUAL_SUPERVISOR_ECALL
    beq t5, t6, 1f
    csrr s2, mcause
    csrr s3, mtval
    csrr s4, CSR_MTINST
    csrr s6, mstatus
    srli s5, s6, 38
    andi s5, s5, 1
    csrr s8, CSR_MTVAL2
    csrr t5, mepc
    addi t5, t5, 4
    csrw mepc, t5
    mret
1:  li t5, MSTATUS_MPP
    csrs mstatus, t5
    li t5, MSTATUS_MPV
    csrc mstatus, t5
    csrw mepc, s10
    mret

// HS-mode trap handler: records scause in s2, stval in s3, htinst in s4,
// hstatus in s7 and htval in s8, and returns to M-mode with an ecall.
.p2align 2
hs_trap:
    csrr s2, scause
    csrr s3, stval
    csrr s4, CSR_HTINST
    csrr s7, hstatus
    csrr s8, CSR_HTVAL
    ecall

// Code run in S, U, HS, HU and VS-mode, through the mappings VA_XC,
// VA_NC and VA_UC. Each case ends with an ecall.
.p2align 12
code_page:
    ld t4, 0(t1)           // CODE_LD
    ecall
    checktag 6, 0          // CODE_CHECKTAG: checktag t1, 0
    ecall
    hlv.d t4, (t1)         // CODE_HLV
    ecall
    jr t1                  // CODE_JR
    ecall
    sd t4, 0(t1)           // CODE_SD
    ecall
    settag 6, 0            // CODE_SETTAG: settag t1, 0
    ecall
.p2align 12
// ld t4, 0(t1) straddling straddle_p0 and straddle_p1, then ecall.
straddle_p0:
    .skip 4094
    .2byte 0x3e83
straddle_p1:
    .2byte 0x0003
    .2byte 0x0073
    .2byte 0x0000
.p2align 12
    .option pop
#else
    // Zimt is RV64-only; pass trivially on RV32.
    li a0, 0
    ret
#endif

#if __riscv_xlen == 64
.section .data
.p2align 14
g_table:                   // Sv39x4 root table
    .fill 16384, 1, 0
.p2align 12
root_table:
    .fill 4096, 1, 0
l1_table:
    .fill 4096, 1, 0
l0_table:
    .fill 4096, 1, 0
l1_top:                    // Section 9: VA 0xFFFFFFFFC0000000
    .fill 4096, 1, 0
page_a:
    .fill 4096, 1, 0
page_b:
    .fill 4096, 1, 0
page_d:
    .fill 4096, 1, 0
page_a2:
    .fill 4096, 1, 0
page_c:
    .fill 4096, 1, 0
tag_s:
    .fill 4096, 1, 0
tag_u:
    .fill 4096, 1, 0
#endif
