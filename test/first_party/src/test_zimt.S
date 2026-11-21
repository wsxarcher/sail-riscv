// Self-checking test for the Zimt memory tagging extension (v0.2, DRAFT).
// Runs in M-mode with mseccfg.MT_MODE enabled and the Smvatag tag table.
//
// NOTE: the CSR addresses of mvitt and mmtagexclude0 are PLACEHOLDERS;
// the draft specification has not allocated CSR addresses yet (see
// model/extensions/Zimt/zimt_regs.sail).

#define CSR_MSECCFG      0x747
#define CSR_MTINST       0x34A
#define CSR_HENVCFG      0x60A
#define CSR_MMTAGEXCL0   0x7C0
#define CSR_MMTAGEXCL1   0x7C1
#define CSR_MVITT        0x7C4
#define CSR_VSVITTS      0x6C2

// A tag table base in unmapped memory.
#define UNMAPPED_TAG_TABLE 0x20000000

// mseccfg.MT_MODE: bits 35:34; mseccfg.PMM: bits 33:32.
#define MT_MODE_SHIFT    34
#define MT_MODE_TAG4     2
#define MT_MODE_TAG7     3
#define PMM_SHIFT        32
#define PMM_PMLEN_7      2

// Zimt instructions are encoded directly (Zimop MOP.RR space, SYSTEM
// opcode, funct3 100) since toolchains do not support Zimt yet.
// Register arguments are architectural register numbers.
.macro gentag rd
  .4byte ((0x43 << 25) | (0x4 << 12) | (\rd << 7) | 0x73)
.endm
.macro addtag rd, rs1, imm4
  .4byte ((0x43 << 25) | (\imm4 << 20) | (\rs1 << 15) | (0x4 << 12) | (\rd << 7) | 0x73)
.endm
.macro checktag rs1, imm4
  .4byte ((0x43 << 25) | (\imm4 << 20) | (\rs1 << 15) | (0x4 << 12) | 0x73)
.endm
.macro settag rs1, imm4
  .4byte ((0x41 << 25) | (\imm4 << 20) | (\rs1 << 15) | (0x4 << 12) | 0x73)
.endm

#define CAUSE_BREAKPOINT     3
#define CAUSE_LOAD_ACCESS    5
#define CAUSE_SOFTWARE_CHECK 18
#define SWCHECK_TVAL_MEM_TAG 4

#define MSTATUS_MIE          0x8
#define MSTATUS_MPP          (3 << 11)
#define MSTATUS_MPP_S        (1 << 11)
#define MSTATUS_MPRV         (1 << 17)
#define MSTATUS_GVA          (1 << 38)
#define MSTATUS_MPV          (1 << 39)
// mcontrol6 (type 6) trigger matching M-mode load addresses, with the
// breakpoint action.
#define MCONTROL6_M_LOAD     ((6 << 60) | (1 << 6) | 1)

.global main
main:
#if __riscv_xlen == 64
    mv s11, ra

    // ------------------------------------------------------------------
    // 1. Enable pointer masking (PMLEN=7) and memory tagging (4-bit
    //    tags) in M-mode. If MT_MODE reads back 0, Zimt is not present
    //    (e.g. experimental extensions disabled): pass trivially.
    li t0, (MT_MODE_TAG4 << MT_MODE_SHIFT) | (PMM_PMLEN_7 << PMM_SHIFT)
    csrs CSR_MSECCFG, t0
    csrr t1, CSR_MSECCFG
    srli t1, t1, MT_MODE_SHIFT
    andi t1, t1, 3
    li t2, MT_MODE_TAG4
    bne t1, t2, pass

    // The reserved MT_MODE value 0b01 must not stick (WARL keep-old).
    li t0, (3 << MT_MODE_SHIFT)
    csrc CSR_MSECCFG, t0
    li t0, (1 << MT_MODE_SHIFT)
    csrs CSR_MSECCFG, t0
    csrr t1, CSR_MSECCFG
    srli t1, t1, MT_MODE_SHIFT
    andi t1, t1, 3
    li t2, 1
    beq t1, t2, fail
    li t0, (MT_MODE_TAG4 << MT_MODE_SHIFT)
    csrs CSR_MSECCFG, t0

    // ------------------------------------------------------------------
    // 2. Point the M-mode tag table (VITT) so that the tag byte of
    //    data_buf lands inside tag_region:
    //      mc_tag_va = mvitt + (va >> 5)        (4-bit tags)
    //    mvitt = (tag_anchor - (data_buf >> 5)) & ~0xFFF, which puts
    //    the tag byte within (tag_anchor - 4096, tag_anchor].
    la t0, tag_region
    li t1, 4096
    add t0, t0, t1         // tag_anchor = tag_region + 4096
    la t2, data_buf
    srli t2, t2, 5
    sub t0, t0, t2
    csrw CSR_MVITT, t0
    // mvitt is 4K-aligned WARL: low 12 bits must read back zero.
    csrr t1, CSR_MVITT
    slli t1, t1, 52
    bnez t1, fail

    // ------------------------------------------------------------------
    // 3. gentag:
    //    a. with an exclusion mask permitting only tag value 5 it must
    //       generate pointer_tag = 5 (in bits 63:60), with the rest of
    //       rd cleared,
    li t0, 0xFFDF          // exclude all 4-bit tags except 5
    csrw CSR_MMTAGEXCL0, t0
    gentag 5               // t0 <- generated tagged (null) pointer
    li t1, 5
    slli t1, t1, 60
    bne t0, t1, fail

    //    b. the exclusion mask is WARL: at least one bit of [15:0] must
    //       remain clear,
    li t0, 0xFFFF
    csrw CSR_MMTAGEXCL0, t0
    csrr t1, CSR_MMTAGEXCL0
    li t2, 0xFFFF
    beq t1, t2, fail
    csrw CSR_MMTAGEXCL0, zero

    //    c. its tags are pseudorandom and uniformly distributed over the
    //       permitted values: with all 16 permitted, 1600 draws give
    //       each value 100 +- 50 times, and fewer than 400 draws are one
    //       above the draw before (mod 16), which a counter always is,
    la t2, tag_counts
    li t3, 1600
    li s4, 0               // draws one above the draw before
    li s5, 0               // the draw before
1:  gentag 5
    srli t4, t0, 60
    slli t5, t4, 3
    add t5, t5, t2
    ld t6, 0(t5)
    addi t6, t6, 1
    sd t6, 0(t5)
    addi t6, s5, 1
    andi t6, t6, 15
    bne t6, t4, 2f
    addi s4, s4, 1
2:  mv s5, t4
    addi t3, t3, -1
    bnez t3, 1b
    li t3, 16
3:  ld t6, 0(t2)
    addi t6, t6, -50
    li t5, 101
    bgeu t6, t5, fail      // the count of a value is not in 50..150
    addi t2, t2, 8
    addi t3, t3, -1
    bnez t3, 3b
    li t5, 400
    bgeu s4, t5, fail

    //    d. with only 0 and 15 permitted, 512 draws are each 0 or 15,
    //       with 15 in 192..320 of them (a cyclic search from a counter
    //       draws 15 for 15 of the 16 counter values),
    li t0, 0x7FFE
    csrw CSR_MMTAGEXCL0, t0
    li t3, 512
    li s4, 0               // draws of 15
1:  gentag 5
    slli t5, t0, 4
    bnez t5, fail          // only the tag bits may be set
    srli t4, t0, 60
    beqz t4, 2f
    li t5, 15
    bne t4, t5, fail
    addi s4, s4, 1
2:  addi t3, t3, -1
    bnez t3, 1b
    addi s4, s4, -192
    li t5, 129
    bgeu s4, t5, fail
    csrw CSR_MMTAGEXCL0, zero

    //    e. with 7-bit tags, if supported, and only 3 and 100 permitted,
    //       256 draws are each 3 or 100 (in bits 63:57), with 100 in
    //       80..176 of them.
    li t0, (3 << MT_MODE_SHIFT)
    csrs CSR_MSECCFG, t0
    csrr t1, CSR_MSECCFG
    srli t1, t1, MT_MODE_SHIFT
    andi t1, t1, 3
    li t2, MT_MODE_TAG7
    bne t1, t2, 3f
    li t0, ~(1 << 3)       // tag values 0-63: only 3 permitted
    csrw CSR_MMTAGEXCL0, t0
    li t0, ~(1 << 36)      // tag values 64-127: only 100 permitted
    csrw CSR_MMTAGEXCL1, t0
    li t3, 256
    li s4, 0               // draws of 100
1:  gentag 5
    slli t5, t0, 7
    bnez t5, fail          // only the tag bits may be set
    srli t4, t0, 57
    li t5, 3
    beq t4, t5, 2f
    li t5, 100
    bne t4, t5, fail
    addi s4, s4, 1
2:  addi t3, t3, -1
    bnez t3, 1b
    addi s4, s4, -80
    li t5, 97
    bgeu s4, t5, fail
    csrw CSR_MMTAGEXCL0, zero
    csrw CSR_MMTAGEXCL1, zero
3:  li t0, (3 << MT_MODE_SHIFT)
    csrc CSR_MSECCFG, t0
    li t0, (MT_MODE_TAG4 << MT_MODE_SHIFT)
    csrs CSR_MSECCFG, t0

    // ------------------------------------------------------------------
    // 4. addtag: in-place tag arithmetic in bits 63:60.
    li t0, 5
    slli t0, t0, 60
    la t2, data_buf
    or t0, t0, t2          // t0 = data_buf tagged with 5
    addtag 6, 5, 2         // t1 <- t0 with pointer_tag += 2
    li t3, 7
    slli t3, t3, 60
    or t3, t3, t2
    bne t1, t3, fail

    // ------------------------------------------------------------------
    // 5. settag/checktag round trip: tag chunk 0 of data_buf with 5;
    //    a matching checktag must not trap.
    settag 5, 0            // t0 still = data_buf tagged with 5
    checktag 5, 0

    // ------------------------------------------------------------------
    // 6. checktag with a mismatching pointer_tag must raise a
    //    software-check exception (cause 18) with xtval = 4.
    la t3, expect_swcheck
    csrr s10, mtvec
    csrw mtvec, t3
    li s9, 0               // trap-seen flag
    addtag 6, 5, 1         // t1 = data_buf tagged with 6
    mv t0, t1
    checktag 5, 0          // mismatch: must trap
    beqz s9, fail
    li s9, 0

    // ------------------------------------------------------------------
    // 7. Implicit checks (paging disabled => every data page is a
    //    tagged-data page):
    //    a. load through a matching tagged pointer succeeds,
    li t0, 5
    slli t0, t0, 60
    la t2, data_buf
    or t0, t0, t2
    ld t4, 0(t0)
    //    b. load through a mismatching pointer traps with tval = 4,
    addtag 6, 5, 3         // t1 = data_buf tagged with 8
    ld t4, 0(t1)
    beqz s9, fail
    li s9, 0
    //    c. store through a mismatching pointer traps as well,
    sd t4, 0(t1)
    beqz s9, fail
    li s9, 0
    //    d. an access via the stack pointer (x2) is never checked.
    mv s8, sp
    mv sp, t1              // sp = mismatching tagged pointer
    ld t4, 0(sp)
    mv sp, s8
    bnez s9, fail

    csrw mtvec, s10

    // ------------------------------------------------------------------
    // 8. Traps around implicit checks, recorded by record_trap (mcause
    //    in s2, mtval in s3, mtinst in s4, mstatus in s5):
    la t3, record_trap
    csrw mtvec, t3
    li s2, 0
    //    a. the tag loads of an implicit check are not matched by
    //       triggers: with an M-mode load address trigger on the tag
    //       byte of data_buf (M-mode breakpoints need mstatus.MIE = 1),
    //       a load through a matching pointer does not trap,
    la t2, data_buf
    csrr t3, CSR_MVITT
    srli t4, t2, 5
    add t3, t3, t4         // tag byte of chunk 0 of data_buf
    csrw tselect, zero
    csrw tdata2, t3
    li t3, MCONTROL6_M_LOAD
    csrw tdata1, t3
    csrsi mstatus, MSTATUS_MIE
    li t0, 5
    slli t0, t0, 60
    or t0, t0, t2          // t0 = data_buf tagged with 5
    ld t4, 0(t0)
    bnez s2, fail
    //    b. a data address breakpoint has priority over the tag check:
    //       with the trigger on data_buf, a load through a mismatching
    //       pointer takes the breakpoint.
    csrw tdata2, t2
    addtag 6, 5, 3         // t1 = data_buf tagged with 8
    ld t4, 0(t1)
    li t3, CAUSE_BREAKPOINT
    bne s2, t3, fail
    bne s3, t2, fail
    csrw tdata1, zero
    csrci mstatus, MSTATUS_MIE
    //    c. a tag load fault does not arise from the access of the
    //       instruction, so mtinst is zero, not the transformed load:
    //       with the tag table in unmapped memory, a checked load takes
    //       a load access fault on the tag address.
    csrr s7, CSR_MVITT
    li t3, UNMAPPED_TAG_TABLE
    csrw CSR_MVITT, t3
    li s2, 0
    li s4, -1
    ld t4, 0(t0)           // t0 = data_buf tagged with 5
    csrw CSR_MVITT, s7
    li t3, CAUSE_LOAD_ACCESS
    bne s2, t3, fail
    srli t3, t2, 5
    li t4, UNMAPPED_TAG_TABLE
    add t3, t3, t4         // tag byte of chunk 0 of data_buf
    bne s3, t3, fail
    bnez s4, fail
    //    d. a tag mismatch traps with GVA clear, as mtval (4) is not a
    //       guest virtual address: load through a mismatching pointer
    //       with MPRV = 1, MPV = 1 and MPP = S (effective privilege VS),
    //       with tagging enabled for VS-mode, which uses the same tag
    //       table.
    li t3, (MT_MODE_TAG4 << MT_MODE_SHIFT) | (PMM_PMLEN_7 << PMM_SHIFT)
    csrs CSR_HENVCFG, t3
    csrr t3, CSR_MVITT
    csrw CSR_VSVITTS, t3
    li s2, 0
    li t3, MSTATUS_MPP
    csrc mstatus, t3
    li t3, MSTATUS_MPRV | MSTATUS_MPV | MSTATUS_MPP_S
    csrs mstatus, t3
    ld t4, 0(t1)           // t1 = data_buf tagged with 8
    li t3, MSTATUS_MPRV
    csrc mstatus, t3
    li t3, (3 << MT_MODE_SHIFT) | (3 << PMM_SHIFT)
    csrc CSR_HENVCFG, t3
    li t3, CAUSE_SOFTWARE_CHECK
    bne s2, t3, fail
    li t3, SWCHECK_TVAL_MEM_TAG
    bne s3, t3, fail
    li t3, MSTATUS_GVA
    and t3, s5, t3
    bnez t3, fail

    csrw mtvec, s10

    // ------------------------------------------------------------------
    // 9. Disable memory tagging: gentag must fall back to Zimop
    //    behavior and zero its destination.
    li t0, (3 << MT_MODE_SHIFT)
    csrc CSR_MSECCFG, t0
    li t0, 42
    gentag 5
    bnez t0, fail

pass:
    mv ra, s11
    li a0, 0
    ret
fail:
    // Disable memory tagging so the exit path is not tag-checked.
    li t0, (3 << MT_MODE_SHIFT)
    csrc CSR_MSECCFG, t0
    mv ra, s11
    li a0, 1
    ret

// Trap handler: expect a software-check exception with tval = 4, set
// the flag in s9 and resume at mepc + 4.
.p2align 6
expect_swcheck:
    csrr t4, mcause
    li t5, CAUSE_SOFTWARE_CHECK
    bne t4, t5, fail
    csrr t4, mtval
    li t5, SWCHECK_TVAL_MEM_TAG
    bne t4, t5, fail
    li s9, 1
    csrr t4, mepc
    addi t4, t4, 4
    csrw mepc, t4
    mret

// Trap handler for section 8: record mcause in s2, mtval in s3, mtinst
// in s4 and mstatus in s5, and resume at mepc + 4.
.p2align 6
record_trap:
    csrr s2, mcause
    csrr s3, mtval
    csrr s4, CSR_MTINST
    csrr s5, mstatus
    csrr t5, mepc
    addi t5, t5, 4
    csrw mepc, t5
    mret
#else
    // Zimt is RV64-only; pass trivially on RV32.
    li a0, 0
    ret
#endif

#if __riscv_xlen == 64
.section .data
.p2align 12
tag_region:
    .fill 8192, 1, 0
data_buf:
    .fill 64, 1, 0
// Section 3c's count of each tag value; its tags, in tag_region, are 0.
tag_counts:
    .fill 128, 1, 0
#endif
