// Self-checking test for the faults and triggers of the Zimt settag
// instruction (v0.2, DRAFT): its store tag operations, including the read
// of a 4-bit tag's read-modify-write, are checked as stores and raise
// store/AMO faults; tag memory must be readable, writable and idempotent;
// and the read-modify-write is matched by triggers like an AMO: store
// address triggers before it, store data triggers after it, and no load
// triggers. Runs in M-mode with mseccfg.MT_MODE enabled around each
// settag and the Smvatag tag table; in sections 4, 5, 7 and 9 the tag
// accesses are translated with Sv39 through MPRV (MPP = S). The
// zimt_settag.json override adds a write-only memory region.
//
// NOTE: the CSR address of mvitt is a PLACEHOLDER; the draft
// specification has not allocated CSR addresses yet (see
// model/extensions/Zimt/zimt_regs.sail).

#define CSR_MSECCFG      0x747
#define CSR_MENVCFG      0x30A
#define CSR_MVITT        0x7C4

// A tag table base in unmapped memory.
#define UNMAPPED_TAG_TABLE 0x20000000

// mseccfg.MT_MODE: bits 35:34; mseccfg.PMM and menvcfg.PMM: bits 33:32.
#define MT_MODE_SHIFT    34
#define MT_MODE_TAG4     2
#define PMM_SHIFT        32
#define PMM_PMLEN_7      2
#define MENVCFG_PBMTE    (1 << 62)

#define CAUSE_BREAKPOINT       3
#define CAUSE_STORE_ACCESS     7
#define CAUSE_STORE_PAGE_FAULT 15

// The write-only memory region of zimt_settag.json.
#define WRITE_ONLY_REGION 0x70000000

// mseccfg.MT_MODE with 7-bit tags.
#define MT_MODE_TAG7     3

// menvcfg.ADUE: hardware updating of PTE A/D bits (Svadu).
#define MENVCFG_ADUE     (1 << 61)

// Sdtrig trigger CSRs, and the fields of an mcontrol6 trigger that
// matches in M-mode and raises a breakpoint exception (action 0).
#define CSR_TSELECT      0x7A0
#define CSR_TDATA1       0x7A1
#define CSR_TDATA2       0x7A2
#define MCONTROL6        ((6 << 60) | (1 << 6))
#define MCONTROL6_LOAD   (MCONTROL6 | 1)
#define MCONTROL6_STORE  (MCONTROL6 | 2)
// Store data, 8 bits (select = data, size = 8-bit).
#define MCONTROL6_STORE_DATA8 (MCONTROL6_STORE | (1 << 21) | (1 << 16))
#define MSTATUS_MIE      (1 << 3)

#define MSTATUS_MPP      (3 << 11)
#define MSTATUS_MPP_S    (1 << 11)
#define MSTATUS_MPRV     (1 << 17)

// Sv39 gigapages of the root table: VA 0x80000000 (index 2) maps the
// test image, VA 0xC0000000 (index 3) maps it again as IO memory
// (Svpbmt), VA 0x100000000 (index 4) is invalid, and VA 0x140000000
// (index 5) maps the image again with D = 0.
#define SATP_SV39        (8 << 60)
#define PTE_RW_ADV       0xC7          // D, A, W, R, V
#define PTE_RW_AV        0x47          // A, W, R, V
#define PTE_RWX_ADV      0xCF          // D, A, X, W, R, V
#define PTE_D            0x80
#define PBMT_IO          (2 << 61)
#define IMAGE_BASE       0x80000000
#define IO_ALIAS         0xC0000000
#define INVALID_VA       0x100000000
#define CLEAN_ALIAS      0x140000000

// settag is encoded directly (Zimop MOP.RR.0, SYSTEM opcode, funct3 100)
// since toolchains do not support Zimt yet. rs1 is a register number.
.macro settag rs1, imm4
  .4byte ((0x41 << 25) | (\imm4 << 20) | (\rs1 << 15) | (0x4 << 12) | 0x73)
.endm

// settag of x5 (t0) with chunk count 0, with memory tagging enabled in
// M-mode only around it (4-bit tags, or mt_mode): the other loads and
// stores are not tag checked.
.macro settag_t0 mt_mode=MT_MODE_TAG4
  li t6, (\mt_mode << MT_MODE_SHIFT)
  csrs CSR_MSECCFG, t6
  settag 5, 0
  csrc CSR_MSECCFG, t6
.endm

// Arm trigger 0 with tdata1 = \tdata1 and tdata2 = the address or data in
// \tdata2_reg, and set mstatus.MIE: an M-mode breakpoint only matches
// while MIE = 1 (no interrupt is enabled in mie).
.macro arm_trigger tdata1, tdata2_reg
  csrw CSR_TSELECT, zero
  csrw CSR_TDATA1, zero
  csrw CSR_TDATA2, \tdata2_reg
  li t5, \tdata1
  csrw CSR_TDATA1, t5
  csrsi mstatus, MSTATUS_MIE
.endm

.macro disarm_trigger
  csrci mstatus, MSTATUS_MIE
  csrw CSR_TDATA1, zero
.endm

.global main
main:
#if __riscv_xlen == 64
    mv s11, ra

    // ------------------------------------------------------------------
    // 1. Enable pointer masking (PMLEN=7) in M-mode and check that
    //    MT_MODE holds 4-bit tags. If it does not, Zimt is not present
    //    (e.g. experimental extensions disabled): pass trivially.
    li t0, (PMM_PMLEN_7 << PMM_SHIFT)
    csrs CSR_MSECCFG, t0
    li t0, (MT_MODE_TAG4 << MT_MODE_SHIFT)
    csrs CSR_MSECCFG, t0
    csrr t1, CSR_MSECCFG
    csrc CSR_MSECCFG, t0
    srli t1, t1, MT_MODE_SHIFT
    andi t1, t1, 3
    li t2, MT_MODE_TAG4
    bne t1, t2, pass

    la t3, record_trap
    csrr s10, mtvec
    csrw mtvec, t3

    // t0 = pointer with the 4-bit tag 5 to chunk 1, whose tag is the
    // upper half of tag byte 0, so settag reads that byte first.
    li t0, (5 << 60) | 0x10

    // ------------------------------------------------------------------
    // 2. The read-modify-write keeps the other half of the byte.
    la t1, tag_region
    csrw CSR_MVITT, t1
    li t2, 0x3c
    sb t2, 0(t1)
    li s2, 0
    settag_t0
    bnez s2, fail
    lbu t2, 0(t1)
    li t3, 0x5c
    bne t2, t3, fail

    // ------------------------------------------------------------------
    // 3. A tag byte in unmapped memory: store/AMO access fault on the
    //    tag address, not a load access fault from the read.
    li t3, UNMAPPED_TAG_TABLE
    csrw CSR_MVITT, t3
    li s2, 0
    settag_t0
    li t3, CAUSE_STORE_ACCESS
    bne s2, t3, fail
    li t3, UNMAPPED_TAG_TABLE
    bne s3, t3, fail

    // ------------------------------------------------------------------
    // 4. Sv39 with MPRV (MPP = S), pointer masking for S-mode and
    //    Svpbmt: a tag byte in an invalid page raises a store page fault
    //    on the tag address, not a load page fault from the read.
    la t3, root_table
    li t4, ((IMAGE_BASE >> 12) << 10) | PTE_RWX_ADV
    sd t4, 2 * 8(t3)
    li t4, PBMT_IO | ((IMAGE_BASE >> 12) << 10) | PTE_RW_ADV
    sd t4, 3 * 8(t3)
    srli t3, t3, 12
    li t4, SATP_SV39
    or t3, t3, t4
    csrw satp, t3
    sfence.vma
    li t3, MENVCFG_PBMTE | (PMM_PMLEN_7 << PMM_SHIFT)
    csrs CSR_MENVCFG, t3
    li t3, INVALID_VA
    csrw CSR_MVITT, t3
    li t3, MSTATUS_MPP
    csrc mstatus, t3
    li t3, MSTATUS_MPRV | MSTATUS_MPP_S
    csrs mstatus, t3
    li s2, 0
    settag_t0
    li t3, CAUSE_STORE_PAGE_FAULT
    bne s2, t3, fail
    li t3, INVALID_VA
    bne s3, t3, fail

    // ------------------------------------------------------------------
    // 5. A tag table in non-idempotent memory, the IO alias of the image:
    //    store/AMO access fault on the tag address, and the tag byte,
    //    tag_region + 0 through the alias, keeps its value. The trap
    //    left MPP = U, so set it to S again.
    li t3, IO_ALIAS - IMAGE_BASE
    la t4, tag_region
    add t3, t3, t4
    csrw CSR_MVITT, t3
    li t4, MSTATUS_MPP
    csrc mstatus, t4
    li t4, MSTATUS_MPP_S
    csrs mstatus, t4
    li t0, (6 << 60) | 0x10
    li s2, 0
    settag_t0
    li t4, MSTATUS_MPRV
    csrc mstatus, t4
    li t4, CAUSE_STORE_ACCESS
    bne s2, t4, fail
    bne s3, t3, fail
    lbu t2, 0(t1)
    li t3, 0x5c
    bne t2, t3, fail

    // ------------------------------------------------------------------
    // 6. Tag storage must be readable: a tag table in write-only memory
    //    raises a store/AMO access fault on the tag address with 4-bit
    //    tags (chunk 1: byte 0) and 7-bit tags (chunk 1: byte 1).
    li t3, WRITE_ONLY_REGION
    csrw CSR_MVITT, t3
    li s2, 0
    settag_t0
    li t4, CAUSE_STORE_ACCESS
    bne s2, t4, fail
    bne s3, t3, fail
    li t0, (0x5a << 57) | 0x10
    li s2, 0
    settag_t0 MT_MODE_TAG7
    bne s2, t4, fail
    addi t3, t3, 1
    bne s3, t3, fail

    // ------------------------------------------------------------------
    // 7. A store address trigger on the tag byte takes priority over the
    //    store page fault of a 4-bit settag (tag byte in the invalid
    //    page, MPRV with MPP = S): breakpoint exception on the tag
    //    address.
    li t0, (5 << 60) | 0x10
    li t3, INVALID_VA
    csrw CSR_MVITT, t3
    arm_trigger MCONTROL6_STORE, t3
    li t4, MSTATUS_MPP
    csrc mstatus, t4
    li t4, MSTATUS_MPRV | MSTATUS_MPP_S
    csrs mstatus, t4
    li s2, 0
    settag_t0
    li t4, MSTATUS_MPRV
    csrc mstatus, t4
    disarm_trigger
    li t4, CAUSE_BREAKPOINT
    bne s2, t4, fail
    bne s3, t3, fail

    // ------------------------------------------------------------------
    // 8. The read of a 4-bit settag is not matched by load triggers: a
    //    load address trigger on the tag byte does not fire, and the
    //    upper half of the byte becomes the tag.
    li t0, (5 << 60) | 0x10
    csrw CSR_MVITT, t1
    li t2, 0x3c
    sb t2, 0(t1)
    arm_trigger MCONTROL6_LOAD, t1
    li s2, 0
    settag_t0
    disarm_trigger
    bnez s2, fail
    lbu t2, 0(t1)
    li t3, 0x5c
    bne t2, t3, fail

    // ------------------------------------------------------------------
    // 9. With Svadu, a store address trigger on the tag byte of a 4-bit
    //    settag fires before any PTE update: in the clean alias of the
    //    image (D = 0), D stays 0. Without the trigger, settag sets it.
    li t0, (5 << 60) | 0x10
    la t3, root_table
    li t4, ((IMAGE_BASE >> 12) << 10) | PTE_RW_AV
    sd t4, 5 * 8(t3)
    sfence.vma
    li t4, MENVCFG_ADUE
    csrs CSR_MENVCFG, t4
    li t3, CLEAN_ALIAS - IMAGE_BASE
    add t3, t3, t1
    csrw CSR_MVITT, t3
    arm_trigger MCONTROL6_STORE, t3
    li t4, MSTATUS_MPP
    csrc mstatus, t4
    li t4, MSTATUS_MPRV | MSTATUS_MPP_S
    csrs mstatus, t4
    li s2, 0
    settag_t0
    li t4, MSTATUS_MPRV
    csrc mstatus, t4
    disarm_trigger
    li t4, CAUSE_BREAKPOINT
    bne s2, t4, fail
    bne s3, t3, fail
    la t4, root_table
    ld t4, 5 * 8(t4)
    andi t4, t4, PTE_D
    bnez t4, fail
    li t4, MSTATUS_MPP
    csrc mstatus, t4
    li t4, MSTATUS_MPRV | MSTATUS_MPP_S
    csrs mstatus, t4
    li s2, 0
    settag_t0
    li t4, MSTATUS_MPRV
    csrc mstatus, t4
    bnez s2, fail
    la t4, root_table
    ld t4, 5 * 8(t4)
    andi t4, t4, PTE_D
    beqz t4, fail

    // ------------------------------------------------------------------
    // 10. A store data trigger on the byte that a 4-bit settag writes
    //    fires after the settag, as for an AMO: the tag is stored and
    //    mepc is the next instruction, which the trap handler skips.
    li t0, (5 << 60) | 0x10
    csrw CSR_MVITT, t1
    li t2, 0x3c
    sb t2, 0(t1)
    li t3, 0x5c
    arm_trigger MCONTROL6_STORE_DATA8, t3
    li s2, 0
    li s4, 0
    li t6, (MT_MODE_TAG4 << MT_MODE_SHIFT)
    csrs CSR_MSECCFG, t6
    settag 5, 0
after_settag:
    // A 4-byte nop, which the trap handler skips.
    .option push
    .option norvc
    nop
    .option pop
    csrc CSR_MSECCFG, t6
    disarm_trigger
    li t4, CAUSE_BREAKPOINT
    bne s2, t4, fail
    la t4, after_settag
    bne s4, t4, fail
    lbu t2, 0(t1)
    bne t2, t3, fail

    call cleanup

pass:
    mv ra, s11
    li a0, 0
    ret
fail:
    call cleanup
    mv ra, s11
    li a0, 1
    ret

// Leave translation, MPRV, memory tagging and the trigger off for the
// exit path.
cleanup:
    csrci mstatus, MSTATUS_MIE
    csrw CSR_TSELECT, zero
    csrw CSR_TDATA1, zero
    li t3, MSTATUS_MPRV
    csrc mstatus, t3
    csrw satp, zero
    sfence.vma
    csrw CSR_MENVCFG, zero
    li t3, (3 << MT_MODE_SHIFT)
    csrc CSR_MSECCFG, t3
    csrw mtvec, s10
    ret

// Trap handler: record mcause in s2, mtval in s3 and mepc in s4, and
// resume at mepc + 4. It only accesses CSRs.
.p2align 6
record_trap:
    csrr s2, mcause
    csrr s3, mtval
    csrr s4, mepc
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
root_table:
    .fill 4096, 1, 0
tag_region:
    .fill 64, 1, 0
#endif
