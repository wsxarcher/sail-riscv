// Self-checking test of the Zimt implicit tag checks of the regular
// accesses other than scalar loads and stores: AMOs (Zaamo, Zacas),
// LR/SC, cbo.zero and vector loads and stores. Runs in M-mode with Bare
// translation, mseccfg.MT_MODE enabled (4-bit tags) and the Smvatag tag
// table, so every data page is a tagged-data page. Section 6 checks their
// trap details: a data address breakpoint (Sdtrig) has priority over the
// tag check (Sail's load and store address triggers fire before the
// access, the timing that the Debug spec suggests; one that fires after
// it would follow the tag check), the tag loads of the check are not
// matched by triggers, a
// fault of a tag load writes 0 to mtinst, and a tag mismatch at effective
// V = 1 leaves GVA clear.
//
// NOTE: the CSR address of mvitt is a PLACEHOLDER; the draft
// specification has not allocated CSR addresses yet (see
// model/extensions/Zimt/zimt_regs.sail).

#define CSR_MSECCFG      0x747
#define CSR_MVITT        0x7C4

// A tag table base in unmapped memory.
#define UNMAPPED_TAG_TABLE 0x20000000

// mseccfg.MT_MODE: bits 35:34; mseccfg.PMM: bits 33:32.
#define MT_MODE_SHIFT    34
#define MT_MODE_TAG4     2
#define PMM_SHIFT        32
#define PMM_PMLEN_7      2

#define CSR_HENVCFG      0x60A
#define CSR_VSVITTS      0x6C2
#define CSR_MTINST       0x34A

#define MSTATUS_MIE      0x8
#define MSTATUS_VS       (3 << 9)
#define MSTATUS_MPP      (3 << 11)
#define MSTATUS_MPP_S    (1 << 11)
#define MSTATUS_MPRV     (1 << 17)
#define MSTATUS_GVA      (1 << 38)
#define MSTATUS_MPV      (1 << 39)

// mcontrol6 (type 6) triggers matching M-mode load and store addresses,
// with the breakpoint action.
#define MCONTROL6_M_LOAD  ((6 << 60) | (1 << 6) | 1)
#define MCONTROL6_M_STORE ((6 << 60) | (1 << 6) | 2)

#define CAUSE_BREAKPOINT     3
#define CAUSE_LOAD_ACCESS    5
#define CAUSE_STORE_ACCESS   7
#define CAUSE_SOFTWARE_CHECK 18
#define SWCHECK_TVAL_MEM_TAG 4

// Zimt and the instructions that the toolchain may not know are encoded
// directly. Register arguments are architectural register numbers.
.macro settag rs1, imm4
  .4byte ((0x41 << 25) | (\imm4 << 20) | (\rs1 << 15) | (0x4 << 12) | 0x73)
.endm
.macro cbo_zero rs1
  .4byte ((4 << 20) | (\rs1 << 15) | (2 << 12) | 0x0F)
.endm
// amocas.q rd, rs2, (rs1): rd and rs2 are even (register pairs).
.macro amocas_q rd, rs2, rs1
  .4byte ((0x05 << 27) | (\rs2 << 20) | (\rs1 << 15) | (0x4 << 12) | (\rd << 7) | 0x2F)
.endm
// amocas.d rd, rs2, (rs1) (Zacas) and amoadd.b rd, rs2, (rs1) (Zabha).
.macro amocas_d rd, rs2, rs1
  .4byte ((0x05 << 27) | (\rs2 << 20) | (\rs1 << 15) | (0x3 << 12) | (\rd << 7) | 0x2F)
.endm
.macro amoadd_b rd, rs2, rs1
  .4byte ((\rs2 << 20) | (\rs1 << 15) | (\rd << 7) | 0x2F)
.endm

// reg = data_buf + off with pointer tag `tag` (clobbers t6).
.macro ptr reg, off, tag
    la \reg, data_buf
    li t6, \off
    add \reg, \reg, t6
    li t6, \tag
    slli t6, t6, 60
    or \reg, \reg, t6
.endm

// Tag the chunks [off >> 4, (off >> 4) + n_m1] of data_buf with `tag`.
.macro set_tags off, tag, n_m1
    ptr t0, \off, \tag
    settag 5, \n_m1
.endm

// Accesses through the stack pointer are never checked, so these read
// and write data_buf whatever its tags. s7 holds the stack pointer.
.macro peek off
    la sp, data_buf
    ld t4, \off(sp)
    mv sp, s7
.endm
.macro poke off, reg
    la sp, data_buf
    sd \reg, \off(sp)
    mv sp, s7
.endm
// Fill the 64-byte block at data_buf + off with `val`, or check it.
.macro fill_block off, val
    li t5, \val
    la sp, data_buf
    .irp i, 0, 8, 16, 24, 32, 40, 48, 56
    sd t5, (\off + \i)(sp)
    .endr
    mv sp, s7
.endm
.macro check_block off, val
    li t5, \val
    la sp, data_buf
    .irp i, 0, 8, 16, 24, 32, 40, 48, 56
    ld t4, (\off + \i)(sp)
    bne t4, t5, fail
    .endr
    mv sp, s7
.endm

// record_trap records mcause in s2, mtval in s3, vstart in s4, mstatus in
// s6 and mtinst in s9.
.macro clear_trap
    li s2, 0
    li s3, 0
    li s4, -1
    li s6, 0
    li s9, -1
.endm
.macro expect_none
    bnez s2, fail
.endm
.macro expect_trap cause, tval, vstart
    li t6, \cause
    bne s2, t6, fail
    li t6, \tval
    bne s3, t6, fail
    li t6, \vstart
    bne s4, t6, fail
.endm
.macro expect_swcheck vstart
    expect_trap CAUSE_SOFTWARE_CHECK, SWCHECK_TVAL_MEM_TAG, \vstart
.endm
// A load access fault at the tag address of the chunk of data_buf + off,
// with the tag table at UNMAPPED_TAG_TABLE.
.macro expect_tag_fault off, vstart
    la t5, data_buf
    li t6, \off
    add t5, t5, t6
    srli t5, t5, 5
    li t6, UNMAPPED_TAG_TABLE
    add t5, t5, t6
    li t6, CAUSE_LOAD_ACCESS
    bne s2, t6, fail
    bne s3, t5, fail
    li t6, \vstart
    bne s4, t6, fail
.endm

// A breakpoint at data_buf + off, at vector element vstart.
.macro expect_breakpoint off, vstart
    li t6, CAUSE_BREAKPOINT
    bne s2, t6, fail
    la t5, data_buf
    li t6, \off
    add t5, t5, t6
    bne s3, t5, fail
    li t6, \vstart
    bne s4, t6, fail
.endm

// Run insn with MPRV = 1, MPV = 1 and MPP = S (effective privilege VS):
// it must raise a software-check exception at vector element vstart, with
// GVA = 0 (xtval = 4 is not a guest virtual address).
.macro vs_swcheck vstart, insn:vararg
    li t3, MSTATUS_MPP
    csrc mstatus, t3
    li t3, MSTATUS_MPRV | MSTATUS_MPV | MSTATUS_MPP_S
    clear_trap
    csrs mstatus, t3
    \insn
    li t3, MSTATUS_MPRV
    csrc mstatus, t3
    expect_swcheck \vstart
    li t3, MSTATUS_GVA
    and t3, s6, t3
    bnez t3, fail
.endm

// Arm trigger 0 with tdata1 = \tdata1 on the address data_buf + off, or on
// the tag byte of the chunk at data_buf + off (4-bit tags, mvitt in s8).
// Disarm it before any other access to that address.
.macro arm tdata1, off
    la t6, data_buf
    li t5, \off
    add t6, t6, t5
    csrw tdata2, t6
    li t6, \tdata1
    csrw tdata1, t6
.endm
.macro arm_tag tdata1, off
    la t6, data_buf
    li t5, \off
    add t6, t6, t5
    srli t6, t6, 5
    add t6, t6, s8
    csrw tdata2, t6
    li t6, \tdata1
    csrw tdata1, t6
.endm
.macro disarm
    csrw tdata1, zero
.endm

.global main
main:
#if __riscv_xlen == 64
    mv s11, ra
    mv s7, sp

    // ------------------------------------------------------------------
    // 1. Enable pointer masking (PMLEN=7) and memory tagging (4-bit
    //    tags) in M-mode. If MT_MODE reads back 0, Zimt is not present
    //    (e.g. experimental extensions disabled): pass trivially. The
    //    M-mode tag table puts the tags of data_buf in tag_region, as in
    //    test_zimt.S.
    li t0, (MT_MODE_TAG4 << MT_MODE_SHIFT) | (PMM_PMLEN_7 << PMM_SHIFT)
    csrs CSR_MSECCFG, t0
    csrr t1, CSR_MSECCFG
    srli t1, t1, MT_MODE_SHIFT
    andi t1, t1, 3
    li t2, MT_MODE_TAG4
    bne t1, t2, pass
    la t0, tag_region
    li t1, 4096
    add t0, t0, t1
    la t2, data_buf
    srli t2, t2, 5
    sub t0, t0, t2
    csrw CSR_MVITT, t0
    csrr s8, CSR_MVITT
    li t0, MSTATUS_VS
    csrs mstatus, t0
    la t0, record_trap
    csrr s10, mtvec
    csrw mtvec, t0

    // ------------------------------------------------------------------
    // 2. AMOs. The chunks 0-3 of data_buf have tag 5:
    set_tags 0, 5, 3
    //    a. a matching AMO is performed,
    ptr t1, 0, 5
    li t2, 3
    clear_trap
    amoadd.d t3, t2, (t1)
    expect_none
    bnez t3, fail
    peek 0
    li t5, 3
    bne t4, t5, fail
    //    b. a mismatching one raises a software-check exception (mtval =
    //       4) and writes neither memory nor rd,
    ptr t1, 0, 6
    li t3, 0x55
    clear_trap
    amoadd.d t3, t2, (t1)
    expect_swcheck 0
    li t5, 0x55
    bne t3, t5, fail
    peek 0
    li t5, 3
    bne t4, t5, fail
    //    c. an AMO through the stack pointer is not checked,
    ptr sp, 8, 6
    li t2, 9
    clear_trap
    amoswap.d t3, t2, (sp)
    mv sp, s7
    expect_none
    peek 8
    li t5, 9
    bne t4, t5, fail
    //    d. a 16-byte amocas.q (Zacas) is checked as well: mismatching, it
    //       traps although its compare would succeed; matching, it swaps,
    li a0, 3
    li a1, 9
    li a2, 0x33
    li a3, 0x99
    ptr t1, 0, 6
    clear_trap
    amocas_q 10, 12, 6
    expect_swcheck 0
    peek 0
    li t5, 3
    bne t4, t5, fail
    ptr t1, 0, 5
    clear_trap
    amocas_q 10, 12, 6
    expect_none
    peek 0
    li t5, 0x33
    bne t4, t5, fail
    peek 8
    li t5, 0x99
    bne t4, t5, fail
    //    e. with the tag table in unmapped memory, the tag load raises a
    //       load access fault at the tag address.
    li t0, UNMAPPED_TAG_TABLE
    csrw CSR_MVITT, t0
    ptr t1, 0, 5
    clear_trap
    amoadd.d t3, t2, (t1)
    csrw CSR_MVITT, s8
    expect_tag_fault 0, 0

    // ------------------------------------------------------------------
    // 3. LR/SC, on the doubleword at data_buf + 16 (chunk 1, tag 5):
    //    a. a matching pair succeeds,
    ptr t1, 16, 5
    li t2, 0x11
    clear_trap
    lr.d t3, (t1)
    sc.d t3, t2, (t1)
    expect_none
    bnez t3, fail
    peek 16
    li t5, 0x11
    bne t4, t5, fail
    //    b. a mismatching LR traps and does not write rd,
    ptr t1, 16, 6
    li t3, 0x55
    clear_trap
    lr.d t3, (t1)
    expect_swcheck 0
    li t5, 0x55
    bne t3, t5, fail
    //    c. a mismatching SC traps whether it would fail (no reservation)
    //       or succeed (after a matching LR), and writes neither memory
    //       nor rd,
    li t2, 0x22
    li t3, 0x66
    clear_trap
    sc.d t3, t2, (t1)
    expect_swcheck 0
    li t5, 0x66
    bne t3, t5, fail
    ptr t0, 16, 5
    lr.d t4, (t0)
    clear_trap
    sc.d t3, t2, (t1)
    expect_swcheck 0
    li t5, 0x66
    bne t3, t5, fail
    peek 16
    li t5, 0x11
    bne t4, t5, fail
    //    d. LR/SC through the stack pointer are not checked.
    ptr sp, 16, 6
    clear_trap
    lr.w t3, (sp)
    sc.w t3, t2, (sp)
    mv sp, s7
    expect_none
    bnez t3, fail

    // ------------------------------------------------------------------
    // 4. cbo.zero, on the 64-byte cache block at data_buf + 64 (chunks
    //    4-7, tag 5):
    set_tags 64, 5, 3
    //    a. a matching cbo.zero through a pointer into the block zeroes
    //       the whole block,
    fill_block 64, -1
    ptr t1, (64 + 20), 5
    clear_trap
    cbo_zero 6
    expect_none
    check_block 64, 0
    //    b. with chunk 6 tagged 7, it traps and zeroes no byte,
    fill_block 64, -1
    set_tags 96, 7, 0
    ptr t1, 64, 5
    clear_trap
    cbo_zero 6
    expect_swcheck 0
    check_block 64, -1
    //    c. a cbo.zero through the stack pointer is not checked,
    ptr sp, 64, 6
    clear_trap
    cbo_zero 2
    mv sp, s7
    expect_none
    check_block 64, 0
    //    d. a tag load fault is at the tag address of the first chunk of
    //       the block.
    li t0, UNMAPPED_TAG_TABLE
    csrw CSR_MVITT, t0
    ptr t1, (64 + 20), 5
    clear_trap
    cbo_zero 6
    csrw CSR_MVITT, s8
    expect_tag_fault 64, 0

    // ------------------------------------------------------------------
    // 5. Vector loads and stores check each element: the 32-bit words
    //    1-8 at data_buf + 128 are in chunk 8 (tag 5, words 1-4) and
    //    chunk 9 (tag 6, words 5-8); chunks 10 and 11 have tag 5.
    li t2, 0x0000000200000001
    poke 128, t2
    li t2, 0x0000000400000003
    poke 136, t2
    li t2, 0x0000000600000005
    poke 144, t2
    li t2, 0x0000000800000007
    poke 152, t2
    set_tags 128, 5, 3
    set_tags 144, 6, 0
    vsetivli t0, 8, e32, m2, ta, ma
    //    a. vle32.v loads elements 0-3 and traps at element 4 (vstart =
    //       4),
    vmv.v.i v2, -1
    ptr t1, 128, 5
    clear_trap
    vle32.v v2, (t1)
    expect_swcheck 4
    vmv.x.s t4, v2
    li t5, 1
    bne t4, t5, fail
    vslidedown.vi v4, v2, 3
    vmv.x.s t4, v4
    li t5, 4
    bne t4, t5, fail
    //    b. vse32.v stores elements 0-3 and traps at element 4, which it
    //       does not store,
    vid.v v4
    vadd.vi v4, v4, 10
    clear_trap
    vse32.v v4, (t1)
    expect_swcheck 4
    peek 136
    li t5, 0x0000000D0000000C
    bne t4, t5, fail
    peek 144
    li t5, 0x0000000600000005
    bne t4, t5, fail
    //    c. the fault-only-first vle32ff.v does not trap, but sets vl to
    //       4; with element 0 mismatching, it traps (vstart = 0),
    clear_trap
    vle32ff.v v2, (t1)
    expect_none
    csrr t4, vl
    li t5, 4
    bne t4, t5, fail
    vsetivli t0, 8, e32, m2, ta, ma
    ptr t1, 128, 6
    clear_trap
    vle32ff.v v2, (t1)
    expect_swcheck 0
    csrr t4, vl
    li t5, 8
    bne t4, t5, fail
    //    d. a strided load with stride 16 traps at element 1 (chunk 9),
    ptr t1, 128, 5
    li t2, 16
    vsetivli t0, 4, e32, m2, ta, ma
    clear_trap
    vlse32.v v2, (t1), t2
    expect_swcheck 1
    //    e. an indexed load with offsets 0, 8, 16, ... traps at element 2,
    vsetivli t0, 8, e32, m2, ta, ma
    vid.v v8
    vsll.vi v8, v8, 3
    clear_trap
    vluxei32.v v2, (t1), v8
    expect_swcheck 2
    //    f. masked-off elements are not accessed: with elements 0-3 active
    //       only, vle32.v does not trap,
    vmv.v.i v0, 15
    clear_trap
    vle32.v v2, (t1), v0.t
    expect_none
    //    g. an access through the stack pointer is not checked,
    ptr sp, 128, 6
    clear_trap
    vle32.v v2, (sp)
    mv sp, s7
    expect_none
    //    h. a mask load (vlm.v) is checked,
    ptr t1, 128, 6
    clear_trap
    vlm.v v2, (t1)
    expect_swcheck 0
    //    i. with the tag table in unmapped memory, a vector load raises a
    //       load access fault at the tag address of element 0,
    li t0, UNMAPPED_TAG_TABLE
    csrw CSR_MVITT, t0
    ptr t1, 128, 5
    clear_trap
    vle32.v v2, (t1)
    csrw CSR_MVITT, s8
    expect_tag_fault 128, 0
    //    j. whole-register loads and stores (VLEN >= 256 reaches chunk 9):
    //       vl1re32.v traps at element 4, vs1r.v at byte element 16.
    csrr t4, vlenb
    li t5, 32
    blt t4, t5, 1f
    ptr t1, 128, 5
    clear_trap
    vl1re32.v v2, (t1)
    expect_swcheck 4
    clear_trap
    vs1r.v v4, (t1)
    expect_swcheck 16
1:

    // ------------------------------------------------------------------
    // 6. Trap details. M-mode breakpoints need mstatus.MIE = 1.
    csrsi mstatus, MSTATUS_MIE
    csrw tselect, zero
    //    a. a data address breakpoint has priority over the tag check:
    //       through a mismatching pointer (tag 6), with a store address
    //       trigger on data_buf, amoadd.d and sc.d, and with a load
    //       address trigger on data_buf + 16, lr.d, take the breakpoint
    //       at the address, and write neither memory nor rd. The sc.d
    //       holds the reservation of an lr.d through the matching pointer
    //       (tag 5) just before it: a successful sc is a store for
    //       triggers, while the Debug spec leaves it unspecified whether a
    //       failing one is (Sail matches it too). An AMO is a load too: a
    //       load address trigger on data_buf takes amoadd.d as well; and
    //       a store address trigger amocas.d (Zacas) and amoadd.b (Zabha),
    ptr t1, 0, 6
    li t2, 3
    li t3, 0x55
    arm MCONTROL6_M_STORE, 0
    clear_trap
    amoadd.d t3, t2, (t1)
    disarm
    expect_breakpoint 0, 0
    li t5, 0x55
    bne t3, t5, fail
    ptr t4, 0, 5
    arm MCONTROL6_M_STORE, 0
    clear_trap
    lr.d t5, (t4)
    sc.d t3, t2, (t1)
    disarm
    expect_breakpoint 0, 0
    li t5, 0x55
    bne t3, t5, fail
    arm MCONTROL6_M_LOAD, 0
    clear_trap
    amoadd.d t3, t2, (t1)
    disarm
    expect_breakpoint 0, 0
    li t5, 0x55
    bne t3, t5, fail
    li a0, 3
    li a1, 0x44
    arm MCONTROL6_M_STORE, 0
    clear_trap
    amocas_d 10, 11, 6
    disarm
    expect_breakpoint 0, 0
    li t5, 3
    bne a0, t5, fail
    arm MCONTROL6_M_STORE, 0
    clear_trap
    amoadd_b 28, 7, 6
    disarm
    expect_breakpoint 0, 0
    li t5, 0x55
    bne t3, t5, fail
    peek 0
    li t5, 0x33
    bne t4, t5, fail
    ptr t1, 16, 6
    arm MCONTROL6_M_LOAD, 16
    clear_trap
    lr.d t3, (t1)
    disarm
    expect_breakpoint 16, 0
    li t5, 0x55
    bne t3, t5, fail
    //    b. so does cbo.zero of the block at data_buf + 64 (chunk 6 tagged
    //       7) with the store address trigger on the block, which it does
    //       not zero,
    fill_block 64, -1
    ptr t1, 64, 5
    arm MCONTROL6_M_STORE, 64
    clear_trap
    cbo_zero 6
    disarm
    expect_breakpoint 64, 0
    check_block 64, -1
    //    c. and element 4 (chunk 9, tag 6) of vle32.v from data_buf + 128
    //       through a pointer with tag 5, with a load address trigger on
    //       it, after elements 0-3 (vstart = 4), which it loads (v2 holds
    //       words 1-4 then, and keeps its elements 4-7); so do element 4
    //       of vse32.v with a store address trigger on it, which stores
    //       elements 0-3 only, element 1 of the strided vlse32.v (stride
    //       16), element 2 of the indexed vluxei32.v (offsets 0, 8, 16,
    //       ...), and element 0 of the fault-only-first vle32ff.v through
    //       a pointer with tag 6 (vl unchanged),
    li t2, 0x0000000200000001
    poke 128, t2
    li t2, 0x0000000400000003
    poke 136, t2
    vsetivli t0, 8, e32, m2, ta, ma
    vmv.v.i v2, -1
    ptr t1, 128, 5
    arm MCONTROL6_M_LOAD, 144
    clear_trap
    vle32.v v2, (t1)
    disarm
    expect_breakpoint 144, 4
    vmv.x.s t4, v2
    li t5, 1
    bne t4, t5, fail
    vslidedown.vi v4, v2, 3
    vmv.x.s t4, v4
    li t5, 4
    bne t4, t5, fail
    vslidedown.vi v4, v2, 4
    vmv.x.s t4, v4
    li t5, -1
    bne t4, t5, fail
    vid.v v4
    vadd.vi v4, v4, 10
    arm MCONTROL6_M_STORE, 144
    clear_trap
    vse32.v v4, (t1)
    disarm
    expect_breakpoint 144, 4
    peek 136
    li t5, 0x0000000D0000000C
    bne t4, t5, fail
    peek 144
    li t5, 0x0000000600000005
    bne t4, t5, fail
    li t2, 16
    vsetivli t0, 4, e32, m2, ta, ma
    arm MCONTROL6_M_LOAD, 144
    clear_trap
    vlse32.v v2, (t1), t2
    disarm
    expect_breakpoint 144, 1
    vsetivli t0, 8, e32, m2, ta, ma
    vid.v v8
    vsll.vi v8, v8, 3
    arm MCONTROL6_M_LOAD, 144
    clear_trap
    vluxei32.v v2, (t1), v8
    disarm
    expect_breakpoint 144, 2
    ptr t1, 128, 6
    arm MCONTROL6_M_LOAD, 128
    clear_trap
    vle32ff.v v2, (t1)
    disarm
    expect_breakpoint 128, 0
    csrr t4, vl
    li t5, 8
    bne t4, t5, fail
    //    d. the tag loads of an implicit check are not matched by
    //       triggers: with a load address trigger on the tag byte of chunk
    //       0, a matching amoadd.d is performed, and a mismatching one
    //       raises a software-check exception; with one on the tag byte of
    //       chunk 9, vle32.v raises it at element 4; and with one on the
    //       tag byte of their first chunk, a matching sd, a matching LR/SC
    //       pair (chunk 1, the same tag byte), a matching cbo.zero of the
    //       block at data_buf + 64 (tagged 5 again) and a matching vse32.v
    //       to data_buf + 160 (chunks 10 and 11) are performed,
    li t2, 1
    ptr t1, 0, 5
    arm_tag MCONTROL6_M_LOAD, 0
    clear_trap
    amoadd.d t3, t2, (t1)
    expect_none
    ptr t1, 0, 6
    clear_trap
    amoadd.d t3, t2, (t1)
    disarm
    expect_swcheck 0
    peek 0
    li t5, 0x34
    bne t4, t5, fail
    ptr t1, 128, 5
    arm_tag MCONTROL6_M_LOAD, 144
    clear_trap
    vle32.v v2, (t1)
    disarm
    expect_swcheck 4
    ptr t1, 0, 5
    li t2, 0x77
    arm_tag MCONTROL6_M_LOAD, 0
    clear_trap
    sd t2, 0(t1)
    expect_none
    ptr t1, 16, 5
    clear_trap
    lr.d t3, (t1)
    sc.d t3, t2, (t1)
    disarm
    expect_none
    bnez t3, fail
    peek 0
    li t5, 0x77
    bne t4, t5, fail
    peek 16
    li t5, 0x77
    bne t4, t5, fail
    set_tags 64, 5, 3
    fill_block 64, -1
    ptr t1, 64, 5
    arm_tag MCONTROL6_M_LOAD, 64
    clear_trap
    cbo_zero 6
    disarm
    expect_none
    check_block 64, 0
    vsetivli t0, 8, e32, m2, ta, ma
    vid.v v4
    ptr t1, 160, 5
    arm_tag MCONTROL6_M_LOAD, 160
    clear_trap
    vse32.v v4, (t1)
    disarm
    expect_none
    peek 160
    li t5, 0x0000000100000000
    bne t4, t5, fail
    peek 184
    li t5, 0x0000000700000006
    bne t4, t5, fail
    csrci mstatus, MSTATUS_MIE
    //    e. a fault of a tag load does not arise from the access of the
    //       instruction, so it writes 0 to mtinst, not the transformed
    //       instruction: with the tag table in unmapped memory, amoadd.d,
    //       lr.d, sc.d, cbo.zero, vle32.v and vse32.v take a load access
    //       fault at the tag address with mtinst = 0; with memory tagging
    //       disabled, amoadd.d to that unmapped memory takes its own
    //       store/AMO access fault, which writes the transformed amoadd.d,
    li t0, UNMAPPED_TAG_TABLE
    csrw CSR_MVITT, t0
    ptr t1, 0, 5
    clear_trap
    amoadd.d t3, t2, (t1)
    csrw CSR_MVITT, s8
    expect_tag_fault 0, 0
    bnez s9, fail
    li t0, UNMAPPED_TAG_TABLE
    csrw CSR_MVITT, t0
    ptr t1, 16, 5
    clear_trap
    lr.d t3, (t1)
    csrw CSR_MVITT, s8
    expect_tag_fault 16, 0
    bnez s9, fail
    li t0, UNMAPPED_TAG_TABLE
    csrw CSR_MVITT, t0
    clear_trap
    sc.d t3, t2, (t1)
    csrw CSR_MVITT, s8
    expect_tag_fault 16, 0
    bnez s9, fail
    li t0, UNMAPPED_TAG_TABLE
    csrw CSR_MVITT, t0
    ptr t1, (64 + 20), 5
    clear_trap
    cbo_zero 6
    csrw CSR_MVITT, s8
    expect_tag_fault 64, 0
    bnez s9, fail
    li t0, UNMAPPED_TAG_TABLE
    csrw CSR_MVITT, t0
    vsetivli t0, 8, e32, m2, ta, ma
    ptr t1, 128, 5
    clear_trap
    vle32.v v2, (t1)
    csrw CSR_MVITT, s8
    expect_tag_fault 128, 0
    bnez s9, fail
    li t0, UNMAPPED_TAG_TABLE
    csrw CSR_MVITT, t0
    clear_trap
    vse32.v v4, (t1)
    csrw CSR_MVITT, s8
    expect_tag_fault 128, 0
    bnez s9, fail
    li t0, (3 << MT_MODE_SHIFT)
    csrc CSR_MSECCFG, t0
    li t1, UNMAPPED_TAG_TABLE
    clear_trap
    amoadd.d t3, t2, (t1)
    li t0, (MT_MODE_TAG4 << MT_MODE_SHIFT)
    csrs CSR_MSECCFG, t0
    li t6, CAUSE_STORE_ACCESS
    bne s2, t6, fail
    li t6, UNMAPPED_TAG_TABLE
    bne s3, t6, fail
    beqz s9, fail
    //    f. a tag mismatch at effective V = 1 leaves GVA clear, as mtval
    //       (4) is not a guest virtual address: amoadd.d of chunk 0 and
    //       vle32.v of chunk 9, and lr.d and sc.d of chunk 1, cbo.zero of
    //       the block at data_buf + 64 and vse32.v of chunk 9, through a
    //       mismatching pointer with MPRV = 1, MPV = 1 and MPP = S
    //       (effective privilege VS, Bare translation), with tagging
    //       enabled for VS-mode, which uses the same tag table.
    li t3, (MT_MODE_TAG4 << MT_MODE_SHIFT) | (PMM_PMLEN_7 << PMM_SHIFT)
    csrs CSR_HENVCFG, t3
    csrw CSR_VSVITTS, s8
    ptr t1, 0, 6
    li t3, MSTATUS_MPP
    csrc mstatus, t3
    li t3, MSTATUS_MPRV | MSTATUS_MPV | MSTATUS_MPP_S
    clear_trap
    csrs mstatus, t3
    amoadd.d t5, t2, (t1)
    li t3, MSTATUS_MPRV
    csrc mstatus, t3
    expect_swcheck 0
    li t3, MSTATUS_GVA
    and t3, s6, t3
    bnez t3, fail
    ptr t1, 144, 5
    li t3, MSTATUS_MPP
    csrc mstatus, t3
    li t3, MSTATUS_MPRV | MSTATUS_MPV | MSTATUS_MPP_S
    clear_trap
    csrs mstatus, t3
    vle32.v v2, (t1)
    li t3, MSTATUS_MPRV
    csrc mstatus, t3
    expect_swcheck 0
    li t3, MSTATUS_GVA
    and t3, s6, t3
    bnez t3, fail
    vsetivli t0, 8, e32, m2, ta, ma
    vs_swcheck 0, vse32.v v4, (t1)
    ptr t1, 16, 6
    vs_swcheck 0, lr.d t5, (t1)
    vs_swcheck 0, sc.d t5, t2, (t1)
    ptr t1, 64, 6
    vs_swcheck 0, cbo_zero 6
    li t3, (3 << MT_MODE_SHIFT) | (3 << PMM_SHIFT)
    csrc CSR_HENVCFG, t3
    csrw CSR_VSVITTS, zero
    csrw mtvec, s10

pass:
    // Disable memory tagging so the exit path is not tag-checked.
    li t0, (3 << MT_MODE_SHIFT) | (3 << PMM_SHIFT)
    csrc CSR_MSECCFG, t0
    mv ra, s11
    li a0, 0
    ret
fail:
    li t0, (3 << MT_MODE_SHIFT) | (3 << PMM_SHIFT)
    csrc CSR_MSECCFG, t0
    csrw mtvec, s10
    mv sp, s7
    mv ra, s11
    li a0, 1
    ret

// Trap handler: record mcause in s2, mtval in s3, vstart in s4, mstatus in
// s6 and mtinst in s9, clear vstart and resume at mepc + 4.
.p2align 6
record_trap:
    csrr s2, mcause
    csrr s3, mtval
    csrr s4, vstart
    csrr s6, mstatus
    csrr s9, CSR_MTINST
    csrw vstart, zero
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
.p2align 6
data_buf:
    .fill 256, 1, 0
#endif
