// With Zicfilp and Zicfiss not supported (see zimt_no_cfi.json), Zimt is
// the only extension that raises software-check exceptions, so their
// exception code (18) must still be a legal value of mcause, scause and
// vscause.

#define CSR_MSECCFG          0x747
#define CSR_VSCAUSE          0x242

// mseccfg.MT_MODE: bits 35:34.
#define MT_MODE_SHIFT        34
#define MT_MODE_TAG4         2

#define CAUSE_SOFTWARE_CHECK 18

.global main
main:
#if __riscv_xlen == 64
    // If MT_MODE does not hold 0b10, Zimt is not present (e.g.
    // experimental extensions disabled): pass trivially.
    li t0, (MT_MODE_TAG4 << MT_MODE_SHIFT)
    csrs CSR_MSECCFG, t0
    csrr t1, CSR_MSECCFG
    csrc CSR_MSECCFG, t0
    srli t1, t1, MT_MODE_SHIFT
    andi t1, t1, 3
    li t2, MT_MODE_TAG4
    bne t1, t2, pass

    li t0, CAUSE_SOFTWARE_CHECK
    csrw mcause, t0
    csrr t1, mcause
    bne t0, t1, fail
    csrw scause, t0
    csrr t1, scause
    bne t0, t1, fail
    csrw CSR_VSCAUSE, t0
    csrr t1, CSR_VSCAUSE
    bne t0, t1, fail
#endif
pass:
    li a0, 0
    ret
fail:
    li a0, 1
    ret
