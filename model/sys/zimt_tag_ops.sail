// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Tag load/store operations for the Zimt memory tagging extension and
// the Svatag/Smvatag virtually-indexed tag table (v0.2, DRAFT).
//
// A memory chunk is 16 bytes; the tag of the chunk containing virtual
// address va lives at
//   mc_tag_va = VITT_BASE + (((va >> 4) * mc_tag_width) >> 3)
// i.e. two 4-bit tags packed per byte, or one 8-bit tag per byte.
// Tag loads/stores flow through vmem_read_addr/vmem_write_addr with
// the Tag payload (the read-modify-write of a 4-bit tag through
// vmem_read_tag_rmw/vmem_write_tag_rmw), so page faults and access
// faults on the tag table are reported against the tag virtual address
// as required. They are single bytes, so they never raise
// address-misaligned exceptions: "such operations must not raise
// misaligned exception" (the resolution of riscv-memory-tagging issue
// #60; the settag exceptions text that allows one without misaligned
// support predates it).

// Software-check exception for a tag mismatch, xtval = 4. xtval does not
// hold a guest virtual address, so GVA is clear, except for HLV*/HSV*
// (`is_hlsv`): their tag mismatches set GVA as required by Zimt.
function make_mem_tag_exception(is_hlsv : bool) -> ExceptionContext =
  make_exception_context(E_Software_Check(), zero_extend(software_check_cause(SWC_MEM_TAG_FAULT)),
                         is_hlsv, None())

// Extract pointer_tag from the masked bits [xlen-1 .. xlen-w] of a pointer.
function extract_pointer_tag(ptr : xlenbits, w : zimt_tag_width) -> bits(7) = {
  let 'w = w;
  zero_extend(ptr[xlen - 1 .. xlen - w])
}

// Insert pointer_tag into bits [xlen-1 .. xlen-w] of a pointer.
function insert_pointer_tag(ptr : xlenbits, tag : bits(7), w : zimt_tag_width) -> xlenbits = {
  let 'w = w;
  [ptr with (xlen - 1) .. (xlen - w) = tag[w - 1 .. 0]]
}

// The mc_tag stored for / compared against pointer_tag `tag`:
// mc_tag_width is 4 for 4-bit pointer tags and 8 for 7-bit ones.
function mc_tag_of_pointer_tag(tag : bits(7), mode : MemTaggingMode) -> bits(8) =
  match mode {
    MT_MODE_Tag4 => zero_extend(tag[3 .. 0]),
    _            => zero_extend(tag),
  }

// Virtual address of the tag-table byte holding the mc_tag of the
// chunk with index `chunk` (= va >> 4), and whether it occupies the
// upper nibble of that byte (mc_tag_width = 4 only).
function zimt_tag_byte_addr(vitt : xlenbits, chunk : xlenbits, mode : MemTaggingMode) -> (xlenbits, bool) =
  match mode {
    MT_MODE_Tag4 => (vitt + (chunk >> 1), chunk[0] == bitone),
    _            => (vitt + chunk, false),
  }

// The index of the chunk `i` chunks after the chunk containing virtual
// address va. Chunk indexes are va >> 4, so like the addresses they wrap
// around from the last chunk of the address space to chunk 0.
function zimt_chunk(va : xlenbits, i : nat) -> xlenbits = (va + to_bits_truncate(xlen, 16 * i)) >> 4

// Perform a "load tag" operation for one memory chunk, with the
// translation context of `access_info`. The tag loads of the implicit
// check of a regular load/store (`implicit`) are implicit accesses that
// are not matched by triggers.
function zimt_load_mc_tag(vitt : xlenbits, chunk : xlenbits, mode : MemTaggingMode,
                          access_info : AccessInfo, implicit : bool)
  -> result(bits(8), ExecutionResult) = {
  let (tag_va, upper_nibble) = zimt_tag_byte_addr(vitt, chunk, mode);
  let loaded : result(bits(8), ExecutionResult) =
    if implicit then vmem_read_implicit_tag(Virtaddr(tag_va), access_info)
    else vmem_read_addr(Virtaddr(tag_va), 1, Load(Tag), access_info, false, false, false);
  match loaded {
    Err(e) => Err(e),
    Ok(byte) => Ok(match mode {
      MT_MODE_Tag4 => if upper_nibble then zero_extend(byte[7 .. 4]) else zero_extend(byte[3 .. 0]),
      _            => byte,
    }),
  }
}

// Perform a "store tag" operation for one memory chunk. For
// mc_tag_width = 4 this is a read-modify-write of the shared byte;
// the spec provides no atomicity guarantee for settag. The read is part
// of the store tag operation, so it is checked like the write (address
// translation, PMP and PMA as a Store(Tag) access) and raises store/AMO
// faults: "settag can raise store page fault or access fault depending
// on how tag storage is organized." Like an AMO, the read-modify-write
// is matched by triggers as a whole: store address triggers before it,
// so that they take priority over its exceptions and precede its PTE
// A/D updates, and store data triggers on the byte written, after it.
// The read is not matched by load triggers, so the triggers that
// settag matches do not depend on mc_tag_width.
function zimt_store_mc_tag(vitt : xlenbits, chunk : xlenbits, mc_tag : bits(8), mode : MemTaggingMode)
  -> result(unit, ExecutionResult) = {
  let (tag_va, upper_nibble) = zimt_tag_byte_addr(vitt, chunk, mode);
  let access_info = default_access_info(Store(Tag));
  match mode {
    MT_MODE_Tag4 => {
      match match_memory_trigger_before(cur_privilege, TriggerAddress(TriggerAddress_Store, tag_va, 1), access_is_gva(access_info)) {
        Some(pti) => return Err(PendingTrigger(pti)),
        None()    => (),
      };
      let byte : bits(8) = match vmem_read_tag_rmw(Virtaddr(tag_va), access_info) {
        Err(e) => return Err(e),
        Ok(b)  => b,
      };
      let value : bits(8) = if upper_nibble then [byte with 7 .. 4 = mc_tag[3 .. 0]]
                            else [byte with 3 .. 0 = mc_tag[3 .. 0]];
      match vmem_write_tag_rmw(Virtaddr(tag_va), value, access_info) {
        Err(e) => return Err(e),
        Ok(()) => (),
      };
      match_memory_trigger_after(cur_privilege, TriggerStore(tag_va, value, 1), access_is_gva(access_info));
      Ok(())
    },
    _ => match vmem_write_addr(Virtaddr(tag_va), 1, mc_tag, Store(Tag), access_info, false, false, false) {
      Err(e) => Err(e),
      Ok(_)  => Ok(()),
    },
  }
}

// A transformed instruction in mtinst/htinst may only describe an
// exception that arises from the explicit memory access of the trapping
// instruction, so a fault of a tag load writes zero there instead
// (unless it already carries a pseudoinstruction value).
function without_transformed_instruction(e : ExecutionResult) -> ExecutionResult =
  match e {
    Trap(priv, ctx, pc) => match ctx.excinst {
      None()  => Trap(priv, { ctx with excinst = Some(zeros()) }, pc),
      Some(_) => e,
    },
    _ => e,
  }

// Check the tags of the chunks that the bytes first .. last overlap
// against `expected`, in increasing address order; returns None() on
// success, or the resulting trap. The tag loads have the translation
// context of the checked access.
function zimt_check_chunks(
  vitt : xlenbits,
  first : xlenbits,
  last : xlenbits,
  expected : bits(8),
  mode : MemTaggingMode,
  access_info : AccessInfo,
) -> option(ExecutionResult) = {
  // The number of chunks after the first one (the bytes may wrap around
  // the end of the address space).
  let nchunks = unsigned((last - [first with 3 .. 0 = zeros()]) >> 4);
  foreach (i from 0 to nchunks) {
    match zimt_load_mc_tag(vitt, zimt_chunk(first, i), mode, access_info, true) {
      Err(e) => return Some(without_transformed_instruction(e)),
      Ok(mc_tag) => if mc_tag != expected then return Some(trap(make_mem_tag_exception(access_info.as_guest))),
    }
  };
  None()
}

// Record whether the instruction being fetched comes from a
// tagcheck-exempt code page, given the result of the translation of one
// of its granules (the first one first).
function zimt_record_fetch(first_granule : bool, ext : ext_ptw) -> unit = {
  let exempt = ext.first_stage_leaf & ext.pte_mtag & ext.pte_x;
  zimt_code_exempt = exempt & (first_granule | zimt_code_exempt)
}

// An instruction whose fetch translation (of either granule) fails was
// not fetched from a tagcheck-exempt code page. Its fetch guest-page
// fault for an implicit access of the VS-stage walk writes a nonzero
// pseudoinstruction to xtinst, which deposits zimt_code_exempt in
// MTAG_I, so it must not keep the value of the previous instruction.
function zimt_fetch_fault() -> unit = zimt_code_exempt = false

// The MemTaggingMode of the implicit tag checks of a regular access
// ("xMT_MODE source"): that of its effective privilege, except for
// HLV*/HSV* executed in HU-mode with effective privilege VU ("Execution
// environment HU and effective privilege VU : hstatus.VUMT_MODE"; from
// HS-mode, and M-mode, VU uses senvcfg.MT_MODE and VS henvcfg.MT_MODE,
// as get_mt_mode does). "If MPRV=1 and mstatus.MTAG_I is set, then load
// and store instructions generate unchecked accesses", and "If
// hstatus.MTAG_I is set, then HLV*/HSV* instructions do not generate
// checked accesses" (MPRV does not affect HLV*/HSV*).
function zimt_access_mt_mode(access_info : AccessInfo) -> MemTaggingMode = {
  let eff_priv = access_info.eff_privilege;
  if access_info.as_guest then {
    if hstatus[MTAG_I] == 0b1 then return MT_MODE_Disabled;
    if eff_priv == VirtualUser & cur_privilege == User then {
      if not(currentlyEnabled(Ext_Zimt)) then return MT_MODE_Disabled;
      return mt_mode(hstatus[VUMT_MODE])
    };
    return get_mt_mode(eff_priv)
  };
  if mstatus[MPRV] == 0b1 & mstatus[MTAG_I] == 0b1 then return MT_MODE_Disabled;
  get_mt_mode(eff_priv)
}

// A user page accessed with a supervisor effective privilege:
// "Supervisor accesses to user pages do not generate checked accesses
// and if memory tagging is enabled for user mode then MTAG bit in first
// stage page tables is ignored."
function zimt_supervisor_to_user(page : ext_ptw, eff_priv : Privilege) -> bool =
  (eff_priv == Supervisor | eff_priv == VirtualSupervisor) & page.pte_u

// A tagged-data page: "a page translated using page tables with MTAG
// bit set and execute permission bit clear in first stage page tables",
// unless its MTAG bit is ignored.
function zimt_tagged_data_page(page : ext_ptw, eff_priv : Privilege) -> bool =
  page.first_stage_leaf & page.pte_mtag & not(page.pte_x) & not(zimt_supervisor_to_user(page, eff_priv))

// ---------------------------------------------------------------------
// Implicit tag checks on regular loads/stores.
//
// When memory tagging is active for a regular Data load/store (scalar
// integer and floating-point loads and stores, and HLV*/HSV*;
// zimt_access_mt_mode gives its MT_MODE), it is checked unless it is
// performed via the stack pointer (x2) or by an instruction from a
// tagcheck-exempt code page ("Instructions fetched from tagcheck-exempt
// code page always generate unchecked memory accesses"), as follows:
//
// * If its first-stage address translation (satp, or vsatp for VS/VU,
//   at its effective privilege) is Bare, every data page is a
//   tagged-data page ("If paging is disabled and memory tagging is
//   enabled for execution environment, then all data pages are
//   tagged-data page"), so all its chunks are checked. The G stage does
//   not count: a VS/VU access with vsatp = Bare is checked whatever
//   hgatp is, and the G stage translates its tag loads, which can then
//   raise load guest-page faults.
//
// * Otherwise its pages are translated first, since their PTEs tell
//   whether it is checked; a translation fault, or a misaligned
//   exception raised before translation, of the access comes first and
//   is raised by the access itself. It is checked if one of its pages is
//   a tagged-data page ("A load/store straddling between tagged-data
//   page and normal page is assumed as tagged-data page for both
//   pages"), in its chunks that are not in a user page accessed by a
//   supervisor.
//
// The tag loads have the translation context of the access (HLV*/HSV*:
// vsvitts or vsvittu as the tag table, two-stage translation and GVA).
//
// TODO: vector/LR/SC/AMO accesses are not checked yet.
// The val declaration (with the type) is in vmem_utils.sail, where
// vmem_read_explicit/vmem_write_explicit invoke this hook.
function zimt_implicit_check(base, raw_addr, vaddr, width, access, access_info, trigger_payload) = {
  if not(currentlyEnabled(Ext_Zimt)) then return None();
  // Only regular data loads/stores are checked (vector/LR/SC/AMO: TODO).
  // HLVX* use LoadExecute: they "always generate unchecked loads".
  let checked_kind : bool = match access {
    Load(Data)  => true,
    Store(Data) => true,
    _           => false,
  };
  if not(checked_kind) then return None();
  // "Memory accesses performed using the stack pointer (x2) as the
  // base register do not generate checked accesses."
  if base == sp then return None();
  let mode = zimt_access_mt_mode(access_info);
  if mode == MT_MODE_Disabled then return None();
  if zimt_code_exempt then return None();
  let eff_priv = access_info.eff_privilege;
  let vitt : xlenbits = match get_vitt_base(eff_priv) {
    Some(b) => b,
    // No tag table available for this privilege: no checked accesses.
    None()  => return None(),
  };
  // Load/store address breakpoints have higher priority than the
  // exceptions of the memory accesses of the instruction, so the
  // triggers of the data access are matched before its pages are
  // translated and the tags are loaded. vmem_read_addr/vmem_write_addr
  // match the same payload again, which gives the same result.
  match match_memory_trigger_before(cur_privilege, trigger_payload, access_is_gva(access_info)) {
    Some(pti) => return Some(PendingTrigger(pti)),
    None()    => (),
  };
  let w = enabled_pointer_tag_width(mode);
  let expected = mc_tag_of_pointer_tag(extract_pointer_tag(raw_addr, w), mode);
  let va = bits_of(vaddr);
  let last = va + to_bits(xlen, width - 1);
  let first_stage_paging : bool = if privLevel_is_virtual(eff_priv)
    then vsatp_mode() != Bare
    else satp_mode(eff_priv) != Bare;
  if not(first_stage_paging) then return zimt_check_chunks(vitt, va, last, expected, mode, access_info);

  if not(is_aligned_addr(vaddr, width)) & is_some(plat_misaligned_exception(access, false)) then return None();
  let (lo_bytes, hi_bytes) = split_on_page_boundary(va, width);
  let va1 = va + to_bits(xlen, lo_bytes);
  // The pages are translated in the order of the split access of
  // vmem_read_addr/vmem_write_addr, so that with Svadu the A/D updates
  // are those of the access when one of its pages faults. A store that
  // then fails the tag check keeps the D bits that its translations set,
  // as when it fails the PMP/PMA checks that follow them.
  let page1_first = hi_bytes != 0 & sys_misaligned_order_decreasing;
  let first_page : ext_ptw = match translateAddr(Virtaddr(if page1_first then va1 else va), access, eff_priv) {
    Ok(_, _, ext) => ext,
    Err(_)        => return None(),
  };
  let other_page : ext_ptw = if hi_bytes == 0 then first_page else
    match translateAddr(Virtaddr(if page1_first then va else va1), access, eff_priv) {
      Ok(_, _, ext) => ext,
      Err(_)        => return None(),
    };
  let (page0, page1) = if page1_first then (other_page, first_page) else (first_page, other_page);
  if not(zimt_tagged_data_page(page0, eff_priv) | zimt_tagged_data_page(page1, eff_priv)) then return None();
  if not(zimt_supervisor_to_user(page0, eff_priv)) then {
    match zimt_check_chunks(vitt, va, va1 - 1, expected, mode, access_info) {
      Some(e) => return Some(e),
      None()  => (),
    }
  };
  if hi_bytes != 0 & not(zimt_supervisor_to_user(page1, eff_priv))
  then zimt_check_chunks(vitt, va1, last, expected, mode, access_info)
  else None()
}
