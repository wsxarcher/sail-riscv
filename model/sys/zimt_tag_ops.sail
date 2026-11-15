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
// as required.

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

// Perform a "load tag" operation for one memory chunk. The tag loads of
// the implicit check of a regular load/store (`implicit`) are implicit
// accesses that are not matched by triggers.
function zimt_load_mc_tag(vitt : xlenbits, chunk : xlenbits, mode : MemTaggingMode, implicit : bool)
  -> result(bits(8), ExecutionResult) = {
  let (tag_va, upper_nibble) = zimt_tag_byte_addr(vitt, chunk, mode);
  let access_info = default_access_info(Load(Tag));
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

// Check the tags of all chunks overlapped by [va, va + width) against
// `expected`; returns None() on success, or the resulting trap.
function zimt_check_chunks forall 'width, is_mem_width('width). (
  vitt : xlenbits,
  va : xlenbits,
  width : int('width),
  expected : bits(8),
  mode : MemTaggingMode,
  access_info : AccessInfo,
) -> option(ExecutionResult) = {
  let first_chunk = va >> 4;
  let last_chunk = (va + to_bits(xlen, width - 1)) >> 4;
  let nchunks = unsigned(last_chunk - first_chunk);
  foreach (i from 0 to nchunks) {
    match zimt_load_mc_tag(vitt, first_chunk + to_bits(xlen, i), mode, true) {
      Err(e) => return Some(without_transformed_instruction(e)),
      Ok(mc_tag) => if mc_tag != expected then return Some(trap(make_mem_tag_exception(access_info.as_guest))),
    }
  };
  None()
}

// ---------------------------------------------------------------------
// Implicit tag checks on regular loads/stores (no-translation
// environments only).
//
// When memory tagging is active at the effective privilege of a
// regular Data load/store and address translation is not in effect
// (Bare mode), every data page is a tagged-data page ("If paging is
// not enabled then all data pages are treated as tagged-data pages")
// and there are no tagcheck-exempt code pages, so the access is
// checked unless it is performed via the stack pointer (x2).
//
// TODO (blocked on spec): with paging enabled, checks are controlled
// by the PTE.MTAG bit, whose position the v0.2 draft has not fixed;
// accesses under paging are currently unchecked. mstatus.MTAG_I /
// hstatus.MTAG_I, HLV*/HSV* (hstatus.VUMT_MODE) and vector/LR/SC/AMO
// accesses are likewise not checked yet.
// The val declaration (with the type) is in vmem_utils.sail, where
// vmem_read_explicit/vmem_write_explicit invoke this hook.
function zimt_implicit_check(base, raw_addr, vaddr, width, access, access_info, trigger_payload) = {
  if not(currentlyEnabled(Ext_Zimt)) then return None();
  // Only regular data loads/stores are checked (vector/LR/SC/AMO: TODO).
  let checked_kind : bool = match access {
    Load(Data)  => true,
    Store(Data) => true,
    _           => false,
  };
  if not(checked_kind) then return None();
  // HLV*/HSV* (hstatus.VUMT_MODE) are not checked yet (see above).
  if access_info.as_guest then return None();
  // "Memory accesses performed using the stack pointer (x2) as the
  // base register do not generate checked accesses."
  if base == sp then return None();
  let eff_priv = access_info.eff_privilege;
  let mode = get_mt_mode(eff_priv);
  if mode == MT_MODE_Disabled then return None();
  // Paging enabled: PTE.MTAG-based checks are TODO (see above).
  let vmem_active : bool = if privLevel_is_virtual(eff_priv)
    then vsatp_mode() != Bare | hgatp_mode() != HBare
    else satp_mode(eff_priv) != Bare;
  if vmem_active then return None();
  let vitt : xlenbits = match get_vitt_base(eff_priv) {
    Some(b) => b,
    // No tag table available for this privilege: no checked accesses.
    None()  => return None(),
  };
  let w = enabled_pointer_tag_width(mode);
  let expected = mc_tag_of_pointer_tag(extract_pointer_tag(raw_addr, w), mode);
  // Load/store address breakpoints have higher priority than the
  // exceptions of the memory accesses of the instruction, so the
  // triggers of the data access are matched before the tags are loaded.
  // vmem_read_addr/vmem_write_addr match the same payload again, which
  // gives the same result.
  match match_memory_trigger_before(cur_privilege, trigger_payload, access_is_gva(access_info)) {
    Some(pti) => return Some(PendingTrigger(pti)),
    None()    => (),
  };
  zimt_check_chunks(vitt, bits_of(vaddr), width, expected, mode, access_info)
}
