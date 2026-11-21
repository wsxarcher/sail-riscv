// =======================================================================================
// This Sail RISC-V architecture model, comprising all files and
// directories except where otherwise noted is subject the BSD
// two-clause license in the LICENSE file.
//
// SPDX-License-Identifier: BSD-2-Clause
// =======================================================================================

// Instructions of the Zimt memory tagging extension (v0.2, DRAFT):
// gentag, addtag, settag, checktag.
//
// All four are taken from the Zimop MOP.RR encoding space (SYSTEM
// opcode, funct3 0b100): gentag/addtag/checktag from MOP.RR.1
// (funct7 0b1000011) and settag from MOP.RR.0 (funct7 0b1000001).
// Within MOP.RR.1, gentag has rs1 = x0 and tag_imm4 = 0, addtag has
// tag_imm4 != 0, and checktag has rd = x0.
//
// The decode clauses are guarded on currentlyEnabled(Ext_Zimt); when
// Zimt is not enabled the encodings fall through to the ZIMOP_MOP_RR
// clause (the `mops` module is loaded after `extensions` for exactly
// this reason). When Zimt is enabled but memory tagging is disabled
// in the current execution environment, the execute clauses implement
// the spec-mandated fallback: zero the destination (identical to
// Zimop), except addtag which copies rs1 to rd so that rd always
// holds a valid pointer on an MT-implementing hart.

union clause instruction = GENTAG : (regidx)
union clause instruction = ADDTAG : (bits(4), regidx, regidx)
union clause instruction = SETTAG : (bits(4), regidx)
union clause instruction = CHECKTAG : (bits(4), regidx)

mapping clause encdec = GENTAG(rd)
  <-> 0b1000011 @ 0b0 @ 0b0000 @ 0b00000 @ 0b100 @ encdec_reg(rd) @ 0b1110011
  when currentlyEnabled(Ext_Zimt) & rd != zreg

mapping clause encdec = ADDTAG(imm, rs1, rd)
  <-> 0b1000011 @ 0b0 @ imm @ encdec_reg(rs1) @ 0b100 @ encdec_reg(rd) @ 0b1110011
  when currentlyEnabled(Ext_Zimt) & imm != 0b0000 & rd != zreg

mapping clause encdec = CHECKTAG(imm, rs1)
  <-> 0b1000011 @ 0b0 @ imm @ encdec_reg(rs1) @ 0b100 @ 0b00000 @ 0b1110011
  when currentlyEnabled(Ext_Zimt) & rs1 != zreg

mapping clause encdec = SETTAG(imm, rs1)
  <-> 0b1000001 @ 0b0 @ imm @ encdec_reg(rs1) @ 0b100 @ 0b00000 @ 0b1110011
  when currentlyEnabled(Ext_Zimt) & rs1 != zreg

// Tag generation of gentag.
//
// gentag "generates a pointer_tag value from the set of tag values
// permitted by the active tag generation exclusion mask", and "the
// implementation must ensure that the generated tag is pseudorandom and
// uniformly distributed over the permitted tag values across
// invocations of gentag". With n permitted values, this implementation
// draws k uniformly from [0, n) with the pseudorandom numbers of
// zimt_gentag_random and returns the k-th permitted value in increasing
// order. The numbers are deterministic, so tests must not rely on
// specific generated values, except when the exclusion mask permits
// exactly one value.

// A k uniformly distributed over [0, n), by Lemire's method: the high
// part of r * n for a 32-bit pseudorandom r, rejecting the r for which
// the low part is below 2^32 mod n, so that every k has as many
// accepted r. A rejection has a probability below n / 2^32 <= 2^-25,
// so this takes the k of the eighth draw if all eight are rejected.
function zimt_uniform_below(n : range(1, 128)) -> range(0, 127) = {
  let threshold = (2 ^ 32) % n;
  var k : range(0, 127) = 0;
  var accepted : bool = false;
  foreach (i from 0 to 7) {
    if not(accepted) then {
      let m = unsigned(zimt_gentag_random()) * n;
      k = unsigned(get_slice_int(7, m, 32));
      accepted = unsigned(get_slice_int(32, m, 0)) >= threshold;
    }
  };
  k
}

// The k-th (from 0) value whose bit is set in `permitted`, which has
// more than k bits set.
function zimt_kth_permitted(permitted : bits(128), k : range(0, 127)) -> range(0, 127) = {
  var seen : int = 0;
  var tag : range(0, 127) = 0;
  foreach (i from 0 to 127) {
    if permitted[i] == bitone then {
      if seen == k then tag = i;
      seen = seen + 1;
    }
  };
  tag
}

// A pseudorandom tag value of width w, uniformly distributed over the
// values that `mask` permits. The exclusion-mask WARL rule keeps one of
// the values 0-15 permitted, so there is always one.
function zimt_generate_tag(mask : bits(128), w : zimt_tag_width) -> range(0, 127) = {
  let values : bits(128) = if w == 4 then zero_extend(0xFFFF) else ones();
  let permitted = not_vec(mask) & values;
  let n = count_ones(permitted);
  assert(n > 0, "Zimt: exclusion mask permits no tag value");
  zimt_kth_permitted(permitted, zimt_uniform_below(n))
}

function clause execute GENTAG(rd) = {
  let mode = get_mt_mode(cur_privilege);
  if mode == MT_MODE_Disabled then {
    // Zimop fallback: zero the destination.
    X(rd) = zeros();
    return RETIRE_SUCCESS
  };
  let w = enabled_pointer_tag_width(mode);
  let tag = zimt_generate_tag(get_mtag_exclusion_mask(cur_privilege), w);
  X(rd) = insert_pointer_tag(zeros(), to_bits(7, tag), w);
  RETIRE_SUCCESS
}

function clause execute ADDTAG(imm, rs1, rd) = {
  let mode = get_mt_mode(cur_privilege);
  if mode == MT_MODE_Disabled then {
    // Implemented-but-disabled: move rs1 to rd (NOT the Zimop
    // zeroing), so rd always holds a valid pointer.
    X(rd) = X(rs1);
    return RETIRE_SUCCESS
  };
  let w = enabled_pointer_tag_width(mode);
  let tag = extract_pointer_tag(X(rs1), w) + zero_extend(imm);
  X(rd) = insert_pointer_tag(X(rs1), tag, w);
  RETIRE_SUCCESS
}

function clause execute SETTAG(imm, rs1) = {
  let mode = get_mt_mode(cur_privilege);
  // Zimop fallback (write x0) is a no-op.
  if mode == MT_MODE_Disabled then return RETIRE_SUCCESS;
  let w = enabled_pointer_tag_width(mode);
  let raw = X(rs1);
  let mc_tag = mc_tag_of_pointer_tag(extract_pointer_tag(raw, w), mode);
  let vitt : xlenbits = match get_vitt_base(cur_privilege) {
    Some(base) => base,
    // No tag table (Svatag/Smvatag not enabled for this privilege).
    None() => return memory_exception(E_SAMO_Access_Fault(), raw, default_access_info(Store(Tag))),
  };
  // Strip the pointer tag via the pointer-masking transform; the
  // first chunk is at the 16-byte aligned address.
  let va = bits_of(transform_effective_address(Virtaddr(raw), default_access_info(Store(Data))));
  let chunk0 = va >> 4;
  foreach (i from 0 to unsigned(imm)) {
    match zimt_store_mc_tag(vitt, chunk0 + to_bits(xlen, i), mc_tag, mode) {
      Err(e) => return e,
      Ok(()) => (),
    }
  };
  RETIRE_SUCCESS
}

function clause execute CHECKTAG(imm, rs1) = {
  let mode = get_mt_mode(cur_privilege);
  // Zimop fallback (write x0) is a no-op.
  if mode == MT_MODE_Disabled then return RETIRE_SUCCESS;
  let w = enabled_pointer_tag_width(mode);
  let raw = X(rs1);
  let expected = mc_tag_of_pointer_tag(extract_pointer_tag(raw, w), mode);
  let vitt : xlenbits = match get_vitt_base(cur_privilege) {
    Some(base) => base,
    None() => return memory_exception(E_Load_Access_Fault(), raw, default_access_info(Load(Tag))),
  };
  let va = bits_of(transform_effective_address(Virtaddr(raw), default_access_info(Load(Data))));
  // checktag checks whole chunks: chunk_count + 1 chunks of 16 bytes
  // starting at the chunk containing va.
  let chunk0 = va >> 4;
  foreach (i from 0 to unsigned(imm)) {
    match zimt_load_mc_tag(vitt, chunk0 + to_bits(xlen, i), mode, false) {
      Err(e) => return e,
      Ok(mc_tag) => if mc_tag != expected then return trap(make_mem_tag_exception(false)),
    }
  };
  RETIRE_SUCCESS
}

mapping clause assembly = GENTAG(rd)
  <-> "gentag" ^ spc() ^ reg_name(rd)
mapping clause assembly = ADDTAG(imm, rs1, rd)
  <-> "addtag" ^ spc() ^ reg_name(rd) ^ sep() ^ reg_name(rs1) ^ sep() ^ hex_bits_4(imm)
mapping clause assembly = SETTAG(imm, rs1)
  <-> "settag" ^ spc() ^ reg_name(rs1) ^ sep() ^ hex_bits_4(imm)
mapping clause assembly = CHECKTAG(imm, rs1)
  <-> "checktag" ^ spc() ^ reg_name(rs1) ^ sep() ^ hex_bits_4(imm)
