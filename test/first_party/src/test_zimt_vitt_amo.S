// test_zimt_paging.S with zimt_vitt_amo.json: the misaligned atomicity
// granule check of main memory raises misaligned exceptions for AMOs and
// LR/SC, and a misaligned LR/SC raises none before its translation. An
// AMO or LR over a page outside the VITT range and the first page of the
// range, which translates its first page only, then raises a misaligned
// exception, which tells it from the access fault that the bytes in its
// next page would raise if the protection of tag storage checked them
// (section 16a).
#define CAUSE_AMO_CROSS  CAUSE_MISALIGNED_STORE
#define CAUSE_LR_CROSS   CAUSE_MISALIGNED_LOAD
#include "test_zimt_paging.S"
