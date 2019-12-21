/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

//#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_scalar.cl"
#include "inc_hash_sha1.cl"
#endif

KERNEL_FQ void m21331_mxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * base
   */

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };
  u32 s2[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }
  s2[0] = hc_swap32_S (0x99655967);
  s2[1] = hc_swap32_S (0x90042504);
  s2[2] = hc_swap32_S (0x49276456);
  s2[3] = hc_swap32_S (0x1A748994);
  
  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update (&ctx0, s, salt_len);

  sha1_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx = ctx0;

    sha1_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_update (&ctx, s2, 16);

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];

    COMPARE_M_SCALAR_PS3 (r0);
  }
}

KERNEL_FQ void m21331_sxx (KERN_ATTR_BASIC ())
{
  /**
   * modifier
   */

  const u64 lid = get_local_id (0);
  const u64 gid = get_global_id (0);

  if (gid >= gid_max) return;

  /**
   * digest
   */

  const u32 search[4] =
  {
    digests_buf[digests_offset].digest_buf[DGST_R0],
    digests_buf[digests_offset].digest_buf[DGST_R1],
    digests_buf[digests_offset].digest_buf[DGST_R2],
    digests_buf[digests_offset].digest_buf[DGST_R3]
  };

  /**
   * base
   */

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32 s[64] = { 0 };
  u32 s2[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32_S (salt_bufs[salt_pos].salt_buf[idx]);
  }
  s2[0] = hc_swap32_S (0x99655967);
  s2[1] = hc_swap32_S (0x90042504);
  s2[2] = hc_swap32_S (0x49276456);
  s2[3] = hc_swap32_S (0x1A748994);
  
  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update (&ctx0, s, salt_len);

  sha1_update_global_swap (&ctx0, pws[gid].i, pws[gid].pw_len);

  /**
   * loop
   */

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos++)
  {
    sha1_ctx_t ctx = ctx0;

    sha1_update_global_swap (&ctx, combs_buf[il_pos].i, combs_buf[il_pos].pw_len);

    sha1_update (&ctx, s2, 16);

    sha1_final (&ctx);

    const u32 r0 = ctx.h[DGST_R0];

    COMPARE_S_SCALAR_PS3 (r0);
  }
}
