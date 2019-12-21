/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include "inc_vendor.h"
#include "inc_types.h"
#include "inc_platform.cl"
#include "inc_common.cl"
#include "inc_simd.cl"
#include "inc_hash_sha1.cl"
#endif

KERNEL_FQ void m21332_mxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32x s[64] = { 0 };
  u32x s2[64] = { 0 };

  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32 (salt_bufs[salt_pos].salt_buf[idx]);
  }
  s2[0] = hc_swap32_S (0xA6648D51);
  s2[1] = hc_swap32_S (0xC1D8DE35);
  s2[2] = hc_swap32_S (0xB139B0E6);
  s2[3] = hc_swap32_S (0x3052E5C3);
  
  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_ctx_vector_t ctx;

    sha1_init_vector_from_scalar (&ctx, &ctx0);

    sha1_update_vector_swap (&ctx, w, pw_len);

    sha1_update_vector (&ctx, s2, 16);

    sha1_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_M_SIMD (r0, r1, r0, r1);
  }
}

KERNEL_FQ void m21332_sxx (KERN_ATTR_VECTOR ())
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

  const u32 pw_len = pws[gid].pw_len;

  u32x w[64] = { 0 };

  for (u32 i = 0, idx = 0; i < pw_len; i += 4, idx += 1)
  {
    w[idx] = pws[gid].i[idx];
  }

  const u32 salt_len = salt_bufs[salt_pos].salt_len;

  u32x s[64] = { 0 };
  u32x s2[64] = { 0 };
  
  for (u32 i = 0, idx = 0; i < salt_len; i += 4, idx += 1)
  {
    s[idx] = hc_swap32 (salt_bufs[salt_pos].salt_buf[idx]);
  }
  s2[0] = hc_swap32_S (0xA6648D51);
  s2[1] = hc_swap32_S (0xC1D8DE35);
  s2[2] = hc_swap32_S (0xB139B0E6);
  s2[3] = hc_swap32_S (0x3052E5C3);
  
  sha1_ctx_t ctx0;

  sha1_init (&ctx0);

  sha1_update_global_swap (&ctx0, salt_bufs[salt_pos].salt_buf, salt_bufs[salt_pos].salt_len);

  /**
   * loop
   */

  u32x w0l = w[0];

  for (u32 il_pos = 0; il_pos < il_cnt; il_pos += VECT_SIZE)
  {
    const u32x w0r = words_buf_r[il_pos / VECT_SIZE];

    const u32x w0 = w0l | w0r;

    w[0] = w0;

    sha1_ctx_vector_t ctx;

    sha1_init_vector_from_scalar (&ctx, &ctx0);

    sha1_update_vector_swap (&ctx, w, pw_len);

    sha1_update_vector (&ctx, s2, 16);

    sha1_final_vector (&ctx);

    const u32x r0 = ctx.h[DGST_R0];
    const u32x r1 = ctx.h[DGST_R1];
    const u32x r2 = ctx.h[DGST_R2];
    const u32x r3 = ctx.h[DGST_R3];

    COMPARE_S_SIMD (r0, r1, r0, r1);
  }
}
