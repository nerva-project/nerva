// Copyright (c) 2018-2024, The Nerva Project
// Copyright (c) 2014-2024, The Monero Project
// 
// All rights reserved.
// 
// Redistribution and use in source and binary forms, with or without modification, are
// permitted provided that the following conditions are met:
// 
// 1. Redistributions of source code must retain the above copyright notice, this list of
//    conditions and the following disclaimer.
// 
// 2. Redistributions in binary form must reproduce the above copyright notice, this list
//    of conditions and the following disclaimer in the documentation and/or other
//    materials provided with the distribution.
// 
// 3. Neither the name of the copyright holder nor the names of its contributors may be
//    used to endorse or promote products derived from this software without specific
//    prior written permission.
// 
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
// STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//
// Adapted from Java code by Sarang Noether

#include <stdlib.h>
#include <openssl/ssl.h>
#include <boost/thread/mutex.hpp>
#include <boost/thread/lock_guard.hpp>
#include "misc_log_ex.h"
#include "span.h"
#include "common/perf_timer.h"
#include "cryptonote_config.h"
extern "C"
{
#include "crypto/crypto-ops.h"
}
#include "rctOps.h"
#include "multiexp.h"
#include "bulletproofs.h"

#undef MONERO_DEFAULT_LOG_CATEGORY
#define MONERO_DEFAULT_LOG_CATEGORY "bulletproofs"

//#define DEBUG_BP

#if 0
#define PERF_TIMER_START_BP(x) PERF_TIMER_START_UNIT(x, 1000000)
#define PERF_TIMER_STOP_BP(x) PERF_TIMER_STOP(x)
#else
#define PERF_TIMER_START_BP(x) ((void)0)
#define PERF_TIMER_STOP_BP(x) ((void)0)
#endif

#define STRAUS_SIZE_LIMIT 232
#define PIPPENGER_SIZE_LIMIT 0

namespace rct
{

static rct::key vector_exponent_v1(const rct::keyV &a, const rct::keyV &b);
static rct::key vector_exponent_v2(const rct::keyV &a, const rct::keyV &b);
static rct::keyV vector_powers(rct::key x, size_t n);
static rct::keyV vector_dup(const rct::key &x, size_t n);
static rct::key inner_product_v1(const rct::keyV &a, const rct::keyV &b);
static rct::key inner_product_v2(const rct::keyV &a, const rct::keyV &b);

static constexpr size_t maxN = 64;
static constexpr size_t maxM = BULLETPROOF_MAX_OUTPUTS;
static rct::key Hi_v1[maxN], Gi_v1[maxN];
static rct::key Hi_v2[maxN*maxM], Gi_v2[maxN*maxM];
static ge_dsmp Gprecomp[64], Hprecomp[64];
static ge_p3 Hi_p3[maxN*maxM], Gi_p3[maxN*maxM];
static std::shared_ptr<straus_cached_data> straus_HiGi_cache;
static std::shared_ptr<pippenger_cached_data> pippenger_HiGi_cache;
static const rct::key TWO = { {0x02, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00 , 0x00, 0x00, 0x00,0x00  } };
static const rct::key MINUS_ONE = { { 0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10 } };
static const rct::key MINUS_INV_EIGHT = { { 0x74, 0xa4, 0x19, 0x7a, 0xf0, 0x7d, 0x0b, 0xf7, 0x05, 0xc2, 0xda, 0x25, 0x2b, 0x5c, 0x0b, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a } };
static const rct::keyV oneN_v1 = vector_powers(rct::identity(), maxN);
static const rct::keyV oneN_v2 = vector_dup(rct::identity(), maxN);
static const rct::keyV twoN = vector_powers(TWO, maxN);
static const rct::key ip12_v1 = inner_product_v1(oneN_v1, twoN);
static const rct::key ip12_v2 = inner_product_v2(oneN_v2, twoN);
static boost::mutex init_mutex;

static inline rct::key multiexp(const std::vector<MultiexpData> &data, size_t HiGi_size)
{
  if (HiGi_size > 0)
  {
    static_assert(232 <= STRAUS_SIZE_LIMIT, "Straus in precalc mode can only be calculated till STRAUS_SIZE_LIMIT");
    return HiGi_size <= 232 && data.size() == HiGi_size ? straus(data, straus_HiGi_cache, 0) : pippenger(data, pippenger_HiGi_cache, HiGi_size, get_pippenger_c(data.size()));
  }
  else
    return data.size() <= 95 ? straus(data, NULL, 0) : pippenger(data, NULL, 0, get_pippenger_c(data.size()));
}

static inline bool is_reduced(const rct::key &scalar)
{
  return sc_check(scalar.bytes) == 0;
}

static rct::key get_exponent(const rct::key &base, size_t idx)
{
  static const std::string salt("bulletproof");
  std::string hashed = std::string((const char*)base.bytes, sizeof(base)) + salt + tools::get_varint_data(idx);
  return rct::hashToPoint(rct::hash2rct(crypto::cn_fast_hash(hashed.data(), hashed.size())));
}

static void init_exponents_v1()
{
  boost::lock_guard<boost::mutex> lock(init_mutex);

  static bool init_done = false;
  if (init_done)
    return;
  for (size_t i = 0; i < maxN; ++i)
  {
    Hi_v1[i] = get_exponent(rct::H, i * 2);
    rct::precomp(Hprecomp[i], Hi_v1[i]);
    Gi_v1[i] = get_exponent(rct::H, i * 2 + 1);
    rct::precomp(Gprecomp[i], Gi_v1[i]);
  }
  init_done = true;
}

static void init_exponents_v2()
{
  boost::lock_guard<boost::mutex> lock(init_mutex);

  static bool init_done = false;
  if (init_done)
    return;
  std::vector<MultiexpData> data;
  data.reserve(maxN*maxM*2);
  for (size_t i = 0; i < maxN*maxM; ++i)
  {
    Hi_v2[i] = get_exponent(rct::H, i * 2);
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&Hi_p3[i], Hi_v2[i].bytes) == 0, "ge_frombytes_vartime failed");
    Gi_v2[i] = get_exponent(rct::H, i * 2 + 1);
    CHECK_AND_ASSERT_THROW_MES(ge_frombytes_vartime(&Gi_p3[i], Gi_v2[i].bytes) == 0, "ge_frombytes_vartime failed");

    data.push_back({rct::zero(), Gi_p3[i]});
    data.push_back({rct::zero(), Hi_p3[i]});
  }

  straus_HiGi_cache = straus_init_cache(data, STRAUS_SIZE_LIMIT);
  pippenger_HiGi_cache = pippenger_init_cache(data, 0, PIPPENGER_SIZE_LIMIT);

  MINFO("Hi/Gi cache size: " << (sizeof(Hi_v2)+sizeof(Gi_v2))/1024 << " kB");
  MINFO("Hi_p3/Gi_p3 cache size: " << (sizeof(Hi_p3)+sizeof(Gi_p3))/1024 << " kB");
  MINFO("Straus cache size: " << straus_get_cache_size(straus_HiGi_cache)/1024 << " kB");
  MINFO("Pippenger cache size: " << pippenger_get_cache_size(pippenger_HiGi_cache)/1024 << " kB");
  size_t cache_size = (sizeof(Hi_v2)+sizeof(Hi_p3))*2 + straus_get_cache_size(straus_HiGi_cache) + pippenger_get_cache_size(pippenger_HiGi_cache);
  MINFO("Total cache size: " << cache_size/1024 << "kB");
  init_done = true;
}

/* Given two scalar arrays, construct a vector commitment */
static rct::key vector_exponent_v1(const rct::keyV &a, const rct::keyV &b)
{
  CHECK_AND_ASSERT_THROW_MES(a.size() == b.size(), "Incompatible sizes of a and b");
  CHECK_AND_ASSERT_THROW_MES(a.size() <= maxN, "Incompatible sizes of a and maxN");
  rct::key res = rct::identity();
  for (size_t i = 0; i < a.size(); ++i)
  {
    rct::key term;
    rct::addKeys3(term, a[i], Gprecomp[i], b[i], Hprecomp[i]);
    rct::addKeys(res, res, term);
  }
  return res;
}

static rct::key vector_exponent_v2(const rct::keyV &a, const rct::keyV &b)
{
  CHECK_AND_ASSERT_THROW_MES(a.size() == b.size(), "Incompatible sizes of a and b");
  CHECK_AND_ASSERT_THROW_MES(a.size() <= maxN*maxM, "Incompatible sizes of a and maxN");

  std::vector<MultiexpData> multiexp_data;
  multiexp_data.reserve(a.size()*2);
  for (size_t i = 0; i < a.size(); ++i)
  {
    multiexp_data.emplace_back(a[i], Gi_p3[i]);
    multiexp_data.emplace_back(b[i], Hi_p3[i]);
  }
  return multiexp(multiexp_data, 2 * a.size());
}

/* Compute a custom vector-scalar commitment */
static rct::key vector_exponent_custom(const rct::keyV &A, const rct::keyV &B, const rct::keyV &a, const rct::keyV &b)
{
  CHECK_AND_ASSERT_THROW_MES(A.size() == B.size(), "Incompatible sizes of A and B");
  CHECK_AND_ASSERT_THROW_MES(a.size() == b.size(), "Incompatible sizes of a and b");
  CHECK_AND_ASSERT_THROW_MES(a.size() == A.size(), "Incompatible sizes of a and A");
  CHECK_AND_ASSERT_THROW_MES(a.size() <= maxN, "Incompatible sizes of a and maxN");
  rct::key res = rct::identity();
  for (size_t i = 0; i < a.size(); ++i)
  {
    rct::key term;
#if 0
    // we happen to know where A and B might fall, so don't bother checking the rest
    ge_dsmp *Acache = NULL, *Bcache = NULL;
    ge_dsmp Acache_custom[1], Bcache_custom[1];
    if (Gi[i] == A[i])
      Acache = Gprecomp + i;
    else if (i<32 && Gi[i+32] == A[i])
      Acache = Gprecomp + i + 32;
    else
    {
      rct::precomp(Acache_custom[0], A[i]);
      Acache = Acache_custom;
    }
    if (i == 0 && B[i] == Hi[0])
      Bcache = Hprecomp;
    else
    {
      rct::precomp(Bcache_custom[0], B[i]);
      Bcache = Bcache_custom;
    }
    rct::addKeys3(term, a[i], *Acache, b[i], *Bcache);
#else
    ge_dsmp Acache, Bcache;
    rct::precomp(Bcache, B[i]);
    rct::addKeys3(term, a[i], A[i], b[i], Bcache);
#endif
    rct::addKeys(res, res, term);
  }
  return res;
}

static rct::key cross_vector_exponent8(size_t size, const std::vector<ge_p3> &A, size_t Ao, const std::vector<ge_p3> &B, size_t Bo, const rct::keyV &a, size_t ao, const rct::keyV &b, size_t bo, const rct::keyV *scale, const ge_p3 *extra_point, const rct::key *extra_scalar)
{
  CHECK_AND_ASSERT_THROW_MES(size + Ao <= A.size(), "Incompatible size for A");
  CHECK_AND_ASSERT_THROW_MES(size + Bo <= B.size(), "Incompatible size for B");
  CHECK_AND_ASSERT_THROW_MES(size + ao <= a.size(), "Incompatible size for a");
  CHECK_AND_ASSERT_THROW_MES(size + bo <= b.size(), "Incompatible size for b");
  CHECK_AND_ASSERT_THROW_MES(size <= maxN*maxM, "size is too large");
  CHECK_AND_ASSERT_THROW_MES(!scale || size == scale->size() / 2, "Incompatible size for scale");
  CHECK_AND_ASSERT_THROW_MES(!!extra_point == !!extra_scalar, "only one of extra point/scalar present");

  std::vector<MultiexpData> multiexp_data;
  multiexp_data.resize(size*2 + (!!extra_point));
  for (size_t i = 0; i < size; ++i)
  {
    sc_mul(multiexp_data[i*2].scalar.bytes, a[ao+i].bytes, INV_EIGHT.bytes);;
    multiexp_data[i*2].point = A[Ao+i];
    sc_mul(multiexp_data[i*2+1].scalar.bytes, b[bo+i].bytes, INV_EIGHT.bytes);
    if (scale)
      sc_mul(multiexp_data[i*2+1].scalar.bytes, multiexp_data[i*2+1].scalar.bytes, (*scale)[Bo+i].bytes);
    multiexp_data[i*2+1].point = B[Bo+i];
  }
  if (extra_point)
  {
    sc_mul(multiexp_data.back().scalar.bytes, extra_scalar->bytes, INV_EIGHT.bytes);
    multiexp_data.back().point = *extra_point;
  }
  return multiexp(multiexp_data, 0);
}

/* Given a scalar, construct a vector of powers */
static rct::keyV vector_powers(rct::key x, size_t n)
{
  rct::keyV res(n);
  if (n == 0)
    return res;
  res[0] = rct::identity();
  if (n == 1)
    return res;
  res[1] = x;
  for (size_t i = 2; i < n; ++i)
  {
    sc_mul(res[i].bytes, res[i-1].bytes, x.bytes);
  }
  return res;
}

static rct::key vector_power_sum(const rct::key &x, size_t n)
{
  if (n == 0)
    return rct::zero();
  rct::key res = rct::identity();
  if (n == 1)
    return res;
  rct::key prev = x;
  for (size_t i = 1; i < n; ++i)
  {
    if (i > 1)
      sc_mul(prev.bytes, prev.bytes, x.bytes);
    sc_add(res.bytes, res.bytes, prev.bytes);
  }
  return res;
}

/* Given two scalar arrays, construct the inner product */
static rct::key inner_product_v1(const rct::keyV &a, const rct::keyV &b)
{
  CHECK_AND_ASSERT_THROW_MES(a.size() == b.size(), "Incompatible sizes of a and b");
  rct::key res = rct::zero();
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_muladd(res.bytes, a[i].bytes, b[i].bytes, res.bytes);
  }
  return res;
}

static rct::key inner_product_v2(const epee::span<const rct::key> &a, const epee::span<const rct::key> &b)
{
  CHECK_AND_ASSERT_THROW_MES(a.size() == b.size(), "Incompatible sizes of a and b");
  rct::key res = rct::zero();
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_muladd(res.bytes, a[i].bytes, b[i].bytes, res.bytes);
  }
  return res;
}

static rct::key inner_product_v2(const rct::keyV &a, const rct::keyV &b)
{
  return inner_product_v2(epee::span<const rct::key>(a.data(), a.size()), epee::span<const rct::key>(b.data(), b.size()));
}

/* Given two scalar arrays, construct the Hadamard product */
static rct::keyV hadamard(const rct::keyV &a, const rct::keyV &b)
{
  CHECK_AND_ASSERT_THROW_MES(a.size() == b.size(), "Incompatible sizes of a and b");
  rct::keyV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_mul(res[i].bytes, a[i].bytes, b[i].bytes);
  }
  return res;
}

/* Given two curvepoint arrays, construct the Hadamard product */
static rct::keyV hadamard2(const rct::keyV &a, const rct::keyV &b)
{
  CHECK_AND_ASSERT_THROW_MES(a.size() == b.size(), "Incompatible sizes of a and b");
  rct::keyV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    rct::addKeys(res[i], a[i], b[i]);
  }
  return res;
}

static void hadamard_fold(std::vector<ge_p3> &v, const rct::keyV *scale, const rct::key &a, const rct::key &b)
{
  CHECK_AND_ASSERT_THROW_MES((v.size() & 1) == 0, "Vector size should be even");
  const size_t sz = v.size() / 2;
  for (size_t n = 0; n < sz; ++n)
  {
    ge_dsmp c[2];
    ge_dsm_precomp(c[0], &v[n]);
    ge_dsm_precomp(c[1], &v[sz + n]);
    rct::key sa, sb;
    if (scale) sc_mul(sa.bytes, a.bytes, (*scale)[n].bytes); else sa = a;
    if (scale) sc_mul(sb.bytes, b.bytes, (*scale)[sz + n].bytes); else sb = b;
    ge_double_scalarmult_precomp_vartime2_p3(&v[n], sa.bytes, c[0], sb.bytes, c[1]);
  }
  v.resize(sz);
}

/* Add two vectors */
static rct::keyV vector_add(const rct::keyV &a, const rct::key &b)
{
  rct::keyV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_add(res[i].bytes, a[i].bytes, b.bytes);
  }
  return res;
}

static rct::keyV vector_add(const rct::keyV &a, const rct::keyV &b)
{
  CHECK_AND_ASSERT_THROW_MES(a.size() == b.size(), "Incompatible sizes of a and b");
  rct::keyV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_add(res[i].bytes, a[i].bytes, b[i].bytes);
  }
  return res;
}

/* Subtract two vectors */
static rct::keyV vector_subtract(const rct::keyV &a, const rct::key &b)
{
  rct::keyV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_sub(res[i].bytes, a[i].bytes, b.bytes);
  }
  return res;
}

static rct::keyV vector_subtract(const rct::keyV &a, const rct::keyV &b)
{
  CHECK_AND_ASSERT_THROW_MES(a.size() == b.size(), "Incompatible sizes of a and b");
  rct::keyV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_sub(res[i].bytes, a[i].bytes, b[i].bytes);
  }
  return res;
}

/* Multiply a scalar and a vector */
static rct::keyV vector_scalar_v1(const rct::keyV &a, const rct::key &x)
{
  rct::keyV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_mul(res[i].bytes, a[i].bytes, x.bytes);
  }
  return res;
}

static rct::keyV vector_scalar_v2(const epee::span<const rct::key> &a, const rct::key &x)
{
  rct::keyV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    sc_mul(res[i].bytes, a[i].bytes, x.bytes);
  }
  return res;
}

static rct::keyV vector_scalar_v2(const rct::keyV &a, const rct::key &x)
{
  return vector_scalar_v2(epee::span<const rct::key>(a.data(), a.size()), x);
}

/* Exponentiate a curve vector by a scalar */
static rct::keyV vector_scalar2_v1(const rct::keyV &a, const rct::key &x)
{
  rct::keyV res(a.size());
  for (size_t i = 0; i < a.size(); ++i)
  {
    rct::scalarmultKey(res[i], a[i], x);
  }
  return res;
}

static rct::keyV vector_dup(const rct::key &x, size_t N)
{
  return rct::keyV(N, x);
}

static rct::key sm(rct::key y, int n, const rct::key &x)
{
  while (n--)
    sc_mul(y.bytes, y.bytes, y.bytes);
  sc_mul(y.bytes, y.bytes, x.bytes);
  return y;
}

static rct::key switch_endianness(rct::key k)
{
  std::reverse(k.bytes, k.bytes + sizeof(k));
  return k;
}

/* Compute the inverse of a scalar, the stupid way */
static rct::key invert_v1(const rct::key &x)
{
  rct::key inv;

  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *X = BN_new();
  BIGNUM *L = BN_new();
  BIGNUM *I = BN_new();

  BN_bin2bn(switch_endianness(x).bytes, sizeof(rct::key), X);
  BN_bin2bn(switch_endianness(rct::curveOrder()).bytes, sizeof(rct::key), L);

  CHECK_AND_ASSERT_THROW_MES(BN_mod_inverse(I, X, L, ctx), "Failed to invert");

  const int len = BN_num_bytes(I);
  CHECK_AND_ASSERT_THROW_MES((size_t)len <= sizeof(rct::key), "Invalid number length");
  inv = rct::zero();
  BN_bn2bin(I, inv.bytes);
  std::reverse(inv.bytes, inv.bytes + len);

  BN_free(I);
  BN_free(L);
  BN_free(X);
  BN_CTX_free(ctx);

#ifdef DEBUG_BP
  rct::key tmp;
  sc_mul(tmp.bytes, inv.bytes, x.bytes);
  CHECK_AND_ASSERT_THROW_MES(tmp == rct::identity(), "invert failed");
#endif
  return inv;
}

static rct::key invert_v2(const rct::key &x)
{
  rct::key _1, _10, _100, _11, _101, _111, _1001, _1011, _1111;

  _1 = x;
  sc_mul(_10.bytes, _1.bytes, _1.bytes);
  sc_mul(_100.bytes, _10.bytes, _10.bytes);
  sc_mul(_11.bytes, _10.bytes, _1.bytes);
  sc_mul(_101.bytes, _10.bytes, _11.bytes);
  sc_mul(_111.bytes, _10.bytes, _101.bytes);
  sc_mul(_1001.bytes, _10.bytes, _111.bytes);
  sc_mul(_1011.bytes, _10.bytes, _1001.bytes);
  sc_mul(_1111.bytes, _100.bytes, _1011.bytes);

  rct::key inv;
  sc_mul(inv.bytes, _1111.bytes, _1.bytes);

  inv = sm(inv, 123 + 3, _101);
  inv = sm(inv, 2 + 2, _11);
  inv = sm(inv, 1 + 4, _1111);
  inv = sm(inv, 1 + 4, _1111);
  inv = sm(inv, 4, _1001);
  inv = sm(inv, 2, _11);
  inv = sm(inv, 1 + 4, _1111);
  inv = sm(inv, 1 + 3, _101);
  inv = sm(inv, 3 + 3, _101);
  inv = sm(inv, 3, _111);
  inv = sm(inv, 1 + 4, _1111);
  inv = sm(inv, 2 + 3, _111);
  inv = sm(inv, 2 + 2, _11);
  inv = sm(inv, 1 + 4, _1011);
  inv = sm(inv, 2 + 4, _1011);
  inv = sm(inv, 6 + 4, _1001);
  inv = sm(inv, 2 + 2, _11);
  inv = sm(inv, 3 + 2, _11);
  inv = sm(inv, 3 + 2, _11);
  inv = sm(inv, 1 + 4, _1001);
  inv = sm(inv, 1 + 3, _111);
  inv = sm(inv, 2 + 4, _1111);
  inv = sm(inv, 1 + 4, _1011);
  inv = sm(inv, 3, _101);
  inv = sm(inv, 2 + 4, _1111);
  inv = sm(inv, 3, _101);
  inv = sm(inv, 1 + 2, _11);

#ifdef DEBUG_BP
  rct::key tmp;
  sc_mul(tmp.bytes, inv.bytes, x.bytes);
  CHECK_AND_ASSERT_THROW_MES(tmp == rct::identity(), "invert failed");
#endif
  return inv;
}

static rct::keyV invert_v2(rct::keyV x)
{
  rct::keyV scratch;
  scratch.reserve(x.size());

  rct::key acc = rct::identity();
  for (size_t n = 0; n < x.size(); ++n)
  {
    scratch.push_back(acc);
    if (n == 0)
      acc = x[0];
    else
      sc_mul(acc.bytes, acc.bytes, x[n].bytes);
  }

  acc = invert_v2(acc);

  rct::key tmp;
  for (int i = x.size(); i-- > 0; )
  {
    sc_mul(tmp.bytes, acc.bytes, x[i].bytes);
    sc_mul(x[i].bytes, acc.bytes, scratch[i].bytes);
    acc = tmp;
  }

  return x;
}

/* Compute the slice of a vector */
static rct::keyV slice_v1(const rct::keyV &a, size_t start, size_t stop)
{
  CHECK_AND_ASSERT_THROW_MES(start < a.size(), "Invalid start index");
  CHECK_AND_ASSERT_THROW_MES(stop <= a.size(), "Invalid stop index");
  CHECK_AND_ASSERT_THROW_MES(start < stop, "Invalid start/stop indices");
  rct::keyV res(stop - start);
  for (size_t i = start; i < stop; ++i)
  {
    res[i - start] = a[i];
  }
  return res;
}

static epee::span<const rct::key> slice_v2(const rct::keyV &a, size_t start, size_t stop)
{
  CHECK_AND_ASSERT_THROW_MES(start < a.size(), "Invalid start index");
  CHECK_AND_ASSERT_THROW_MES(stop <= a.size(), "Invalid stop index");
  CHECK_AND_ASSERT_THROW_MES(start < stop, "Invalid start/stop indices");
  return epee::span<const rct::key>(&a[start], stop - start);
}

static rct::key hash_cache_mash(rct::key &hash_cache, const rct::key &mash0, const rct::key &mash1)
{
  rct::keyV data;
  data.reserve(3);
  data.push_back(hash_cache);
  data.push_back(mash0);
  data.push_back(mash1);
  return hash_cache = rct::hash_to_scalar(data);
}

static rct::key hash_cache_mash(rct::key &hash_cache, const rct::key &mash0, const rct::key &mash1, const rct::key &mash2)
{
  rct::keyV data;
  data.reserve(4);
  data.push_back(hash_cache);
  data.push_back(mash0);
  data.push_back(mash1);
  data.push_back(mash2);
  return hash_cache = rct::hash_to_scalar(data);
}

static rct::key hash_cache_mash(rct::key &hash_cache, const rct::key &mash0, const rct::key &mash1, const rct::key &mash2, const rct::key &mash3)
{
  rct::keyV data;
  data.reserve(5);
  data.push_back(hash_cache);
  data.push_back(mash0);
  data.push_back(mash1);
  data.push_back(mash2);
  data.push_back(mash3);
  return hash_cache = rct::hash_to_scalar(data);
}

Bulletproof bulletproof_PROVE(const rct::key &sv, const rct::key &gamma, bool v2)
{
  if (v2)
    return bulletproof_PROVE_v2(sv, gamma);
  else
    return bulletproof_PROVE_v1(sv, gamma);
}

/* Given a value v (0..2^N-1) and a mask gamma, construct a range proof */
Bulletproof bulletproof_PROVE_v1(const rct::key &sv, const rct::key &gamma)
{
  init_exponents_v1();

  PERF_TIMER_UNIT(PROVE, 1000000);

  constexpr size_t logN = 6; // log2(64)
  constexpr size_t N = 1<<logN;

  rct::key V;
  rct::keyV aL(N), aR(N);

  PERF_TIMER_START_BP(PROVE_v);
  rct::addKeys2(V, gamma, sv, rct::H);
  PERF_TIMER_STOP_BP(PROVE_v);

  PERF_TIMER_START_BP(PROVE_aLaR);
  for (size_t i = N; i-- > 0; )
  {
    if (sv[i/8] & (((uint64_t)1)<<(i%8)))
    {
      aL[i] = rct::identity();
    }
    else
    {
      aL[i] = rct::zero();
    }
    sc_sub(aR[i].bytes, aL[i].bytes, rct::identity().bytes);
  }
  PERF_TIMER_STOP_BP(PROVE_aLaR);

  rct::key hash_cache = rct::hash_to_scalar(V);

  // DEBUG: Test to ensure this recovers the value
#ifdef DEBUG_BP
  uint64_t test_aL = 0, test_aR = 0;
  for (size_t i = 0; i < N; ++i)
  {
    if (aL[i] == rct::identity())
      test_aL += ((uint64_t)1)<<i;
    if (aR[i] == rct::zero())
      test_aR += ((uint64_t)1)<<i;
  }
  uint64_t v_test = 0;
  for (int n = 0; n < 8; ++n) v_test |= (((uint64_t)sv[n]) << (8*n));
  CHECK_AND_ASSERT_THROW_MES(test_aL == v_test, "test_aL failed");
  CHECK_AND_ASSERT_THROW_MES(test_aR == v_test, "test_aR failed");
#endif

  PERF_TIMER_START_BP(PROVE_step1);
  // PAPER LINES 38-39
  rct::key alpha = rct::skGen();
  rct::key ve = vector_exponent_v1(aL, aR);
  rct::key A;
  rct::addKeys(A, ve, rct::scalarmultBase(alpha));

  // PAPER LINES 40-42
  rct::keyV sL = rct::skvGen(N), sR = rct::skvGen(N);
  rct::key rho = rct::skGen();
  ve = vector_exponent_v1(sL, sR);
  rct::key S;
  rct::addKeys(S, ve, rct::scalarmultBase(rho));

  // PAPER LINES 43-45
  rct::key y = hash_cache_mash(hash_cache, A, S);
  rct::key z = hash_cache = rct::hash_to_scalar(y);

  // Polynomial construction before PAPER LINE 46
  rct::key t0 = rct::zero();
  rct::key t1 = rct::zero();
  rct::key t2 = rct::zero();

  const auto yN = vector_powers(y, N);

  rct::key ip1y = inner_product_v1(oneN_v1, yN);
  rct::key tmp;
  sc_muladd(t0.bytes, z.bytes, ip1y.bytes, t0.bytes);

  rct::key zsq;
  sc_mul(zsq.bytes, z.bytes, z.bytes);
  sc_muladd(t0.bytes, zsq.bytes, sv.bytes, t0.bytes);

  rct::key k = rct::zero();
  sc_mulsub(k.bytes, zsq.bytes, ip1y.bytes, k.bytes);

  rct::key zcu;
  sc_mul(zcu.bytes, zsq.bytes, z.bytes);
  sc_mulsub(k.bytes, zcu.bytes, ip12_v1.bytes, k.bytes);
  sc_add(t0.bytes, t0.bytes, k.bytes);

  // DEBUG: Test the value of t0 has the correct form
#ifdef DEBUG_BP
  rct::key test_t0 = rct::zero();
  rct::key iph = inner_product(aL, hadamard(aR, yN));
  sc_add(test_t0.bytes, test_t0.bytes, iph.bytes);
  rct::key ips = inner_product(vector_subtract(aL, aR), yN);
  sc_muladd(test_t0.bytes, z.bytes, ips.bytes, test_t0.bytes);
  rct::key ipt = inner_product(twoN, aL);
  sc_muladd(test_t0.bytes, zsq.bytes, ipt.bytes, test_t0.bytes);
  sc_add(test_t0.bytes, test_t0.bytes, k.bytes);
  CHECK_AND_ASSERT_THROW_MES(t0 == test_t0, "t0 check failed");
#endif
  PERF_TIMER_STOP_BP(PROVE_step1);

  PERF_TIMER_START_BP(PROVE_step2);
  const auto HyNsR = hadamard(yN, sR);
  const auto vpIz = vector_scalar_v1(oneN_v1, z);
  const auto vp2zsq = vector_scalar_v1(twoN, zsq);
  const auto aL_vpIz = vector_subtract(aL, vpIz);
  const auto aR_vpIz = vector_add(aR, vpIz);

  rct::key ip1 = inner_product_v1(aL_vpIz, HyNsR);
  sc_add(t1.bytes, t1.bytes, ip1.bytes);

  rct::key ip2 = inner_product_v1(sL, vector_add(hadamard(yN, aR_vpIz), vp2zsq));
  sc_add(t1.bytes, t1.bytes, ip2.bytes);

  rct::key ip3 = inner_product_v1(sL, HyNsR);
  sc_add(t2.bytes, t2.bytes, ip3.bytes);

  // PAPER LINES 47-48
  rct::key tau1 = rct::skGen(), tau2 = rct::skGen();

  rct::key T1 = rct::addKeys(rct::scalarmultKey(rct::H, t1), rct::scalarmultBase(tau1));
  rct::key T2 = rct::addKeys(rct::scalarmultKey(rct::H, t2), rct::scalarmultBase(tau2));

  // PAPER LINES 49-51
  rct::key x = hash_cache_mash(hash_cache, z, T1, T2);

  // PAPER LINES 52-53
  rct::key taux = rct::zero();
  sc_mul(taux.bytes, tau1.bytes, x.bytes);
  rct::key xsq;
  sc_mul(xsq.bytes, x.bytes, x.bytes);
  sc_muladd(taux.bytes, tau2.bytes, xsq.bytes, taux.bytes);
  sc_muladd(taux.bytes, gamma.bytes, zsq.bytes, taux.bytes);
  rct::key mu;
  sc_muladd(mu.bytes, x.bytes, rho.bytes, alpha.bytes);

  // PAPER LINES 54-57
  rct::keyV l = vector_add(aL_vpIz, vector_scalar_v1(sL, x));
  rct::keyV r = vector_add(hadamard(yN, vector_add(aR_vpIz, vector_scalar_v1(sR, x))), vp2zsq);
  PERF_TIMER_STOP_BP(PROVE_step2);

  PERF_TIMER_START_BP(PROVE_step3);
  rct::key t = inner_product_v1(l, r);

  // DEBUG: Test if the l and r vectors match the polynomial forms
#ifdef DEBUG_BP
  rct::key test_t;
  sc_muladd(test_t.bytes, t1.bytes, x.bytes, t0.bytes);
  sc_muladd(test_t.bytes, t2.bytes, xsq.bytes, test_t.bytes);
  CHECK_AND_ASSERT_THROW_MES(test_t == t, "test_t check failed");
#endif

  // PAPER LINES 32-33
  rct::key x_ip = hash_cache_mash(hash_cache, x, taux, mu, t);

  // These are used in the inner product rounds
  size_t nprime = N;
  rct::keyV Gprime(N);
  rct::keyV Hprime(N);
  rct::keyV aprime(N);
  rct::keyV bprime(N);
  const rct::key yinv = invert_v1(y);
  rct::key yinvpow = rct::identity();
  for (size_t i = 0; i < N; ++i)
  {
    Gprime[i] = Gi_v1[i];
    Hprime[i] = scalarmultKey(Hi_v1[i], yinvpow);
    sc_mul(yinvpow.bytes, yinvpow.bytes, yinv.bytes);
    aprime[i] = l[i];
    bprime[i] = r[i];
  }
  rct::keyV L(logN);
  rct::keyV R(logN);
  int round = 0;
  rct::keyV w(logN); // this is the challenge x in the inner product protocol
  PERF_TIMER_STOP_BP(PROVE_step3);

  PERF_TIMER_START_BP(PROVE_step4);
  // PAPER LINE 13
  while (nprime > 1)
  {
    // PAPER LINE 15
    nprime /= 2;

    // PAPER LINES 16-17
    rct::key cL = inner_product_v1(slice_v1(aprime, 0, nprime), slice_v1(bprime, nprime, bprime.size()));
    rct::key cR = inner_product_v1(slice_v1(aprime, nprime, aprime.size()), slice_v1(bprime, 0, nprime));

    // PAPER LINES 18-19
    L[round] = vector_exponent_custom(slice_v1(Gprime, nprime, Gprime.size()), slice_v1(Hprime, 0, nprime), slice_v1(aprime, 0, nprime), slice_v1(bprime, nprime, bprime.size()));
    sc_mul(tmp.bytes, cL.bytes, x_ip.bytes);
    rct::addKeys(L[round], L[round], rct::scalarmultKey(rct::H, tmp));
    R[round] = vector_exponent_custom(slice_v1(Gprime, 0, nprime), slice_v1(Hprime, nprime, Hprime.size()), slice_v1(aprime, nprime, aprime.size()), slice_v1(bprime, 0, nprime));
    sc_mul(tmp.bytes, cR.bytes, x_ip.bytes);
    rct::addKeys(R[round], R[round], rct::scalarmultKey(rct::H, tmp));

    // PAPER LINES 21-22
    w[round] = hash_cache_mash(hash_cache, L[round], R[round]);

    // PAPER LINES 24-25
    const rct::key winv = invert_v1(w[round]);
    Gprime = hadamard2(vector_scalar2_v1(slice_v1(Gprime, 0, nprime), winv), vector_scalar2_v1(slice_v1(Gprime, nprime, Gprime.size()), w[round]));
    Hprime = hadamard2(vector_scalar2_v1(slice_v1(Hprime, 0, nprime), w[round]), vector_scalar2_v1(slice_v1(Hprime, nprime, Hprime.size()), winv));

    // PAPER LINES 28-29
    aprime = vector_add(vector_scalar_v1(slice_v1(aprime, 0, nprime), w[round]), vector_scalar_v1(slice_v1(aprime, nprime, aprime.size()), winv));
    bprime = vector_add(vector_scalar_v1(slice_v1(bprime, 0, nprime), winv), vector_scalar_v1(slice_v1(bprime, nprime, bprime.size()), w[round]));

    ++round;
  }
  PERF_TIMER_STOP_BP(PROVE_step4);

  // PAPER LINE 58 (with inclusions from PAPER LINE 8 and PAPER LINE 20)
  return Bulletproof(V, A, S, T1, T2, taux, mu, L, R, aprime[0], bprime[0], t);
}

Bulletproof bulletproof_PROVE_v2(const rct::key &sv, const rct::key &gamma)
{
  return bulletproof_PROVE_v2(rct::keyV(1, sv), rct::keyV(1, gamma));
}

Bulletproof bulletproof_PROVE(uint64_t v, const rct::key &gamma, bool v2) {
  if (v2)
    return bulletproof_PROVE_v2(v, gamma);
  else
    return bulletproof_PROVE_v1(v, gamma);
}

Bulletproof bulletproof_PROVE_v1(uint64_t v, const rct::key &gamma)
{
  // vG + gammaH
  PERF_TIMER_START_BP(PROVE_v);
  rct::key sv = rct::zero();
  sv.bytes[0] = v & 255;
  sv.bytes[1] = (v >> 8) & 255;
  sv.bytes[2] = (v >> 16) & 255;
  sv.bytes[3] = (v >> 24) & 255;
  sv.bytes[4] = (v >> 32) & 255;
  sv.bytes[5] = (v >> 40) & 255;
  sv.bytes[6] = (v >> 48) & 255;
  sv.bytes[7] = (v >> 56) & 255;
  PERF_TIMER_STOP_BP(PROVE_v);
  return bulletproof_PROVE_v1(sv, gamma);
}

Bulletproof bulletproof_PROVE_v2(uint64_t v, const rct::key &gamma)
{
  return bulletproof_PROVE_v2(std::vector<uint64_t>(1, v), rct::keyV(1, gamma));
}

Bulletproof bulletproof_PROVE_v2(const rct::keyV &sv, const rct::keyV &gamma)
{
  CHECK_AND_ASSERT_THROW_MES(sv.size() == gamma.size(), "Incompatible sizes of sv and gamma");
  CHECK_AND_ASSERT_THROW_MES(!sv.empty(), "sv is empty");
  for (const rct::key &sve: sv)
    CHECK_AND_ASSERT_THROW_MES(is_reduced(sve), "Invalid sv input");
  for (const rct::key &g: gamma)
    CHECK_AND_ASSERT_THROW_MES(is_reduced(g), "Invalid gamma input");

  init_exponents_v2();

  PERF_TIMER_UNIT(PROVE, 1000000);

  constexpr size_t logN = 6; // log2(64)
  constexpr size_t N = 1<<logN;
  size_t M, logM;
  for (logM = 0; (M = 1<<logM) <= maxM && M < sv.size(); ++logM);
  CHECK_AND_ASSERT_THROW_MES(M <= maxM, "sv/gamma are too large");
  const size_t logMN = logM + logN;
  const size_t MN = M * N;

  rct::keyV V(sv.size());
  rct::keyV aL(MN), aR(MN);
  rct::keyV aL8(MN), aR8(MN);
  rct::key tmp, tmp2;

  PERF_TIMER_START_BP(PROVE_v);
  for (size_t i = 0; i < sv.size(); ++i)
  {
    rct::key gamma8, sv8;
    sc_mul(gamma8.bytes, gamma[i].bytes, INV_EIGHT.bytes);
    sc_mul(sv8.bytes, sv[i].bytes, INV_EIGHT.bytes);
    rct::addKeys2(V[i], gamma8, sv8, rct::H);
  }
  PERF_TIMER_STOP_BP(PROVE_v);

  PERF_TIMER_START_BP(PROVE_aLaR);
  for (size_t j = 0; j < M; ++j)
  {
    for (size_t i = N; i-- > 0; )
    {
      if (j < sv.size() && (sv[j][i/8] & (((uint64_t)1)<<(i%8))))
      {
        aL[j*N+i] = rct::identity();
        aL8[j*N+i] = INV_EIGHT;
        aR[j*N+i] = aR8[j*N+i] = rct::zero();
      }
      else
      {
        aL[j*N+i] = aL8[j*N+i] = rct::zero();
        aR[j*N+i] = MINUS_ONE;
        aR8[j*N+i] = MINUS_INV_EIGHT;
      }
    }
  }
  PERF_TIMER_STOP_BP(PROVE_aLaR);

  // DEBUG: Test to ensure this recovers the value
#ifdef DEBUG_BP
  for (size_t j = 0; j < M; ++j)
  {
    uint64_t test_aL = 0, test_aR = 0;
    for (size_t i = 0; i < N; ++i)
    {
      if (aL[j*N+i] == rct::identity())
        test_aL += ((uint64_t)1)<<i;
      if (aR[j*N+i] == rct::zero())
        test_aR += ((uint64_t)1)<<i;
    }
    uint64_t v_test = 0;
    if (j < sv.size())
      for (int n = 0; n < 8; ++n) v_test |= (((uint64_t)sv[j][n]) << (8*n));
    CHECK_AND_ASSERT_THROW_MES(test_aL == v_test, "test_aL failed");
    CHECK_AND_ASSERT_THROW_MES(test_aR == v_test, "test_aR failed");
  }
#endif

try_again:
  rct::key hash_cache = rct::hash_to_scalar(V);

  PERF_TIMER_START_BP(PROVE_step1);
  // PAPER LINES 38-39
  rct::key alpha = rct::skGen();
  rct::key ve = vector_exponent_v2(aL8, aR8);
  rct::key A;
  sc_mul(tmp.bytes, alpha.bytes, INV_EIGHT.bytes);
  rct::addKeys(A, ve, rct::scalarmultBase(tmp));

  // PAPER LINES 40-42
  rct::keyV sL = rct::skvGen(MN), sR = rct::skvGen(MN);
  rct::key rho = rct::skGen();
  ve = vector_exponent_v2(sL, sR);
  rct::key S;
  rct::addKeys(S, ve, rct::scalarmultBase(rho));
  S = rct::scalarmultKey(S, INV_EIGHT);

  // PAPER LINES 43-45
  rct::key y = hash_cache_mash(hash_cache, A, S);
  if (y == rct::zero())
  {
    PERF_TIMER_STOP_BP(PROVE_step1);
    MINFO("y is 0, trying again");
    goto try_again;
  }
  rct::key z = hash_cache = rct::hash_to_scalar(y);
  if (z == rct::zero())
  {
    PERF_TIMER_STOP_BP(PROVE_step1);
    MINFO("z is 0, trying again");
    goto try_again;
  }

  // Polynomial construction by coefficients
  rct::keyV l0 = vector_subtract(aL, z);
  const rct::keyV &l1 = sL;

  // This computes the ugly sum/concatenation from PAPER LINE 65
  rct::keyV zero_twos(MN);
  const rct::keyV zpow = vector_powers(z, M+2);
  for (size_t i = 0; i < MN; ++i)
  {
    zero_twos[i] = rct::zero();
    for (size_t j = 1; j <= M; ++j)
    {
      if (i >= (j-1)*N && i < j*N)
      {
        CHECK_AND_ASSERT_THROW_MES(1+j < zpow.size(), "invalid zpow index");
        CHECK_AND_ASSERT_THROW_MES(i-(j-1)*N < twoN.size(), "invalid twoN index");
        sc_muladd(zero_twos[i].bytes, zpow[1+j].bytes, twoN[i-(j-1)*N].bytes, zero_twos[i].bytes);
      }
    }
  }

  rct::keyV r0 = vector_add(aR, z);
  const auto yMN = vector_powers(y, MN);
  r0 = hadamard(r0, yMN);
  r0 = vector_add(r0, zero_twos);
  rct::keyV r1 = hadamard(yMN, sR);

  // Polynomial construction before PAPER LINE 46
  rct::key t1_1 = inner_product_v2(l0, r1);
  rct::key t1_2 = inner_product_v2(l1, r0);
  rct::key t1;
  sc_add(t1.bytes, t1_1.bytes, t1_2.bytes);
  rct::key t2 = inner_product_v2(l1, r1);

  PERF_TIMER_STOP_BP(PROVE_step1);

  PERF_TIMER_START_BP(PROVE_step2);
  // PAPER LINES 47-48
  rct::key tau1 = rct::skGen(), tau2 = rct::skGen();

  rct::key T1, T2;
  ge_p3 p3;
  sc_mul(tmp.bytes, t1.bytes, INV_EIGHT.bytes);
  sc_mul(tmp2.bytes, tau1.bytes, INV_EIGHT.bytes);
  ge_double_scalarmult_base_vartime_p3(&p3, tmp.bytes, &ge_p3_H, tmp2.bytes);
  ge_p3_tobytes(T1.bytes, &p3);
  sc_mul(tmp.bytes, t2.bytes, INV_EIGHT.bytes);
  sc_mul(tmp2.bytes, tau2.bytes, INV_EIGHT.bytes);
  ge_double_scalarmult_base_vartime_p3(&p3, tmp.bytes, &ge_p3_H, tmp2.bytes);
  ge_p3_tobytes(T2.bytes, &p3);

  // PAPER LINES 49-51
  rct::key x = hash_cache_mash(hash_cache, z, T1, T2);
  if (x == rct::zero())
  {
    PERF_TIMER_STOP_BP(PROVE_step2);
    MINFO("x is 0, trying again");
    goto try_again;
  }

  // PAPER LINES 52-53
  rct::key taux;
  sc_mul(taux.bytes, tau1.bytes, x.bytes);
  rct::key xsq;
  sc_mul(xsq.bytes, x.bytes, x.bytes);
  sc_muladd(taux.bytes, tau2.bytes, xsq.bytes, taux.bytes);
  for (size_t j = 1; j <= sv.size(); ++j)
  {
    CHECK_AND_ASSERT_THROW_MES(j+1 < zpow.size(), "invalid zpow index");
    sc_muladd(taux.bytes, zpow[j+1].bytes, gamma[j-1].bytes, taux.bytes);
  }
  rct::key mu;
  sc_muladd(mu.bytes, x.bytes, rho.bytes, alpha.bytes);

  // PAPER LINES 54-57
  rct::keyV l = l0;
  l = vector_add(l, vector_scalar_v2(l1, x));
  rct::keyV r = r0;
  r = vector_add(r, vector_scalar_v2(r1, x));
  PERF_TIMER_STOP_BP(PROVE_step2);

  PERF_TIMER_START_BP(PROVE_step3);
  rct::key t = inner_product_v2(l, r);

  // DEBUG: Test if the l and r vectors match the polynomial forms
#ifdef DEBUG_BP
  rct::key test_t;
  const rct::key t0 = inner_product(l0, r0);
  sc_muladd(test_t.bytes, t1.bytes, x.bytes, t0.bytes);
  sc_muladd(test_t.bytes, t2.bytes, xsq.bytes, test_t.bytes);
  CHECK_AND_ASSERT_THROW_MES(test_t == t, "test_t check failed");
#endif

  // PAPER LINES 32-33
  rct::key x_ip = hash_cache_mash(hash_cache, x, taux, mu, t);
  if (x_ip == rct::zero())
  {
    PERF_TIMER_STOP_BP(PROVE_step3);
    MINFO("x_ip is 0, trying again");
    goto try_again;
  }

  // These are used in the inner product rounds
  size_t nprime = MN;
  std::vector<ge_p3> Gprime(MN);
  std::vector<ge_p3> Hprime(MN);
  rct::keyV aprime(MN);
  rct::keyV bprime(MN);
  const rct::key yinv = invert_v2(y);
  rct::keyV yinvpow(MN);
  yinvpow[0] = rct::identity();
  yinvpow[1] = yinv;
  for (size_t i = 0; i < MN; ++i)
  {
    Gprime[i] = Gi_p3[i];
    Hprime[i] = Hi_p3[i];
    if (i > 1)
      sc_mul(yinvpow[i].bytes, yinvpow[i-1].bytes, yinv.bytes);
    aprime[i] = l[i];
    bprime[i] = r[i];
  }
  rct::keyV L(logMN);
  rct::keyV R(logMN);
  int round = 0;
  rct::keyV w(logMN); // this is the challenge x in the inner product protocol
  PERF_TIMER_STOP_BP(PROVE_step3);

  PERF_TIMER_START_BP(PROVE_step4);
  // PAPER LINE 13
  const rct::keyV *scale = &yinvpow;
  while (nprime > 1)
  {
    // PAPER LINE 15
    nprime /= 2;

    // PAPER LINES 16-17
    PERF_TIMER_START_BP(PROVE_inner_product);
    rct::key cL = inner_product_v2(slice_v2(aprime, 0, nprime), slice_v2(bprime, nprime, bprime.size()));
    rct::key cR = inner_product_v2(slice_v2(aprime, nprime, aprime.size()), slice_v2(bprime, 0, nprime));
    PERF_TIMER_STOP_BP(PROVE_inner_product);

    // PAPER LINES 18-19
    PERF_TIMER_START_BP(PROVE_LR);
    sc_mul(tmp.bytes, cL.bytes, x_ip.bytes);
    L[round] = cross_vector_exponent8(nprime, Gprime, nprime, Hprime, 0, aprime, 0, bprime, nprime, scale, &ge_p3_H, &tmp);
    sc_mul(tmp.bytes, cR.bytes, x_ip.bytes);
    R[round] = cross_vector_exponent8(nprime, Gprime, 0, Hprime, nprime, aprime, nprime, bprime, 0, scale, &ge_p3_H, &tmp);
    PERF_TIMER_STOP_BP(PROVE_LR);

    // PAPER LINES 21-22
    w[round] = hash_cache_mash(hash_cache, L[round], R[round]);
    if (w[round] == rct::zero())
    {
      PERF_TIMER_STOP_BP(PROVE_step4);
      MINFO("w[round] is 0, trying again");
      goto try_again;
    }

    // PAPER LINES 24-25
    const rct::key winv = invert_v2(w[round]);
    if (nprime > 1)
    {
      PERF_TIMER_START_BP(PROVE_hadamard2);
      hadamard_fold(Gprime, NULL, winv, w[round]);
      hadamard_fold(Hprime, scale, w[round], winv);
      PERF_TIMER_STOP_BP(PROVE_hadamard2);
    }

    // PAPER LINES 28-29
    PERF_TIMER_START_BP(PROVE_prime);
    aprime = vector_add(vector_scalar_v2(slice_v2(aprime, 0, nprime), w[round]), vector_scalar_v2(slice_v2(aprime, nprime, aprime.size()), winv));
    bprime = vector_add(vector_scalar_v2(slice_v2(bprime, 0, nprime), winv), vector_scalar_v2(slice_v2(bprime, nprime, bprime.size()), w[round]));
    PERF_TIMER_STOP_BP(PROVE_prime);

    scale = NULL;
    ++round;
  }
  PERF_TIMER_STOP_BP(PROVE_step4);

  // PAPER LINE 58 (with inclusions from PAPER LINE 8 and PAPER LINE 20)
  return Bulletproof(std::move(V), A, S, T1, T2, taux, mu, std::move(L), std::move(R), aprime[0], bprime[0], t);
}

Bulletproof bulletproof_PROVE_v2(const std::vector<uint64_t> &v, const rct::keyV &gamma)
{
  CHECK_AND_ASSERT_THROW_MES(v.size() == gamma.size(), "Incompatible sizes of v and gamma");

  // vG + gammaH
  PERF_TIMER_START_BP(PROVE_v);
  rct::keyV sv(v.size());
  for (size_t i = 0; i < v.size(); ++i)
  {
    sv[i] = rct::zero();
    sv[i].bytes[0] = v[i] & 255;
    sv[i].bytes[1] = (v[i] >> 8) & 255;
    sv[i].bytes[2] = (v[i] >> 16) & 255;
    sv[i].bytes[3] = (v[i] >> 24) & 255;
    sv[i].bytes[4] = (v[i] >> 32) & 255;
    sv[i].bytes[5] = (v[i] >> 40) & 255;
    sv[i].bytes[6] = (v[i] >> 48) & 255;
    sv[i].bytes[7] = (v[i] >> 56) & 255;
  }
  PERF_TIMER_STOP_BP(PROVE_v);
  return bulletproof_PROVE_v2(sv, gamma);
}

struct proof_data_t
{
  rct::key x, y, z, x_ip;
  std::vector<rct::key> w;
  size_t logM, inv_offset;
};

bool bulletproof_VERIFY(const Bulletproof &proof, bool v2)
{
  if (v2)
    return bulletproof_VERIFY_v2(proof);
  else
    return bulletproof_VERIFY_v1(proof);
}

/* Given a range proof, determine if it is valid */
bool bulletproof_VERIFY_v1(const Bulletproof &proof)
{
  init_exponents_v1();

  CHECK_AND_ASSERT_MES(proof.V.size() == 1, false, "V does not have exactly one element");
  CHECK_AND_ASSERT_MES(proof.L.size() == proof.R.size(), false, "Mismatched L and R sizes");
  CHECK_AND_ASSERT_MES(proof.L.size() > 0, false, "Empty proof");
  CHECK_AND_ASSERT_MES(proof.L.size() == 6, false, "Proof is not for 64 bits");

  const size_t logN = proof.L.size();
  const size_t N = 1 << logN;

  // Reconstruct the challenges
  PERF_TIMER_START_BP(VERIFY);
  PERF_TIMER_START_BP(VERIFY_start);
  rct::key hash_cache = rct::hash_to_scalar(proof.V[0]);
  rct::key y = hash_cache_mash(hash_cache, proof.A, proof.S);
  rct::key z = hash_cache = rct::hash_to_scalar(y);
  rct::key x = hash_cache_mash(hash_cache, z, proof.T1, proof.T2);
  PERF_TIMER_STOP_BP(VERIFY_start);

  PERF_TIMER_START_BP(VERIFY_line_60);
  // Reconstruct the challenges
  rct::key x_ip = hash_cache_mash(hash_cache, x, proof.taux, proof.mu, proof.t);
  PERF_TIMER_STOP_BP(VERIFY_line_60);

  PERF_TIMER_START_BP(VERIFY_line_61);
  // PAPER LINE 61
  rct::key L61Left = rct::addKeys(rct::scalarmultBase(proof.taux), rct::scalarmultKey(rct::H, proof.t));

  rct::key k = rct::zero();
  const auto yN = vector_powers(y, N);
  rct::key ip1y = inner_product_v1(oneN_v1, yN);
  rct::key zsq;
  sc_mul(zsq.bytes, z.bytes, z.bytes);
  rct::key tmp, tmp2;
  sc_mulsub(k.bytes, zsq.bytes, ip1y.bytes, k.bytes);
  rct::key zcu;
  sc_mul(zcu.bytes, zsq.bytes, z.bytes);
  sc_mulsub(k.bytes, zcu.bytes, ip12_v1.bytes, k.bytes);
  PERF_TIMER_STOP_BP(VERIFY_line_61);

  PERF_TIMER_START_BP(VERIFY_line_61rl);
  sc_muladd(tmp.bytes, z.bytes, ip1y.bytes, k.bytes);
  rct::key L61Right = rct::scalarmultKey(rct::H, tmp);

  CHECK_AND_ASSERT_MES(proof.V.size() == 1, false, "proof.V does not have exactly one element");
  tmp = rct::scalarmultKey(proof.V[0], zsq);
  rct::addKeys(L61Right, L61Right, tmp);

  tmp = rct::scalarmultKey(proof.T1, x);
  rct::addKeys(L61Right, L61Right, tmp);

  rct::key xsq;
  sc_mul(xsq.bytes, x.bytes, x.bytes);
  tmp = rct::scalarmultKey(proof.T2, xsq);
  rct::addKeys(L61Right, L61Right, tmp);
  PERF_TIMER_STOP_BP(VERIFY_line_61rl);

  if (!(L61Right == L61Left))
  {
    MERROR("Verification failure at step 1");
    return false;
  }

  PERF_TIMER_START_BP(VERIFY_line_62);
  // PAPER LINE 62
  rct::key P = rct::addKeys(proof.A, rct::scalarmultKey(proof.S, x));
  PERF_TIMER_STOP_BP(VERIFY_line_62);

  // Compute the number of rounds for the inner product
  const size_t rounds = proof.L.size();
  CHECK_AND_ASSERT_MES(rounds > 0, false, "Zero rounds");

  PERF_TIMER_START_BP(VERIFY_line_21_22);
  // PAPER LINES 21-22
  // The inner product challenges are computed per round
  rct::keyV w(rounds);
  for (size_t i = 0; i < rounds; ++i)
  {
    w[i] = hash_cache_mash(hash_cache, proof.L[i], proof.R[i]);
  }
  PERF_TIMER_STOP_BP(VERIFY_line_21_22);

  PERF_TIMER_START_BP(VERIFY_line_24_25);
  // Basically PAPER LINES 24-25
  // Compute the curvepoints from G[i] and H[i]
  rct::key inner_prod = rct::identity();
  rct::key yinvpow = rct::identity();
  rct::key ypow = rct::identity();

  PERF_TIMER_START_BP(VERIFY_line_24_25_invert);
  const rct::key yinv = invert_v1(y);
  rct::keyV winv(rounds);
  for (size_t i = 0; i < rounds; ++i)
    winv[i] = invert_v1(w[i]);
  PERF_TIMER_STOP_BP(VERIFY_line_24_25_invert);

  for (size_t i = 0; i < N; ++i)
  {
    // Convert the index to binary IN REVERSE and construct the scalar exponent
    rct::key g_scalar = proof.a;
    rct::key h_scalar;
    sc_mul(h_scalar.bytes, proof.b.bytes, yinvpow.bytes);

    for (size_t j = rounds; j-- > 0; )
    {
      size_t J = w.size() - j - 1;

      if ((i & (((size_t)1)<<j)) == 0)
      {
        sc_mul(g_scalar.bytes, g_scalar.bytes, winv[J].bytes);
        sc_mul(h_scalar.bytes, h_scalar.bytes, w[J].bytes);
      }
      else
      {
        sc_mul(g_scalar.bytes, g_scalar.bytes, w[J].bytes);
        sc_mul(h_scalar.bytes, h_scalar.bytes, winv[J].bytes);
      }
    }

    // Adjust the scalars using the exponents from PAPER LINE 62
    sc_add(g_scalar.bytes, g_scalar.bytes, z.bytes);
    sc_mul(tmp.bytes, zsq.bytes, twoN[i].bytes);
    sc_muladd(tmp.bytes, z.bytes, ypow.bytes, tmp.bytes);
    sc_mulsub(h_scalar.bytes, tmp.bytes, yinvpow.bytes, h_scalar.bytes);

    // Now compute the basepoint's scalar multiplication
    // Each of these could be written as a multiexp operation instead
    rct::addKeys3(tmp, g_scalar, Gprecomp[i], h_scalar, Hprecomp[i]);
    rct::addKeys(inner_prod, inner_prod, tmp);

    if (i != N-1)
    {
      sc_mul(yinvpow.bytes, yinvpow.bytes, yinv.bytes);
      sc_mul(ypow.bytes, ypow.bytes, y.bytes);
    }
  }
  PERF_TIMER_STOP_BP(VERIFY_line_24_25);

  PERF_TIMER_START_BP(VERIFY_line_26);
  // PAPER LINE 26
  rct::key pprime;
  sc_sub(tmp.bytes, rct::zero().bytes, proof.mu.bytes);
  rct::addKeys(pprime, P, rct::scalarmultBase(tmp));

  for (size_t i = 0; i < rounds; ++i)
  {
    sc_mul(tmp.bytes, w[i].bytes, w[i].bytes);
    sc_mul(tmp2.bytes, winv[i].bytes, winv[i].bytes);
#if 1
    ge_dsmp cacheL, cacheR;
    rct::precomp(cacheL, proof.L[i]);
    rct::precomp(cacheR, proof.R[i]);
    rct::addKeys3(tmp, tmp, cacheL, tmp2, cacheR);
    rct::addKeys(pprime, pprime, tmp);
#else
    rct::addKeys(pprime, pprime, rct::scalarmultKey(proof.L[i], tmp));
    rct::addKeys(pprime, pprime, rct::scalarmultKey(proof.R[i], tmp2));
#endif
  }
  sc_mul(tmp.bytes, proof.t.bytes, x_ip.bytes);
  rct::addKeys(pprime, pprime, rct::scalarmultKey(rct::H, tmp));
  PERF_TIMER_STOP_BP(VERIFY_line_26);

  PERF_TIMER_START_BP(VERIFY_step2_check);
  sc_mul(tmp.bytes, proof.a.bytes, proof.b.bytes);
  sc_mul(tmp.bytes, tmp.bytes, x_ip.bytes);
  tmp = rct::scalarmultKey(rct::H, tmp);
  rct::addKeys(tmp, tmp, inner_prod);
  PERF_TIMER_STOP_BP(VERIFY_step2_check);
  if (!(pprime == tmp))
  {
    MERROR("Verification failure at step 2");
    return false;
  }

  PERF_TIMER_STOP_BP(VERIFY);
  return true;
}

bool bulletproof_VERIFY_v2(const Bulletproof &proof)
{
  std::vector<const Bulletproof*> proofs;
  proofs.push_back(&proof);
  return bulletproof_VERIFY_v2(proofs);
}

bool bulletproof_VERIFY_v2(const std::vector<const Bulletproof*> &proofs)
{
  init_exponents_v2();

  PERF_TIMER_START_BP(VERIFY);

  const size_t logN = 6;
  const size_t N = 1 << logN;

  // sanity and figure out which proof is longest
  size_t max_length = 0;
  size_t nV = 0;
  std::vector<proof_data_t> proof_data;
  proof_data.reserve(proofs.size());
  size_t inv_offset = 0;
  std::vector<rct::key> to_invert;
  to_invert.reserve(11 * sizeof(proofs));
  size_t max_logM = 0;
  for (const Bulletproof *p: proofs)
  {
    const Bulletproof &proof = *p;

    // check scalar range
    CHECK_AND_ASSERT_MES(is_reduced(proof.taux), false, "Input scalar not in range");
    CHECK_AND_ASSERT_MES(is_reduced(proof.mu), false, "Input scalar not in range");
    CHECK_AND_ASSERT_MES(is_reduced(proof.a), false, "Input scalar not in range");
    CHECK_AND_ASSERT_MES(is_reduced(proof.b), false, "Input scalar not in range");
    CHECK_AND_ASSERT_MES(is_reduced(proof.t), false, "Input scalar not in range");

    CHECK_AND_ASSERT_MES(proof.V.size() >= 1, false, "V does not have at least one element");
    CHECK_AND_ASSERT_MES(proof.L.size() == proof.R.size(), false, "Mismatched L and R sizes");
    CHECK_AND_ASSERT_MES(proof.L.size() > 0, false, "Empty proof");

    max_length = std::max(max_length, proof.L.size());
    nV += proof.V.size();

    // Reconstruct the challenges
    PERF_TIMER_START_BP(VERIFY_start);
    proof_data.resize(proof_data.size() + 1);
    proof_data_t &pd = proof_data.back();
    rct::key hash_cache = rct::hash_to_scalar(proof.V);
    pd.y = hash_cache_mash(hash_cache, proof.A, proof.S);
    CHECK_AND_ASSERT_MES(!(pd.y == rct::zero()), false, "y == 0");
    pd.z = hash_cache = rct::hash_to_scalar(pd.y);
    CHECK_AND_ASSERT_MES(!(pd.z == rct::zero()), false, "z == 0");
    pd.x = hash_cache_mash(hash_cache, pd.z, proof.T1, proof.T2);
    CHECK_AND_ASSERT_MES(!(pd.x == rct::zero()), false, "x == 0");
    pd.x_ip = hash_cache_mash(hash_cache, pd.x, proof.taux, proof.mu, proof.t);
    CHECK_AND_ASSERT_MES(!(pd.x_ip == rct::zero()), false, "x_ip == 0");
    PERF_TIMER_STOP_BP(VERIFY_start);

    size_t M;
    for (pd.logM = 0; (M = 1<<pd.logM) <= maxM && M < proof.V.size(); ++pd.logM);
    CHECK_AND_ASSERT_MES(proof.L.size() == 6+pd.logM, false, "Proof is not the expected size");
    max_logM = std::max(pd.logM, max_logM);

    const size_t rounds = pd.logM+logN;
    CHECK_AND_ASSERT_MES(rounds > 0, false, "Zero rounds");

    PERF_TIMER_START_BP(VERIFY_line_21_22);
    // PAPER LINES 21-22
    // The inner product challenges are computed per round
    pd.w.resize(rounds);
    for (size_t i = 0; i < rounds; ++i)
    {
      pd.w[i] = hash_cache_mash(hash_cache, proof.L[i], proof.R[i]);
      CHECK_AND_ASSERT_MES(!(pd.w[i] == rct::zero()), false, "w[i] == 0");
    }
    PERF_TIMER_STOP_BP(VERIFY_line_21_22);

    pd.inv_offset = inv_offset;
    for (size_t i = 0; i < rounds; ++i)
      to_invert.push_back(pd.w[i]);
    to_invert.push_back(pd.y);
    inv_offset += rounds + 1;
  }
  CHECK_AND_ASSERT_MES(max_length < 32, false, "At least one proof is too large");
  size_t maxMN = 1u << max_length;

  rct::key tmp;

  std::vector<MultiexpData> multiexp_data;
  multiexp_data.reserve(nV + (2 * (max_logM + logN) + 4) * proofs.size() + 2 * maxMN);
  multiexp_data.resize(2 * maxMN);

  PERF_TIMER_START_BP(VERIFY_line_24_25_invert);
  const std::vector<rct::key> inverses = invert_v2(to_invert);
  PERF_TIMER_STOP_BP(VERIFY_line_24_25_invert);

  // setup weighted aggregates
  rct::key z1 = rct::zero();
  rct::key z3 = rct::zero();
  rct::keyV m_z4(maxMN, rct::zero()), m_z5(maxMN, rct::zero());
  rct::key m_y0 = rct::zero(), y1 = rct::zero();
  int proof_data_index = 0;
  rct::keyV w_cache;
  rct::keyV proof8_V, proof8_L, proof8_R;
  for (const Bulletproof *p: proofs)
  {
    const Bulletproof &proof = *p;
    const proof_data_t &pd = proof_data[proof_data_index++];

    CHECK_AND_ASSERT_MES(proof.L.size() == 6+pd.logM, false, "Proof is not the expected size");
    const size_t M = 1 << pd.logM;
    const size_t MN = M*N;
    const rct::key weight_y = rct::skGen();
    const rct::key weight_z = rct::skGen();

    // pre-multiply some points by 8
    proof8_V.resize(proof.V.size()); for (size_t i = 0; i < proof.V.size(); ++i) proof8_V[i] = rct::scalarmult8(proof.V[i]);
    proof8_L.resize(proof.L.size()); for (size_t i = 0; i < proof.L.size(); ++i) proof8_L[i] = rct::scalarmult8(proof.L[i]);
    proof8_R.resize(proof.R.size()); for (size_t i = 0; i < proof.R.size(); ++i) proof8_R[i] = rct::scalarmult8(proof.R[i]);
    rct::key proof8_T1 = rct::scalarmult8(proof.T1);
    rct::key proof8_T2 = rct::scalarmult8(proof.T2);
    rct::key proof8_S = rct::scalarmult8(proof.S);
    rct::key proof8_A = rct::scalarmult8(proof.A);

    PERF_TIMER_START_BP(VERIFY_line_61);
    // PAPER LINE 61
    sc_mulsub(m_y0.bytes, proof.taux.bytes, weight_y.bytes, m_y0.bytes);

    const rct::keyV zpow = vector_powers(pd.z, M+3);

    rct::key k;
    const rct::key ip1y = vector_power_sum(pd.y, MN);
    sc_mulsub(k.bytes, zpow[2].bytes, ip1y.bytes, rct::zero().bytes);
    for (size_t j = 1; j <= M; ++j)
    {
      CHECK_AND_ASSERT_MES(j+2 < zpow.size(), false, "invalid zpow index");
      sc_mulsub(k.bytes, zpow[j+2].bytes, ip12_v2.bytes, k.bytes);
    }
    PERF_TIMER_STOP_BP(VERIFY_line_61);

    PERF_TIMER_START_BP(VERIFY_line_61rl_new);
    sc_muladd(tmp.bytes, pd.z.bytes, ip1y.bytes, k.bytes);
    sc_sub(tmp.bytes, proof.t.bytes, tmp.bytes);
    sc_muladd(y1.bytes, tmp.bytes, weight_y.bytes, y1.bytes);
    for (size_t j = 0; j < proof8_V.size(); j++)
    {
      sc_mul(tmp.bytes, zpow[j+2].bytes, weight_y.bytes);
      multiexp_data.emplace_back(tmp, proof8_V[j]);
    }
    sc_mul(tmp.bytes, pd.x.bytes, weight_y.bytes);
    multiexp_data.emplace_back(tmp, proof8_T1);
    rct::key xsq;
    sc_mul(xsq.bytes, pd.x.bytes, pd.x.bytes);
    sc_mul(tmp.bytes, xsq.bytes, weight_y.bytes);
    multiexp_data.emplace_back(tmp, proof8_T2);
    PERF_TIMER_STOP_BP(VERIFY_line_61rl_new);

    PERF_TIMER_START_BP(VERIFY_line_62);
    // PAPER LINE 62
    multiexp_data.emplace_back(weight_z, proof8_A);
    sc_mul(tmp.bytes, pd.x.bytes, weight_z.bytes);
    multiexp_data.emplace_back(tmp, proof8_S);
    PERF_TIMER_STOP_BP(VERIFY_line_62);

    // Compute the number of rounds for the inner product
    const size_t rounds = pd.logM+logN;
    CHECK_AND_ASSERT_MES(rounds > 0, false, "Zero rounds");

    PERF_TIMER_START_BP(VERIFY_line_24_25);
    // Basically PAPER LINES 24-25
    // Compute the curvepoints from G[i] and H[i]
    rct::key yinvpow = rct::identity();
    rct::key ypow = rct::identity();

    const rct::key *winv = &inverses[pd.inv_offset];
    const rct::key yinv = inverses[pd.inv_offset + rounds];

    // precalc
    PERF_TIMER_START_BP(VERIFY_line_24_25_precalc);
    w_cache.resize(1<<rounds);
    w_cache[0] = winv[0];
    w_cache[1] = pd.w[0];
    for (size_t j = 1; j < rounds; ++j)
    {
      const size_t slots = 1<<(j+1);
      for (size_t s = slots; s-- > 0; --s)
      {
        sc_mul(w_cache[s].bytes, w_cache[s/2].bytes, pd.w[j].bytes);
        sc_mul(w_cache[s-1].bytes, w_cache[s/2].bytes, winv[j].bytes);
      }
    }
    PERF_TIMER_STOP_BP(VERIFY_line_24_25_precalc);

    for (size_t i = 0; i < MN; ++i)
    {
      rct::key g_scalar = proof.a;
      rct::key h_scalar;
      if (i == 0)
        h_scalar = proof.b;
      else
        sc_mul(h_scalar.bytes, proof.b.bytes, yinvpow.bytes);

      // Convert the index to binary IN REVERSE and construct the scalar exponent
      sc_mul(g_scalar.bytes, g_scalar.bytes, w_cache[i].bytes);
      sc_mul(h_scalar.bytes, h_scalar.bytes, w_cache[(~i) & (MN-1)].bytes);

      // Adjust the scalars using the exponents from PAPER LINE 62
      sc_add(g_scalar.bytes, g_scalar.bytes, pd.z.bytes);
      CHECK_AND_ASSERT_MES(2+i/N < zpow.size(), false, "invalid zpow index");
      CHECK_AND_ASSERT_MES(i%N < twoN.size(), false, "invalid twoN index");
      sc_mul(tmp.bytes, zpow[2+i/N].bytes, twoN[i%N].bytes);
      if (i == 0)
      {
        sc_add(tmp.bytes, tmp.bytes, pd.z.bytes);
        sc_sub(h_scalar.bytes, h_scalar.bytes, tmp.bytes);
      }
      else
      {
        sc_muladd(tmp.bytes, pd.z.bytes, ypow.bytes, tmp.bytes);
        sc_mulsub(h_scalar.bytes, tmp.bytes, yinvpow.bytes, h_scalar.bytes);
      }

      sc_mulsub(m_z4[i].bytes, g_scalar.bytes, weight_z.bytes, m_z4[i].bytes);
      sc_mulsub(m_z5[i].bytes, h_scalar.bytes, weight_z.bytes, m_z5[i].bytes);

      if (i == 0)
      {
        yinvpow = yinv;
        ypow = pd.y;
      }
      else if (i != MN-1)
      {
        sc_mul(yinvpow.bytes, yinvpow.bytes, yinv.bytes);
        sc_mul(ypow.bytes, ypow.bytes, pd.y.bytes);
      }
    }

    PERF_TIMER_STOP_BP(VERIFY_line_24_25);

    // PAPER LINE 26
    PERF_TIMER_START_BP(VERIFY_line_26_new);
    sc_muladd(z1.bytes, proof.mu.bytes, weight_z.bytes, z1.bytes);
    for (size_t i = 0; i < rounds; ++i)
    {
      sc_mul(tmp.bytes, pd.w[i].bytes, pd.w[i].bytes);
      sc_mul(tmp.bytes, tmp.bytes, weight_z.bytes);
      multiexp_data.emplace_back(tmp, proof8_L[i]);
      sc_mul(tmp.bytes, winv[i].bytes, winv[i].bytes);
      sc_mul(tmp.bytes, tmp.bytes, weight_z.bytes);
      multiexp_data.emplace_back(tmp, proof8_R[i]);
    }
    sc_mulsub(tmp.bytes, proof.a.bytes, proof.b.bytes, proof.t.bytes);
    sc_mul(tmp.bytes, tmp.bytes, pd.x_ip.bytes);
    sc_muladd(z3.bytes, tmp.bytes, weight_z.bytes, z3.bytes);
    PERF_TIMER_STOP_BP(VERIFY_line_26_new);
  }

  // now check all proofs at once
  PERF_TIMER_START_BP(VERIFY_step2_check);
  sc_sub(tmp.bytes, m_y0.bytes, z1.bytes);
  multiexp_data.emplace_back(tmp, rct::G);
  sc_sub(tmp.bytes, z3.bytes, y1.bytes);
  multiexp_data.emplace_back(tmp, rct::H);
  for (size_t i = 0; i < maxMN; ++i)
  {
    multiexp_data[i * 2] = {m_z4[i], Gi_p3[i]};
    multiexp_data[i * 2 + 1] = {m_z5[i], Hi_p3[i]};
  }
  if (!(multiexp(multiexp_data, 2 * maxMN) == rct::identity()))
  {
    PERF_TIMER_STOP_BP(VERIFY_step2_check);
    MERROR("Verification failure");
    return false;
  }
  PERF_TIMER_STOP_BP(VERIFY_step2_check);

  PERF_TIMER_STOP_BP(VERIFY);
  return true;
}

bool bulletproof_VERIFY_v2(const std::vector<Bulletproof> &proofs)
{
  std::vector<const Bulletproof*> proof_pointers;
  proof_pointers.reserve(proofs.size());
  for (const Bulletproof &proof: proofs)
    proof_pointers.push_back(&proof);
  return bulletproof_VERIFY_v2(proof_pointers);
}

}
