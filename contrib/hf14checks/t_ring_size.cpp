// Ring size 16 at HF14: the consensus rule, and what it costs.
//
// Two things are pinned here:
//  - the fork-gated rule in cryptonote_basic_impl, exhaustively over the fork
//    versions and ring sizes that matter. The rule has to keep accepting the
//    old size for historical blocks, accept either size at the fork that
//    introduces the new one, and accept only the new one after that;
//  - the size and verification cost a real CLSAG signature gains going from
//    ring 5 to ring 16, so a regression in either is visible.
#include "check.h"

#include <chrono>
#include <vector>

#include "cryptonote_config.h"
#include "cryptonote_basic/cryptonote_basic_impl.h"

#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "device/device.hpp"

using namespace rct;

static void rule_across_fork_versions()
{
  // Historical blocks: only the old size, on every version below the fork.
  for (uint8_t v = 1; v < HF_VERSION_RING_SIZE_16; ++v)
  {
    CHECK_TRUE(cryptonote::is_valid_ring_size(v, DEFAULT_RINGSIZE));
    CHECK_FALSE(cryptonote::is_valid_ring_size(v, DEFAULT_RINGSIZE_V14));
    CHECK_TRUE(cryptonote::get_ring_size(v) == (size_t)DEFAULT_RINGSIZE);
  }

  // From the fork onwards the old size is gone, starting at the fork itself:
  // there is no version at which both pass.
  for (uint8_t v = HF_VERSION_RING_SIZE_16; v <= HF_VERSION_RING_SIZE_16 + 3; ++v)
  {
    CHECK_FALSE(cryptonote::is_valid_ring_size(v, DEFAULT_RINGSIZE));
    CHECK_TRUE(cryptonote::is_valid_ring_size(v, DEFAULT_RINGSIZE_V14));
    CHECK_TRUE(cryptonote::get_ring_size(v) == (size_t)DEFAULT_RINGSIZE_V14);
  }

  // Nothing else is ever acceptable, on any version.
  const size_t nonsense[] = {0, 1, 2, 3, 4, 6, 7, 10, 11, 12, 15, 17, 32, 128};
  for (uint8_t v = 1; v <= HF_VERSION_RING_SIZE_16 + 3; ++v)
    for (size_t r : nonsense)
      CHECK_FALSE(cryptonote::is_valid_ring_size(v, r));
}

// Build a spendable ring of the requested size and return the signature.
static clsag make_clsag(size_t N, ctkeyV &pubs, key &Cout, key &message)
{
  const size_t idx = N / 2;
  pubs.clear();
  message = identity();

  for (size_t i = 0; i < N; ++i)
  {
    key sk;
    ctkey tmp;
    skpkGen(sk, tmp.dest);
    skpkGen(sk, tmp.mask);
    pubs.push_back(tmp);
  }

  key p, t, t2, u;
  skpkGen(p, pubs[idx].dest);
  t = skGen();
  u = skGen();
  addKeys2(pubs[idx].mask, t, u, H);
  t2 = skGen();
  addKeys2(Cout, t2, u, H);

  ctkey insk;
  insk.dest = p;
  insk.mask = t;
  return proveRctCLSAGSimple(message, pubs, insk, t2, Cout, idx, hw::get_device("default"));
}

// s, c1 and D go on the wire per input; I comes from the input itself.
static size_t clsag_wire_size(const clsag &sig)
{
  return sig.s.size() * sizeof(key) + sizeof(sig.c1) + sizeof(sig.D);
}

static double median(std::vector<double> v)
{
  std::sort(v.begin(), v.end());
  return v.size() & 1 ? v[v.size() / 2] : 0.5 * (v[v.size() / 2 - 1] + v[v.size() / 2]);
}

static void cost_of_the_bigger_ring()
{
  ctkeyV pubs_old, pubs_new;
  key Cout_old, Cout_new, msg_old, msg_new;

  const clsag old_sig = make_clsag(DEFAULT_RINGSIZE, pubs_old, Cout_old, msg_old);
  const clsag new_sig = make_clsag(DEFAULT_RINGSIZE_V14, pubs_new, Cout_new, msg_new);

  // both have to actually verify, or the numbers below mean nothing
  CHECK_TRUE(verRctCLSAGSimple(msg_old, old_sig, pubs_old, Cout_old));
  CHECK_TRUE(verRctCLSAGSimple(msg_new, new_sig, pubs_new, Cout_new));

  const size_t old_bytes = clsag_wire_size(old_sig);
  const size_t new_bytes = clsag_wire_size(new_sig);

  // CLSAG is 32 * (ring + 2) bytes per input, so the delta is fixed by the ring
  CHECK_TRUE(old_bytes == 32 * (DEFAULT_RINGSIZE + 2));
  CHECK_TRUE(new_bytes == 32 * (DEFAULT_RINGSIZE_V14 + 2));
  CHECK_TRUE(new_bytes - old_bytes == 32 * (DEFAULT_RINGSIZE_V14 - DEFAULT_RINGSIZE));

  // verification cost, interleaved so drift hits both arms equally
  const int rounds = 60;
  std::vector<double> t_old, t_new;
  for (int i = 0; i < rounds; ++i)
  {
    auto a = std::chrono::steady_clock::now();
    verRctCLSAGSimple(msg_old, old_sig, pubs_old, Cout_old);
    auto b = std::chrono::steady_clock::now();
    verRctCLSAGSimple(msg_new, new_sig, pubs_new, Cout_new);
    auto c = std::chrono::steady_clock::now();
    t_old.push_back(std::chrono::duration<double, std::milli>(b - a).count());
    t_new.push_back(std::chrono::duration<double, std::milli>(c - b).count());
  }
  const double m_old = median(t_old), m_new = median(t_new);

  std::printf("   ring %2d: %4zu bytes/input, verify %.3f ms\n", DEFAULT_RINGSIZE, old_bytes, m_old);
  std::printf("   ring %2d: %4zu bytes/input, verify %.3f ms\n", DEFAULT_RINGSIZE_V14, new_bytes, m_new);
  std::printf("   delta  : +%zu bytes/input, verify %.2fx\n", new_bytes - old_bytes, m_new / m_old);
}

int main()
{
  RUN(rule_across_fork_versions);
  RUN(cost_of_the_bigger_ring);
  return check_summary("t_ring_size");
}
