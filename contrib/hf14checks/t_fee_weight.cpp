// Fee and weight arithmetic on real serialized type-7 transactions.
//
// The wallet's estimators live in an anonymous namespace (wallet2.cpp:812
// estimate_rct_tx_size, :874 estimate_tx_weight) so they cannot be linked;
// they are transcribed here verbatim and checked against the linkable
// consensus side. If wallet2.cpp changes, this transcription must follow.
//
// Three claims are pinned:
//  - the wallet's BP+ clawback equals what consensus adds to a real
//    transaction's weight (get_transaction_weight - blob size), exactly,
//    across output counts;
//  - the size estimator upper-bounds real serialized type-7 transactions,
//    tightly;
//  - with the legacy flags the estimator reproduces the pre-HF14 numbers,
//    so pre-fork fees do not move.
#include "check.h"
#include "rct_samples.h"

#include <cstring>

#include "cryptonote_basic/cryptonote_basic.h"
#include "cryptonote_basic/cryptonote_format_utils.h"

// --- transcribed from src/wallet/wallet2.cpp:812, log lines dropped ---
static size_t wallet_estimate_rct_tx_size(int n_inputs, int mixin, int n_outputs, size_t extra_size,
                                          bool bulletproof, bool clsag, bool bulletproof_plus)
{
  size_t size = 0;

  // tx prefix
  size += 1 + 6;
  size += n_inputs * (1+6+(mixin+1)*2+32);
  size += n_outputs * (6+32);
  size += extra_size;

  // rct signatures
  size += 1;
  if (bulletproof || bulletproof_plus)
  {
    size_t log_padded_outputs = 0;
    while ((1<<log_padded_outputs) < n_outputs)
      ++log_padded_outputs;
    size += (2 * (6 + log_padded_outputs) + (bulletproof_plus ? 6 : (4 + 5))) * 32 + 3;
  }
  else
    size += (2*64*32+32+64*32) * n_outputs;

  if (clsag)
    size += n_inputs * (32 * (mixin+1) + 64);
  else
    size += n_inputs * (64 * (mixin+1) + 32);

  size += 32 * n_inputs;
  if (clsag || bulletproof_plus)
    size += 8 * n_outputs;
  else
    size += 2 * 32 * n_outputs;
  size += 32 * n_outputs;
  size += 4;
  return size;
}

// --- the clawback arithmetic from src/wallet/wallet2.cpp:874, applied to the
// transaction's real output count instead of estimate_tx_weight's
// n_outputs + 1 (the change output is already real here) ---
static uint64_t wallet_clawback(int real_outputs)
{
  if (real_outputs <= 2)
    return 0;
  const uint64_t bp_base = (32 * (6 + 7 * 2)) / 2;
  size_t log_padded_outputs = 2;
  while ((1<<log_padded_outputs) < real_outputs)
    ++log_padded_outputs;
  uint64_t nlr = 2 * (6 + log_padded_outputs);
  const uint64_t bp_size = 32 * (6 + nlr);
  return (bp_base * (1<<log_padded_outputs) - bp_size) * 4 / 5;
}

// A serializable transaction around a real signature: version 2, nin ring
// inputs, nout outputs, empty extra. Only the shape matters to the weight
// and size arithmetic.
static cryptonote::transaction make_tx(int bp_version, size_t nin, size_t nout, size_t ring)
{
  cryptonote::transaction tx;
  tx.version = 2;
  tx.unlock_time = 0;
  for (size_t i = 0; i < nin; ++i)
  {
    cryptonote::txin_to_key in;
    in.amount = 0;
    in.key_offsets.assign(ring, 1);
    const rct::key ki = rct::pkGen();
    memcpy(&in.k_image, ki.bytes, 32);
    tx.vin.push_back(in);
  }
  for (size_t o = 0; o < nout; ++o)
  {
    cryptonote::txout_to_key tk;
    const rct::key pk = rct::pkGen();
    memcpy(&tk.key, pk.bytes, 32);
    cryptonote::tx_out out;
    out.amount = 0;
    out.target = tk;
    tx.vout.push_back(out);
  }
  tx.extra.clear();
  tx.rct_signatures = make_sample_sig(bp_version, nin, nout, ring);
  return tx;
}

static void clawback_equals_consensus()
{
  const size_t nouts[] = {2, 3, 4, 5, 8, 16};
  for (size_t nout : nouts)
  {
    cryptonote::transaction tx = make_tx(4, 2, nout, 8);
    CHECK_TRUE(tx.rct_signatures.type == rct::RCTTypeBulletproofPlus);
    const cryptonote::blobdata blob = cryptonote::t_serializable_object_to_blob(tx);
    const uint64_t weight = cryptonote::get_transaction_weight(tx, blob.size());
    const uint64_t consensus = weight - blob.size();
    const uint64_t wallet = wallet_clawback((int)nout);
    std::printf("   %2zu outputs: blob %5zu, clawback consensus %5llu, wallet %5llu\n",
                nout, blob.size(), (unsigned long long)consensus, (unsigned long long)wallet);
    CHECK_TRUE(consensus == wallet);
  }
}

static void estimator_covers_real_type7_txs()
{
  struct { size_t nin, nout, ring; } shapes[] = {
    {1, 2, 4}, {2, 2, 8}, {2, 3, 8}, {4, 4, 16}, {2, 16, 8},
  };
  for (const auto &s : shapes)
  {
    cryptonote::transaction tx = make_tx(4, s.nin, s.nout, s.ring);
    const cryptonote::blobdata blob = cryptonote::t_serializable_object_to_blob(tx);
    const size_t est = wallet_estimate_rct_tx_size((int)s.nin, (int)(s.ring - 1), (int)s.nout, 0,
                                                   true, true, true);
    std::printf("   %zu-in/%zu-out/ring %2zu: real %5zu, estimated %5zu (overshoot %zd)\n",
                s.nin, s.nout, s.ring, blob.size(), est, (ssize_t)est - (ssize_t)blob.size());
    // The estimator over-budgets exactly where its comments say it does:
    // 6 bytes per amount varint (real: 1 byte, amounts are 0 here), 2 per
    // key offset (real: 1, offsets are 1), 7 for version+unlock (real: 5)
    // and 4 for the fee (real: 2, fee is 5000). Everything else it counts
    // must match the serializer to the byte, so the overshoot is exact:
    // any drift in the estimator or the serializer breaks the equality.
    const size_t expected_overshoot = s.nin * (4 + s.ring) + 4 * s.nout + 4;
    CHECK_TRUE(est == blob.size() + expected_overshoot);

    // the weight the fee is computed on is covered too
    const uint64_t weight = cryptonote::get_transaction_weight(tx, blob.size());
    CHECK_TRUE(est + wallet_clawback((int)s.nout) >= weight);
  }
}

static void legacy_estimates_unchanged()
{
  // golden values computed from origin/master's estimate_rct_tx_size
  // (wallet2.cpp:802 there), which has no clsag/bulletproof_plus arguments
  CHECK_TRUE(wallet_estimate_rct_tx_size(2, 7, 2, 0, true, false, false) == 2281);
  CHECK_TRUE(wallet_estimate_rct_tx_size(1, 10, 2, 0, true, false, false) == 1848);
}

int main()
{
  RUN(clawback_equals_consensus);
  RUN(estimator_covers_real_type7_txs);
  RUN(legacy_estimates_unchanged);
  return check_summary("t_fee_weight");
}
