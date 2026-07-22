// CLSAG battery, ported from Monero master 52f02f2 tests/unit_tests/ringct.cpp
// TEST(ringct, CLSAG). Body kept as upstream wrote it; gtest scaffolding
// replaced. Covers a correct signature plus every tamper case upstream
// exercises: bad message, index, z, C, p, P at creation; empty / short /
// long / corrupted s, bad c1, bad I, bad D, torsioned D, swapped I and D
// at verification.
#include "check.h"

#include "string_tools.h"
#include "ringct/rctOps.h"
#include "ringct/rctSigs.h"
#include "device/device.hpp"

using namespace rct;

static void clsag_battery()
{
  const size_t N = 11;
  const size_t idx = 5;
  ctkeyV pubs;
  key p, t, t2, u;
  const key message = identity();
  ctkey backup;
  clsag sig;

  for (size_t i = 0; i < N; ++i)
  {
    key sk;
    ctkey tmp;

    skpkGen(sk, tmp.dest);
    skpkGen(sk, tmp.mask);

    pubs.push_back(tmp);
  }

  // Set P[idx]
  skpkGen(p, pubs[idx].dest);

  // Set C[idx]
  t = skGen();
  u = skGen();
  addKeys2(pubs[idx].mask, t, u, H);

  // Set commitment offset
  key Cout;
  t2 = skGen();
  addKeys2(Cout, t2, u, H);

  // Prepare generation inputs
  ctkey insk;
  insk.dest = p;
  insk.mask = t;

  // bad message
  sig = proveRctCLSAGSimple(zero(), pubs, insk, t2, Cout, idx, hw::get_device("default"));
  CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));

  // bad index at creation
  try
  {
    sig = proveRctCLSAGSimple(message, pubs, insk, t2, Cout, (idx + 1) % N, hw::get_device("default"));
    CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad z at creation
  try
  {
    ctkey insk2;
    insk2.dest = insk.dest;
    insk2.mask = skGen();
    sig = proveRctCLSAGSimple(message, pubs, insk2, t2, Cout, idx, hw::get_device("default"));
    CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad C at creation
  backup = pubs[idx];
  pubs[idx].mask = scalarmultBase(skGen());
  try
  {
    sig = proveRctCLSAGSimple(message, pubs, insk, t2, Cout, idx, hw::get_device("default"));
    CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }
  pubs[idx] = backup;

  // bad p at creation
  try
  {
    ctkey insk2;
    insk2.dest = skGen();
    insk2.mask = insk.mask;
    sig = proveRctCLSAGSimple(message, pubs, insk2, t2, Cout, idx, hw::get_device("default"));
    CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }

  // bad P at creation
  backup = pubs[idx];
  pubs[idx].dest = scalarmultBase(skGen());
  try
  {
    sig = proveRctCLSAGSimple(message, pubs, insk, t2, Cout, idx, hw::get_device("default"));
    CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  }
  catch (...) { /* either exception, or failure to verify above */ }
  pubs[idx] = backup;

  // Test correct signature
  sig = proveRctCLSAGSimple(message, pubs, insk, t2, Cout, idx, hw::get_device("default"));
  CHECK_TRUE(verRctCLSAGSimple(message, sig, pubs, Cout));

  // empty s
  auto sbackup = sig.s;
  sig.s.clear();
  CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  sig.s = sbackup;

  // too few s elements
  key backup_key;
  backup_key = sig.s.back();
  sig.s.pop_back();
  CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  sig.s.push_back(backup_key);

  // too many s elements
  sig.s.push_back(skGen());
  CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  sig.s.pop_back();

  // bad s in clsag at verification
  for (auto &s: sig.s)
  {
    backup_key = s;
    s = skGen();
    CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
    s = backup_key;
  }

  // bad c1 in clsag at verification
  backup_key = sig.c1;
  sig.c1 = skGen();
  CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  sig.c1 = backup_key;

  // bad I in clsag at verification
  backup_key = sig.I;
  sig.I = scalarmultBase(skGen());
  CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  sig.I = backup_key;

  // bad D in clsag at verification
  backup_key = sig.D;
  sig.D = scalarmultBase(skGen());
  CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  sig.D = backup_key;

  // D not in main subgroup in clsag at verification
  backup_key = sig.D;
  key x;
  CHECK_TRUE(epee::string_tools::hex_to_pod("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa", x));
  sig.D = addKeys(sig.D, x);
  CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  sig.D = backup_key;

  // swapped I and D in clsag at verification
  std::swap(sig.I, sig.D);
  CHECK_FALSE(verRctCLSAGSimple(message, sig, pubs, Cout));
  std::swap(sig.I, sig.D);

  // check it's still good, in case we failed to restore
  CHECK_TRUE(verRctCLSAGSimple(message, sig, pubs, Cout));
}

int main()
{
  RUN(clsag_battery);
  return check_summary("t_clsag");
}
