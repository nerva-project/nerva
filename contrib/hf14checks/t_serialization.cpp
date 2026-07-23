// The 6/7 renumbering through all three encoders, on real signatures.
// bp_version 2/3/4 must produce type bytes 5/6/7 (Monero's 5/6 are our 6/7;
// our 5 is already Bulletproof2 on chain), and each type must roundtrip
// bit-stable through the binary archive, the boost archive and the JSON
// encoder. The JSON leg goes through a string, which exercises the read_hex
// fix (rapidjson GetStringLength vs Size).
#include "check.h"
#include "rct_samples.h"

#include <sstream>

#include "serialization/binary_archive.h"
#include "cryptonote_basic/cryptonote_boost_serialization.h"
#include <boost/archive/portable_binary_oarchive.hpp>
#include <boost/archive/portable_binary_iarchive.hpp>
#include "serialization/json_object.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

// The wire encoding of a signature: base + prunable, exactly the fields the
// network serializes (message and mixRing are reconstructed by the daemon).
// Used as the canonical comparator for every encoder.
static bool bin_dump(rct::rctSig &s, size_t nin, size_t nout, size_t mixin, std::string &blob)
{
  std::stringstream ss;
  binary_archive<true> ar(ss);
  if (!s.serialize_rctsig_base(ar, nin, nout))
    return false;
  if (!s.p.serialize_rctsig_prunable(ar, s.type, nin, nout, mixin))
    return false;
  blob = ss.str();
  return true;
}

static bool bin_parse(rct::rctSig &s, size_t nin, size_t nout, size_t mixin, const std::string &blob)
{
  std::istringstream ss(blob);
  binary_archive<false> ar(ss);
  if (!s.serialize_rctsig_base(ar, nin, nout))
    return false;
  if (!s.p.serialize_rctsig_prunable(ar, s.type, nin, nout, mixin))
    return false;
  return true;
}

static const size_t NIN = 2, NOUT = 3, RING = 8, MIXIN = RING - 1;

// What the daemon does to a parsed signature before verifying: outPk.dest
// comes from the tx outputs and CLSAG I from the tx key images (restored
// from the original here), while the range proof's V is recomputed from the
// serialized outPk masks the way expand_transaction_1 does. If the parsed
// masks or proof were off, verification below would catch it.
static void expand_parsed(rct::rctSig &back, const rct::rctSig &orig)
{
  for (size_t i = 0; i < back.outPk.size(); ++i)
    back.outPk[i].dest = orig.outPk[i].dest;
  if (back.type == rct::RCTTypeBulletproofPlus && !back.p.bulletproofs_plus.empty())
  {
    rct::BulletproofPlus &bp = back.p.bulletproofs_plus[0];
    bp.V.resize(back.outPk.size());
    for (size_t i = 0; i < back.outPk.size(); ++i)
      bp.V[i] = rct::scalarmultKey(back.outPk[i].mask, rct::INV_EIGHT);
  }
  else if (back.type == rct::RCTTypeCLSAG && !back.p.bulletproofs.empty())
  {
    rct::Bulletproof &bp = back.p.bulletproofs[0];
    bp.V.resize(back.outPk.size());
    for (size_t i = 0; i < back.outPk.size(); ++i)
      bp.V[i] = rct::scalarmultKey(back.outPk[i].mask, rct::INV_EIGHT);
  }
  for (size_t i = 0; i < back.p.CLSAGs.size(); ++i)
    back.p.CLSAGs[i].I = orig.p.CLSAGs[i].I;
}

static void roundtrip_type(int bp_version, uint8_t expect_type)
{
  rct::rctSig sig = make_sample_sig(bp_version, NIN, NOUT, RING);
  CHECK_TRUE(sig.type == expect_type);

  std::string blob;
  CHECK_TRUE(bin_dump(sig, NIN, NOUT, MIXIN, blob));
  CHECK_TRUE((uint8_t)blob[0] == expect_type);  // the type byte leads the wire encoding

  // binary archive: parse back, re-dump, must be bit-identical; the parsed
  // signature must still verify (mixRing/message restored the way the daemon
  // reconstructs them)
  {
    rct::rctSig back{};
    CHECK_TRUE(bin_parse(back, NIN, NOUT, MIXIN, blob));
    std::string again;
    CHECK_TRUE(bin_dump(back, NIN, NOUT, MIXIN, again));
    CHECK_TRUE(again == blob);
    if (expect_type >= rct::RCTTypeCLSAG)
    {
      expand_parsed(back, sig);
      CHECK_TRUE(rct::verRctSemanticsSimple(back));
      back.message = sig.message;
      back.mixRing = sig.mixRing;
      CHECK_TRUE(rct::verRctNonSemanticsSimple(back));
    }
  }

  // boost archive (wallet cache / unsigned tx sets)
  {
    std::ostringstream oss;
    boost::archive::portable_binary_oarchive oar(oss);
    oar << sig;
    std::istringstream iss(oss.str());
    boost::archive::portable_binary_iarchive iar(iss);
    rct::rctSig back{};
    iar >> back;
    std::string again;
    CHECK_TRUE(bin_dump(back, NIN, NOUT, MIXIN, again));
    CHECK_TRUE(again == blob);
  }

  // JSON, through a serialized string
  {
    rapidjson::Document doc;
    doc.SetObject();
    rapidjson::Value val;
    cryptonote::json::toJsonValue(doc, sig, val);

    rapidjson::StringBuffer buf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buf);
    val.Accept(writer);

    rapidjson::Document doc2;
    CHECK_FALSE(doc2.Parse(buf.GetString()).HasParseError());
    rct::rctSig back{};
    cryptonote::json::fromJsonValue(doc2, back);
    std::string again;
    CHECK_TRUE(bin_dump(back, NIN, NOUT, MIXIN, again));
    CHECK_TRUE(again == blob);
  }
}

static void type5_stays_5() { roundtrip_type(2, rct::RCTTypeBulletproof2); }
static void type6_is_clsag() { roundtrip_type(3, rct::RCTTypeCLSAG); }
static void type7_is_bp_plus() { roundtrip_type(4, rct::RCTTypeBulletproofPlus); }

// The type byte is part of the signed message; a 6 relabeled as 7 must not
// come back as a valid type-7 signature.
static void type_byte_is_load_bearing()
{
  rct::rctSig sig = make_sample_sig(3, NIN, NOUT, RING);
  std::string blob;
  CHECK_TRUE(bin_dump(sig, NIN, NOUT, MIXIN, blob));
  blob[0] = (char)rct::RCTTypeBulletproofPlus;
  rct::rctSig back{};
  const bool parsed = bin_parse(back, NIN, NOUT, MIXIN, blob);
  if (parsed)
    expand_parsed(back, sig);
  CHECK_TRUE(!parsed || !rct::verRctSemanticsSimple(back));
}

// The point of the format change: same shape, smaller signature.
static void type7_is_smaller_than_type5()
{
  rct::rctSig s5 = make_sample_sig(2, NIN, NOUT, RING);
  rct::rctSig s7 = make_sample_sig(4, NIN, NOUT, RING);
  std::string b5, b7;
  CHECK_TRUE(bin_dump(s5, NIN, NOUT, MIXIN, b5));
  CHECK_TRUE(bin_dump(s7, NIN, NOUT, MIXIN, b7));
  std::printf("   type 5: %zu bytes, type 7: %zu bytes\n", b5.size(), b7.size());
  CHECK_TRUE(b7.size() < b5.size());
}

int main()
{
  RUN(type5_stays_5);
  RUN(type6_is_clsag);
  RUN(type7_is_bp_plus);
  RUN(type_byte_is_load_bearing);
  RUN(type7_is_smaller_than_type5);
  return check_summary("t_serialization");
}
