//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Checks the library behaviour that the application guide in agents/ states as fact. When a test here fails, the
  library has changed in a way the guide describes: update the guide file named in the failure message (and this
  test), or fix the regression. See "Keeping agents/ current" in AGENTS.md.
 */

#include <cmath>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "gtest/gtest.h"
#include "key/key-ser.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

namespace {

const char CKKS_MD[] = "update agents/reference/ckks.md";
const char BFV_MD[] = "update agents/reference/bfv-bgv.md";
const char README_MD[] = "update agents/README.md";
const char TROUBLE_MD[] = "update agents/reference/troubleshooting.md";
const char MULTIPARTY_MD[] = "update agents/reference/multiparty.md";
const char SERIAL_MD[] = "update agents/reference/serialization.md";

// The guide documents the default build, which uses 64-bit native integers.
class UTAgentGuide : public ::testing::Test {
  protected:
    void SetUp() override {
#if NATIVEINT != 64
        GTEST_SKIP() << "The agent guide documents the 64-bit build";
#endif
    }

    void TearDown() override {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
};

template <typename Params>
CryptoContext<DCRTPoly> MakeContext(Params& parameters, bool advanced = true) {
    parameters.SetSecurityLevel(HEORG24_128);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    if (advanced)
        cc->Enable(ADVANCEDSHE);
    return cc;
}

// Runs f and returns the message of the exception it throws, or an empty string.
template <typename F>
std::string MessageOf(F f) {
    try {
        f();
    } catch (const std::exception& e) {
        return e.what();
    }
    return "";
}

std::vector<int64_t> DecryptPacked(const CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly>& sk,
                                   ConstCiphertext<DCRTPoly>& ct, size_t n) {
    Plaintext result;
    cc->Decrypt(sk, ct, &result);
    result->SetLength(n);
    return result->GetPackedValue();
}

std::vector<double> DecryptReal(const CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly>& sk,
                                ConstCiphertext<DCRTPoly>& ct, size_t n) {
    Plaintext result;
    cc->Decrypt(sk, ct, &result);
    result->SetLength(n);
    return result->GetRealPackedValue();
}

}  // namespace

TEST_F(UTAgentGuide, CKKS_Defaults) {
    CCParams<CryptoContextCKKSRNS> parameters;
    EXPECT_EQ(parameters.GetMultiplicativeDepth(), 1U) << CKKS_MD;
    EXPECT_EQ(parameters.GetScalingModSize(), 50U) << CKKS_MD;
    EXPECT_EQ(parameters.GetFirstModSize(), 60U) << CKKS_MD;
    EXPECT_EQ(parameters.GetScalingTechnique(), FLEXIBLEAUTOEXT) << CKKS_MD;
    EXPECT_EQ(parameters.GetSecretKeyDist(), UNIFORM_TERNARY) << CKKS_MD;
    EXPECT_EQ(parameters.GetSecurityLevel(), HEStd_128_classic) << CKKS_MD;
}

TEST_F(UTAgentGuide, CKKS_RingDimension) {
    const std::vector<std::pair<uint32_t, uint32_t>> table = {{1, 16384},  {5, 32768},   {10, 32768},
                                                              {20, 65536}, {30, 131072}, {40, 131072}};
    for (const auto& [depth, ringDim] : table) {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(depth);
        parameters.SetScalingModSize(50);
        auto cc = MakeContext(parameters);
        EXPECT_EQ(cc->GetRingDimension(), ringDim) << "depth " << depth << ": " << CKKS_MD;
        // batch size defaults to half the ring dimension
        EXPECT_EQ(cc->GetEncodingParams()->GetBatchSize(), ringDim / 2) << CKKS_MD;
    }
}

TEST_F(UTAgentGuide, CKKS_LevelsRotationsAndSums) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(6);
    parameters.SetScalingModSize(50);
    // twice the length of the input, so that wrapping at the batch size differs from wrapping at the input length
    parameters.SetBatchSize(16);
    auto cc = MakeContext(parameters);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1, -1});

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, -0.5, -0.25, 0.1, 0.9};
    auto ct = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x));

    // levels used by each operation
    EXPECT_EQ(ct->GetLevel(), 0U) << CKKS_MD;
    EXPECT_EQ(cc->EvalMult(ct, ct)->GetLevel(), 1U) << CKKS_MD;
    EXPECT_EQ(cc->EvalMult(ct, 3.0)->GetLevel(), 1U) << CKKS_MD;
    EXPECT_EQ(cc->EvalMult(ct, cc->MakeCKKSPackedPlaintext(x))->GetLevel(), 1U) << CKKS_MD;
    EXPECT_EQ(cc->EvalAdd(ct, 1.5)->GetLevel(), 0U) << CKKS_MD;
    EXPECT_EQ(cc->EvalAdd(ct, ct)->GetLevel(), 0U) << CKKS_MD;
    EXPECT_EQ(cc->EvalRotate(ct, 1)->GetLevel(), 0U) << CKKS_MD;
    EXPECT_EQ(cc->EvalPoly(ct, {1.0, 0.0, 0.5, 0.0, 0.25})->GetLevel(), 3U) << CKKS_MD;
    // degree 13 costs 5 levels, one less on [-1, 1]
    EXPECT_EQ(cc->EvalLogistic(ct, -1, 1, 13)->GetLevel(), 4U) << CKKS_MD;
    EXPECT_EQ(cc->EvalLogistic(ct, -2, 2, 13)->GetLevel(), 5U) << CKKS_MD;

    // a positive index moves values towards slot 0, and the rotation wraps at the batch size
    auto left = DecryptReal(cc, keys.secretKey, cc->EvalRotate(ct, 1), 16);
    auto right = DecryptReal(cc, keys.secretKey, cc->EvalRotate(ct, -1), 16);
    EXPECT_NEAR(left[0], x[1], 1e-6) << CKKS_MD;
    EXPECT_NEAR(left[7], 0.0, 1e-6) << CKKS_MD;
    EXPECT_NEAR(left[15], x[0], 1e-6) << CKKS_MD;
    EXPECT_NEAR(right[0], 0.0, 1e-6) << CKKS_MD;
    EXPECT_NEAR(right[1], x[0], 1e-6) << CKKS_MD;

    // operands at different levels combine directly
    auto x4 = cc->EvalMult(cc->EvalMult(ct, ct), cc->EvalMult(ct, ct));
    auto mixed = DecryptReal(cc, keys.secretKey, cc->EvalAdd(x4, ct), 8);
    EXPECT_NEAR(mixed[0], std::pow(x[0], 4) + x[0], 1e-6) << CKKS_MD;

    double sum = 0;
    for (double v : x)
        sum += v;
    // summing over the batch size puts the total in every slot
    auto total = DecryptReal(cc, keys.secretKey, cc->EvalSum(ct, 16), 16);
    EXPECT_NEAR(total[0], sum, 1e-6) << CKKS_MD;
    EXPECT_NEAR(total[9], sum, 1e-6) << CKKS_MD;
}

TEST_F(UTAgentGuide, CKKS_BootstrappingParameters) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(HYBRID_TERNARY);
    parameters.SetScalingModSize(59);
    parameters.SetFirstModSize(60);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    uint32_t depth = 10 + FHECKKSRNS::GetBootstrapDepth({4, 4}, HYBRID_TERNARY);
    parameters.SetMultiplicativeDepth(depth);
    auto cc = MakeContext(parameters);
    cc->Enable(FHE);
    EXPECT_EQ(cc->GetRingDimension(), 131072U) << CKKS_MD;
}

TEST_F(UTAgentGuide, CKKS_ErrorMessages) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    parameters.SetBatchSize(8);
    auto cc = MakeContext(parameters, false);
    auto keys = cc->KeyGen();
    auto ct = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(std::vector<double>{0.5, 1, 2, 3}));

    auto contains = [](const std::string& message, const std::string& part) {
        return message.find(part) != std::string::npos;
    };

    EXPECT_TRUE(
            contains(MessageOf([&] { cc->EvalMult(ct, ct); }), "Call EvalMultKeyGen() to have EvalMultKey available"))
            << TROUBLE_MD;
    cc->EvalMultKeyGen(keys.secretKey);

    EXPECT_TRUE(contains(MessageOf([&] { cc->EvalRotate(ct, 1); }), "EvalAutomorphismKeys are not generated"))
            << TROUBLE_MD;
    cc->EvalRotateKeyGen(keys.secretKey, {1});
    EXPECT_TRUE(contains(MessageOf([&] { cc->EvalRotate(ct, 3); }), "EvalKey for index [")) << TROUBLE_MD;

    EXPECT_TRUE(contains(MessageOf([&] { cc->EvalPoly(ct, {1.0, 2.0, 3.0}); }), "Enable(ADVANCEDSHE) must be called"))
            << TROUBLE_MD;

    // going past the multiplicative depth is reported at decryption
    auto tooDeep = cc->EvalMult(cc->EvalMult(ct, ct), ct);
    EXPECT_TRUE(contains(MessageOf([&] {
                             Plaintext result;
                             cc->Decrypt(keys.secretKey, tooDeep, &result);
                         }),
                         "approximation error is too high"))
            << README_MD << " and " << TROUBLE_MD;

    // a second multiplication past the depth throws at the multiplication
    EXPECT_TRUE(contains(MessageOf([&] { cc->EvalMult(tooDeep, ct); }), "is insufficient; increase it"))
            << README_MD << " and " << TROUBLE_MD;
    auto scaledTwice = cc->EvalMult(cc->EvalMult(ct, 2.0), 2.0);
    EXPECT_TRUE(contains(MessageOf([&] { cc->EvalMult(scaledTwice, 2.0); }),
                         "Removing last element of DCRTPoly renders it invalid"))
            << TROUBLE_MD;

    // EvalSum needs its own keys; rotation keys are not enough
    cc->Enable(ADVANCEDSHE);
    EXPECT_TRUE(contains(MessageOf([&] { cc->EvalSum(ct, 4); }), "EvalKey for index [")) << TROUBLE_MD;
}

TEST_F(UTAgentGuide, CKKS_BootstrappingSlots) {
    // the toy parameters of the guide; the ciphertext must be encoded with the slots given to the setup
    uint32_t numSlots = 8;
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(HYBRID_TERNARY);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1 << 12);
    parameters.SetScalingModSize(59);
    parameters.SetFirstModSize(60);
    parameters.SetScalingTechnique(FLEXIBLEAUTO);
    std::vector<uint32_t> levelBudget = {3, 3};
    parameters.SetMultiplicativeDepth(10 + FHECKKSRNS::GetBootstrapDepth(levelBudget, HYBRID_TERNARY));
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    cc->EvalBootstrapSetup(levelBudget, {0, 0}, numSlots);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalBootstrapKeyGen(keys.secretKey, numSlots);

    std::vector<double> x = {0.25, 0.5, 0.75, 1.0, -0.9, 0.1, 0.3, -0.4};
    auto ct = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, numSlots));
    auto refreshed = DecryptReal(cc, keys.secretKey, cc->EvalBootstrap(ct), numSlots);
    for (size_t i = 0; i < x.size(); ++i)
        EXPECT_NEAR(refreshed[i], x[i], 1e-3) << CKKS_MD;

    auto fullyPacked = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(x));
    std::string message = MessageOf([&] { cc->EvalBootstrap(fullyPacked); });
    EXPECT_NE(message.find("Precomputations for"), std::string::npos) << CKKS_MD << " and " << TROUBLE_MD;
    EXPECT_NE(message.find("slots not found"), std::string::npos) << CKKS_MD << " and " << TROUBLE_MD;
}

TEST_F(UTAgentGuide, Serialization_Failures) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(50);
    auto cc = MakeContext(parameters);
    auto keys = cc->KeyGen();
    auto ct = cc->Encrypt(keys.publicKey, cc->MakeCKKSPackedPlaintext(std::vector<double>{0.5, 1}));

    // a file that cannot be opened is reported by the return value
    Ciphertext<DCRTPoly> fromFile;
    EXPECT_FALSE(Serial::DeserializeFromFile("no-such-directory/ct.bin", fromFile, SerType::BINARY)) << SERIAL_MD;
    EXPECT_FALSE(Serial::SerializeToFile("no-such-directory/ct.bin", ct, SerType::BINARY)) << SERIAL_MD;

    // truncated data throws
    std::stringstream whole;
    Serial::Serialize(ct, whole, SerType::BINARY);
    std::string bytes = whole.str();
    std::stringstream truncated(bytes.substr(0, bytes.size() / 2));
    Ciphertext<DCRTPoly> fromStream;
    EXPECT_NE(MessageOf([&] { Serial::Deserialize(fromStream, truncated, SerType::BINARY); }), "") << SERIAL_MD;

    // the key serializers return false when the context or the key tag has no keys
    std::stringstream keyStream;
    EXPECT_FALSE(cc->SerializeEvalMultKey(keyStream, SerType::BINARY, cc)) << SERIAL_MD;
    EXPECT_FALSE(cc->SerializeEvalAutomorphismKey(keyStream, SerType::BINARY, cc)) << SERIAL_MD;
    EXPECT_FALSE(cc->SerializeEvalMultKey(keyStream, SerType::BINARY, std::string("no such tag"))) << SERIAL_MD;
    cc->EvalMultKeyGen(keys.secretKey);
    EXPECT_TRUE(cc->SerializeEvalMultKey(keyStream, SerType::BINARY, cc)) << SERIAL_MD;

    // a key stream that is not open throws
    std::ifstream missing("no-such-directory/mult.key", std::ios::in | std::ios::binary);
    EXPECT_NE(MessageOf([&] { cc->DeserializeEvalMultKey(missing, SerType::BINARY); }), "") << SERIAL_MD;
}

TEST_F(UTAgentGuide, BFV_BGV_DefaultsAndRingDimension) {
    CCParams<CryptoContextBFVRNS> defaults;
    EXPECT_EQ(defaults.GetPlaintextModulus(), 0U) << BFV_MD;
    EXPECT_EQ(defaults.GetMultiplicativeDepth(), 1U) << BFV_MD;
    EXPECT_EQ(defaults.GetSecurityLevel(), HEStd_128_classic) << BFV_MD;

    EXPECT_NE(MessageOf([] {
                  CCParams<CryptoContextBFVRNS> parameters;
                  GenCryptoContext(parameters);
              }).find("PlaintextModulus is not set"),
              std::string::npos)
            << TROUBLE_MD;

    const std::vector<std::pair<uint32_t, uint32_t>> table = {{1, 8192}, {2, 8192}, {4, 16384}, {8, 16384}};
    for (const auto& [depth, ringDim] : table) {
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(65537);
        parameters.SetMultiplicativeDepth(depth);
        EXPECT_EQ(MakeContext(parameters)->GetRingDimension(), ringDim) << "depth " << depth << ": " << BFV_MD;
    }

    // a larger plaintext modulus can raise it
    CCParams<CryptoContextBFVRNS> larger;
    larger.SetPlaintextModulus(1074266113);
    larger.SetMultiplicativeDepth(8);
    EXPECT_EQ(MakeContext(larger)->GetRingDimension(), 32768U) << BFV_MD;

    const std::vector<std::pair<uint32_t, uint32_t>> tableBGV = {{1, 8192}, {2, 16384}, {4, 16384}, {8, 32768}};
    for (const auto& [depth, ringDim] : tableBGV) {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetPlaintextModulus(65537);
        parameters.SetMultiplicativeDepth(depth);
        EXPECT_EQ(MakeContext(parameters)->GetRingDimension(), ringDim) << "BGV depth " << depth << ": " << BFV_MD;
    }
}

TEST_F(UTAgentGuide, BFV_PlaintextModulusTable) {
    // every modulus in the guide's table must suit packed encoding and compute correctly
    for (uint64_t t : {65537ULL, 786433ULL, 21495809ULL, 1074266113ULL, 1099512938497ULL, 1125899915231233ULL}) {
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetPlaintextModulus(t);
        parameters.SetMultiplicativeDepth(1);
        auto cc = MakeContext(parameters);
        ASSERT_EQ((t - 1) % (2 * cc->GetRingDimension()), 0U) << "t = " << t << ": " << BFV_MD;

        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        int64_t big = static_cast<int64_t>(std::sqrt(static_cast<double>((t - 1) / 2))) - 1;
        auto ct = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({big, -big, 3}));
        auto square = DecryptPacked(cc, keys.secretKey, cc->EvalMult(ct, ct), 3);
        EXPECT_EQ(square[0], big * big) << "t = " << t << ": " << BFV_MD;
        EXPECT_EQ(square[1], big * big) << "t = " << t << ": " << BFV_MD;
        EXPECT_EQ(square[2], 9) << "t = " << t << ": " << BFV_MD;
    }
}

TEST_F(UTAgentGuide, BGV_PlaintextModulusLimit) {
    // BGV accepts the table up to the 31-bit entry
    {
        uint64_t t = 1074266113ULL;
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetPlaintextModulus(t);
        parameters.SetMultiplicativeDepth(1);
        auto cc = MakeContext(parameters);
        ASSERT_EQ((t - 1) % (2 * cc->GetRingDimension()), 0U) << BFV_MD;
        auto keys = cc->KeyGen();
        cc->EvalMultKeyGen(keys.secretKey);
        int64_t big = static_cast<int64_t>(std::sqrt(static_cast<double>((t - 1) / 2))) - 1;
        auto ct = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({big, -big, 3}));
        auto square = DecryptPacked(cc, keys.secretKey, cc->EvalMult(ct, ct), 3);
        EXPECT_EQ(square[0], big * big) << BFV_MD;
        EXPECT_EQ(square[2], 9) << BFV_MD;
    }
    // and rejects the two largest entries
    for (uint64_t t : {1099512938497ULL, 1125899915231233ULL}) {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetPlaintextModulus(t);
        parameters.SetMultiplicativeDepth(1);
        EXPECT_NE(MessageOf([&] { MakeContext(parameters); }).find("We do not support moduli greater than"),
                  std::string::npos)
                << "t = " << t << ": " << BFV_MD << " and " << TROUBLE_MD;
    }
}

TEST_F(UTAgentGuide, BFV_WrapRotationAndSum) {
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(1);
    auto cc = MakeContext(parameters);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    cc->EvalSumKeyGen(keys.secretKey);
    cc->EvalRotateKeyGen(keys.secretKey, {1, -1, 2, 3});
    uint32_t ringDim = cc->GetRingDimension();

    // arithmetic is modulo the plaintext modulus, with no error
    auto big = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({1000, -5}));
    auto sq = DecryptPacked(cc, keys.secretKey, cc->EvalMult(big, big), 2);
    EXPECT_EQ(sq[0], 16945) << BFV_MD;
    EXPECT_EQ(sq[1], 25) << BFV_MD;

    // rotation: two rows of N/2, each rotated on its own; a short vector gets zeros shifted in
    std::vector<int64_t> v = {1, 2, 3, 4, -5, 6, 7, 8};
    auto ct = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(v));
    auto left = DecryptPacked(cc, keys.secretKey, cc->EvalRotate(ct, 1), ringDim);
    EXPECT_EQ(left[0], 2) << BFV_MD;
    EXPECT_EQ(left[6], 8) << BFV_MD;
    EXPECT_EQ(left[7], 0) << BFV_MD;
    EXPECT_EQ(left[ringDim / 2 - 1], 1) << BFV_MD;
    EXPECT_EQ(left[ringDim - 1], 0) << BFV_MD;
    // a rotation index without a key is reported as a bare map::at
    EXPECT_EQ(MessageOf([&] { cc->EvalRotate(ct, 5); }), "map::at") << TROUBLE_MD;
    auto right = DecryptPacked(cc, keys.secretKey, cc->EvalRotate(ct, -1), 9);
    EXPECT_EQ(right[0], 0) << BFV_MD;
    EXPECT_EQ(right[1], 1) << BFV_MD;
    EXPECT_EQ(right[8], 8) << BFV_MD;

    // EvalSum: slot i holds the sum of slots i ... i+n-1, and n is rounded up to a power of two
    auto sum8 = DecryptPacked(cc, keys.secretKey, cc->EvalSum(ct, 8), 2);
    EXPECT_EQ(sum8[0], 26) << BFV_MD;
    EXPECT_EQ(sum8[1], 25) << BFV_MD;
    EXPECT_EQ(DecryptPacked(cc, keys.secretKey, cc->EvalSum(ct, 5), 1)[0], 26) << BFV_MD;

    // one multiplication followed by rotations and a sum fits in depth 1
    std::vector<int64_t> a(64), b(64, 2);
    for (size_t i = 0; i < a.size(); ++i)
        a[i] = i + 1;
    auto product = cc->EvalMult(cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(a)),
                                cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext(b)));
    auto window = cc->EvalAdd(cc->EvalAdd(product, cc->EvalRotate(product, 1)),
                              cc->EvalAdd(cc->EvalRotate(product, 2), cc->EvalRotate(product, 3)));
    EXPECT_EQ(DecryptPacked(cc, keys.secretKey, cc->EvalSum(window, 64), 1)[0], 16620) << BFV_MD;
}

TEST_F(UTAgentGuide, BGV_DepthExceeded) {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);
    auto cc = MakeContext(parameters);
    auto keys = cc->KeyGen();
    cc->EvalMultKeyGen(keys.secretKey);
    auto ct = cc->Encrypt(keys.publicKey, cc->MakePackedPlaintext({2}));
    const char guide[] = "update agents/README.md, agents/reference/bfv-bgv.md and agents/reference/troubleshooting.md";

    // within the depth the result is exact
    ct = cc->EvalMult(ct, ct);
    EXPECT_EQ(DecryptPacked(cc, keys.secretKey, ct, 1)[0], 4) << guide;
    ct = cc->EvalMult(ct, ct);
    EXPECT_EQ(DecryptPacked(cc, keys.secretKey, ct, 1)[0], 16) << guide;

    // one multiplication past the depth raises no error and decrypts to a wrong value
    EXPECT_EQ(MessageOf([&] { ct = cc->EvalMult(ct, ct); }), "") << guide;
    EXPECT_NE(DecryptPacked(cc, keys.secretKey, ct, 1)[0], 256) << guide;

    // the next one throws
    EXPECT_NE(MessageOf([&] { ct = cc->EvalMult(ct, ct); }).find("Too few towers to support ModReduce"),
              std::string::npos)
            << guide;
}

TEST_F(UTAgentGuide, PRE_NeedsMode) {
    auto reEncrypts = [](auto parameters, bool setMode) {
        if (setMode)
            parameters.SetPREMode(INDCPA);
        auto cc = MakeContext(parameters, false);
        cc->Enable(PRE);
        auto alice = cc->KeyGen();
        auto bob = cc->KeyGen();
        return MessageOf([&] { cc->ReKeyGen(alice.secretKey, bob.publicKey); });
    };

    CCParams<CryptoContextBGVRNS> bgv;
    bgv.SetPlaintextModulus(65537);
    CCParams<CryptoContextBFVRNS> bfv;
    bfv.SetPlaintextModulus(65537);
    CCParams<CryptoContextCKKSRNS> ckks;

    // without a PRE mode, CKKS and BGV refuse to generate a re-encryption key
    EXPECT_NE(reEncrypts(bgv, false).find("PRE is disabled"), std::string::npos) << MULTIPARTY_MD;
    EXPECT_NE(reEncrypts(ckks, false).find("PRE is disabled"), std::string::npos) << MULTIPARTY_MD;
    // INDCPA is supported by every scheme
    EXPECT_EQ(reEncrypts(bgv, true), "") << MULTIPARTY_MD;
    EXPECT_EQ(reEncrypts(ckks, true), "") << MULTIPARTY_MD;
    EXPECT_EQ(reEncrypts(bfv, true), "") << MULTIPARTY_MD;
    // BFV also accepts the default mode
    EXPECT_EQ(reEncrypts(bfv, false), "") << MULTIPARTY_MD;

    // FIXED_NOISE_HRA is a BGV mode
    bfv.SetPREMode(FIXED_NOISE_HRA);
    EXPECT_NE(MessageOf([&] { MakeContext(bfv, false); }).find("is not supported for BFVRNS"), std::string::npos)
            << MULTIPARTY_MD;
    bgv.SetPREMode(FIXED_NOISE_HRA);
    EXPECT_EQ(MessageOf([&] { MakeContext(bgv, false); }), "") << MULTIPARTY_MD;
}

TEST_F(UTAgentGuide, PRE_NoiseFloodingSetup) {
    // the settings the guide lists for NOISE_FLOODING_HRA; `omit` leaves one of them out
    auto generate = [](int omit) {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetPlaintextModulus(2);
        parameters.SetPREMode(NOISE_FLOODING_HRA);
        if (omit != 1)
            parameters.SetScalingTechnique(FIXEDMANUAL);
        if (omit != 2)
            parameters.SetPRENumHops(2);
        if (omit != 3)
            parameters.SetMultiplicativeDepth(0);
        if (omit != 4)
            parameters.SetRingDim(32768);
        CryptoContext<DCRTPoly> cc;
        std::string message = MessageOf([&] { cc = MakeContext(parameters, false); });
        return std::make_pair(cc, message);
    };

    // each omission is rejected with a message that names the setting
    const std::vector<std::string> named = {"FIXEDMANUAL", "PRENumHops", "multiplicativeDepth", "ringDim"};
    for (int omit = 1; omit <= 4; ++omit)
        EXPECT_NE(generate(omit).second.find(named[omit - 1]), std::string::npos)
                << "setting " << omit << " is no longer required: " << MULTIPARTY_MD;

    auto [cc, message] = generate(0);
    ASSERT_EQ(message, "") << MULTIPARTY_MD;
    cc->Enable(PRE);
    auto alice = cc->KeyGen();
    auto bob = cc->KeyGen();
    auto ct = cc->Encrypt(alice.publicKey, cc->MakeCoefPackedPlaintext({1, 0, 1, 1}));
    auto ctBob = cc->ReEncrypt(ct, cc->ReKeyGen(alice.secretKey, bob.publicKey));
    Plaintext result;
    cc->Decrypt(bob.secretKey, ctBob, &result);
    result->SetLength(4);
    EXPECT_EQ(result->GetCoefPackedValue(), (std::vector<int64_t>{1, 0, 1, 1})) << MULTIPARTY_MD;
}
