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
  HYBRID key switching with the double decomposition of the key: the key digits over QP are decomposed into small
  residues and the inner products with the ciphertext digits are computed over a small basis, which replaces the
  basis extension of every ciphertext digit to QP. The result is the same key switching output as plain HYBRID, so
  the tests check the usual precision of leveled operations (relinearization, rotations, hoisted rotations),
  of CKKS bootstrapping (hoisted linear transforms and polynomial evaluation) and of BGV (exact integer
  arithmetic), for several numbers of ciphertext digits (dnum) and key digit sizes, and the serialization of the
  context and of the decomposed keys.
 */
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <sstream>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "openfhe.h"

// serialization
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/ckksrns/ckksrns-ser.h"

using namespace lbcrypto;

namespace {

struct Config {
    uint32_t dnum;         // number of ciphertext digits (0: default)
    uint32_t ddDigitSize;  // limbs of QP per key digit (0: plain HYBRID)
    uint32_t scalingBits;
    uint32_t firstBits;
};

CryptoContext<DCRTPoly> MakeCKKSContext(const Config& c, uint32_t ringDim, uint32_t depth, ScalingTechnique st,
                                        SecretKeyDist skd = UNIFORM_TERNARY) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(skd);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(ringDim);
    parameters.SetScalingModSize(c.scalingBits);
    parameters.SetFirstModSize(c.firstBits);
    parameters.SetScalingTechnique(st);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetNumLargeDigits(c.dnum);
    parameters.SetDoubleDecompDigitSize(c.ddDigitSize);
    parameters.SetMultiplicativeDepth(depth);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

double MaxError(const std::vector<double>& a, const std::vector<double>& b, uint32_t n) {
    double err = 0.0;
    for (uint32_t i = 0; i < n; ++i)
        err = std::max(err, std::abs(a[i] - b[i]));
    return err;
}

// relinearization (a chain of squarings), a rotation, a hoisted rotation and a rotate-and-sum, compared with the
// plaintext computation
void CheckLeveledOps(const Config& c, uint32_t ringDim, double tolerance) {
    constexpr uint32_t depth = 4;
    auto cc = MakeCKKSContext(c, ringDim, depth, FLEXIBLEAUTO);
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    cc->EvalRotateKeyGen(kp.secretKey, {1, -3, 8});

    const uint32_t slots = cc->GetEncodingParams()->GetBatchSize();
    std::vector<double> x(slots);
    for (uint32_t i = 0; i < slots; ++i)
        x[i] = std::sin(0.37 * i + 0.11) * 0.5;
    auto ct = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(x));

    // x^8 through three squarings
    auto ct2 = cc->EvalMult(ct, ct);
    auto ct4 = cc->EvalMult(ct2, ct2);
    auto ct8 = cc->EvalMult(ct4, ct4);
    std::vector<double> x8(slots);
    for (uint32_t i = 0; i < slots; ++i)
        x8[i] = std::pow(x[i], 8);

    // rotations of x^2
    auto rot1 = cc->EvalRotate(ct2, 1);
    auto rotM3 = cc->EvalRotate(ct2, -3);
    auto precomp = cc->EvalFastRotationPrecompute(ct2);
    auto fast8 = cc->EvalFastRotation(ct2, 8, 2 * ringDim, precomp);
    auto fast1 = cc->EvalFastRotation(ct2, 1, 2 * ringDim, precomp);
    auto fastExt = cc->KeySwitchDown(cc->EvalFastRotationExt(ct2, 8, precomp, true));
    std::vector<double> x2(slots), r1(slots), rM3(slots), r8(slots);
    for (uint32_t i = 0; i < slots; ++i)
        x2[i] = x[i] * x[i];
    for (uint32_t i = 0; i < slots; ++i) {
        r1[i] = x2[(i + 1) % slots];
        rM3[i] = x2[(i + slots - 3) % slots];
        r8[i] = x2[(i + 8) % slots];
    }

    auto check = [&](ConstCiphertext<DCRTPoly> ctxt, const std::vector<double>& expected, const char* what) {
        Plaintext result;
        cc->Decrypt(kp.secretKey, ctxt, &result);
        result->SetLength(slots);
        const double err = MaxError(result->GetRealPackedValue(), expected, slots);
        EXPECT_LT(err, tolerance) << what << " (dnum " << c.dnum << ", key digit size " << c.ddDigitSize << ")";
    };
    check(ct8, x8, "three squarings");
    check(rot1, r1, "rotation by 1");
    check(rotM3, rM3, "rotation by -3");
    check(fast8, r8, "hoisted rotation by 8");
    check(fast1, r1, "hoisted rotation by 1");
    check(fastExt, r8, "hoisted rotation by 8 in the extended basis");
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

}  // namespace

TEST(UTCKKSRNS_DOUBLE_DECOMP, LeveledOpsOneLimbDigits) {
    // one limb per ciphertext digit (dnum = depth + 1 limbs), several key digit sizes
    for (uint32_t dd : {1u, 2u, 3u, 7u})
        CheckLeveledOps({5, dd, 50, 60}, 1 << 12, 1e-8);
}

TEST(UTCKKSRNS_DOUBLE_DECOMP, LeveledOpsLargerDigits) {
    CheckLeveledOps({2, 3, 50, 60}, 1 << 12, 1e-8);
    CheckLeveledOps({3, 2, 50, 60}, 1 << 12, 1e-8);
    CheckLeveledOps({0, 4, 50, 60}, 1 << 12, 1e-8);
}

TEST(UTCKKSRNS_DOUBLE_DECOMP, LeveledOpsSmallPrimes) {
    CheckLeveledOps({5, 4, 30, 40}, 1 << 12, 1e-4);
    CheckLeveledOps({5, 2, 24, 30}, 1 << 12, 1e-2);
}

// CKKS bootstrapping exercises the hoisted linear transforms (extended-basis rotations), the polynomial
// evaluation (relinearizations) and the sparse-secret switch
TEST(UTCKKSRNS_DOUBLE_DECOMP, Bootstrapping) {
    const std::vector<uint32_t> levelBudget = {2, 2};
    const uint32_t depth = 2 + FHECKKSRNS::GetBootstrapDepth(levelBudget, SPARSE_ENCAPSULATED);
    for (const Config& c : {Config{depth + 1, 3, 59, 60}, Config{3, 4, 59, 60}}) {
        auto cc = MakeCKKSContext(c, 1 << 12, depth, FLEXIBLEAUTO, SPARSE_ENCAPSULATED);
        const uint32_t slots = cc->GetEncodingParams()->GetBatchSize();
        cc->EvalBootstrapSetup(levelBudget, {0, 0}, slots);
        auto kp = cc->KeyGen();
        cc->EvalMultKeyGen(kp.secretKey);
        cc->EvalBootstrapKeyGen(kp.secretKey, slots);

        std::vector<double> x(slots);
        for (uint32_t i = 0; i < slots; ++i)
            x[i] = std::sin(0.37 * i + 0.11);
        auto ct = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(x, 1, depth - 1, nullptr, slots));
        auto ctBoot = cc->EvalBootstrap(ct);
        Plaintext result;
        cc->Decrypt(kp.secretKey, ctBoot, &result);
        result->SetLength(slots);
        const double err = MaxError(result->GetRealPackedValue(), x, slots);
        EXPECT_GT(-std::log2(std::max(err, 1e-18)), 20.0) << "dnum " << c.dnum << ", key digit size " << c.ddDigitSize;
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
}

// the context (with its decomposition digit size) and the decomposed keys survive a serialization round trip
TEST(UTCKKSRNS_DOUBLE_DECOMP, Serialization) {
    const Config c{2, 2, 50, 60};
    auto cc = MakeCKKSContext(c, 1 << 12, 3, FIXEDAUTO);
    auto kp = cc->KeyGen();
    cc->EvalMultKeyGen(kp.secretKey);
    cc->EvalRotateKeyGen(kp.secretKey, {2});
    const uint32_t slots = cc->GetEncodingParams()->GetBatchSize();
    std::vector<double> x(slots, 0.25);
    for (uint32_t i = 0; i < slots; ++i)
        x[i] = 0.1 * (i % 7);
    auto ct = cc->Encrypt(kp.publicKey, cc->MakeCKKSPackedPlaintext(x));

    std::stringstream ccStream, keyStream, rotStream, ctStream, skStream;
    Serial::Serialize(cc, ccStream, SerType::BINARY);
    cc->SerializeEvalMultKey(keyStream, SerType::BINARY);
    cc->SerializeEvalAutomorphismKey(rotStream, SerType::BINARY);
    Serial::Serialize(ct, ctStream, SerType::BINARY);
    Serial::Serialize(kp.secretKey, skStream, SerType::BINARY);
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    cc->ClearEvalMultKeys();
    cc->ClearEvalAutomorphismKeys();

    CryptoContext<DCRTPoly> cc2;
    Serial::Deserialize(cc2, ccStream, SerType::BINARY);
    cc2->DeserializeEvalMultKey(keyStream, SerType::BINARY);
    cc2->DeserializeEvalAutomorphismKey(rotStream, SerType::BINARY);
    Ciphertext<DCRTPoly> ct2;
    Serial::Deserialize(ct2, ctStream, SerType::BINARY);
    PrivateKey<DCRTPoly> sk2;
    Serial::Deserialize(sk2, skStream, SerType::BINARY);

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(cc2->GetCryptoParameters());
    EXPECT_EQ(cryptoParams->GetDoubleDecompDigitSize(), c.ddDigitSize);
    auto sq = cc2->EvalMult(ct2, ct2);
    auto rot = cc2->EvalRotate(sq, 2);
    std::vector<double> expected(slots);
    for (uint32_t i = 0; i < slots; ++i)
        expected[i] = x[(i + 2) % slots] * x[(i + 2) % slots];
    Plaintext result;
    cc2->Decrypt(sk2, rot, &result);
    result->SetLength(slots);
    EXPECT_LT(MaxError(result->GetRealPackedValue(), expected, slots), 1e-8);
    CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

// BGV: the plaintext modulus scaling of the division by P, exact results
TEST(UTBGVRNS_DOUBLE_DECOMP, LeveledOps) {
    for (const auto& cfg : {std::pair<uint32_t, uint32_t>{0, 2}, std::pair<uint32_t, uint32_t>{5, 1}}) {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetPlaintextModulus(65537);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(1 << 12);
        parameters.SetMultiplicativeDepth(3);
        parameters.SetKeySwitchTechnique(HYBRID);
        parameters.SetNumLargeDigits(cfg.first);
        parameters.SetDoubleDecompDigitSize(cfg.second);
        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        auto kp = cc->KeyGen();
        cc->EvalMultKeyGen(kp.secretKey);
        cc->EvalRotateKeyGen(kp.secretKey, {1, -2});

        const uint32_t slots = cc->GetEncodingParams()->GetBatchSize();
        std::vector<int64_t> x(slots);
        for (uint32_t i = 0; i < slots; ++i)
            x[i] = static_cast<int64_t>((i * 7919) % 1000) - 500;
        auto ct = cc->Encrypt(kp.publicKey, cc->MakePackedPlaintext(x));
        auto ct2 = cc->EvalMult(ct, ct);
        auto ct4 = cc->EvalMult(ct2, ct2);
        auto rot = cc->EvalRotate(ct2, 1);
        auto rotM2 = cc->EvalRotate(ct4, -2);

        auto check = [&](ConstCiphertext<DCRTPoly> ctxt, const std::vector<int64_t>& expected, const char* what) {
            Plaintext result;
            cc->Decrypt(kp.secretKey, ctxt, &result);
            result->SetLength(slots);
            EXPECT_EQ(result->GetPackedValue(), expected)
                    << what << " (dnum " << cfg.first << ", key digit size " << cfg.second << ")";
        };
        auto modt = [](int64_t v) {
            int64_t r = v % 65537;
            if (r > 65536 / 2)
                r -= 65537;
            if (r < -65536 / 2)
                r += 65537;
            return r;
        };
        std::vector<int64_t> x2(slots), x4(slots), r1(slots), rM2(slots);
        for (uint32_t i = 0; i < slots; ++i) {
            x2[i] = modt(x[i] * x[i]);
            x4[i] = modt(x2[i] * x2[i]);
        }
        // BGV rotations act on the two rows of slots / 2 values of the packed encoding
        const uint32_t row = slots / 2;
        for (uint32_t i = 0; i < slots; ++i) {
            const uint32_t base = (i < row) ? 0 : row;
            r1[i] = x2[base + (i - base + 1) % row];
            rM2[i] = x4[base + (i - base + row - 2) % row];
        }
        check(ct2, x2, "square");
        check(ct4, x4, "fourth power");
        check(rot, r1, "rotation by 1");
        check(rotM2, rM2, "rotation by -2");
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
}
