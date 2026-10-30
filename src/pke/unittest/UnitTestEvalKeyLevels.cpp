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
  Tests for generating evaluation keys at a specified level and for compressing existing
  evaluation keys (https://github.com/openfheorg/openfhe-development/issues/413):
  - Eval*KeyGen with a nonzero number of dropped levels produces keys with fewer RNS limbs
    that work on ciphertexts at (or above) that level and are rejected below it.
  - CompressEvalKey reduces the number of RNS limbs of an existing key.
  - The cryptocontext automorphism key map keeps the key with the most towers when keys
    for the same index are inserted repeatedly.
  - EvalBootstrapKeyGen generates each rotation key over the towers of the largest ciphertext
    it is applied to: per level of CoeffsToSlots from the raised level down, and per level of
    SlotsToCoeffs from the towers of the ciphertext entering it down (bootstrapping itself
    with these keys is covered by the bootstrapping tests).
  - EvalCKKStoFHEWKeyGen generates the rotation keys and the conjugation key of its SlotsToCoeffs
    transform over the two towers the ciphertext is compressed to before the transform.
 */

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "UnitTestUtils.h"
#include "cryptocontext-ser.h"
#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "key/key-ser.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "scheme/bgvrns/gen-cryptocontext-bgvrns.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "scheme/ckksrns/ckksrns-schemeswitching.h"
#include "scheme/ckksrns/ckksrns-ser.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "scheme/scheme-swch-params.h"

using namespace lbcrypto;

namespace {

constexpr uint32_t MULT_DEPTH = 4;
constexpr uint32_t RING_DIM = 1 << 8;
constexpr size_t VEC_SIZE = 8;

CryptoContext<DCRTPoly> MakeCKKSContext(KeySwitchTechnique ksTech) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(MULT_DEPTH);
    parameters.SetScalingModSize(45);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(RING_DIM);
    parameters.SetKeySwitchTechnique(ksTech);
    // BV key switching with full RNS digits adds noise on the order of the RNS moduli,
    // which CKKS cannot absorb at this scale; use digit decomposition instead (this also
    // exercises the digit-window path of the level-aware key generation)
    if (ksTech == BV)
        parameters.SetDigitSize(15);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

CryptoContext<DCRTPoly> MakeBGVContext(KeySwitchTechnique ksTech) {
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(MULT_DEPTH);
    parameters.SetPlaintextModulus(65537);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(RING_DIM);
    parameters.SetKeySwitchTechnique(ksTech);

    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

enum class TestScheme { CKKS, BGV };

CryptoContext<DCRTPoly> MakeContext(TestScheme scheme, KeySwitchTechnique ksTech) {
    return (scheme == TestScheme::CKKS) ? MakeCKKSContext(ksTech) : MakeBGVContext(ksTech);
}

// a separate context for the EvalSum tests: EvalSum(Rows/Cols) requires a batch size, which
// changes the packing (and so the rotation semantics) of the other tests
CryptoContext<DCRTPoly> MakeSumContext(TestScheme scheme, KeySwitchTechnique ksTech) {
    CryptoContext<DCRTPoly> cc;
    if (scheme == TestScheme::CKKS) {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetMultiplicativeDepth(MULT_DEPTH);
        parameters.SetScalingModSize(45);
        parameters.SetScalingTechnique(FIXEDMANUAL);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(RING_DIM);
        parameters.SetKeySwitchTechnique(ksTech);
        parameters.SetBatchSize(VEC_SIZE);
        if (ksTech == BV)
            parameters.SetDigitSize(15);
        cc = GenCryptoContext(parameters);
    } else {
        CCParams<CryptoContextBGVRNS> parameters;
        parameters.SetMultiplicativeDepth(MULT_DEPTH);
        parameters.SetPlaintextModulus(65537);
        parameters.SetScalingTechnique(FIXEDMANUAL);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(RING_DIM);
        parameters.SetKeySwitchTechnique(ksTech);
        parameters.SetBatchSize(VEC_SIZE);
        cc = GenCryptoContext(parameters);
    }
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    return cc;
}

Plaintext MakeTestPlaintext(TestScheme scheme, const CryptoContext<DCRTPoly>& cc) {
    if (scheme == TestScheme::CKKS) {
        std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 2.0, 3.0, 4.0, 5.0};
        return cc->MakeCKKSPackedPlaintext(x);
    }
    std::vector<int64_t> x = {1, 2, 3, 4, 5, 6, 7, 8};
    return cc->MakePackedPlaintext(x);
}

// drops `levels` RNS limbs from the ciphertext without changing the encrypted value
Ciphertext<DCRTPoly> DropCiphertextLevels(TestScheme scheme, const CryptoContext<DCRTPoly>& cc,
                                          ConstCiphertext<DCRTPoly>& ciphertext, uint32_t levels) {
    if (scheme == TestScheme::CKKS)
        return cc->LevelReduce(ciphertext, nullptr, levels);

    auto result = ciphertext->Clone();
    for (uint32_t i = 0; i < levels; ++i)
        result = cc->ModReduce(result);
    return result;
}

// checks the decryption of `ciphertext` against the values of `expected` shifted left by
// `shift` (vacated positions are checked against zero, matching the zero padding of the
// encoded test vector)
void CheckDecryption(TestScheme scheme, const CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly>& secretKey,
                     ConstCiphertext<DCRTPoly>& ciphertext, const Plaintext& expected, uint32_t shift,
                     const std::string& failmsg) {
    Plaintext result;
    cc->Decrypt(secretKey, ciphertext, &result);
    result->SetLength(VEC_SIZE);

    if (scheme == TestScheme::CKKS) {
        const auto expectedVals = expected->GetRealPackedValue();
        const auto resultVals = result->GetRealPackedValue();
        for (size_t i = 0; i < VEC_SIZE; ++i) {
            double expectedVal = (i + shift < VEC_SIZE) ? expectedVals[i + shift] : 0.0;
            EXPECT_TRUE(checkEquality(resultVals[i], expectedVal, EPSILON_HIGH)) << failmsg << " at slot " << i;
        }
    } else {
        const auto expectedVals = expected->GetPackedValue();
        const auto resultVals = result->GetPackedValue();
        for (size_t i = 0; i < VEC_SIZE; ++i) {
            int64_t expectedVal = (i + shift < VEC_SIZE) ? expectedVals[i + shift] : 0;
            EXPECT_EQ(resultVals[i], expectedVal) << failmsg << " at slot " << i;
        }
    }
}

uint32_t GetAutomorphismKeyTowers(const std::string& keyTag) {
    const auto& keyMap = CryptoContextImpl<DCRTPoly>::GetEvalAutomorphismKeyMap(keyTag);
    return keyMap.begin()->second->GetAVector()[0].GetNumOfElements();
}

std::string TestLabel(TestScheme scheme, KeySwitchTechnique ksTech) {
    std::string label = (scheme == TestScheme::CKKS) ? "CKKS" : "BGV";
    return label + ((ksTech == HYBRID) ? "/HYBRID" : "/BV");
}

const std::vector<std::pair<TestScheme, KeySwitchTechnique>> TEST_CASES = {
        {TestScheme::CKKS, HYBRID},
        {TestScheme::CKKS, BV},
        {TestScheme::BGV, HYBRID},
        {TestScheme::BGV, BV},
};

}  // anonymous namespace

// rotation keys generated at a level work for ciphertexts at that level and are rejected
// for ciphertexts with more towers
TEST(UTGENERAL_EVAL_KEY_LEVELS, RotationKeysAtLevel) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    constexpr uint32_t levels = 2;
    for (const auto& [scheme, ksTech] : TEST_CASES) {
        const std::string failmsg = "RotationKeysAtLevel " + TestLabel(scheme, ksTech);
        try {
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
            auto cc = MakeContext(scheme, ksTech);
            auto kp = cc->KeyGen();

            // a reduced key must have exactly `levels` fewer towers than a full key
            cc->EvalRotateKeyGen(kp.secretKey, {1}, levels);
            const uint32_t reducedTowers = GetAutomorphismKeyTowers(kp.secretKey->GetKeyTag());

            auto ptxt = MakeTestPlaintext(scheme, cc);
            auto ct = cc->Encrypt(kp.publicKey, ptxt);
            auto ctReduced = DropCiphertextLevels(scheme, cc, ct, levels);

            auto ctRot = cc->EvalRotate(ctReduced, 1);
            CheckDecryption(scheme, cc, kp.secretKey, ctRot, ptxt, 1, failmsg);

            // a ciphertext with more towers than the key must be rejected
            EXPECT_THROW(cc->EvalRotate(ct, 1), OpenFHEException) << failmsg;

            // a full key generated for another secret key has `levels` more towers
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
            auto kp2 = cc->KeyGen();
            cc->EvalRotateKeyGen(kp2.secretKey, {1});
            const uint32_t fullTowers = GetAutomorphismKeyTowers(kp2.secretKey->GetKeyTag());
            EXPECT_EQ(reducedTowers + levels, fullTowers) << failmsg;

            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
}

// for duplicate rotation indices, the automorphism key map keeps the key with the most towers
TEST(UTGENERAL_EVAL_KEY_LEVELS, KeyMapKeepsMostTowers) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    constexpr uint32_t levels = 2;
    for (const auto& [scheme, ksTech] : TEST_CASES) {
        const std::string failmsg = "KeyMapKeepsMostTowers " + TestLabel(scheme, ksTech);
        try {
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
            auto cc = MakeContext(scheme, ksTech);
            auto kp = cc->KeyGen();

            cc->EvalRotateKeyGen(kp.secretKey, {1}, levels);
            const uint32_t reducedTowers = GetAutomorphismKeyTowers(kp.secretKey->GetKeyTag());

            // requesting a full key for the same index must replace the reduced key
            cc->EvalRotateKeyGen(kp.secretKey, {1});
            const uint32_t fullTowers = GetAutomorphismKeyTowers(kp.secretKey->GetKeyTag());
            EXPECT_EQ(reducedTowers + levels, fullTowers) << failmsg;

            // requesting a reduced key again must keep the full key
            cc->EvalRotateKeyGen(kp.secretKey, {1}, levels);
            EXPECT_EQ(fullTowers, GetAutomorphismKeyTowers(kp.secretKey->GetKeyTag())) << failmsg;

            // the retained full key must work for a freshly encrypted ciphertext
            auto ptxt = MakeTestPlaintext(scheme, cc);
            auto ct = cc->Encrypt(kp.publicKey, ptxt);
            auto ctRot = cc->EvalRotate(ct, 1);
            CheckDecryption(scheme, cc, kp.secretKey, ctRot, ptxt, 1, failmsg);

            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
}

// relinearization keys generated at a level work for multiplications at that level and are
// rejected for ciphertexts with more towers
TEST(UTGENERAL_EVAL_KEY_LEVELS, EvalMultKeyAtLevel) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    constexpr uint32_t levels = 2;
    for (const auto& [scheme, ksTech] : TEST_CASES) {
        const std::string failmsg = "EvalMultKeyAtLevel " + TestLabel(scheme, ksTech);
        try {
            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
            auto cc = MakeContext(scheme, ksTech);
            auto kp = cc->KeyGen();

            cc->EvalMultKeyGen(kp.secretKey, levels);

            Plaintext ptxt;
            if (scheme == TestScheme::CKKS) {
                std::vector<double> x = {0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0};
                ptxt = cc->MakeCKKSPackedPlaintext(x);
            } else {
                std::vector<int64_t> x = {1, 2, 3, 4, 5, 6, 7, 8};
                ptxt = cc->MakePackedPlaintext(x);
            }
            auto ct = cc->Encrypt(kp.publicKey, ptxt);
            auto ctReduced = DropCiphertextLevels(scheme, cc, ct, levels);

            auto ctMult = cc->EvalMult(ctReduced, ctReduced);
            Plaintext result;
            cc->Decrypt(kp.secretKey, ctMult, &result);
            result->SetLength(VEC_SIZE);
            if (scheme == TestScheme::CKKS) {
                const auto vals = ptxt->GetRealPackedValue();
                const auto resultVals = result->GetRealPackedValue();
                for (size_t i = 0; i < VEC_SIZE; ++i)
                    EXPECT_TRUE(checkEquality(resultVals[i], vals[i] * vals[i], EPSILON_HIGH))
                            << failmsg << " at slot " << i;
            } else {
                const auto vals = ptxt->GetPackedValue();
                const auto resultVals = result->GetPackedValue();
                for (size_t i = 0; i < VEC_SIZE; ++i)
                    EXPECT_EQ(resultVals[i], vals[i] * vals[i]) << failmsg << " at slot " << i;
            }

            // a ciphertext with more towers than the relinearization key must be rejected
            EXPECT_THROW(cc->EvalMult(ct, ct), OpenFHEException) << failmsg;

            // requesting a full relinearization key must replace the reduced key
            cc->EvalMultKeyGen(kp.secretKey);
            auto ctMultFull = cc->EvalMult(ct, ct);
            cc->Decrypt(kp.secretKey, ctMultFull, &result);
            result->SetLength(VEC_SIZE);

            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
}

// CompressEvalKey reduces the number of RNS limbs of an existing key-switching key, and the
// compressed key still switches correctly at the reduced level
TEST(UTGENERAL_EVAL_KEY_LEVELS, CompressEvalKey) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    constexpr uint32_t levels = 2;
    for (const auto& [scheme, ksTech] : TEST_CASES) {
        const std::string failmsg = "CompressEvalKey " + TestLabel(scheme, ksTech);
        try {
            auto cc = MakeContext(scheme, ksTech);
            auto kp = cc->KeyGen();
            auto kp2 = cc->KeyGen();

            auto evalKey = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);
            auto evalKeyCompressed = cc->CompressEvalKey(evalKey, levels);

            EXPECT_EQ(evalKey->GetAVector()[0].GetNumOfElements(),
                      evalKeyCompressed->GetAVector()[0].GetNumOfElements() + levels)
                    << failmsg;

            auto ptxt = MakeTestPlaintext(scheme, cc);
            auto ct = cc->Encrypt(kp.publicKey, ptxt);
            auto ctReduced = DropCiphertextLevels(scheme, cc, ct, levels);

            // the compressed key switches a reduced ciphertext to the second secret key
            auto ctSwitched = cc->KeySwitch(ctReduced, evalKeyCompressed);
            CheckDecryption(scheme, cc, kp2.secretKey, ctSwitched, ptxt, 0, failmsg);

            // a ciphertext with more towers than the compressed key must be rejected
            EXPECT_THROW(cc->KeySwitch(ct, evalKeyCompressed), OpenFHEException) << failmsg;

            // compressing by at least the number of available limbs must be rejected
            const uint32_t sizeQ = cc->GetElementParams()->GetParams().size();
            EXPECT_THROW(cc->CompressEvalKey(evalKey, sizeQ), OpenFHEException) << failmsg;
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
}

// EvalSum keys generated at a level work for ciphertexts at that level and are rejected for
// ciphertexts with more towers; EvalSumRows/EvalSumCols keys are generated with reduced towers
TEST(UTGENERAL_EVAL_KEY_LEVELS, EvalSumKeysAtLevel) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    constexpr uint32_t levels = 2;
    for (const auto& [scheme, ksTech] : TEST_CASES) {
        const std::string failmsg = "EvalSumKeysAtLevel " + TestLabel(scheme, ksTech);
        try {
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
            auto cc = MakeSumContext(scheme, ksTech);
            auto kp = cc->KeyGen();

            cc->EvalSumKeyGen(kp.secretKey, levels);

            // every key in the generated map must have the reduced number of towers
            const uint32_t reducedTowers = GetAutomorphismKeyTowers(kp.secretKey->GetKeyTag());
            for (const auto& [indx, key] :
                 CryptoContextImpl<DCRTPoly>::GetEvalAutomorphismKeyMap(kp.secretKey->GetKeyTag())) {
                EXPECT_EQ(key->GetAVector()[0].GetNumOfElements(), reducedTowers) << failmsg << " at index " << indx;
            }

            auto ptxt = MakeTestPlaintext(scheme, cc);
            auto ct = cc->Encrypt(kp.publicKey, ptxt);
            auto ctReduced = DropCiphertextLevels(scheme, cc, ct, levels);

            auto ctSum = cc->EvalSum(ctReduced, VEC_SIZE);
            Plaintext result;
            cc->Decrypt(kp.secretKey, ctSum, &result);
            result->SetLength(VEC_SIZE);
            if (scheme == TestScheme::CKKS) {
                const auto vals = ptxt->GetRealPackedValue();
                double expected = 0.0;
                for (size_t i = 0; i < VEC_SIZE; ++i)
                    expected += vals[i];
                EXPECT_TRUE(checkEquality(result->GetRealPackedValue()[0], expected, EPSILON_HIGH)) << failmsg;
            } else {
                const auto vals = ptxt->GetPackedValue();
                int64_t expected = 0;
                for (size_t i = 0; i < VEC_SIZE; ++i)
                    expected += vals[i];
                EXPECT_EQ(result->GetPackedValue()[0], expected) << failmsg;
            }

            // a ciphertext with more towers than the keys must be rejected
            EXPECT_THROW(cc->EvalSum(ct, VEC_SIZE), OpenFHEException) << failmsg;

            // EvalSumRows/EvalSumCols key generation is supported for CKKS only; check that the
            // returned key maps also have the reduced number of towers
            if (scheme == TestScheme::CKKS) {
                auto rowKeys = cc->EvalSumRowsKeyGen(kp.secretKey, VEC_SIZE / 2, 0, levels);
                for (const auto& [indx, key] : *rowKeys)
                    EXPECT_EQ(key->GetAVector()[0].GetNumOfElements(), reducedTowers)
                            << failmsg << " (rows) at index " << indx;

                auto colKeys = cc->EvalSumColsKeyGen(kp.secretKey, levels);
                for (const auto& [indx, key] : *colKeys)
                    EXPECT_EQ(key->GetAVector()[0].GetNumOfElements(), reducedTowers)
                            << failmsg << " (cols) at index " << indx;
            }

            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
}

// reduced and compressed keys survive a serialization round trip and still key-switch
// correctly at their level
TEST(UTGENERAL_EVAL_KEY_LEVELS, SerializeReducedKeys) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    constexpr uint32_t levels = 2;
    for (const auto& [scheme, ksTech] : TEST_CASES) {
        const std::string failmsg = "SerializeReducedKeys " + TestLabel(scheme, ksTech);
        try {
            // deserialized keys resolve their cryptocontext through the factory registry;
            // clear it so they attach to the context created below
            CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
            auto cc = MakeContext(scheme, ksTech);
            auto kp = cc->KeyGen();
            auto kp2 = cc->KeyGen();

            auto keyReduced = cc->KeySwitchGen(kp.secretKey, kp2.secretKey, levels);
            auto keyCompressed = cc->CompressEvalKey(cc->KeySwitchGen(kp.secretKey, kp2.secretKey), levels);

            for (const auto& key : {keyReduced, keyCompressed}) {
                std::stringstream ss;
                Serial::Serialize(key, ss, SerType::BINARY);
                EvalKey<DCRTPoly> keyDeser;
                Serial::Deserialize(keyDeser, ss, SerType::BINARY);
                ASSERT_TRUE(keyDeser != nullptr) << failmsg;
                EXPECT_EQ(keyDeser->GetAVector()[0].GetNumOfElements(), key->GetAVector()[0].GetNumOfElements())
                        << failmsg;

                auto ptxt = MakeTestPlaintext(scheme, cc);
                auto ct = cc->Encrypt(kp.publicKey, ptxt);
                auto ctReduced = DropCiphertextLevels(scheme, cc, ct, levels);
                auto ctSwitched = cc->KeySwitch(ctReduced, keyDeser);
                CheckDecryption(scheme, cc, kp2.secretKey, ctSwitched, ptxt, 0, failmsg);
            }
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
}

// generating keys at a level equal to (or above) the number of RNS limbs must be rejected
TEST(UTGENERAL_EVAL_KEY_LEVELS, LevelsOutOfRange) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    for (const auto& [scheme, ksTech] : TEST_CASES) {
        const std::string failmsg = "LevelsOutOfRange " + TestLabel(scheme, ksTech);
        try {
            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
            auto cc = MakeContext(scheme, ksTech);
            auto kp = cc->KeyGen();

            const uint32_t sizeQ = cc->GetElementParams()->GetParams().size();
            EXPECT_THROW(cc->EvalRotateKeyGen(kp.secretKey, {1}, sizeQ), OpenFHEException) << failmsg;
            EXPECT_THROW(cc->EvalMultKeyGen(kp.secretKey, sizeQ), OpenFHEException) << failmsg;

            CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
            CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
        } catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        } catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }
    }
}

// key generation at a nonzero level is not supported for BFV
TEST(UTGENERAL_EVAL_KEY_LEVELS, BFVNotSupported) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    const std::string failmsg = "BFVNotSupported";
    try {
        CCParams<CryptoContextBFVRNS> parameters;
        parameters.SetMultiplicativeDepth(MULT_DEPTH);
        parameters.SetPlaintextModulus(65537);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(RING_DIM);

        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);

        auto kp = cc->KeyGen();
        EXPECT_THROW(cc->EvalRotateKeyGen(kp.secretKey, {1}, 1), OpenFHEException) << failmsg;
        EXPECT_THROW(cc->EvalMultKeyGen(kp.secretKey, 1), OpenFHEException) << failmsg;
        EXPECT_THROW(cc->EvalSumKeyGen(kp.secretKey, 1), OpenFHEException) << failmsg;
        auto kp2 = cc->KeyGen();
        auto evalKey = cc->KeySwitchGen(kp.secretKey, kp2.secretKey);
        EXPECT_THROW(cc->CompressEvalKey(evalKey, 1), OpenFHEException) << failmsg;

        // level 0 keeps working for BFV
        cc->EvalMultKeyGen(kp.secretKey);
        CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
    } catch (std::exception& e) {
        std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
        EXPECT_TRUE(0 == 1) << failmsg;
    } catch (...) {
        UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
    }
}

//===========================================================================================================
// Bootstrapping keys: each rotation key is generated over the towers of the largest ciphertext it is applied to,
// per level of CoeffsToSlots (from the raised level L0 down) and of SlotsToCoeffs (from lDec + lvlbDec down, see
// the setups); an index shared by several levels or both transforms gets the larger key.
// Checked for ModRaise-first and StC-first regular bootstrapping and for FE functional bootstrapping with
// sparse packing, so that the rotation by slots (shared by the partial sums of both levels) is in the key set.
namespace {

constexpr uint32_t BOOT_RING_DIM = 1 << 10;
constexpr uint32_t BOOT_SLOTS = BOOT_RING_DIM / 4;
const std::vector<uint32_t> BOOT_LEVEL_BUDGET = {3, 3};

CryptoContext<DCRTPoly> MakeBootstrapContext(ScalingTechnique st, uint32_t depth, bool feFBT) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetSecretKeyDist(UNIFORM_TERNARY);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(BOOT_RING_DIM);
#if NATIVEINT == 128
    const uint32_t scalingModSize = 78;
    const uint32_t firstModSize = 89;
#else
    const uint32_t scalingModSize = 59;
    const uint32_t firstModSize = 60;
#endif
    parameters.SetScalingModSize(scalingModSize);
    // FE functional bootstrapping requires the first modulus to be twice the scaling factor
    parameters.SetFirstModSize(feFBT ? scalingModSize + 1 : firstModSize);
    parameters.SetScalingTechnique(st);
    parameters.SetKeySwitchTechnique(HYBRID);
    parameters.SetMultiplicativeDepth(depth);
    if (feFBT) {
        parameters.SetCKKSDataType(COMPLEX);
        parameters.SetBatchSize(BOOT_SLOTS);
    }
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(ADVANCEDSHE);
    cc->Enable(FHE);
    return cc;
}

// every rotation key has the towers of one level of a transform: towersCtS - k for the k-th level of CoeffsToSlots
// or towersStC - k for the k-th level of SlotsToCoeffs (composite degree 1), a deeper level of SlotsToCoeffs has
// keys of its own, and the key of the rotation by slots and the conjugation key are full-size
void CheckBootstrapKeyLevels(const CryptoContext<DCRTPoly>& cc, const KeyPair<DCRTPoly>& kp, uint32_t towersCtS,
                             uint32_t towersStC, const std::string& failmsg) {
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
    const uint32_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();
    const uint32_t sizeP = cryptoParams->GetParamsP()->GetParams().size();
    const uint32_t M = cc->GetCyclotomicOrder();
    ASSERT_LT(towersStC, towersCtS) << failmsg;

    std::set<uint32_t> allowed = {sizeQ};
    for (uint32_t k = 0; k < BOOT_LEVEL_BUDGET[0]; ++k)
        allowed.insert(towersCtS - k);
    for (uint32_t k = 0; k < BOOT_LEVEL_BUDGET[1]; ++k)
        allowed.insert(towersStC - k);

    const auto towersQ = [sizeP](const EvalKey<DCRTPoly>& key) {
        return key->GetAVector()[0].GetNumOfElements() - sizeP;
    };

    const auto& keyMap = CryptoContextImpl<DCRTPoly>::GetEvalAutomorphismKeyMap(kp.secretKey->GetKeyTag());
    uint32_t minTowers = sizeQ;
    for (const auto& [autoIndex, key] : keyMap) {
        const uint32_t towers = towersQ(key);
        EXPECT_TRUE(allowed.count(towers))
                << failmsg << ", automorphism index " << autoIndex << " has " << towers << " towers";
        minTowers = std::min(minTowers, towers);
    }
    // a rotation shared with a higher level takes the larger key, so not every level needs keys of its own, but
    // the levels below the first one of SlotsToCoeffs are not all shared
    EXPECT_LT(minTowers, towersStC) << failmsg << ": a deeper level of SlotsToCoeffs should have keys of its own";

    // the conjugation key is applied to the output of CoeffsToSlots; the rotation by slots also folds the partial
    // sum at the raised level
    const uint32_t autoSlots = cc->GetScheme()->FindAutomorphismIndex(BOOT_SLOTS, M);
    ASSERT_TRUE(keyMap.count(M - 1) && keyMap.count(autoSlots)) << failmsg;
    EXPECT_EQ(towersQ(keyMap.at(M - 1)), sizeQ) << failmsg;
    EXPECT_EQ(towersQ(keyMap.at(autoSlots)), towersCtS) << failmsg;
}

}  // namespace

TEST(UTGENERAL_EVAL_KEY_LEVELS, BootstrapKeysAtLevel) {
#if NATIVEINT == 128
    const std::vector<ScalingTechnique> techniques = {FIXEDAUTO};
#else
    const std::vector<ScalingTechnique> techniques = {FLEXIBLEAUTO, FLEXIBLEAUTOEXT};
#endif
    const uint32_t depthBT = FHECKKSRNS::GetBootstrapDepth(BOOT_LEVEL_BUDGET, UNIFORM_TERNARY);
    const uint32_t depth = 2 + depthBT;

    for (const bool stcFirst : {false, true}) {
        for (const auto st : techniques) {
            const std::string failmsg = std::string("BootstrapKeysAtLevel ") +
                                        (stcFirst ? "StC-first " : "ModRaise-first ") + std::to_string(st);
            try {
                auto cc = MakeBootstrapContext(st, depth, false);
                cc->EvalBootstrapSetup(BOOT_LEVEL_BUDGET, {0, 0}, BOOT_SLOTS, 0, true, stcFirst);
                auto kp = cc->KeyGen();
                cc->EvalBootstrapKeyGen(kp.secretKey, BOOT_SLOTS);

                // the towers of the ciphertext entering SlotsToCoeffs: lDec + lvlbDec, with lDec = 1 for StC-first
                // (SlotsToCoeffs ends on the tower the modulus raise starts from) and L0 - depthBT for ModRaise-first,
                // where L0 excludes the extra modulus of FLEXIBLEAUTOEXT
                const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
                const uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size() - (st == FLEXIBLEAUTOEXT);
                const uint32_t towersStC = (stcFirst ? 1 : L0 - depthBT) + BOOT_LEVEL_BUDGET[1];
                CheckBootstrapKeyLevels(cc, kp, L0, towersStC, failmsg);

                CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
            } catch (std::exception& e) {
                std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
                EXPECT_TRUE(0 == 1) << failmsg;
            } catch (...) {
                UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
            }
        }
    }

#if NATIVEINT != 128
    // FE functional bootstrapping: SlotsToCoeffs runs first, on the depleted input (lDec = 1)
    const std::string failmsg = "BootstrapKeysAtLevel FE functional bootstrapping";
    try {
        auto cc = MakeBootstrapContext(FLEXIBLEAUTO, depth, true);
        cc->EvalFEFuncBootstrapSetup(BOOT_LEVEL_BUDGET, {0, 0}, BOOT_SLOTS);
        auto kp = cc->KeyGen();
        cc->EvalBootstrapKeyGen(kp.secretKey, BOOT_SLOTS);
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
        const uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size();
        CheckBootstrapKeyLevels(cc, kp, L0, 1 + BOOT_LEVEL_BUDGET[1], failmsg);
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    } catch (std::exception& e) {
        std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
        EXPECT_TRUE(0 == 1) << failmsg;
    } catch (...) {
        UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
    }
#endif
}

//===========================================================================================================
// Scheme switching keys: the SlotsToCoeffs transform of CKKS to FHEW runs on a ciphertext compressed to two
// towers, so EvalCKKStoFHEWKeyGen generates its rotation keys and the conjugation key over two towers
// (switching itself with these keys is covered by the scheme switching tests).
TEST(UTGENERAL_EVAL_KEY_LEVELS, CKKStoFHEWKeysAtLevel) {
    const std::string failmsg = "CKKStoFHEWKeysAtLevel";
    try {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecretKeyDist(UNIFORM_TERNARY);
        parameters.SetSecurityLevel(HEStd_NotSet);
        parameters.SetRingDim(64);
        parameters.SetMultiplicativeDepth(13);
#if NATIVEINT == 128
        parameters.SetScalingModSize(70);
        parameters.SetFirstModSize(80);
#else
        parameters.SetScalingModSize(50);
        parameters.SetFirstModSize(60);
#endif
        parameters.SetScalingTechnique(FIXEDAUTO);
        parameters.SetKeySwitchTechnique(HYBRID);
        parameters.SetNumLargeDigits(3);
        auto cc = GenCryptoContext(parameters);
        cc->Enable(PKE);
        cc->Enable(KEYSWITCH);
        cc->Enable(LEVELEDSHE);
        cc->Enable(ADVANCEDSHE);
        cc->Enable(SCHEMESWITCH);

        auto kp = cc->KeyGen();
        SchSwchParams params;
        params.SetSecurityLevelCKKS(HEStd_NotSet);
        params.SetSecurityLevelFHEW(TOY);
        params.SetCtxtModSizeFHEWLargePrec(25);
        params.SetNumSlotsCKKS(8);
        params.SetBStepLTrCKKStoFHEW(16);
        auto privateKeyFHEW = cc->EvalCKKStoFHEWSetup(params);
        cc->EvalCKKStoFHEWKeyGen(kp, privateKeyFHEW);

        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(cc->GetCryptoParameters());
        const uint32_t sizeP = cryptoParams->GetParamsP()->GetParams().size();
        const auto& keyMap = CryptoContextImpl<DCRTPoly>::GetEvalAutomorphismKeyMap(kp.secretKey->GetKeyTag());
        EXPECT_FALSE(keyMap.empty()) << failmsg;
        for (const auto& [autoIndex, key] : keyMap)
            EXPECT_EQ(key->GetAVector()[0].GetNumOfElements() - sizeP, 2u)
                    << failmsg << ", automorphism index " << autoIndex;

        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    } catch (std::exception& e) {
        std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
        EXPECT_TRUE(0 == 1) << failmsg;
    } catch (...) {
        UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
    }
}
