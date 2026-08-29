//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
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

#include "cryptocontext.h"
#include "encoding/ckkspackedencoding.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "UnitTestException.h"
#include "UnitTestUtils.h"
#include "utils/debug.h"

#include <memory>
#include <vector>

using namespace lbcrypto;

static const std::vector<uint32_t> DEPTHS_TO_TEST = {1, 5, 10};

TEST(UTCKKS_EXPAND_RING, EncodeThenExpandRingMatchesUncompressedExpansion) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    for (uint32_t depth : DEPTHS_TO_TEST) {
        const std::string failmsg("EncodeThenExpandRingMatchesUncompressedExpansion, depth=" +
                                  std::to_string(depth));
        SCOPED_TRACE(failmsg);

        try {
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetMultiplicativeDepth(depth);
            parameters.SetScalingModSize(50);
            parameters.SetFirstModSize(60);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetSecurityLevel(HEStd_128_classic);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(LEVELEDSHE);

            const uint32_t slots = cc->GetRingDimension() / 8;

            std::vector<double> x(slots);
            for (uint32_t i = 0; i < slots; ++i)
                x[i] = static_cast<double>(i) - static_cast<double>(slots) / 2.0;

            Plaintext ptxt = cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, slots);
            DCRTPoly big   = ptxt->GetElement<DCRTPoly>();

            const uint32_t bigDim   = big.GetRingDimension();
            const uint32_t smallDim = 2 * slots;
            const uint32_t gap      = bigDim / smallDim;

            DCRTPoly bigCoeff = big;
            bigCoeff.SetFormat(Format::COEFFICIENT);
            auto bigParams  = bigCoeff.GetParams();
            const auto& tow = bigParams->GetParams();

            std::vector<std::shared_ptr<ILNativeParams>> smallTowerParams;
            for (const auto& p : tow) {
                NativeInteger modulus   = p->GetModulus();
                NativeInteger smallRoot = p->GetRootOfUnity().ModExp(NativeInteger(gap), modulus);
                smallTowerParams.push_back(std::make_shared<ILNativeParams>(2 * smallDim, modulus, smallRoot));
            }
            auto smallParams = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(2 * smallDim, smallTowerParams);

            DCRTPoly small(smallParams, Format::COEFFICIENT, true);
            for (uint32_t t = 0; t < tow.size(); ++t) {
                NativePoly bigTower = bigCoeff.GetElementAtIndex(t);
                const NativeVector& bigVals = bigTower.GetValues();

                NativeVector smallVals(smallDim, tow[t]->GetModulus());
                for (uint32_t i = 0; i < smallDim; ++i)
                    smallVals[i] = bigVals[gap * i];

                NativePoly smallTower = small.GetElementAtIndex(t);
                smallTower.SetValues(std::move(smallVals), Format::COEFFICIENT);
                small.SetElementAtIndex(t, std::move(smallTower));
            }
            small.SetFormat(Format::EVALUATION);

            DCRTPoly expanded = small.ExpandRing(bigParams);

            EXPECT_EQ(expanded, big) << failmsg;
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }

        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    OpenFHEParallelControls.UnitTestStop();
}

TEST(UTCKKS_EXPAND_RING, CompressedEncodeMatchesUncompressedEncode) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    for (uint32_t depth : DEPTHS_TO_TEST) {
        const std::string failmsg("CompressedEncodeMatchesUncompressedEncode, depth=" + std::to_string(depth));
        SCOPED_TRACE(failmsg);

        try {
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetMultiplicativeDepth(depth);
            parameters.SetScalingModSize(50);
            parameters.SetFirstModSize(60);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetSecurityLevel(HEStd_128_classic);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(LEVELEDSHE);

            const uint32_t slots = cc->GetRingDimension() / 8;

            std::vector<double> x(slots);
            for (uint32_t i = 0; i < slots; ++i)
                x[i] = static_cast<double>(i) - static_cast<double>(slots) / 2.0;

            Plaintext uncompressed = cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, slots, false);
            Plaintext compressed   = cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, slots, true);

            auto compressedCKKS = std::dynamic_pointer_cast<CKKSPackedEncoding>(compressed);
            ASSERT_NE(compressedCKKS, nullptr) << failmsg;

            EXPECT_TRUE(compressedCKKS->IsCompressed()) << failmsg;
            EXPECT_EQ(compressed->GetElementRingDimension(), 2 * slots) << failmsg;
            EXPECT_EQ(compressedCKKS->GetCompressionGap(), cc->GetRingDimension() / (2 * slots)) << failmsg;
            EXPECT_EQ(compressedCKKS->GetExpandedElement(), uncompressed->GetElement<DCRTPoly>()) << failmsg;
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }

        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    OpenFHEParallelControls.UnitTestStop();
}

TEST(UTCKKS_EXPAND_RING, CompressedEncodeReducesStorage) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    for (uint32_t depth : DEPTHS_TO_TEST) {
        const std::string failmsg("CompressedEncodeReducesStorage, depth=" + std::to_string(depth));
        SCOPED_TRACE(failmsg);

        try {
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetMultiplicativeDepth(depth);
            parameters.SetScalingModSize(50);
            parameters.SetFirstModSize(60);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetSecurityLevel(HEStd_128_classic);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(LEVELEDSHE);

            const uint32_t slots = cc->GetRingDimension() / 16;
            const uint32_t gap   = cc->GetRingDimension() / (2 * slots);

            std::vector<double> x(slots);
            for (uint32_t i = 0; i < slots; ++i)
                x[i] = static_cast<double>(i) - static_cast<double>(slots) / 2.0;

            Plaintext uncompressed = cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, slots, false);
            Plaintext compressed   = cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, slots, true);

            const DCRTPoly& uncompressedElement = uncompressed->GetElement<DCRTPoly>();
            const DCRTPoly& compressedElement   = compressed->GetElement<DCRTPoly>();

            ASSERT_EQ(uncompressedElement.GetNumOfElements(), compressedElement.GetNumOfElements()) << failmsg;

            size_t uncompressedBytes = static_cast<size_t>(uncompressedElement.GetRingDimension()) *
                                       uncompressedElement.GetNumOfElements() * sizeof(NativeInteger);
            size_t compressedBytes = static_cast<size_t>(compressedElement.GetRingDimension()) *
                                     compressedElement.GetNumOfElements() * sizeof(NativeInteger);

            EXPECT_EQ(compressedElement.GetRingDimension(), uncompressedElement.GetRingDimension() / gap) << failmsg;
            EXPECT_EQ(uncompressedBytes, compressedBytes * gap) << failmsg;
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }

        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    OpenFHEParallelControls.UnitTestStop();
}

TEST(UTCKKS_EXPAND_RING, CompressedEncryptDecrypt) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    for (uint32_t depth : DEPTHS_TO_TEST) {
        const std::string failmsg("CompressedEncryptDecrypt, depth=" + std::to_string(depth));
        SCOPED_TRACE(failmsg);

        try {
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetMultiplicativeDepth(depth);
            parameters.SetScalingModSize(50);
            parameters.SetFirstModSize(60);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetSecurityLevel(HEStd_128_classic);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);

            const uint32_t slots = cc->GetRingDimension() / 16;

            std::vector<double> x(slots);
            for (uint32_t i = 0; i < slots; ++i)
                x[i] = static_cast<double>(i) - static_cast<double>(slots) / 2.0;

            Plaintext compressed = cc->MakeCKKSPackedPlaintext(x, 1, 0, nullptr, slots, true);
            auto compressedCKKS  = std::dynamic_pointer_cast<CKKSPackedEncoding>(compressed);
            ASSERT_NE(compressedCKKS, nullptr) << failmsg;
            ASSERT_TRUE(compressedCKKS->IsCompressed()) << failmsg;

            KeyPair<DCRTPoly> keyPair = cc->KeyGen();

            auto ciphertext = cc->Encrypt(keyPair.publicKey, compressed);
            ASSERT_NE(ciphertext, nullptr) << failmsg;
            EXPECT_EQ(ciphertext->GetElements()[0].GetRingDimension(), cc->GetRingDimension()) << failmsg;

            Plaintext result;
            cc->Decrypt(keyPair.secretKey, ciphertext, &result);
            result->SetLength(slots);

            checkEquality(x, result->GetRealPackedValue(), EPSILON_HIGH, failmsg);
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }

        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    OpenFHEParallelControls.UnitTestStop();
}

TEST(UTCKKS_EXPAND_RING, CompressedCiphertextPlaintextArithmetic) {
    setupSignals();
    OpenFHEParallelControls.UnitTestStart();

    for (uint32_t depth : DEPTHS_TO_TEST) {
        const std::string failmsg("CompressedCiphertextPlaintextArithmetic, depth=" + std::to_string(depth));
        SCOPED_TRACE(failmsg);

        try {
            CCParams<CryptoContextCKKSRNS> parameters;
            parameters.SetMultiplicativeDepth(depth);
            parameters.SetScalingModSize(50);
            parameters.SetFirstModSize(60);
            parameters.SetScalingTechnique(FIXEDMANUAL);
            parameters.SetSecurityLevel(HEStd_128_classic);

            auto cc = GenCryptoContext(parameters);
            cc->Enable(PKE);
            cc->Enable(KEYSWITCH);
            cc->Enable(LEVELEDSHE);

            const uint32_t slots  = cc->GetRingDimension() / 16;
            const double multEps  = 0.01;

            std::vector<double> y(slots), z(slots);
            for (uint32_t i = 0; i < slots; ++i) {
                y[i] = 0.01 * static_cast<double>(i) - 0.5;
                z[i] = 0.01 * static_cast<double>(i) + 0.25;
            }

            KeyPair<DCRTPoly> keyPair = cc->KeyGen();
            cc->EvalMultKeyGen(keyPair.secretKey);

            Plaintext ptxtY = cc->MakeCKKSPackedPlaintext(y, 1, 0, nullptr, slots, false);
            auto ctxtY      = cc->Encrypt(keyPair.publicKey, ptxtY);

            Plaintext ptxtZCompressed = cc->MakeCKKSPackedPlaintext(z, 1, 0, nullptr, slots, true);
            ASSERT_TRUE(std::dynamic_pointer_cast<CKKSPackedEncoding>(ptxtZCompressed)->IsCompressed()) << failmsg;

            std::vector<double> expectedAdd(slots), expectedSub(slots), expectedMult(slots);
            for (uint32_t i = 0; i < slots; ++i) {
                expectedAdd[i]  = y[i] + z[i];
                expectedSub[i]  = y[i] - z[i];
                expectedMult[i] = y[i] * z[i];
            }

            Plaintext resAdd;
            cc->Decrypt(keyPair.secretKey, cc->EvalAdd(ctxtY, ptxtZCompressed), &resAdd);
            resAdd->SetLength(slots);
            checkEquality(expectedAdd, resAdd->GetRealPackedValue(), EPSILON_HIGH, failmsg + " (add, same level)");

            Plaintext resSub;
            cc->Decrypt(keyPair.secretKey, cc->EvalSub(ctxtY, ptxtZCompressed), &resSub);
            resSub->SetLength(slots);
            checkEquality(expectedSub, resSub->GetRealPackedValue(), EPSILON_HIGH, failmsg + " (sub, same level)");

            auto ctxtMult = cc->EvalMult(ctxtY, ptxtZCompressed);
            cc->RescaleInPlace(ctxtMult);
            Plaintext resMult;
            cc->Decrypt(keyPair.secretKey, ctxtMult, &resMult);
            resMult->SetLength(slots);
            checkEquality(expectedMult, resMult->GetRealPackedValue(), multEps, failmsg + " (mult, same level)");

            if (depth > 1) {
                auto ctxtYSquared = cc->EvalMult(ctxtY, ctxtY);
                cc->RescaleInPlace(ctxtYSquared);
                ASSERT_EQ(ctxtYSquared->GetLevel(), 1u) << failmsg;

                std::vector<double> ySquared(slots), expectedMorphedAdd(slots), expectedMorphedMult(slots);
                for (uint32_t i = 0; i < slots; ++i) {
                    ySquared[i]           = y[i] * y[i];
                    expectedMorphedAdd[i] = ySquared[i] + z[i];
                    expectedMorphedMult[i] = ySquared[i] * z[i];
                }

                Plaintext resMorphedAdd;
                cc->Decrypt(keyPair.secretKey, cc->EvalAdd(ctxtYSquared, ptxtZCompressed), &resMorphedAdd);
                resMorphedAdd->SetLength(slots);
                checkEquality(expectedMorphedAdd, resMorphedAdd->GetRealPackedValue(), multEps,
                             failmsg + " (add, morphed)");

                auto ctxtMorphedMult = cc->EvalMult(ctxtYSquared, ptxtZCompressed);
                cc->RescaleInPlace(ctxtMorphedMult);
                Plaintext resMorphedMult;
                cc->Decrypt(keyPair.secretKey, ctxtMorphedMult, &resMorphedMult);
                resMorphedMult->SetLength(slots);
                checkEquality(expectedMorphedMult, resMorphedMult->GetRealPackedValue(), multEps,
                             failmsg + " (mult, morphed)");
            }
        }
        catch (std::exception& e) {
            std::cerr << "Exception thrown from " << failmsg << ": " << e.what() << std::endl;
            EXPECT_TRUE(0 == 1) << failmsg;
        }
        catch (...) {
            UNIT_TEST_HANDLE_ALL_EXCEPTIONS;
        }

        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }

    OpenFHEParallelControls.UnitTestStop();
}
