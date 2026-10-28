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
/*
  Unit tests for the selection of the ring dimension from the security level and the secret key distribution,
  including the levels of the Security Guidelines for Implementing Homomorphic Encryption (HEORG24_*) and the
  level for sparse secrets of Hamming weight 192 (HE_SPARSE_H192_128)
 */

#include <cstdint>
#include <memory>

#include "cryptocontext.h"
#include "gen-cryptocontext.h"
#include "gtest/gtest.h"
#include "lattice/stdlatticeparms.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns.h"
#include "scheme/bgvrns/gen-cryptocontext-bgvrns.h"
#include "scheme/ckksrns/gen-cryptocontext-ckksrns.h"
#include "utils/exception.h"

using namespace lbcrypto;

class UTSecurityLevel : public ::testing::Test {
  protected:
    void SetUp() {
        OpenFHEParallelControls.UnitTestStart();
    }
    void TearDown() {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
        OpenFHEParallelControls.UnitTestStop();
    }

    static CCParams<CryptoContextCKKSRNS> CKKSParams(SecretKeyDist skd, SecurityLevel level) {
        CCParams<CryptoContextCKKSRNS> parameters;
        parameters.SetSecretKeyDist(skd);
        parameters.SetSecurityLevel(level);
        parameters.SetRingDim(0);
        parameters.SetMultiplicativeDepth(3);
        parameters.SetScalingModSize(52);
        parameters.SetFirstModSize(60);
        parameters.SetScalingTechnique(FIXEDMANUAL);
        parameters.SetKeySwitchTechnique(BV);
        return parameters;
    }
};

// log2(Q) = 60 + 3 * 52 (+1 for the alternating prime selection) lies between the 2024 bound (214 bits) and the
// 2018 bound (218 bits) for N = 8192, so the two security levels select different ring dimensions
TEST_F(UTSecurityLevel, ckks_heorg24_ring_dimension) {
    auto cc2018 = GenCryptoContext(CKKSParams(UNIFORM_TERNARY, HEStd_128_classic));
    EXPECT_EQ(cc2018->GetRingDimension(), (uint32_t)8192);

    auto cc2024 = GenCryptoContext(CKKSParams(UNIFORM_TERNARY, HEORG24_128));
    EXPECT_EQ(cc2024->GetRingDimension(), (uint32_t)16384);

    uint32_t logQ = cc2024->GetModulus().GetMSB();
    EXPECT_LE(logQ, StdLatticeParm::FindMaxQ(HEStd_ternary, HEORG24_128, 16384));
    EXPECT_GT(logQ, StdLatticeParm::FindMaxQ(HEStd_ternary, HEORG24_128, 8192));

    // a ring dimension below the 2024 bound is rejected
    auto parameters = CKKSParams(UNIFORM_TERNARY, HEORG24_128);
    parameters.SetRingDim(8192);
    EXPECT_THROW(GenCryptoContext(parameters), OpenFHEException);
}

// the Gaussian column has its own table
TEST_F(UTSecurityLevel, ckks_heorg24_gaussian) {
    auto parameters = CKKSParams(GAUSSIAN, HEORG24_256);
    parameters.SetMultiplicativeDepth(1);
    parameters.SetScalingModSize(40);
    parameters.SetFirstModSize(50);  // log2(Q) = 91 bits: above the N = 4096 bound (58) and below the N = 8192 one
    auto cc = GenCryptoContext(parameters);
    EXPECT_EQ(cc->GetRingDimension(), (uint32_t)8192);
}

// sparse secrets with HE_SPARSE_H192_128: the smallest tabulated ring dimension is 2^15
TEST_F(UTSecurityLevel, ckks_sparse_h192) {
    auto cc = GenCryptoContext(CKKSParams(SPARSE_TERNARY, HE_SPARSE_H192_128));
    EXPECT_EQ(cc->GetRingDimension(), (uint32_t)32768);
    EXPECT_LE(cc->GetModulus().GetMSB(), StdLatticeParm::FindMaxQ(HEStd_sparse, HE_SPARSE_H192_128, 32768));

    auto parameters = CKKSParams(SPARSE_ENCAPSULATED, HE_SPARSE_H192_128);
    parameters.SetRingDim(16384);
    EXPECT_THROW(GenCryptoContext(parameters), OpenFHEException) << "N = 16384 is not in the sparse table";

    // the sparse level is defined only for sparse secrets
    EXPECT_THROW(GenCryptoContext(CKKSParams(UNIFORM_TERNARY, HE_SPARSE_H192_128)), OpenFHEException);
    EXPECT_THROW(GenCryptoContext(CKKSParams(HYBRID_TERNARY, HE_SPARSE_H192_128)), OpenFHEException);
    EXPECT_THROW(GenCryptoContext(CKKSParams(GAUSSIAN, HE_SPARSE_H192_128)), OpenFHEException);
}

// the same selection logic is used by BGV and BFV
TEST_F(UTSecurityLevel, bgv_bfv_security_levels) {
    CCParams<CryptoContextBGVRNS> bgv;
    bgv.SetPlaintextModulus(65537);
    bgv.SetMultiplicativeDepth(1);
    bgv.SetSecretKeyDist(SPARSE_TERNARY);
    bgv.SetSecurityLevel(HE_SPARSE_H192_128);
    auto ccBGV = GenCryptoContext(bgv);
    EXPECT_EQ(ccBGV->GetRingDimension(), (uint32_t)32768);

    bgv.SetSecretKeyDist(UNIFORM_TERNARY);
    EXPECT_THROW(GenCryptoContext(bgv), OpenFHEException);

    bgv.SetSecurityLevel(HEORG24_192);
    auto ccBGV192 = GenCryptoContext(bgv);
    uint32_t n = ccBGV192->GetRingDimension();
    auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(ccBGV192->GetCryptoParameters());
    uint32_t logQP = (bgv.GetKeySwitchTechnique() == HYBRID) ? cryptoParams->GetParamsQP()->GetModulus().GetMSB() :
                                                               ccBGV192->GetModulus().GetMSB();
    EXPECT_LE(logQP, StdLatticeParm::FindMaxQ(HEStd_ternary, HEORG24_192, n));

    CCParams<CryptoContextBFVRNS> bfv;
    bfv.SetPlaintextModulus(65537);
    bfv.SetMultiplicativeDepth(1);
    bfv.SetSecretKeyDist(UNIFORM_TERNARY);
    bfv.SetSecurityLevel(HE_SPARSE_H192_128);
    EXPECT_THROW(GenCryptoContext(bfv), OpenFHEException);

    bfv.SetSecurityLevel(HEORG24_128);
    auto ccBFV = GenCryptoContext(bfv);
    EXPECT_GE(ccBFV->GetRingDimension(), (uint32_t)4096);
}
