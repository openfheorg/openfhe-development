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
  This code tests the utils for selecting lattice parameters.
  unit tests for the utility to to find security parameters using the HomomorphicEncryption.org HE standard
  and the Security Guidelines for Implementing Homomorphic Encryption
 */

#include <cstdint>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "lattice/lat-hal.h"
#include "lattice/stdlatticeparms.h"
#include "utils/exception.h"
#include "utils/inttypes.h"

using namespace lbcrypto;

class UTLatticeParams : public ::testing::Test {
  protected:
    virtual void SetUp() {
        OpenFHEParallelControls.UnitTestStart();
    }

    virtual void TearDown() {
        OpenFHEParallelControls.UnitTestStop();
    }
};

// tests the edge cases when log q is right near the point where the ring dimension
// needs to be doubled to be compliant with the HE security standard
TEST_F(UTLatticeParams, edge_cases) {
    uint32_t maxQ = StdLatticeParm::FindMaxQ(HEStd_ternary, HEStd_128_classic, 4096);
    uint32_t ringDim = StdLatticeParm::FindRingDim(HEStd_ternary, HEStd_128_classic, maxQ);
    EXPECT_EQ(ringDim, (uint32_t)4096) << "Ring dimension is incorrect for an edge case of curQ = maxQ";
    ringDim = StdLatticeParm::FindRingDim(HEStd_ternary, HEStd_128_classic, maxQ - 1);
    EXPECT_EQ(ringDim, (uint32_t)4096) << "Ring dimension is incorrect for an edge case of curQ = maxQ - 1";
    ringDim = StdLatticeParm::FindRingDim(HEStd_ternary, HEStd_128_classic, maxQ + 1);
    EXPECT_EQ(ringDim, (uint32_t)8192) << "Ring dimension is incorrect for an edge case of curQ = maxQ + 1";
}

// the same edge cases for the tables of the Security Guidelines for Implementing Homomorphic Encryption
TEST_F(UTLatticeParams, heorg24_edge_cases) {
    uint32_t maxQ = StdLatticeParm::FindMaxQ(HEStd_ternary, HEORG24_128, 4096);
    EXPECT_EQ(maxQ, (uint32_t)106) << "Table 5.2 value for ternary secrets, N = 4096, 128 bits";
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_ternary, HEORG24_128, maxQ), (uint32_t)4096);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_ternary, HEORG24_128, maxQ - 1), (uint32_t)4096);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_ternary, HEORG24_128, maxQ + 1), (uint32_t)8192);

    maxQ = StdLatticeParm::FindMaxQ(HEStd_error, HEORG24_256, 131072);
    EXPECT_EQ(maxQ, (uint32_t)1868) << "Table 5.2 value for Gaussian secrets, N = 131072, 256 bits";
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_error, HEORG24_256, maxQ), (uint32_t)131072);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_error, HEORG24_256, maxQ + 1), (uint32_t)262144)
            << "Moduli above the largest row should double the largest tabulated ring dimension";

    // there are no rows for N = 1024 at the 192- and 256-bit levels: small moduli map to N = 2048
    EXPECT_EQ(StdLatticeParm::FindMaxQ(HEStd_ternary, HEORG24_192, 1024), (uint32_t)0);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_ternary, HEORG24_192, 20), (uint32_t)2048);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_error, HEORG24_256, 20), (uint32_t)2048);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_ternary, HEORG24_128, 20), (uint32_t)1024);
}

// the 2024 guidelines are never more permissive than the 2018 standard for the same ring dimension
TEST_F(UTLatticeParams, heorg24_not_above_hestd) {
    const std::vector<std::pair<SecurityLevel, SecurityLevel>> levels = {
            {HEORG24_128, HEStd_128_classic}, {HEORG24_192, HEStd_192_classic}, {HEORG24_256, HEStd_256_classic}};
    for (DistributionType dist : {HEStd_ternary, HEStd_error}) {
        for (const auto& lv : levels) {
            for (uint32_t n = 1024; n <= 131072; n *= 2) {
                uint32_t qNew = StdLatticeParm::FindMaxQ(dist, lv.first, n);
                uint32_t qOld = StdLatticeParm::FindMaxQ(dist, lv.second, n);
                if (qNew == 0)
                    continue;
                EXPECT_LE(qNew, qOld) << "dist " << dist << ", level " << lv.first << ", N = " << n;
            }
        }
    }
}

// the table for sparse secrets of Hamming weight 192 has rows only for N = 2^15, 2^16, and 2^17
TEST_F(UTLatticeParams, sparse_h192_table) {
    EXPECT_EQ(StdLatticeParm::FindMaxQ(HEStd_sparse, HE_SPARSE_H192_128, 16384), (uint32_t)0);
    EXPECT_EQ(StdLatticeParm::FindMaxQ(HEStd_sparse, HE_SPARSE_H192_128, 32768), (uint32_t)767);
    EXPECT_EQ(StdLatticeParm::FindMaxQ(HEStd_sparse, HE_SPARSE_H192_128, 65536), (uint32_t)1553);
    EXPECT_EQ(StdLatticeParm::FindMaxQ(HEStd_sparse, HE_SPARSE_H192_128, 131072), (uint32_t)3104);

    // small moduli map to the smallest tabulated ring dimension
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_sparse, HE_SPARSE_H192_128, 300), (uint32_t)32768);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_sparse, HE_SPARSE_H192_128, 767), (uint32_t)32768);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_sparse, HE_SPARSE_H192_128, 768), (uint32_t)65536);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_sparse, HE_SPARSE_H192_128, 1553), (uint32_t)65536);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_sparse, HE_SPARSE_H192_128, 1554), (uint32_t)131072);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_sparse, HE_SPARSE_H192_128, 3104), (uint32_t)131072);
    EXPECT_EQ(StdLatticeParm::FindRingDim(HEStd_sparse, HE_SPARSE_H192_128, 3105), (uint32_t)262144);

    // the sparse table is only used with the sparse distribution type and vice versa
    EXPECT_THROW(StdLatticeParm::FindRingDim(HEStd_sparse, HEStd_128_classic, 300), OpenFHEException);
    EXPECT_THROW(StdLatticeParm::FindRingDim(HEStd_sparse, HEORG24_128, 300), OpenFHEException);
    EXPECT_THROW(StdLatticeParm::FindRingDim(HEStd_ternary, HE_SPARSE_H192_128, 300), OpenFHEException);
    EXPECT_THROW(StdLatticeParm::FindRingDim(HEStd_error, HE_SPARSE_H192_128, 300), OpenFHEException);
}

// selection of the table column from the secret key distribution and the security level
TEST_F(UTLatticeParams, distribution_type_selection) {
    EXPECT_EQ(StdLatticeParm::GetDistributionType(SPARSE_TERNARY, HE_SPARSE_H192_128), HEStd_sparse);
    EXPECT_EQ(StdLatticeParm::GetDistributionType(SPARSE_ENCAPSULATED, HE_SPARSE_H192_128), HEStd_sparse);
    EXPECT_THROW(StdLatticeParm::GetDistributionType(UNIFORM_TERNARY, HE_SPARSE_H192_128), OpenFHEException);
    EXPECT_THROW(StdLatticeParm::GetDistributionType(HYBRID_TERNARY, HE_SPARSE_H192_128), OpenFHEException);
    EXPECT_THROW(StdLatticeParm::GetDistributionType(GAUSSIAN, HE_SPARSE_H192_128), OpenFHEException);

    EXPECT_EQ(StdLatticeParm::GetDistributionType(GAUSSIAN, HEORG24_128), HEStd_error);
    EXPECT_EQ(StdLatticeParm::GetDistributionType(GAUSSIAN, HEStd_128_classic), HEStd_error);
    EXPECT_EQ(StdLatticeParm::GetDistributionType(UNIFORM_TERNARY, HEORG24_192), HEStd_ternary);
    EXPECT_EQ(StdLatticeParm::GetDistributionType(HYBRID_TERNARY, HEORG24_256), HEStd_ternary);
    // sparse secrets fall back to the uniform ternary tables for the other levels (backward compatibility)
    EXPECT_EQ(StdLatticeParm::GetDistributionType(SPARSE_TERNARY, HEStd_128_classic), HEStd_ternary);
    EXPECT_EQ(StdLatticeParm::GetDistributionType(SPARSE_TERNARY, HEORG24_128), HEStd_ternary);
    // HEStd_NotSet accepts any distribution
    EXPECT_EQ(StdLatticeParm::GetDistributionType(SPARSE_TERNARY, HEStd_NotSet), HEStd_ternary);
    EXPECT_EQ(StdLatticeParm::GetDistributionType(GAUSSIAN, HEStd_NotSet), HEStd_error);
}

// string and integer conversions of the new security levels
TEST_F(UTLatticeParams, security_level_conversions) {
    const std::vector<SecurityLevel> levels = {
            HEStd_128_classic, HEStd_192_classic, HEStd_256_classic, HEStd_128_quantum, HEStd_192_quantum,
            HEStd_256_quantum, HEORG24_128,       HEORG24_192,       HEORG24_256,       HE_SPARSE_H192_128};
    for (SecurityLevel lv : levels) {
        std::ostringstream os;
        os << lv;
        EXPECT_EQ(convertToSecurityLevel(os.str()), lv) << os.str();
        EXPECT_EQ(convertToSecurityLevel(static_cast<uint32_t>(lv)), lv) << os.str();
    }
    // the values of the pre-existing enumerators are unchanged (they are stored in serialized cryptocontexts)
    EXPECT_EQ(static_cast<uint32_t>(HEStd_NotSet), (uint32_t)6);
    EXPECT_EQ(convertToSecurityLevel("HEStd_NotSet"), HEStd_NotSet);
    EXPECT_THROW(convertToSecurityLevel(static_cast<uint32_t>(HEStd_NotSet)), OpenFHEException);
    EXPECT_THROW(convertToSecurityLevel(static_cast<uint32_t>(HE_SPARSE_H192_128) + 1), OpenFHEException);
    EXPECT_THROW(convertToSecurityLevel("HEORG24_512"), OpenFHEException);
}
