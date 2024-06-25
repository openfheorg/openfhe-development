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
  This code exercises the encoding libraries of the OpenFHE lattice encryption library.
*/

#define PROFILE

#include "encoding/encodings.h"
#include "gtest/gtest.h"
#include "lattice/lat-hal.h"
#include "math/math-hal.h"
#include "utils/utilities.h"

#include <iostream>

using namespace lbcrypto;

class UTGENERAL_ENCODING : public ::testing::Test {
protected:
    virtual void SetUp() {}

    virtual void TearDown() {
        // Code here will be called immediately after each test
        // (right before the destructor).
    }
};

TEST_F(UTGENERAL_ENCODING, coef_packed_encoding) {
    std::vector<int64_t> value = {32, 17, 8, -12, -32, 22, -101, 6};
    uint32_t m                 = 16;

    auto lp = std::make_shared<ILParamsImpl<BigInteger>>(m);
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(256));

    CoefPackedEncoding se(lp, ep, value);
    se.Encode();
    se.Decode();
    se.SetLength(value.size());
    EXPECT_EQ(se.GetCoefPackedValue(), value) << "COEF_PACKED_ENCODING";
}

TEST_F(UTGENERAL_ENCODING, packed_int_ptxt_encoding) {
    uint32_t m         = 22;
    PlaintextModulus p = 89;
    BigInteger modulusQ("955263939794561");
    BigInteger squareRootOfRoot("941018665059848");
    BigInteger bigmodulus("80899135611688102162227204937217");
    BigInteger bigroot("77936753846653065954043047918387");

    auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
    ChineseRemainderTransformArb<BigVector>().SetCylotomicPolynomial(cycloPoly, modulusQ);

    auto lp = std::make_shared<ILParams>(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot);
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(p, 8));

    PackedEncoding::SetParams(m, ep);

    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 0, 0};
    PackedEncoding se(lp, ep, vectorOfInts1);
    se.Encode();
    se.Decode();
    EXPECT_EQ(se.GetPackedValue(), vectorOfInts1) << "packed int";
}

TEST_F(UTGENERAL_ENCODING, packed_int_ptxt_encoding_negative) {
    uint32_t m         = 22;
    PlaintextModulus p = 89;
    BigInteger modulusQ("955263939794561");
    BigInteger squareRootOfRoot("941018665059848");
    BigInteger bigmodulus("80899135611688102162227204937217");
    BigInteger bigroot("77936753846653065954043047918387");

    auto cycloPoly = GetCyclotomicPolynomial<BigVector>(m, modulusQ);
    ChineseRemainderTransformArb<BigVector>().SetCylotomicPolynomial(cycloPoly, modulusQ);

    auto lp = std::make_shared<ILParams>(m, modulusQ, squareRootOfRoot, bigmodulus, bigroot);
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(p, 8));

    PackedEncoding::SetParams(m, ep);

    std::vector<int64_t> vectorOfInts1 = {1, 2, -3, 4, 5, -6, 7, 8, 0, 0};
    PackedEncoding se(lp, ep, vectorOfInts1);
    se.Encode();
    se.Decode();
    EXPECT_EQ(se.GetPackedValue(), vectorOfInts1) << "packed int";
}

TEST_F(UTGENERAL_ENCODING, packed_int_ptxt_encoding_DCRTPoly_prime_cyclotomics) {
    uint32_t init_size   = 3;
    uint32_t dcrtBits    = 24;
    uint32_t dcrtBitsBig = 57;

    uint32_t m = 1811;

    PlaintextModulus p = 2 * m + 1;
    BigInteger modulusP(p);

    uint32_t mArb = 2 * m;
    uint32_t mNTT = pow(2, ceil(log2(2 * m - 1)));

    // populate the towers for the small modulus

    std::vector<NativeInteger> init_moduli(init_size);
    std::vector<NativeInteger> init_rootsOfUnity(init_size);

    init_moduli[0]       = LastPrime<NativeInteger>(dcrtBits, mArb);
    init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

    for (uint32_t i = 1; i < init_size; ++i) {
        init_moduli[i]       = PreviousPrime(init_moduli[i - 1], mArb);
        init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
    }

    // populate the towers for the big modulus

    std::vector<NativeInteger> init_moduli_NTT(init_size);
    std::vector<NativeInteger> init_rootsOfUnity_NTT(init_size);

    init_moduli_NTT[0]       = LastPrime<NativeInteger>(dcrtBitsBig, mNTT);
    init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

    for (uint32_t i = 1; i < init_size; ++i) {
        init_moduli_NTT[i]       = PreviousPrime(init_moduli_NTT[i - 1], mNTT);
        init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
    }

    auto paramsDCRT = std::make_shared<ILDCRTParams<BigInteger>>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT,
                                                                 init_rootsOfUnity_NTT);

    EncodingParams ep(std::make_shared<EncodingParamsImpl>(p));

    PackedEncoding::SetParams(m, ep);

    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 0, 0};
    PackedEncoding se(paramsDCRT, ep, vectorOfInts1);

    se.Encode();
    se.GetElement<DCRTPoly>().SetFormat(Format::COEFFICIENT);

    se.GetElement<DCRTPoly>().SwitchFormat();
    se.GetElement<DCRTPoly>().SwitchFormat();

    se.Decode();

    se.SetLength(vectorOfInts1.size());

    EXPECT_EQ(se.GetPackedValue(), vectorOfInts1) << "packed int - prime cyclotomics";
}

TEST_F(UTGENERAL_ENCODING, packed_int_ptxt_encoding_DCRTPoly_prime_cyclotomics_negative) {
    uint32_t init_size   = 3;
    uint32_t dcrtBits    = 24;
    uint32_t dcrtBitsBig = 57;

    uint32_t m = 1811;

    PlaintextModulus p = 2 * m + 1;
    BigInteger modulusP(p);

    uint32_t mArb = 2 * m;
    uint32_t mNTT = pow(2, ceil(log2(2 * m - 1)));

    // populate the towers for the small modulus
    std::vector<NativeInteger> init_moduli(init_size);
    std::vector<NativeInteger> init_rootsOfUnity(init_size);

    init_moduli[0]       = LastPrime<NativeInteger>(dcrtBits, mArb);
    init_rootsOfUnity[0] = RootOfUnity(mArb, init_moduli[0]);

    for (uint32_t i = 1; i < init_size; ++i) {
        init_moduli[i]       = PreviousPrime(init_moduli[i - 1], mArb);
        init_rootsOfUnity[i] = RootOfUnity(mArb, init_moduli[i]);
    }

    // populate the towers for the big modulus

    std::vector<NativeInteger> init_moduli_NTT(init_size);
    std::vector<NativeInteger> init_rootsOfUnity_NTT(init_size);

    init_moduli_NTT[0]       = LastPrime<NativeInteger>(dcrtBitsBig, mNTT);
    init_rootsOfUnity_NTT[0] = RootOfUnity(mNTT, init_moduli_NTT[0]);

    for (uint32_t i = 1; i < init_size; ++i) {
        init_moduli_NTT[i]       = PreviousPrime(init_moduli_NTT[i - 1], mNTT);
        init_rootsOfUnity_NTT[i] = RootOfUnity(mNTT, init_moduli_NTT[i]);
    }

    auto paramsDCRT = std::make_shared<ILDCRTParams<BigInteger>>(m, init_moduli, init_rootsOfUnity, init_moduli_NTT,
                                                                 init_rootsOfUnity_NTT);

    EncodingParams ep(std::make_shared<EncodingParamsImpl>(p));

    PackedEncoding::SetParams(m, ep);

    std::vector<int64_t> vectorOfInts1 = {1, 2, -3, 4, 5, 6, -7, 8, 0, 0};
    PackedEncoding se(paramsDCRT, ep, vectorOfInts1);

    se.Encode();
    se.GetElement<DCRTPoly>().SetFormat(Format::COEFFICIENT);

    se.GetElement<DCRTPoly>().SwitchFormat();
    se.GetElement<DCRTPoly>().SwitchFormat();

    se.Decode();

    se.SetLength(vectorOfInts1.size());

    EXPECT_EQ(se.GetPackedValue(), vectorOfInts1) << "packed int - prime cyclotomics";
}

TEST_F(UTGENERAL_ENCODING, string_encoding) {
    std::string value = "Hello, world!";
    uint32_t m        = 64;

    auto lp = std::make_shared<ILParamsImpl<BigInteger>>(m);
    EncodingParams ep(std::make_shared<EncodingParamsImpl>(256));

    StringEncoding se(lp, ep, value);
    se.Encode();
    se.Decode();
    EXPECT_EQ(se.GetStringValue(), value) << "string encode/decode";

    // truncate!
    auto lp2 = std::make_shared<ILParamsImpl<BigInteger>>(4);
    StringEncoding se2(lp2, ep, value);
    se2.Encode();
    se2.Decode();
    EXPECT_EQ(se2.GetStringValue(), value.substr(0, lp2->GetRingDimension())) << "string truncate encode/decode";
}
