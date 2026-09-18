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
  Regression tests for the 128-bit CKKS scalar operations
  (https://github.com/openfheorg/openfhe-development/issues/1258 and
  https://openfhe.discourse.group/t/2362): EvalAdd/EvalSub/EvalMult with a double operand
  convert the operand to a 128-bit integer by shifting the 52-bit mantissa by a count derived
  from the operand's exponent. That count was applied unchecked, so tiny operands shifted by
  more than the width of the intermediate type and large operands overflowed it silently.
*/

#include <algorithm>
#include <cmath>
#include <complex>
#include <cstddef>
#include <limits>
#include <string>
#include <vector>

#include "openfhe.h"
#include "gtest/gtest.h"

using namespace lbcrypto;

#if NATIVEINT == 128
namespace {
// The scalar conversion splits an operand into mantissa * 2^n1, keeps MANTISSA_BITS bits of the
// mantissa and shifts them by (SCALING_MOD_SIZE - MANTISSA_BITS + n1). Deriving the test
// magnitudes from these two constants keeps the exercised shift counts fixed if the context
// parameters are ever retuned.
constexpr uint32_t SCALING_MOD_SIZE = 90;
constexpr uint32_t MANTISSA_BITS    = 52;

// Exponent offsets below the scaling factor. An operand of 2^-(SCALING_MOD_SIZE + offset) is
// shifted right by (MANTISSA_BITS - 1 + offset), so these cover shifts of 51, 52, 63, 64, 65,
// 127, 128 and 129 - either side of both the 64-bit and the 128-bit word boundary.
constexpr int32_t TINY_OFFSETS[] = {0, 1, 12, 13, 14, 76, 77, 78};

CryptoContext<DCRTPoly> MakeContext(uint32_t multiplicativeDepth, uint32_t firstModSize) {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(multiplicativeDepth);
    parameters.SetScalingModSize(SCALING_MOD_SIZE);
    parameters.SetFirstModSize(firstModSize);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);
    parameters.SetBatchSize(8);
    parameters.SetCKKSDataType(COMPLEX);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

// Exact polynomial comparison, reporting only the first mismatching coefficient. Comparing the
// elements with EXPECT_EQ would print every coefficient of every tower of both operands
// (hundreds of kilobytes) whenever a case fails.
::testing::AssertionResult ElementsEqual(const Ciphertext<DCRTPoly>& actual, const Ciphertext<DCRTPoly>& expected) {
    const auto& actualElements   = actual->GetElements();
    const auto& expectedElements = expected->GetElements();
    if (actualElements.size() != expectedElements.size())
        return ::testing::AssertionFailure()
               << "element count " << actualElements.size() << " != " << expectedElements.size();
    for (size_t i = 0; i < actualElements.size(); ++i) {
        const auto& actualTowers   = actualElements[i].GetAllElements();
        const auto& expectedTowers = expectedElements[i].GetAllElements();
        if (actualTowers.size() != expectedTowers.size())
            return ::testing::AssertionFailure()
                   << "element " << i << ": tower count " << actualTowers.size() << " != " << expectedTowers.size();
        for (size_t j = 0; j < actualTowers.size(); ++j) {
            for (size_t k = 0; k < actualTowers[j].GetLength(); ++k) {
                if (actualTowers[j][k] != expectedTowers[j][k])
                    return ::testing::AssertionFailure()
                           << "element " << i << ", tower " << j << ", coefficient " << k << ": "
                           << actualTowers[j][k].ToString() << " != " << expectedTowers[j][k].ToString();
            }
        }
    }
    return ::testing::AssertionSuccess();
}

std::complex<double> FirstSlot(const CryptoContext<DCRTPoly>& cc, const PrivateKey<DCRTPoly>& secretKey,
                               const Ciphertext<DCRTPoly>& ciphertext) {
    Plaintext decoded;
    cc->Decrypt(secretKey, ciphertext, &decoded);
    return decoded->GetCKKSPackedValue()[0];
}

// Checks both components of a slot against an expected complex value, scaling the tolerance by
// the expected magnitude so that a large real part cannot mask a wrong imaginary part.
void ExpectSlotNear(const std::complex<double>& actual, const std::complex<double>& expected) {
    EXPECT_NEAR(actual.real(), expected.real(), 1e-6 * std::max(1.0, std::abs(expected.real())));
    EXPECT_NEAR(actual.imag(), expected.imag(), 1e-6 * std::max(1.0, std::abs(expected.imag())));
}

class UTCKKSRNS_SCALAR : public ::testing::Test {
protected:
    void TearDown() override {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
};

// Operands below the integer precision of the scaling factor must underflow to zero. Before the
// fix they shifted by an out-of-range count, and a negative operand additionally rounded to -1
// (an arithmetic shift floors), which showed up as a result near -2^-SCALING_MOD_SIZE instead of
// zero.
TEST_F(UTCKKSRNS_SCALAR, TinyOperands) {
    auto cc          = MakeContext(2, SCALING_MOD_SIZE + 10);
    auto keys        = cc->KeyGen();
    auto plaintext   = cc->MakeCKKSPackedPlaintext(std::vector<double>(8, 1.0));
    auto ciphertext  = cc->Encrypt(keys.publicKey, plaintext);
    auto zeroProduct = cc->EvalMult(ciphertext, 0.0);

    // A ciphertext whose scale has already been raised by a multiplication. EvalAdd/EvalSub only
    // run the CRTMult loop over crtPowP when GetNoiseScaleDeg() > 1, so without this the modular
    // reduction of crtPowP would go untested.
    auto scaled = cc->EvalMult(ciphertext, 1.0);
    ASSERT_GT(scaled->GetNoiseScaleDeg(), 1u);

    const int32_t smallestExponent = -static_cast<int32_t>(SCALING_MOD_SIZE);
    std::vector<double> magnitudes;
    for (int32_t offset : TINY_OFFSETS)
        magnitudes.push_back(std::ldexp(1.0, smallestExponent - offset));
    magnitudes.push_back(std::numeric_limits<double>::denorm_min());

    for (double magnitude : magnitudes) {
        // Mirrors the conversion in GetElementForEvalAddOrSub/GetElementForEvalMult: the mantissa
        // is shifted right by (MANTISSA_BITS - SCALING_MOD_SIZE - exponent) bits. Reporting the
        // count makes it obvious which word boundary a failing case sits on.
        int32_t exponent = 0;
        std::frexp(magnitude, &exponent);
        const int32_t shift = static_cast<int32_t>(MANTISSA_BITS) - static_cast<int32_t>(SCALING_MOD_SIZE) - exponent;
        SCOPED_TRACE("right shift of " + std::to_string(shift) + " bits");

        for (double sign : {1.0, -1.0}) {
            double operand = sign * magnitude;
            SCOPED_TRACE(operand);
            auto product = cc->EvalMult(ciphertext, operand);
            std::complex<double> complexOperand(operand, -operand);
            if (magnitude < std::ldexp(1.0, smallestExponent)) {
                // Exact polynomial comparisons detect errors far below CKKS's usual decryption
                // tolerance, including negative values rounding to -1.
                EXPECT_TRUE(ElementsEqual(product, zeroProduct));
                EXPECT_TRUE(ElementsEqual(cc->EvalAdd(ciphertext, operand), ciphertext));
                EXPECT_TRUE(ElementsEqual(cc->EvalSub(ciphertext, operand), ciphertext));
                EXPECT_TRUE(ElementsEqual(cc->EvalMult(ciphertext, complexOperand), zeroProduct));
                EXPECT_TRUE(ElementsEqual(cc->EvalAdd(ciphertext, complexOperand), ciphertext));
                EXPECT_TRUE(ElementsEqual(cc->EvalSub(ciphertext, complexOperand), ciphertext));

                // Same underflow, but through the crtPowP path taken at a raised scale.
                EXPECT_TRUE(ElementsEqual(cc->EvalAdd(scaled, operand), scaled));
                EXPECT_TRUE(ElementsEqual(cc->EvalSub(scaled, operand), scaled));
                EXPECT_TRUE(ElementsEqual(cc->EvalAdd(scaled, complexOperand), scaled));
                EXPECT_TRUE(ElementsEqual(cc->EvalSub(scaled, complexOperand), scaled));
            }
            else {
                // The smallest representable power of two must survive conversion.
                EXPECT_FALSE(ElementsEqual(product, zeroProduct));
                EXPECT_NEAR(FirstSlot(cc, keys.secretKey, product).real() / operand, 1.0, 1e-6);
            }
        }
    }
}

// Operands large enough that mantissa * 2^shift no longer fits into 128 bits used to wrap
// silently: at SCALING_MOD_SIZE 90 the product overflows from 2^37 upwards, so EvalMult by 1e12
// returned about -9.95e10. Each operand here is well within the ciphertext modulus, so the
// results must be exact to CKKS precision.
TEST_F(UTCKKSRNS_SCALAR, LargeOperands) {
    auto cc         = MakeContext(3, SCALING_MOD_SIZE + 10);
    auto keys       = cc->KeyGen();
    auto plaintext  = cc->MakeCKKSPackedPlaintext(std::vector<double>(8, 1.0));
    auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    // A ciphertext at a raised scale, so that EvalAdd/EvalSub also run the CRTMult loop over
    // crtPowP that is only reached when GetNoiseScaleDeg() > 1.
    auto scaled = cc->EvalMult(ciphertext, 2.0);
    ASSERT_GT(scaled->GetNoiseScaleDeg(), 1u);

    // 2^37 is the first magnitude that overflowed; the rest bracket it on both sides.
    for (double magnitude : {std::ldexp(1.0, 20), std::ldexp(1.0, 36), std::ldexp(1.0, 37), std::ldexp(1.0, 38),
                             std::ldexp(1.0, 50), 1.0e12, 1.0e15}) {
        for (double sign : {1.0, -1.0}) {
            double operand = sign * magnitude;
            SCOPED_TRACE(operand);

            auto product = cc->EvalMult(ciphertext, operand);
            cc->RescaleInPlace(product);
            ExpectSlotNear(FirstSlot(cc, keys.secretKey, product), {operand, 0.0});

            ExpectSlotNear(FirstSlot(cc, keys.secretKey, cc->EvalAdd(ciphertext, operand)), {1.0 + operand, 0.0});
            ExpectSlotNear(FirstSlot(cc, keys.secretKey, cc->EvalSub(ciphertext, operand)), {1.0 - operand, 0.0});

            // The ciphertext holds 2.0 at twice the scale; the constant has to be raised to the
            // same scale before it is added.
            ExpectSlotNear(FirstSlot(cc, keys.secretKey, cc->EvalAdd(scaled, operand)), {2.0 + operand, 0.0});
            ExpectSlotNear(FirstSlot(cc, keys.secretKey, cc->EvalSub(scaled, operand)), {2.0 - operand, 0.0});

            // Complex operands whose real and imaginary parts are both large and distinct, so a
            // component that is dropped, swapped or wrongly signed is visible in the result.
            const std::complex<double> complexOperand(operand, -0.5 * operand);

            auto complexProduct = cc->EvalMult(ciphertext, complexOperand);
            cc->RescaleInPlace(complexProduct);
            ExpectSlotNear(FirstSlot(cc, keys.secretKey, complexProduct), complexOperand);

            ExpectSlotNear(FirstSlot(cc, keys.secretKey, cc->EvalAdd(ciphertext, complexOperand)),
                           1.0 + complexOperand);
            ExpectSlotNear(FirstSlot(cc, keys.secretKey, cc->EvalSub(ciphertext, complexOperand)),
                           1.0 - complexOperand);
            ExpectSlotNear(FirstSlot(cc, keys.secretKey, cc->EvalAdd(scaled, complexOperand)), 2.0 + complexOperand);
            ExpectSlotNear(FirstSlot(cc, keys.secretKey, cc->EvalSub(scaled, complexOperand)), 2.0 - complexOperand);
        }
    }
}

// Operands outside the representable range at either end produce meaningless plaintexts, but
// they must not shift by an out-of-range count on the way there - the reported failure was a
// shift of 1035 bits for a 128-bit type, reached both by denorm_min and by 1e300. The assertion
// here is only that the operations complete; a build with -fsanitize=shift (or UBSan) is what
// turns this into a check of the shift counts themselves.
TEST_F(UTCKKSRNS_SCALAR, UnrepresentableOperandsDoNotShiftOutOfRange) {
    auto cc         = MakeContext(1, SCALING_MOD_SIZE);
    auto keys       = cc->KeyGen();
    auto plaintext  = cc->MakeCKKSPackedPlaintext(std::vector<double>(8, 1.0));
    auto ciphertext = cc->Encrypt(keys.publicKey, plaintext);

    for (double magnitude : {1.0e300, std::numeric_limits<double>::max(), std::numeric_limits<double>::denorm_min()}) {
        for (double sign : {1.0, -1.0}) {
            double operand = sign * magnitude;
            SCOPED_TRACE(operand);
            EXPECT_NO_THROW(cc->EvalMult(ciphertext, operand));
            EXPECT_NO_THROW(cc->EvalAdd(ciphertext, operand));
            EXPECT_NO_THROW(cc->EvalSub(ciphertext, operand));
        }
    }
}
}  // namespace
#endif
