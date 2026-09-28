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
  Regression tests for the 128-bit CKKS plaintext encodings
  (https://github.com/openfheorg/openfhe-development/issues/1257). Encode() and
  MakeAuxPlaintext() express each slot as mantissa * 2^exponent and rescale the mantissa by a
  shift derived from the exponent. The shift count was applied unchecked, so inputs below the
  integer precision shifted by more than the width of the intermediate type and a negative input
  floored to -1 instead of underflowing to zero, while inputs above the representable range
  wrapped into a different plaintext instead of being rejected.
*/

#include <cmath>
#include <complex>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "gtest/gtest.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-fhe.h"

using namespace lbcrypto;

#if NATIVEINT == 128
namespace {
constexpr uint32_t SCALING_MOD_SIZE = 90;
constexpr uint32_t SLOTS = 8;

// A constant slot vector encodes into the constant and X^(N/2) coefficients only: FitToNativeVector
// places the 2 * SLOTS scaled values at a stride of N / (2 * SLOTS), and the inverse transform of a
// constant vector cancels exactly everywhere else.
CryptoContext<DCRTPoly> MakeContext() {
    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetScalingModSize(SCALING_MOD_SIZE);
    parameters.SetFirstModSize(100);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);
    parameters.SetBatchSize(SLOTS);
    parameters.SetCKKSDataType(COMPLEX);
    auto cc = GenCryptoContext(parameters);
    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    return cc;
}

Plaintext EncodeConstant(const CryptoContext<DCRTPoly>& cc, bool auxiliary, std::complex<double> value,
                         uint32_t depth) {
    std::vector<std::complex<double>> values(SLOTS, value);
    if (auxiliary)
        return FHECKKSRNS::MakeAuxPlaintext(*cc, cc->GetCryptoParameters()->GetElementParams(), values, depth, 0,
                                            SLOTS);
    return cc->MakeCKKSPackedPlaintext(values, depth);
}

// magnitude * 2^SCALING_MOD_SIZE truncated toward zero, derived from the exact 53-bit significand
// rather than by repeating the encoding's own shift logic. Test magnitudes must have an even
// significand so that the encoding's rounding to 52 bits is exact and the two agree.
NativeInteger ExpectedUnits(double magnitude) {
    if (magnitude == 0.0)
        return NativeInteger(0);
    int32_t exponent = 0;
    const double mantissa = std::frexp(std::fabs(magnitude), &exponent);
    const uint64_t units = static_cast<uint64_t>(std::ldexp(mantissa, 53));
    const int32_t shift = exponent - 53 + static_cast<int32_t>(SCALING_MOD_SIZE);
    if (shift >= 0)
        return NativeInteger(units) << shift;
    return (shift <= -64) ? NativeInteger(0) : NativeInteger(units >> (-shift));
}

// Reports only the first mismatching coefficient. A fatal assertion here would abort the whole test
// at the first failing case, leaving the later shift boundaries unexercised; returning a result lets
// every case be checked independently without printing every coefficient.
// `units` is the unsigned expected magnitude; `realSign` and `imagSign` are -1, 0 or 1. The sign is
// applied per tower because the negation depends on that tower's modulus.
::testing::AssertionResult CoefficientsEqual(const Plaintext& plaintext, const NativeInteger& units, int realSign,
                                             int imagSign, uint32_t depth) {
    auto poly = plaintext->GetElement<DCRTPoly>();
    poly.SetFormat(Format::COEFFICIENT);
    for (const auto& tower : poly.GetAllElements()) {
        const auto& modulus = tower.GetModulus();
        auto scaled = units.Mod(modulus);
        for (uint32_t d = 1; d < depth; ++d)
            scaled = scaled.ModMul(NativeInteger(1) << SCALING_MOD_SIZE, modulus);
        auto signedValue = [&](int sign) {
            if (sign == 0)
                return NativeInteger(0);
            return sign < 0 ? NativeInteger(0).ModSub(scaled, modulus) : scaled;
        };
        const auto real = signedValue(realSign);
        const auto imag = signedValue(imagSign);
        for (uint32_t i = 0; i < tower.GetLength(); ++i) {
            NativeInteger expected(0);
            if (i == 0)
                expected = real;
            else if (i == tower.GetLength() / 2)
                expected = imag;
            if (tower[i] != expected)
                return ::testing::AssertionFailure() << "modulus " << modulus.ToString() << ", coefficient " << i
                                                     << ": " << tower[i].ToString() << " != " << expected.ToString();
        }
    }
    return ::testing::AssertionSuccess();
}

const std::vector<std::complex<double>>& Directions() {
    static const std::vector<std::complex<double>> directions{{1, 0}, {-1, 0}, {0, 1}, {0, -1}, {1, -1}, {-1, 1}};
    return directions;
}

int Sign(double component) {
    return (component > 0) - (component < 0);
}

// Encodes `magnitude * direction` in every slot, for both encoders and both scaling degrees, and
// compares the exact residues; decryption noise would hide a spurious coefficient of -1.
void CheckExactEncoding(const CryptoContext<DCRTPoly>& cc, bool auxiliary, double magnitude) {
    const NativeInteger units = ExpectedUnits(magnitude);
    for (uint32_t depth : {1u, 2u}) {
        SCOPED_TRACE("depth " + std::to_string(depth));
        for (const auto& direction : Directions()) {
            SCOPED_TRACE(direction);
            auto plaintext = EncodeConstant(cc, auxiliary, magnitude * direction, depth);
            EXPECT_TRUE(CoefficientsEqual(plaintext, units, Sign(direction.real()), Sign(direction.imag()), depth));
        }
    }
}

class UTCKKSRNS_ENCODING : public ::testing::TestWithParam<bool> {
  protected:
    void TearDown() override {
        CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
    }
};

// Inputs below the integer precision of the scaling factor must encode to zero for either sign.
TEST_P(UTCKKSRNS_ENCODING, TinyInputs) {
    auto cc = MakeContext();

    // Exponents either side of the representable limit (-SCALING_MOD_SIZE) and of the 64-bit and
    // 128-bit word boundaries, plus the much larger subnormal shift.
    const std::vector<int32_t> exponents = {-89, -90, -91, -102, -103, -104, -166, -167, -168};
    std::vector<double> magnitudes{0.0};
    for (int32_t exponent : exponents)
        magnitudes.push_back(std::ldexp(1.0, exponent));
    magnitudes.push_back(std::numeric_limits<double>::denorm_min());

    for (double magnitude : magnitudes) {
        // The mantissa is shifted right by this many bits; the encoding must underflow to zero
        // rather than evaluate a count at or beyond the width of the intermediate type.
        int32_t exponent = 0;
        std::frexp(magnitude, &exponent);
        SCOPED_TRACE("right shift of " + std::to_string(52 - static_cast<int32_t>(SCALING_MOD_SIZE) - exponent) +
                     " bits");
        SCOPED_TRACE(magnitude);
        CheckExactEncoding(cc, GetParam(), magnitude);
    }
}

// Everyday magnitudes must keep encoding exactly: they run the same shared helper through its
// positive branch, which the tiny and oversized cases never reach.
TEST_P(UTCKKSRNS_ENCODING, OrdinaryInputs) {
    auto cc = MakeContext();
    for (double magnitude : {0.5, 1.0, 2.5, 3.0, 1024.0}) {
        SCOPED_TRACE(magnitude);
        CheckExactEncoding(cc, GetParam(), magnitude);
    }
}

// The mirror of TinyInputs: an input whose scaled mantissa no longer fits the representation used
// by FitToNativeVector must be rejected rather than wrap into a different plaintext. Before the
// fix, encoding 2^36 at SCALING_MOD_SIZE 90 decoded as -2^36 and 1e12 decoded as 3.79e10.
TEST_P(UTCKKSRNS_ENCODING, OverflowBoundary) {
    auto cc = MakeContext();

    // The limit is Max128BitValue() / 2, which the mantissa reaches one ulp below
    // 2^(126 - SCALING_MOD_SIZE): the largest accepted magnitude and the smallest rejected one are
    // adjacent doubles, so this pins the guard rather than bracketing it by a factor of two.
    const double firstRejected = std::ldexp(1.0, 126 - static_cast<int32_t>(SCALING_MOD_SIZE));
    const double lastAccepted = std::nextafter(std::nextafter(firstRejected, 0.0), 0.0);
    const double oneUlpRejected = std::nextafter(firstRejected, 0.0);

    for (double magnitude : {lastAccepted, std::ldexp(1.0, 20), 1.0}) {
        SCOPED_TRACE(magnitude);
        CheckExactEncoding(cc, GetParam(), magnitude);
    }

    // pRemaining reaches 127 at 2^88 and grows from there, so the shift guard is covered as well as
    // the magnitude guard.
    for (double magnitude : {oneUlpRejected, firstRejected, std::ldexp(1.0, 88), std::ldexp(1.0, 89),
                             std::ldexp(1.0, 100), 1.0e12, 1.0e15, 1.0e300}) {
        for (double sign : {1.0, -1.0}) {
            SCOPED_TRACE(sign * magnitude);
            EXPECT_THROW(EncodeConstant(cc, GetParam(), {sign * magnitude, 0.0}, 1), OpenFHEException);
            EXPECT_THROW(EncodeConstant(cc, GetParam(), {0.0, sign * magnitude}, 1), OpenFHEException);
            EXPECT_THROW(EncodeConstant(cc, GetParam(), {sign * magnitude, -sign * magnitude}, 2), OpenFHEException);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(UnitTests, UTCKKSRNS_ENCODING, ::testing::Bool(),
                         [](const ::testing::TestParamInfo<bool>& info) {
                             return info.param ? "Auxiliary" : "Packed";
                         });
}  // namespace
#endif
