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
  Assigning a signed vector to a polynomial must reduce each coefficient modulo that polynomial's
  modulus. Three cases were wrong before: the signed minimum was negated as a signed value
  (undefined behaviour), magnitudes at or above the modulus were stored unreduced, and a negative
  operand that is an exact multiple of the modulus was stored as the modulus itself.
*/

#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "gtest/gtest.h"
#include "lattice/lat-hal.h"
#include "math/hal/intnat/ubintnat.h"
#include "math/nbtheory.h"
#include "testdefs.h"
#include "utils/utilities.h"

using namespace lbcrypto;

namespace {
constexpr uint32_t CYCLOTOMIC_ORDER = 8;

// Coefficients worth assigning against a modulus: the extremes of the signed type, exact multiples
// of the modulus (whose negative residue is zero), and values either side of it. Anything outside
// the range of Signed is dropped rather than truncated into a different value.
template <typename Signed>
std::vector<std::vector<Signed>> SignedCases(int64_t modulus) {
    constexpr int64_t lowest  = static_cast<int64_t>(std::numeric_limits<Signed>::min());
    constexpr int64_t highest = static_cast<int64_t>(std::numeric_limits<Signed>::max());
    const std::vector<std::vector<int64_t>> candidates{{lowest, lowest + 1, highest, -1},
                                                       {-modulus, modulus, -2 * modulus, 2 * modulus},
                                                       {-modulus - 1, modulus + 1, 0, 1, 42},
                                                       {lowest},
                                                       {}};
    std::vector<std::vector<Signed>> cases;
    cases.reserve(candidates.size());
    for (const auto& candidate : candidates) {
        std::vector<Signed> values;
        for (int64_t value : candidate) {
            if (value >= lowest && value <= highest)
                values.push_back(static_cast<Signed>(value));
        }
        cases.push_back(std::move(values));
    }
    return cases;
}

// Signed remainder provides an independent oracle, including for the signed minimum.
int64_t ExpectedResidue(int64_t value, int64_t modulus) {
    const int64_t residue = value % modulus;
    return (residue < 0) ? residue + modulus : residue;
}

// The modulus comes from the polynomial rather than from the caller, so the oracle cannot drift
// away from the parameters the element was built with.
template <typename Element, typename Signed>
void CheckSignedAssignment(Element& poly) {
    using Integer         = typename Element::Integer;
    const int64_t modulus = static_cast<int64_t>(poly.GetModulus().ConvertToInt());
    SCOPED_TRACE("modulus " + std::to_string(modulus));
    for (const auto& values : SignedCases<Signed>(modulus)) {
        poly = values;
        EXPECT_EQ(poly.GetFormat(), Format::COEFFICIENT);
        for (size_t i = 0; i < poly.GetLength(); ++i) {
            const int64_t expected = i < values.size() ? ExpectedResidue(static_cast<int64_t>(values[i]), modulus) : 0;
            EXPECT_EQ(poly[i], Integer(static_cast<uint64_t>(expected))) << "coefficient " << i;
        }
    }
}

template <typename Element>
void SignedPolyAssignment(const std::string& msg) {
    SCOPED_TRACE(msg);
    using Integer = typename Element::Integer;
    // A modulus that fits a single word and one above 2^32, so that the reduction and the
    // modulus - residue adjustment are both exercised on wide values.
    for (uint32_t bits : {7u, 60u}) {
        const Integer modulus{LastPrime<Integer>(bits, CYCLOTOMIC_ORDER)};
        const Integer root{RootOfUnity<Integer>(CYCLOTOMIC_ORDER, modulus)};
        auto params = std::make_shared<typename Element::Params>(CYCLOTOMIC_ORDER, modulus, root);
        for (bool initialize : {false, true}) {
            SCOPED_TRACE(initialize);
            Element poly(params, Format::EVALUATION, initialize);
            CheckSignedAssignment<Element, int64_t>(poly);
            Element poly32(params, Format::EVALUATION, initialize);
            CheckSignedAssignment<Element, int32_t>(poly32);
        }
    }
}

template <typename Element, typename Signed>
void CheckSignedDCRTAssignment(Element& poly) {
    // The towers carry different moduli; the boundary cases are built against the first one and
    // every tower is then checked against its own modulus.
    const int64_t modulus = static_cast<int64_t>(poly.GetAllElements()[0].GetModulus().ConvertToInt());
    SCOPED_TRACE("first tower modulus " + std::to_string(modulus));
    for (const auto& values : SignedCases<Signed>(modulus)) {
        poly = values;
        EXPECT_EQ(poly.GetFormat(), Format::COEFFICIENT);
        for (const auto& tower : poly.GetAllElements()) {
            const int64_t towerModulus = static_cast<int64_t>(tower.GetModulus().ConvertToInt());
            SCOPED_TRACE(towerModulus);
            EXPECT_EQ(tower.GetFormat(), Format::COEFFICIENT);
            for (size_t i = 0; i < tower.GetLength(); ++i) {
                const int64_t expected =
                    i < values.size() ? ExpectedResidue(static_cast<int64_t>(values[i]), towerModulus) : 0;
                EXPECT_EQ(tower[i], NativeInteger(static_cast<uint64_t>(expected))) << "coefficient " << i;
            }
        }
    }
}

template <typename Element>
void SignedDCRTAssignment(const std::string& msg) {
    SCOPED_TRACE(msg);
    for (uint32_t bits : {14u, 50u}) {
        std::vector<NativeInteger> moduli;
        std::vector<NativeInteger> roots;
        NativeInteger modulus{LastPrime<NativeInteger>(bits, CYCLOTOMIC_ORDER)};
        for (uint32_t i = 0; i < 3; ++i) {
            moduli.push_back(modulus);
            roots.push_back(RootOfUnity<NativeInteger>(CYCLOTOMIC_ORDER, modulus));
            modulus = PreviousPrime<NativeInteger>(modulus, CYCLOTOMIC_ORDER);
        }
        auto params = std::make_shared<typename Element::Params>(CYCLOTOMIC_ORDER, moduli, roots);
        for (bool initialize : {false, true}) {
            SCOPED_TRACE(initialize);
            Element poly(params, Format::EVALUATION, initialize);
            CheckSignedDCRTAssignment<Element, int64_t>(poly);
            Element poly32(params, Format::EVALUATION, initialize);
            CheckSignedDCRTAssignment<Element, int32_t>(poly32);
        }
    }
}

// SignedToResidue backs the assignments above and is also instantiated for integer types narrower
// than its int64_t operand, where the reduction has to happen before the conversion: converting
// first discards the high bits and yields a different residue. The uint64_t overload is the one
// the assignments call per coefficient once they have checked the modulus width, so it is
// checked alongside the IntType one.
template <typename IntType>
void CheckSignedToResidue(uint64_t modulusValue, const std::string& msg) {
    SCOPED_TRACE(msg + ", modulus " + std::to_string(modulusValue));
    const IntType modulus{modulusValue};
    const int64_t signedModulus = static_cast<int64_t>(modulusValue);
    constexpr int64_t lowest    = std::numeric_limits<int64_t>::min();
    constexpr int64_t highest   = std::numeric_limits<int64_t>::max();
    // 2^32 + 1 and its negation are wider than a 32-bit destination but reduce to small residues.
    for (int64_t value : {lowest, lowest + 1, highest, int64_t(-4294967297), int64_t(4294967297), -signedModulus,
                          signedModulus, int64_t(-1), int64_t(0), int64_t(1), int64_t(42)}) {
        SCOPED_TRACE(value);
        const uint64_t expected = static_cast<uint64_t>(ExpectedResidue(value, signedModulus));
        EXPECT_EQ(SignedToResidue(value, modulusValue), expected);
        EXPECT_EQ(SignedToResidue(value, modulus), IntType(expected));
    }
}

TEST(UTSignedToResidue, ReducesBeforeNarrowing) {
    using Native32 = intnat::NativeIntegerT<uint32_t>;
    CheckSignedToResidue<Native32>(73, "32-bit native");
    CheckSignedToResidue<Native32>((uint64_t(1) << 31) - 1, "32-bit native");
    CheckSignedToResidue<NativeInteger>(73, "native");
    CheckSignedToResidue<NativeInteger>((uint64_t(1) << 40) + 15, "native");
    CheckSignedToResidue<BigInteger>(73, "big");
    CheckSignedToResidue<BigInteger>((uint64_t(1) << 62) + 135, "big");

    // A modulus too wide for uint64_t skips the pre-reduction; the conversion is exact there.
    const BigInteger wide{(BigInteger(1) << 100) + BigInteger(3)};
    EXPECT_EQ(SignedToResidue(int64_t(42), wide), BigInteger(42));
    EXPECT_EQ(SignedToResidue(int64_t(-42), wide), wide - BigInteger(42));
    EXPECT_EQ(SignedToResidue(std::numeric_limits<int64_t>::min(), wide), wide - BigInteger("9223372036854775808"));
}

}  // namespace

TEST(UTPoly, SignedVectorAssignment) {
    RUN_ALL_POLYS(SignedPolyAssignment, "Signed vector assignment");
}

TEST(UTDCRTPoly, SignedVectorAssignment) {
    RUN_BIG_DCRTPOLYS(SignedDCRTAssignment, "Signed DCRT vector assignment");
}
