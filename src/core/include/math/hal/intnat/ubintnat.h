//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
 This file contains the main class for native integers. It implements the same methods as other mathematical backends.
*/

#ifndef LBCRYPTO_MATH_HAL_INTNAT_UBINTNAT_H
#define LBCRYPTO_MATH_HAL_INTNAT_UBINTNAT_H

#include "math/hal/basicint.h"
#include "math/hal/bigintbackend.h"
#include "math/hal/integer.h"
#include "math/nbtheory.h"

#include "utils/debug.h"
#include "utils/exception.h"
#include "utils/inttypes.h"
#include "utils/openfhebase64.h"
#include "utils/serializable.h"

#include <cstdint>
// #include <cstdlib>
// #include <fstream>
#include <functional>
#include <iostream>
#include <limits>
// #include <memory>
// #include <sstream>
#include <string>
#include <type_traits>
// #include <typeinfo>
#include <vector>
#include <utility>

// the default behavior of the native integer layer is
// to assume that the user does not need bounds/range checks
// in the native integer code
// if you want them, change this #define to true
// we use a #define to resolve which to use at compile time
// sadly, making the choice according to some setting that
// is checked at runtime has awful performance; using this
// #define in a simple expression causes the compiler to
// optimize away the test
#define NATIVEINT_DO_CHECKS false
#define NATIVEINT_BARRET_MOD

// TODO: remove these?
using U32BITS = uint32_t;
using U64BITS = uint64_t;
#if defined(HAVE_INT128)
using U128BITS = uint128_t;
#endif

namespace intnat {

// Forward declare class and give it an alias for the expected type
template <typename IntType>
class NativeIntegerT;
using NativeInteger = NativeIntegerT<BasicInteger>;

template <typename IntType>
class NativeVectorT;

// constexpr double LOG2_10 = 3.32192809;  //!< @brief A pre-computed  constant of Log base 2 of 10.
// constexpr usint BARRETT_LEVELS = 8;  //!< @brief The number of levels (precomputed
//!< values) used in the Barrett reductions.

/**
 * @brief Struct to determine other datatyps based on utype.
 * @tparam utype primitive integer data type.
 */
template <typename utype>
struct DataTypes {
    using SignedType       = void;
    using DoubleType       = void;
    using SignedDoubleType = void;
};
template <>
struct DataTypes<uint32_t> {
    using SignedType       = int32_t;
    using DoubleType       = uint64_t;
    using SignedDoubleType = int64_t;
};
template <>
struct DataTypes<uint64_t> {
    using SignedType = int64_t;
#if defined(HAVE_INT128)
    using DoubleType       = uint128_t;
    using SignedDoubleType = int128_t;
#else
    using DoubleType       = uint64_t;
    using SignedDoubleType = int64_t;
#endif
};
#if defined(HAVE_INT128)
template <>
struct DataTypes<uint128_t> {
    using SignedType       = int128_t;
    using DoubleType       = uint128_t;
    using SignedDoubleType = int128_t;
};
#endif

/**
 * @brief Main class for big integers represented as an array of native
 * (primitive) unsigned integers
 * @tparam NativeInt native unsigned integer type
 */
template <typename NativeInt>
class NativeIntegerT final : public lbcrypto::BigIntegerInterface<NativeIntegerT<NativeInt>> {
private:
    NativeInt m_value{0};

    // variable to store the maximum value of the integral data type.
    static constexpr NativeInt m_uintMax{std::numeric_limits<NativeInt>::max()};
    // variable to store the bit width of the integral data type.
    //    static constexpr usint m_uintBitLength{sizeof(NativeInt) * 8};
    static constexpr usint m_uintBitLength{std::numeric_limits<NativeInt>::digits};

    friend class NativeVectorT<NativeIntegerT<NativeInt>>;

public:
    using Integer         = NativeInt;
    using SignedNativeInt = typename DataTypes<NativeInt>::SignedType;
    using DNativeInt      = typename DataTypes<NativeInt>::DoubleType;
    using SDNativeInt     = typename DataTypes<NativeInt>::SignedDoubleType;

    // data structure to represent a double-word integer as two single-word integers
    struct typeD {
        NativeInt hi{0};
        NativeInt lo{0};
        inline std::string ConvertToString() const {
            return std::string("hi [" + toString(hi) + "], lo [" + toString(lo) + "]");
        }
    };

    explicit operator NativeInt() const {
        return m_value;
    }
    explicit operator bool() const {
        return m_value != 0;
    }

    constexpr NativeIntegerT() = default;
    constexpr NativeIntegerT(const NativeIntegerT& val) noexcept : m_value{val.m_value} {}
    constexpr NativeIntegerT(NativeIntegerT&& val) noexcept : m_value{std::move(val.m_value)} {}

    NativeIntegerT(const std::string& val) {
        this->NativeIntegerT::SetValue(val);
    }

    explicit NativeIntegerT(const char* strval) {
        this->NativeIntegerT::SetValue(std::string(strval));
    }
    // explicit NativeIntegerT(const char strval) : m_value{NativeInt(strval - '0')} {}

    template <typename T, std::enable_if_t<std::is_integral_v<T>, bool> = true>
    constexpr NativeIntegerT(T val) noexcept : m_value(val) {}

    template <typename T, std::enable_if_t<std::is_same_v<T, M2Integer> || std::is_same_v<T, M4Integer> ||
                                               std::is_same_v<T, M6Integer>,
                                           bool> = true>
    constexpr NativeIntegerT(T val) noexcept : m_value{val.template ConvertToInt<NativeInt>()} {}

    template <typename T, std::enable_if_t<std::is_floating_point_v<T>, bool> = true>
    NativeIntegerT(T val) = delete;

    constexpr NativeIntegerT& operator=(const NativeIntegerT& val) noexcept {
        m_value = val.m_value;
        return *this;
    }

    constexpr NativeIntegerT& operator=(NativeIntegerT&& val) noexcept {
        m_value = std::move(val.m_value);
        return *this;
    }

    NativeIntegerT& operator=(const std::string& val) {
        this->NativeIntegerT::SetValue(val);
        return *this;
    }

    NativeIntegerT& operator=(const char* strval) {
        this->NativeIntegerT::SetValue(std::string(strval));
        return *this;
    }

    template <typename T, std::enable_if_t<std::is_integral_v<T>, bool> = true>
    constexpr NativeIntegerT& operator=(T val) noexcept {
        m_value = val;
        return *this;
    }

    template <typename T, std::enable_if_t<std::is_same_v<T, M2Integer> || std::is_same_v<T, M4Integer> ||
                                               std::is_same_v<T, M6Integer>,
                                           bool> = true>
    constexpr NativeIntegerT& operator=(T val) noexcept {
        m_value = val.template ConvertToInt<NativeInt>();
        return *this;
    }

    template <typename T, std::enable_if_t<std::is_floating_point_v<T>, bool> = true>
    NativeIntegerT& operator=(T val) = delete;

    /**
   * Basic set method for setting the value of a native integer
   *
   * @param &strval is the string representation of the native integer to be
   * copied.
   */
    void SetValue(const std::string& str) {
        NativeInt acc{0}, tst{0};
        for (auto c : str) {
            if ((c - '0') > 9)
                OPENFHE_THROW(lbcrypto::type_error, "String contains a non-digit");
            if ((acc = (10 * acc) + static_cast<NativeInt>(c - '0')) < tst)
                OPENFHE_THROW(lbcrypto::math_error, str + " is too large to fit in this native integer object");
            tst = acc;
        }
        m_value = acc;
    }

    /**
   * Basic set method for setting the value of a native integer
   *
   * @param &val is the big binary integer representation of the native
   * integer to be assigned.
   */
    void SetValue(const NativeIntegerT& val) {
        m_value = val.m_value;
    }

    /**
   *  Set this int to 1.
   */
    void SetIdentity() {
        m_value = static_cast<NativeInt>(1);
    }

    /**
   * Addition operation.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
    NativeIntegerT Add(const NativeIntegerT& b) const {
        return NATIVEINT_DO_CHECKS ? AddCheck(b) : AddFast(b);
    }

    /**
   * AddCheck is the addition operation with bounds checking.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
    NativeIntegerT AddCheck(const NativeIntegerT& b) const {
        auto r{m_value + b.m_value};
        if (r < m_value || r < b.m_value)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT AddCheck: Overflow");
        return {r};
    }

    /**
   * AddFast is the addition operation without bounds checking.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
    NativeIntegerT AddFast(const NativeIntegerT& b) const {
        return {b.m_value + m_value};
    }

    /**
   * Addition operation. In-place variant.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
    NativeIntegerT& AddEq(const NativeIntegerT& b) {
        return NATIVEINT_DO_CHECKS ? AddEqCheck(b) : AddEqFast(b);
    }

    /**
   * AddEqCheck is the addition in place operation with bounds checking.
   * In-place variant.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
    NativeIntegerT& AddEqCheck(const NativeIntegerT& b) {
        auto oldv{m_value};
        if ((m_value += b.m_value) < oldv)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT AddEqCheck: Overflow");
        return *this;
    }

    /**
   * AddEqFast is the addition in place operation without bounds checking.
   * In-place variant.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
    NativeIntegerT& AddEqFast(const NativeIntegerT& b) {
        return *this = b.m_value + m_value;
    }

    /**
   * Subtraction operation.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
    NativeIntegerT Sub(const NativeIntegerT& b) const {
        return NATIVEINT_DO_CHECKS ? SubCheck(b) : SubFast(b);
    }

    /**
   * SubCheck is the subtraction operation with bounds checking.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
    NativeIntegerT SubCheck(const NativeIntegerT& b) const {
        return {m_value <= b.m_value ? 0 : m_value - b.m_value};
    }

    /**
   * SubFast is the subtraction operation without bounds checking.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
    // no saturated subtraction? functionality differs from BigInteger Backends
    NativeIntegerT SubFast(const NativeIntegerT& b) const {
        return {m_value - b.m_value};
    }

    /**
   * Subtraction operation. In-place variant.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
    NativeIntegerT& SubEq(const NativeIntegerT& b) {
        return NATIVEINT_DO_CHECKS ? SubEqCheck(b) : SubEqFast(b);
    }

    /**
   * SubEqCheck is the subtraction in place operation with bounds checking.
   * In-place variant.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
    NativeIntegerT& SubEqCheck(const NativeIntegerT& b) {
        if (m_value < b.m_value)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT SubEqCheck: neg value");
        return *this = m_value - b.m_value;
    }

    /**
   * SubEqFast is the subtraction in place operation without bounds checking.
   * In-place variant.
   *
   * @param b is the value to add to this.
   * @return result of the addition operation.
   */
    NativeIntegerT& SubEqFast(const NativeIntegerT& b) {
        return *this = m_value - b.m_value;
    }

    // overloaded binary operators based on integer arithmetic and comparison
    // functions.
    NativeIntegerT operator-() const {
        return NativeIntegerT().Sub(*this);
    }

    /**
   * Multiplication operation.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
    NativeIntegerT Mul(const NativeIntegerT& b) const {
        return NATIVEINT_DO_CHECKS ? MulCheck(b) : MulFast(b);
    }

    /**
   * MulCheck is the multiplication operation with bounds checking.
   *
   * @param b is the value to multiply with
   * @return result of the multiplication operation
   */
    NativeIntegerT MulCheck(const NativeIntegerT& b) const {
        auto p{b.m_value * m_value};
        if (p < m_value || p < b.m_value)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT MulCheck: Overflow");
        return {p};
    }

    /**
   * MulFast is the multiplication operation without bounds checking.
   *
   * @param b is the value to multiply with.
   * @return result of the multiplication operation.
   */
    NativeIntegerT MulFast(const NativeIntegerT& b) const {
        return {b.m_value * m_value};
    }

    /**
   * Multiplication operation. In-place variant.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
    NativeIntegerT& MulEq(const NativeIntegerT& b) {
        return NATIVEINT_DO_CHECKS ? MulEqCheck(b) : MulEqFast(b);
    }

    /**
   * MulEqCheck is the multiplication in place operation with bounds checking.
   * In-place variant.
   *
   * @param b is the value to multiply with
   * @return result of the multiplication operation
   */
    NativeIntegerT& MulEqCheck(const NativeIntegerT& b) {
        auto oldv{m_value};
        if ((m_value *= b.m_value) < oldv)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT MulEqCheck: Overflow");
        return *this;
    }

    /**
   * MulEqFast is the multiplication in place operation without bounds
   * checking. In-place variant.
   *
   * @param b is the value to multiply with
   * @return result of the multiplication operation
   */
    NativeIntegerT& MulEqFast(const NativeIntegerT& b) {
        return *this = b.m_value * m_value;
    }

    /**
   * Division operation.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
    NativeIntegerT DividedBy(const NativeIntegerT& b) const {
        if (b.m_value == 0)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT DividedBy: zero");
        return {m_value / b.m_value};
    }

    /**
   * Division operation. In-place variant.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
    NativeIntegerT& DividedByEq(const NativeIntegerT& b) {
        if (b.m_value == 0)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT DividedByEq: zero");
        return *this = m_value / b.m_value;
    }

    /**
   * Exponentiation operation. Returns x^p.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
    NativeIntegerT Exp(usint p) const {
        NativeInt r{1};
        for (auto x = m_value; p > 0; p >>= 1, x *= x)
            r *= (p & 0x1) ? x : 1;
        return {r};
    }

    /**
   * Exponentiation operation. Returns x^p. In-place variant.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
    NativeIntegerT& ExpEq(usint p) {
        auto x{m_value};
        m_value = 1;
        for (; p > 0; p >>= 1, x *= x)
            m_value *= (p & 0x1) ? x : 1;
        return *this;
    }

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    NativeIntegerT MultiplyAndRound(const NativeIntegerT& p, const NativeIntegerT& q) const {
        if (q.m_value == 0)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT MultiplyAndRound: Divide by zero");
        return static_cast<NativeInt>(p.ConvertToDouble() * (this->ConvertToDouble() / q.ConvertToDouble()) + 0.5);
    }

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    NativeIntegerT& MultiplyAndRoundEq(const NativeIntegerT& p, const NativeIntegerT& q) {
        if (q.m_value == 0)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT MultiplyAndRoundEq: Divide by zero");
        return *this =
                   static_cast<NativeInt>(p.ConvertToDouble() * (this->ConvertToDouble() / q.ConvertToDouble()) + 0.5);
    }

    /**
   * Computes the quotient of x*p/q, where x,p,q are all NativeInt numbers, x
   * is the current value; uses DNativeInt arithmetic
   *
   * @param p is the multiplicand
   * @param q is the divisor
   * @return the quotient
   */
    //    template <typename T = NativeInt>
    //    NativeIntegerT MultiplyAndDivideQuotient(const NativeIntegerT& p, const NativeIntegerT& q) const {
    //        DNativeInt xD{m_value};
    //        DNativeInt pD{p.m_value};
    //        DNativeInt qD{q.m_value};
    //        return static_cast<NativeIntegerT>(xD * pD / qD);
    //    }

    /**
   * Computes the remainder of x*p/q, where x,p,q are all NativeInt numbers, x
   * is the current value; uses DNativeInt arithmetic. In-place variant.
   *
   * @param p is the multiplicand
   * @param q is the divisor
   * @return the remainder
   */
    //    template <typename T = NativeInt>
    //    NativeIntegerT MultiplyAndDivideRemainder(const NativeIntegerT& p, const NativeIntegerT& q) const {
    //        DNativeInt xD{m_value};
    //        DNativeInt pD{p.m_value};
    //        DNativeInt qD{q.m_value};
    //        return static_cast<NativeIntegerT>(xD * pD % qD);
    //    }

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    NativeIntegerT DivideAndRound(const NativeIntegerT& q) const {
        if (q.m_value == 0)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT DivideAndRound: zero");
        auto ans{m_value / q.m_value};
        auto rem{m_value % q.m_value};
        auto halfQ{q.m_value >> 1};
        if (rem > halfQ)
            return {ans + 1};
        return {ans};
    }

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation. In-place variant.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    NativeIntegerT& DivideAndRoundEq(const NativeIntegerT& q) {
        if (q.m_value == 0)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT DivideAndRoundEq: zero");
        auto ans{m_value / q.m_value};
        auto rem{m_value % q.m_value};
        auto halfQ{q.m_value >> 1};
        if (rem > halfQ)
            return *this = ans + 1;
        return *this = ans;
    }

    /**
   * Naive modulus operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
    NativeIntegerT Mod(const NativeIntegerT& modulus) const {
        return {m_value % modulus.m_value};
    }

    /**
   * Naive modulus operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
    NativeIntegerT& ModEq(const NativeIntegerT& modulus) {
        return *this = m_value % modulus.m_value;
    }

    /**
   * Precomputes a parameter mu for Barrett modular reduction.
   *
   * @return the precomputed parameter mu.
   */
    template <typename T = NativeInt>
    NativeIntegerT ComputeMu(typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) const {
        if (m_value == 0)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT ComputeMu: Divide by zero");
        auto&& tmp{DNativeInt{1} << (2 * lbcrypto::GetMSB(m_value) + 3)};
        return {tmp / DNativeInt(m_value)};
    }

    template <typename T = NativeInt>
    NativeIntegerT ComputeMu(typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) const {
        if (m_value == 0)
            OPENFHE_THROW(lbcrypto::math_error, "NativeIntegerT ComputeMu: Divide by zero");
        auto&& tmp{bigintbackend::BigInteger{1} << (2 * lbcrypto::GetMSB(m_value) + 3)};
        return {(tmp / bigintbackend::BigInteger(m_value)).template ConvertToInt<NativeInt>()};
    }

    /**
   * Barrett modulus operation.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
    // TODO: pass modulus.GetMSB() with mu for faster vector ops?
    NativeIntegerT Mod(const NativeIntegerT& modulus, const NativeIntegerT& mu) const {
        typeD tmp;
        NativeIntegerT ans{*this};
        ModMu(tmp, ans, modulus.m_value, mu.m_value, modulus.GetMSB() - 2);
        return ans;
    }

    /**
   * Barrett modulus operation. In-place variant.
   * Implements generalized Barrett modular reduction algorithm. Uses one
   * precomputed value of mu.
   *
   * @param &modulus is the modulus to perform.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus operation.
   */
    NativeIntegerT& ModEq(const NativeIntegerT& modulus, const NativeIntegerT& mu) {
        typeD tmp;
        ModMu(tmp, *this, modulus.m_value, mu.m_value, modulus.GetMSB() - 2);
        return *this;
    }

    /**
   * Modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    NativeIntegerT ModAdd(const NativeIntegerT& b, const NativeIntegerT& modulus) const {
        auto av{m_value};
        auto bv{b.m_value};
        auto& mv{modulus.m_value};
        if (av >= mv)
            av %= mv;
        if (bv >= mv)
            bv %= mv;
        av += bv;
        if (av >= mv)
            av -= mv;
        return {av};
    }

    /**
   * Modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    NativeIntegerT& ModAddEq(const NativeIntegerT& b, const NativeIntegerT& modulus) {
        auto bv{b.m_value};
        auto& mv{modulus.m_value};
        if (m_value >= mv)
            m_value = m_value % mv;
        if (bv >= mv)
            bv = bv % mv;
        m_value += bv;
        if (m_value >= mv)
            m_value -= mv;
        return *this;
    }

    /**
   * Modulus addition where operands are < modulus.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    NativeIntegerT ModAddFast(const NativeIntegerT& b, const NativeIntegerT& modulus) const {
        auto r{m_value + b.m_value};
        auto& mv{modulus.m_value};
        if (r >= mv)
            r -= mv;
        return {r};
    }
    /**
   * Modulus addition where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    NativeIntegerT& ModAddFastEq(const NativeIntegerT& b, const NativeIntegerT& modulus) {
        auto& mv{modulus.m_value};
        m_value += b.m_value;
        if (m_value >= mv)
            m_value -= mv;
        return *this;
    }

    /**
   * Barrett modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
    template <typename T = NativeInt>
    NativeIntegerT ModAdd(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                          typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) const {
        auto& mv{modulus.m_value};
#ifdef NATIVEINT_BARRET_MOD
        auto av{*this};
        auto bv{b};
        if (av.m_value >= mv)
            av.ModEq(modulus, mu);
        if (bv.m_value >= mv)
            bv.ModEq(modulus, mu);
        av.m_value += bv.m_value;
        if (av.m_value >= mv)
            av.m_value -= mv;
        return av;
#else
        auto bv{b.m_value};
        auto av{m_value};
        if (bv >= mv)
            bv = bv % mv;
        if (av >= mv)
            av = av % mv;
        av = av + bv;
        if (av >= mv)
            return {av - mv};
        return {av};
#endif
    }

    template <typename T = NativeInt>
    NativeIntegerT ModAdd(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                          typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) const {
        auto av{*this};
        auto bv{b};
        auto& mv{modulus.m_value};
        if (av.m_value >= mv)
            av.ModEq(modulus, mu);
        if (bv.m_value >= mv)
            bv.ModEq(modulus, mu);
        av.m_value += bv.m_value;
        if (av.m_value >= mv)
            av.m_value -= mv;
        return av;
    }

    /**
   * Barrett modulus addition operation. In-place variant.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
    template <typename T = NativeInt>
    NativeIntegerT& ModAddEq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                             typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) {
        auto& mv{modulus.m_value};
#ifdef NATIVEINT_BARRET_MOD
        auto av{*this};
        auto bv{b};
        if (av.m_value >= mv)
            av.ModEq(modulus, mu);
        if (bv.m_value >= mv)
            bv.ModEq(modulus, mu);
        m_value = av.m_value + bv.m_value;
        if (m_value >= mv)
            m_value -= mv;
        return *this;
#else
        auto bv{b.m_value};
        auto av{m_value};
        if (bv >= mv)
            bv = bv % mv;
        if (av >= mv)
            av = av % mv;
        av = av + bv;
        if (av >= mv)
            return *this = av - mv;
        return *this = av;
#endif
    }

    template <typename T = NativeInt>
    NativeIntegerT& ModAddEq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                             typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) {
        auto av{*this};
        auto bv{b};
        auto& mv{modulus.m_value};
        if (av.m_value >= mv)
            av.ModEq(modulus, mu);
        if (bv.m_value >= mv)
            bv.ModEq(modulus, mu);
        m_value = av.m_value + bv.m_value;
        if (m_value >= mv)
            m_value -= mv;
        return *this;
    }

    /**
   * Modulus subtraction operation.
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    NativeIntegerT ModSub(const NativeIntegerT& b, const NativeIntegerT& modulus) const {
        auto av{m_value};
        auto bv{b.m_value};
        auto& mv{modulus.m_value};
        if (av >= mv)
            av %= mv;
        if (bv >= mv)
            bv %= mv;
        if (av < bv)
            return {av + mv - bv};
        return {av - bv};
    }

    /**
   * Modulus subtraction operation. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    NativeIntegerT& ModSubEq(const NativeIntegerT& b, const NativeIntegerT& modulus) {
        auto av{m_value};
        auto bv{b.m_value};
        auto& mv{modulus.m_value};
        if (av >= mv)
            av = av % mv;
        if (bv >= mv)
            bv = bv % mv;
        if (av < bv)
            return *this = av + mv - bv;
        return *this = av - bv;
    }

    /**
   * Modulus subtraction where operands are < modulus.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    NativeIntegerT ModSubFast(const NativeIntegerT& b, const NativeIntegerT& modulus) const {
        if (m_value < b.m_value)
            return {m_value + modulus.m_value - b.m_value};
        return {m_value - b.m_value};
    }

    /**
   * Modulus subtraction where operands are < modulus. In-place variant.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    NativeIntegerT& ModSubFastEq(const NativeIntegerT& b, const NativeIntegerT& modulus) {
        if (m_value < b.m_value)
            return *this = m_value + modulus.m_value - b.m_value;
        return *this = m_value - b.m_value;
    }

    /**
   * Barrett modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
    template <typename T = NativeInt>
    NativeIntegerT ModSub(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                          typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) const {
        auto& mv{modulus.m_value};
#ifdef NATIVEINT_BARRET_MOD
        auto av{*this};
        auto bv{b};
        if (av.m_value >= mv)
            av.ModEq(modulus, mu);
        if (bv.m_value >= mv)
            bv.ModEq(modulus, mu);
        if (av.m_value < bv.m_value)
            return {av.m_value + mv - bv.m_value};
        return {av.m_value - bv.m_value};
#else
        auto av{m_value};
        auto bv{b.m_value};
        if (av >= mv)
            av = av % mv;
        if (bv >= mv)
            bv = bv % mv;
        if (av < bv)
            return {av + mv - bv};
        return {av - bv};
#endif
    }

    template <typename T = NativeInt>
    NativeIntegerT ModSub(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                          typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) const {
        auto av{*this};
        auto bv{b};
        auto& mv{modulus.m_value};
        if (av.m_value >= mv)
            av.ModEq(modulus, mu);
        if (bv.m_value >= mv)
            bv.ModEq(modulus, mu);
        if (av.m_value < bv.m_value)
            return {av.m_value + mv - bv.m_value};
        return {av.m_value - bv.m_value};
    }

    template <typename T = NativeInt>
    NativeIntegerT& ModSubEq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                             typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) {
        auto& mv{modulus.m_value};
#ifdef NATIVEINT_BARRET_MOD
        auto av{*this};
        auto bv{b};
        if (av.m_value >= mv)
            av.ModEq(modulus, mu);
        if (bv.m_value >= mv)
            bv.ModEq(modulus, mu);
        if (av.m_value < bv.m_value)
            return *this = av.m_value + mv - bv.m_value;
        return *this = av.m_value - bv.m_value;
#else
        auto bv{b.m_value};
        auto av{m_value};
        if (bv >= mv)
            bv = bv % mv;
        if (av >= mv)
            av = av % mv;
        if (av < bv)
            return *this = av + mv - bv;
        return *this = av - bv;
#endif
    }

    template <typename T = NativeInt>
    NativeIntegerT& ModSubEq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                             typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) {
        auto av{*this};
        auto bv{b};
        auto& mv{modulus.m_value};
        if (av.m_value >= mv)
            av.ModEq(modulus, mu);
        if (bv.m_value >= mv)
            bv.ModEq(modulus, mu);
        if (av.m_value < bv.m_value)
            return *this = av.m_value + mv - bv.m_value;
        return *this = av.m_value - bv.m_value;
    }

    /**
   * Modulus multiplication operation.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    template <typename T = NativeInt>
    NativeIntegerT ModMul(const NativeIntegerT& b, const NativeIntegerT& modulus,
                          typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) const {
        auto av{m_value};
        auto bv{b.m_value};
        auto& mv{modulus.m_value};
        if (av >= mv)
            av = av % mv;
        if (bv >= mv)
            bv = bv % mv;
        DNativeInt rv{static_cast<DNativeInt>(av) * bv};
        DNativeInt dmv{mv};
        if (rv >= dmv)
            rv %= dmv;
        return {rv};
    }

    template <typename T = NativeInt>
    NativeIntegerT ModMul(const NativeIntegerT& b, const NativeIntegerT& modulus,
                          typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) const {
        typeD tmp;
        auto av{*this};
        auto& mv{modulus.m_value};
        auto mu{modulus.ComputeMu().m_value};
        int64_t n{modulus.GetMSB() - 2};
        if (av.m_value >= mv)
            ModMu(tmp, av, mv, mu, n);
        auto bv{b};
        if (bv.m_value >= mv)
            ModMu(tmp, bv, mv, mu, n);
        MultD(av.m_value, bv.m_value, tmp);
        typeD r{tmp};
        MultD(RShiftD(tmp, n), mu, tmp);
        MultD(RShiftD(tmp, n + 7), mv, tmp);
        SubtractD(r, tmp);
        if (r.lo >= mv)
            r.lo -= mv;
        return {r.lo};
    }

    /**
   * Modulus multiplication operation. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    template <typename T = NativeInt>
    NativeIntegerT& ModMulEq(const NativeIntegerT& b, const NativeIntegerT& modulus,
                             typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) {
        auto av{m_value};
        auto bv{b.m_value};
        auto& mv{modulus.m_value};
        if (av >= mv)
            av = av % mv;
        if (bv >= mv)
            bv = bv % mv;
        DNativeInt rv{static_cast<DNativeInt>(av) * bv};
        DNativeInt dmv{mv};
        if (rv >= dmv)
            rv %= dmv;
        return *this = static_cast<NativeInt>(rv);
    }

    template <typename T = NativeInt>
    NativeIntegerT& ModMulEq(const NativeIntegerT& b, const NativeIntegerT& modulus,
                             typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) {
        auto av{*this};
        auto& mv{modulus.m_value};
        typeD tmp;
        auto mu{modulus.ComputeMu().m_value};
        int64_t n{modulus.GetMSB() - 2};
        if (av.m_value >= mv)
            ModMu(tmp, av, mv, mu, n);
        auto bv{b};
        if (bv.m_value >= mv)
            ModMu(tmp, bv, mv, mu, n);
        MultD(av.m_value, bv.m_value, tmp);
        typeD r = tmp;
        MultD(RShiftD(tmp, n), mu, tmp);
        MultD(RShiftD(tmp, n + 7), mv, tmp);
        SubtractD(r, tmp);
        m_value = r.lo;
        if (r.lo >= mv)
            m_value -= mv;
        return *this;
    }

    /**
   * Barrett modulus multiplication.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    template <typename T = NativeInt>
    NativeIntegerT ModMul(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                          typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) const {
#ifdef NATIVEINT_BARRET_MOD
        auto av{*this};
        auto& mv{modulus.m_value};
        typeD tmp;
        int64_t n{modulus.GetMSB() - 2};
        if (av.m_value >= mv)
            ModMu(tmp, av, mv, mu.m_value, n);
        auto bv{b};
        if (bv.m_value >= mv)
            ModMu(tmp, bv, mv, mu.m_value, n);
        MultD(av.m_value, bv.m_value, tmp);
        auto rv = GetD(tmp);
        MultD(RShiftD(tmp, n), mu.m_value, tmp);
        rv -= DNativeInt(mv) * (GetD(tmp) >> n + 7);
        NativeIntegerT r(rv);
        if (r.m_value >= mv)
            r.m_value -= mv;
        return r;
#else
        auto& mv{modulus.m_value};
        auto bv{b.m_value};
        auto av{m_value};
        if (bv >= mv)
            bv = bv % mv;
        if (av >= mv)
            av = av % mv;
        DNativeInt rv{static_cast<DNativeInt>(av) * bv};
        DNativeInt dmv{mv};
        if (rv >= dmv)
            return {rv % dmv};
        return {rv};
#endif
    }

    template <typename T = NativeInt>
    NativeIntegerT ModMul(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                          typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) const {
        auto av{*this};
        auto& mv{modulus.m_value};
        typeD tmp;
        int64_t n{modulus.GetMSB() - 2};
        if (av.m_value >= mv)
            ModMu(tmp, av, mv, mu.m_value, n);
        auto bv{b};
        if (bv.m_value >= mv)
            ModMu(tmp, bv, mv, mu.m_value, n);
        MultD(av.m_value, bv.m_value, tmp);
        typeD r = tmp;
        MultD(RShiftD(tmp, n), mu.m_value, tmp);
        MultD(RShiftD(tmp, n + 7), mv, tmp);
        SubtractD(r, tmp);
        if (r.lo >= mv)
            r.lo -= mv;
        return {r.lo};
    }

    /**
   * Barrett modulus multiplication. In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    template <typename T = NativeInt>
    NativeIntegerT& ModMulEq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                             typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) {
#ifdef NATIVEINT_BARRET_MOD
        auto av{*this};
        auto bv{b};
        auto& mv{modulus.m_value};
        typeD tmp;
        auto& muv{mu.m_value};
        int64_t n{modulus.GetMSB() - 2};
        if (av.m_value >= mv)
            ModMu(tmp, av, mv, muv, n);
        if (bv.m_value >= mv)
            ModMu(tmp, bv, mv, muv, n);
        MultD(av.m_value, bv.m_value, tmp);
        auto rv = GetD(tmp);
        MultD(RShiftD(tmp, n), muv, tmp);
        rv -= DNativeInt(mv) * (GetD(tmp) >> n + 7);
        m_value = static_cast<NativeInt>(rv);
        if (m_value >= mv)
            m_value -= mv;
        return *this;
#else
        auto& mv{modulus.m_value};
        auto bv{b.m_value};
        auto av{m_value};
        if (bv >= mv)
            bv = bv % mv;
        if (av >= mv)
            av = av % mv;
        DNativeInt rv{static_cast<DNativeInt>(av) * bv};
        DNativeInt dmv{mv};
        if (rv >= dmv)
            return *this = static_cast<NativeInt>(rv % dmv);
        return *this = static_cast<NativeInt>(rv);
#endif
    }

    template <typename T = NativeInt>
    NativeIntegerT& ModMulEq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                             typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) {
        int64_t n{modulus.GetMSB() - 2};
        auto av{*this};
        auto bv{b};
        auto& mv{modulus.m_value};
        typeD tmp;
        if (av.m_value >= mv)
            ModMu(tmp, av, mv, mu.m_value, n);
        if (bv.m_value >= mv)
            ModMu(tmp, bv, mv, mu.m_value, n);
        MultD(av.m_value, bv.m_value, tmp);
        typeD r = tmp;
        MultD(RShiftD(tmp, n), mu.m_value, tmp);
        MultD(RShiftD(tmp, n + 7), mv, tmp);
        SubtractD(r, tmp);
        m_value = r.lo;
        if (r.lo >= mv)
            m_value -= mv;
        return *this;
    }

    /**
   * Modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    template <typename T = NativeInt>
    NativeIntegerT ModMulFast(const NativeIntegerT& b, const NativeIntegerT& modulus,
                              typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) const {
        DNativeInt rv{static_cast<DNativeInt>(m_value) * b.m_value};
        DNativeInt dmv{modulus.m_value};
        if (rv >= dmv)
            rv %= dmv;
        return {rv};
    }

    template <typename T = NativeInt>
    NativeIntegerT ModMulFast(const NativeIntegerT& b, const NativeIntegerT& modulus,
                              typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) const {
        int64_t n = modulus.GetMSB() - 2;
        auto& mv{modulus.m_value};
        typeD prod;
        MultD(m_value, b.m_value, prod);
        typeD r = prod;
        MultD(RShiftD(prod, n), modulus.ComputeMu().m_value, prod);
        MultD(RShiftD(prod, n + 7), mv, prod);
        SubtractD(r, prod);
        if (r.lo >= mv)
            r.lo -= mv;
        return {r.lo};
    }

    /**
   * Modulus multiplication that assumes the operands are < modulus. In-place
   * variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    // TODO: find what in Matrix<DCRTPoly> is calling ModMulFastEq incorrectly
    template <typename T = NativeInt>
    NativeIntegerT ModMulFastEq(const NativeIntegerT& b, const NativeIntegerT& modulus,
                                typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) {
        DNativeInt rv{static_cast<DNativeInt>(m_value) * b.m_value};
        DNativeInt dmv{modulus.m_value};
        if (rv >= dmv)
            rv %= dmv;
        return *this = static_cast<NativeInt>(rv);
    }

    template <typename T = NativeInt>
    NativeIntegerT ModMulFastEq(const NativeIntegerT& b, const NativeIntegerT& modulus,
                                typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) {
        int64_t n = modulus.GetMSB() - 2;
        auto& mv{modulus.m_value};
        typeD prod;
        MultD(m_value, b.m_value, prod);
        typeD r = prod;
        MultD(RShiftD(prod, n), modulus.ComputeMu().m_value, prod);
        MultD(RShiftD(prod, n + 7), mv, prod);
        SubtractD(r, prod);
        m_value = r.lo;
        if (r.lo >= mv)
            m_value -= mv;
        return *this;
    }

    /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    /* Source: http://homes.esat.kuleuven.be/~fvercaut/papers/bar_mont.pdf
    @article{knezevicspeeding,
    title={Speeding Up Barrett and Montgomery Modular Multiplications},
    author={Knezevic, Miroslav and Vercauteren, Frederik and Verbauwhede,
    Ingrid}
    }
    We use the Generalized Barrett modular reduction algorithm described in
    Algorithm 2 of the Source. The algorithm was originally proposed in J.-F.
    Dhem. Modified version of the Barrett algorithm. Technical report, 1994
    and described in more detail in the PhD thesis of the author published at
    http://users.belgacom.net/dhem/these/these_public.pdf (Section 2.2.4).
    We take \alpha equal to n + 3. So in our case, \mu = 2^(n + \alpha) =
    2^(2*n + 3). Generally speaking, the value of \alpha should be \ge \gamma
    + 1, where \gamma + n is the number of digits in the dividend. We use the
    upper bound of dividend assuming that none of the dividends will be larger
    than 2^(2*n + 3). The value of \mu is computed by NativeVector::ComputeMu.
    */
    template <typename T = NativeInt>
    NativeIntegerT ModMulFast(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                              typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) const {
        int64_t n = modulus.GetMSB() - 2;
        auto& mv{modulus.m_value};
        typeD tmp;
        MultD(m_value, b.m_value, tmp);
        auto rv = GetD(tmp);
        MultD(RShiftD(tmp, n), mu.m_value, tmp);
        rv -= DNativeInt(mv) * (GetD(tmp) >> n + 7);
        NativeIntegerT r(rv);
        if (r.m_value >= mv)
            r.m_value -= mv;
        return r;
    }

    template <typename T = NativeInt>
    NativeIntegerT ModMulFast(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                              typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) const {
        int64_t n = modulus.GetMSB() - 2;
        auto& mv{modulus.m_value};
        typeD prod;
        MultD(m_value, b.m_value, prod);
        typeD r = prod;
        MultD(RShiftD(prod, n), mu.m_value, prod);
        MultD(RShiftD(prod, n + 7), mv, prod);
        SubtractD(r, prod);
        if (r.lo >= mv)
            r.lo -= mv;
        return {r.lo};
    }

    /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   * In-place variant.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    template <typename T = NativeInt>
    NativeIntegerT& ModMulFastEq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                                 typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) {
        typeD tmp;
        MultD(m_value, b.m_value, tmp);
        auto rv{GetD(tmp)};
        int64_t n{modulus.GetMSB() - 2};
        MultD(RShiftD(tmp, n), mu.m_value, tmp);
        auto& mv{modulus.m_value};
        rv -= DNativeInt(mv) * (GetD(tmp) >> n + 7);
        m_value = NativeInt(rv);
        if (m_value >= mv)
            m_value -= mv;
        return *this;
    }

    template <typename T = NativeInt>
    NativeIntegerT& ModMulFastEq(const NativeIntegerT& b, const NativeIntegerT& modulus, const NativeIntegerT& mu,
                                 typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) {
        int64_t n{modulus.GetMSB() - 2};
        typeD prod;
        MultD(m_value, b.m_value, prod);
        typeD r{prod};
        auto& mv{modulus.m_value};
        MultD(RShiftD(prod, n), mu.m_value, prod);
        MultD(RShiftD(prod, n + 7), mv, prod);
        SubtractD(r, prod);
        m_value = r.lo;
        if (r.lo >= mv)
            m_value -= mv;
        return *this;
    }

    /*  The next three subroutines implement the modular multiplication
    algorithm for the case when the multiplicand is used multiple times (known
    in advance), as in NTT. The algorithm is described in
    https://arxiv.org/pdf/1205.2926.pdf (Dave Harvey, FASTER ARITHMETIC FOR
    NUMBER-THEORETIC TRANSFORMS). The algorithm is described in lines 5-7 of
    Algorithm 2. The algorithm was originally proposed and implemented in NTL
    (https://www.shoup.net/ntl/) by Victor Shoup.
    */

    /**
   * Precomputation for a multiplicand.
   *
   * @param modulus is the modulus to perform operations with.
   * @return the precomputed factor.
   */
    template <typename T = NativeInt>
    NativeIntegerT PrepModMulConst(
        const NativeIntegerT& modulus,
        typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type = true) const {
        if (modulus.m_value == 0)
            OPENFHE_THROW(lbcrypto::math_error, "Divide by zero");
        auto&& w{DNativeInt(m_value) << NativeIntegerT::MaxBits()};
        return {w / DNativeInt(modulus.m_value)};
    }

    template <typename T = NativeInt>
    NativeIntegerT PrepModMulConst(
        const NativeIntegerT& modulus,
        typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type = true) const {
        if (modulus.m_value == 0)
            OPENFHE_THROW(lbcrypto::math_error, "Divide by zero");
        auto&& w{bigintbackend::BigInteger(m_value) << NativeIntegerT::MaxBits()};
        return {(w / bigintbackend::BigInteger(modulus.m_value)).template ConvertToInt<NativeInt>()};
    }

    /**
   * Modular multiplication using a precomputation for the multiplicand.
   *
   * @param &b is the NativeIntegerT to multiply.
   * @param modulus is the modulus to perform operations with.
   * @param &bInv precomputation for b.
   * @return is the result of the modulus multiplication operation.
   */
    NativeIntegerT ModMulFastConst(const NativeIntegerT& b, const NativeIntegerT& modulus,
                                   const NativeIntegerT& bInv) const {
        NativeInt q = MultDHi(m_value, bInv.m_value) + 1;
        auto yprime = static_cast<SignedNativeInt>(m_value * b.m_value - q * modulus.m_value);
        return {yprime >= 0 ? yprime : yprime + modulus.m_value};
    }

    /**
   * Modular multiplication using a precomputation for the multiplicand.
   * In-place variant.
   *
   * @param &b is the NativeIntegerT to multiply.
   * @param modulus is the modulus to perform operations with.
   * @param &bInv precomputation for b.
   * @return is the result of the modulus multiplication operation.
   */
    NativeIntegerT& ModMulFastConstEq(const NativeIntegerT& b, const NativeIntegerT& modulus,
                                      const NativeIntegerT& bInv) {
        NativeInt q = MultDHi(m_value, bInv.m_value) + 1;
        auto yprime = static_cast<SignedNativeInt>(m_value * b.m_value - q * modulus.m_value);
        m_value     = static_cast<NativeInt>(yprime >= 0 ? yprime : yprime + modulus.m_value);
        return *this;
    }

    /**
   * Modulus exponentiation operation.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
    template <typename T = NativeInt>
    NativeIntegerT ModExp(const NativeIntegerT& b, const NativeIntegerT& mod,
                          typename std::enable_if<!std::is_same<T, DNativeInt>::value, bool>::type = true) const {
        DNativeInt t{m_value};
        DNativeInt p{b.m_value};
        DNativeInt m{mod.m_value};
        DNativeInt r{1};
        if (p & 0x1) {
            r = r * t;
            if (r >= m)
                r = r % m;
        }
        while (p >>= 1) {
            t = t * t;
            if (t >= m)
                t = t % m;
            if (p & 0x1) {
                r = r * t;
                if (r >= m)
                    r = r % m;
            }
        }
        return {r};
    }

    template <typename T = NativeInt>
    NativeIntegerT ModExp(const NativeIntegerT& b, const NativeIntegerT& mod,
                          typename std::enable_if<std::is_same<T, DNativeInt>::value, bool>::type = true) const {
        NativeIntegerT t{m_value % mod.m_value};
        NativeIntegerT p{b.m_value};
        NativeIntegerT mu{mod.ComputeMu()};
        NativeIntegerT r{1};
        if (p.m_value & 0x1)
            r.ModMulFastEq(t, mod, mu);
        while (p.m_value >>= 1) {
            t.ModMulFastEq(t, mod, mu);
            if (p.m_value & 0x1)
                r.ModMulFastEq(t, mod, mu);
        }
        return {r};
    }

    /**
   * Modulus exponentiation operation. In-place variant.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
    NativeIntegerT& ModExpEq(const NativeIntegerT& b, const NativeIntegerT& mod) {
        return *this = this->NativeIntegerT::ModExp(b, mod);
    }

    /**
   * Modulus inverse operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
    NativeIntegerT ModInverse(const NativeIntegerT& mod) const {
        SignedNativeInt modulus(mod.m_value);
        SignedNativeInt a(m_value % mod.m_value);
        if (a == 0) {
            std::string msg = NativeIntegerT::toString(m_value) + " does not have a ModInverse using " +
                              NativeIntegerT::toString(mod.m_value);
            OPENFHE_THROW(lbcrypto::math_error, msg);
        }
        if (modulus == 1)
            return NativeIntegerT();

        SignedNativeInt y{0};
        SignedNativeInt x{1};
        while (a > 1) {
            auto t  = modulus;
            auto q  = a / t;
            modulus = a % t;
            a       = t;
            t       = y;
            y       = x - q * y;
            x       = t;
        }
        if (x < 0)
            x += mod.m_value;
        return {x};
    }

    /**
   * Modulus inverse operation. In-place variant.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
    NativeIntegerT& ModInverseEq(const NativeIntegerT& mod) {
        return *this = this->NativeIntegerT::ModInverse(mod);
    }

    /**
   * Left shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    NativeIntegerT LShift(usshort shift) const {
        return {m_value << shift};
    }

    /**
   * Left shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    NativeIntegerT& LShiftEq(usshort shift) {
        return *this = m_value << shift;
    }

    /**
   * Right shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    NativeIntegerT RShift(usshort shift) const {
        return {m_value >> shift};
    }

    /**
   * Right shift operation. In-place variant.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    NativeIntegerT& RShiftEq(usshort shift) {
        return *this = m_value >> shift;
    }

    /**
   * Compares the current NativeIntegerT to NativeIntegerT a.
   *
   * @param a is the NativeIntegerT to be compared with.
   * @return  -1 for strictly less than, 0 for equal to and 1 for strictly
   * greater than conditons.
   */
    int Compare(const NativeIntegerT& a) const {
        return (m_value < a.m_value) ? -1 : (m_value > a.m_value) ? 1 : 0;
    }

    /**
   * Converts the value to an int.
   *
   * @return the int representation of the value as usint.
   */
    template <typename T = NativeInt, std::enable_if_t<std::is_integral_v<T>, bool> = true>
    constexpr T ConvertToInt() const noexcept {
        // static_assert(sizeof(T) >= sizeof(m_value), "ConvertToInt(): Narrowing Conversion");
        return static_cast<T>(m_value);
    }

    /**
   * Converts the value to an double.
   *
   * @return double representation of the value.
   */
    constexpr double ConvertToDouble() const noexcept {
        return static_cast<double>(m_value);
    }

    /**
   * Convert a string representation of a binary number to a NativeIntegerT.
   *
   * @param bitString the binary num in string.
   * @return the binary number represented as a big binary int.
   */
    static NativeIntegerT FromBinaryString(const std::string& bitString) {
        if (bitString.length() > NativeIntegerT::MaxBits())
            OPENFHE_THROW(lbcrypto::math_error, "Bit string is too long to fit in an intnat");
        NativeInt v{0};
        for (size_t i = 0; i < bitString.length(); ++i) {
            auto n = bitString[i] - '0';
            if (n < 0 || n > 1)
                OPENFHE_THROW(lbcrypto::math_error, "Bit string must contain only 0 or 1");
            v = (v << 1) | static_cast<NativeInt>(n);
        }
        return {v};
    }

    /**
   * Returns the MSB location of the value.
   *
   * @return the index of the most significant bit.
   */
    usint GetMSB() const {
        return lbcrypto::GetMSB(m_value);
    }

    /**
   * Get the number of digits using a specific base - support for arbitrary
   * base may be needed.
   *
   * @param base is the base with which to determine length in.
   * @return the length of the representation in a specific base.
   */

    // TODO: only base 2?
    usint GetLengthForBase(usint base) const {
        return NativeIntegerT::GetMSB();
    }

    /**
   * Get a specific digit at "digit" index; big integer is seen as an array of
   * digits, where a 0 <= digit < base Warning: only power-of-2 bases are
   * currently supported. Example: for number 83, index 2 and base 4 we have:
   *
   *                         index:0,1,2,3
   * 83 --base 4 decomposition--> (3,0,1,1) --at index 2--> 1
   *
   * The return number is 1.
   *
   * @param index is the "digit" index of the requested digit
   * @param base is the base with which to determine length in.
   * @return is the requested digit
   */

    // TODO: * i to << i
    usint GetDigitAtIndexForBase(usint index, usint base) const {
        usint DigitLen = ceil(log2(base));
        usint digit    = 0;
        usint newIndex = 1 + (index - 1) * DigitLen;
        for (usint i = 1; i < base; i <<= 1) {
            digit += GetBitAtIndex(newIndex++) * i;
        }
        return digit;
    }

    /**
   * Gets the bit at the specified index.
   *
   * @param index is the index of the bit to get.
   * @return resulting bit.
   */
    uschar GetBitAtIndex(usint index) const {
        if (index == 0)
            OPENFHE_THROW(lbcrypto::math_error, "Zero index in GetBitAtIndex");
        return static_cast<uschar>((m_value >> (index - 1)) & 0x1);
    }

    /**
   * A zero allocator that is called by the Matrix class.
   * It is used to initialize a Matrix of NativeIntegerT objects.
   */
    static constexpr NativeIntegerT Allocator() noexcept {
        return NativeIntegerT();
    }

    // STRINGS & STREAMS

    /**
   * Stores the based 10 equivalent/Decimal value of the NativeIntegerT in a
   * string object and returns it.
   *
   * @return value of this NativeIntegerT in base 10 represented as a string.
   */
    std::string ToString() const {
        return toString(m_value);
    }

    static const std::string IntegerTypeName() {
        return "UBNATINT";
    }

    /**
   * Console output operation.
   *
   * @param os is the std ostream object.
   * @param ptr_obj is NativeIntegerT to be printed.
   * @return is the ostream object.
   */
    friend std::ostream& operator<<(std::ostream& os, const NativeIntegerT& ptr_obj) {
        os << ptr_obj.ToString();
        return os;
    }

    template <class Archive, typename T = void>
    typename std::enable_if_t<std::is_same_v<NativeInt, U64BITS> || std::is_same_v<NativeInt, U32BITS>, T> load(
        Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(lbcrypto::deserialize_error, "serialized object version " + std::to_string(version) +
                                                           " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", m_value));
    }

#if defined(HAVE_INT128)
    template <class Archive>
    typename std::enable_if_t<std::is_same_v<NativeInt, U128BITS> && !cereal::traits::is_text_archive<Archive>::value,
                              void>
    load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(lbcrypto::deserialize_error, "serialized object version " + std::to_string(version) +
                                                           " is from a later version of the library");
        }
        // get an array with 2 unint64_t values for m_value
        uint64_t vec[2];
        ar(::cereal::binary_data(vec, sizeof(vec)));  // 2*8 - size in bytes
        m_value = vec[1];                             // most significant word
        m_value <<= 64;
        m_value += vec[0];  // least significant word
    }

    template <class Archive>
    typename std::enable_if_t<std::is_same_v<NativeInt, U128BITS> && cereal::traits::is_text_archive<Archive>::value,
                              void>
    load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(lbcrypto::deserialize_error, "serialized object version " + std::to_string(version) +
                                                           " is from a later version of the library");
        }
        // get an array with 2 unint64_t values for m_value
        uint64_t vec[2];
        ar(::cereal::make_nvp("i", vec));
        m_value = vec[1];  // most significant word
        m_value <<= 64;
        m_value += vec[0];  // least significant word
    }
#endif

    template <class Archive, typename T = void>
    typename std::enable_if_t<std::is_same_v<NativeInt, U64BITS> || std::is_same<NativeInt, U32BITS>::value, T> save(
        Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", m_value));
    }

#if defined(HAVE_INT128)
    template <class Archive>
    typename std::enable_if_t<std::is_same_v<NativeInt, U128BITS> && !cereal::traits::is_text_archive<Archive>::value,
                              void>
    save(Archive& ar, std::uint32_t const version) const {
        // save 2 unint64_t values instead of uint128_t
        constexpr U128BITS mask = (static_cast<U128BITS>(1) << 64) - 1;
        uint64_t vec[2];
        vec[0] = m_value & mask;  // least significant word
        vec[1] = m_value >> 64;   // most significant word
        ar(::cereal::binary_data(vec, sizeof(vec)));
    }

    template <class Archive>
    typename std::enable_if_t<std::is_same_v<NativeInt, U128BITS> && cereal::traits::is_text_archive<Archive>::value,
                              void>
    save(Archive& ar, std::uint32_t const version) const {
        // save 2 unint64_t values instead of uint128_t
        constexpr U128BITS mask = (static_cast<U128BITS>(1) << 64) - 1;
        uint64_t vec[2];
        vec[0] = m_value & mask;  // least significant word
        vec[1] = m_value >> 64;   // most significant word
        ar(::cereal::make_nvp("i", vec));
    }
#endif

    std::string SerializedObjectName() const {
        return "NATInteger";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

    static constexpr usint MaxBits() noexcept {
        return m_uintBitLength;
    }

    static constexpr bool IsNativeInt() noexcept {
        return true;
    }

private:
    // Computes res -= a;
    static void SubtractD(typeD& res, const typeD& a) {
        if (res.lo < a.lo) {
            res.lo += m_uintMax + 1 - a.lo;
            res.hi--;
        }
        else {
            res.lo -= a.lo;
        }
        res.hi -= a.hi;
    }

    /**
   * Right shifts a typeD integer by a specific number of bits
   * and stores the result as a single-word integer.
   *
   * @param &x double-word input
   * @param shift the number of bits to shift by
   * @return the result of right-shifting
   */
    static NativeInt RShiftD(const typeD& x, int64_t shift) {
        return (x.lo >> shift) | (x.hi << (NativeIntegerT::MaxBits() - shift));
    }

    /**
   * Multiplies two single-word integers and stores the result in a
   * typeD data structure.
   *
   * @param a multiplier
   * @param b multiplicand
   * @param &x result of multiplication
   */
    static void MultD(U32BITS a, U32BITS b, typeD& res) {
        U64BITS c{static_cast<U64BITS>(a) * b};
        res.hi = static_cast<U32BITS>(c >> 32);
        res.lo = static_cast<U32BITS>(c);
    }

    static void MultD(U64BITS a, U64BITS b, typeD& res) {
#if defined(__x86_64__)
    #if defined(HAVE_INT128)
        U128BITS c{static_cast<U128BITS>(a) * b};
        res.hi = static_cast<U64BITS>(c >> 64);
        res.lo = static_cast<U64BITS>(c);
    #else
        // clang-format off
    __asm__("mulq %[b]"
            : [ lo ] "=a"(res.lo), [ hi ] "=d"(res.hi)
            : [ a ] "%[lo]"(a), [ b ] "rm"(b)
            : "cc");
                // clang-format on
    #endif
#elif defined(__aarch64__)
        typeD x;
        x.hi = 0;
        x.lo = a;
        U64BITS y(b);
        res.lo = x.lo * y;
        asm("umulh %0, %1, %2\n\t" : "=r"(res.hi) : "r"(x.lo), "r"(y));
        res.hi += x.hi * y;
#elif defined(__arm__)  // 32 bit processor
        uint64_t wres(0), wa(a), wb(b);
        wres   = wa * wb;
        res.hi = wres >> 32;
        res.lo = (uint32_t)wres & 0xFFFFFFFF;
#elif __riscv
        U128BITS wres(0), wa(a), wb(b);
        wres   = wa * wb;
        res.hi = (uint64_t)(wres >> 64);
        res.lo = (uint64_t)wres;
#elif defined(__EMSCRIPTEN__)  // web assembly
        U64BITS a1 = a >> 32;
        U64BITS a2 = (uint32_t)a;
        U64BITS b1 = b >> 32;
        U64BITS b2 = (uint32_t)b;

        // use schoolbook multiplication
        res.hi            = a1 * b1;
        res.lo            = a2 * b2;
        U64BITS lowBefore = res.lo;

        U64BITS p1   = a2 * b1;
        U64BITS p2   = a1 * b2;
        U64BITS temp = p1 + p2;
        res.hi += temp >> 32;
        res.lo += U64BITS((uint32_t)temp) << 32;

        // adds the carry to the high word
        if (lowBefore > res.lo)
            res.hi++;

        // if there is an overflow in temp, add 2^32
        if ((temp < p1) || (temp < p2))
            res.hi += (U64BITS)1 << 32;
#else
    #error Architecture not supported for MultD()
#endif
    }

#if defined(HAVE_INT128)
    static void MultD(U128BITS a, U128BITS b, typeD& res) {
        static constexpr U128BITS masklo = (static_cast<U128BITS>(1) << 64) - 1;
        static constexpr U128BITS onehi  = static_cast<U128BITS>(1) << 64;

        U128BITS a1{a >> 64};
        U128BITS a2{a & masklo};
        U128BITS b1{b >> 64};
        U128BITS b2{b & masklo};
        U128BITS a1b2{a1 * b2};
        U128BITS a2b1{a2 * b1};
        U128BITS tmp{a1b2 + a2b1};
        U128BITS lo{a2 * b2};

        res = {a1 * b1, lo};
        res.lo += tmp << 64;
        if (lo > res.lo)
            ++res.hi;
        if ((tmp < a1b2) || (tmp < a2b1))
            res.hi += onehi;
        res.hi += tmp >> 64;
    }
#endif

    /**
   * Multiplies two single-word integers and stores the high word of the
   * result
   *
   * @param a multiplier
   * @param b multiplicand
   * @return the high word of the result
   */
    static NativeInt MultDHi(NativeInt a, NativeInt b) {
        typeD x;
        MultD(a, b, x);
        return x.hi;
    }

    /**
   * Converts a double-word integer from typeD representation
   * to DNativeInt.
   *
   * @param &x double-word input
   * @return the result as DNativeInt
   */
    static DNativeInt GetD(const typeD& x) {
        return (DNativeInt(x.hi) << NativeIntegerT::MaxBits()) | x.lo;
    }

    static std::string toString(uint32_t value) noexcept {
        return std::to_string(value);
    }

    static std::string toString(uint64_t value) noexcept {
        return std::to_string(value);
    }

#if defined(HAVE_INT128)
    // TODO
    static std::string toString(uint128_t value) noexcept {
        constexpr size_t maxChars = 15;
        constexpr uint128_t divisor{0x38d7ea4c68000};  // 10**15
        std::string tmp(46, '0');
        auto msd_it = tmp.end() - 1;
        auto it     = tmp.end();
        for (auto i = 3; i != 0; --i, it -= maxChars) {
            auto part = static_cast<uint64_t>(value % divisor);
            value /= divisor;
            if (part) {
                auto s{std::to_string(part)};
                msd_it = it - s.size();
                tmp.replace(it - s.size(), it, s.begin(), s.end());
            }
        }
        return std::string(msd_it, tmp.end());
    }
#endif

    template <typename T = NativeInt>
    static void ModMu(typeD& prod, NativeIntegerT& a, const T& mv, const T& mu, int64_t n,
                      typename std::enable_if_t<!std::is_same_v<T, DNativeInt>, bool> = true) {
        prod = {0, a.m_value};
        MultD(RShiftD(prod, n), mu, prod);
        a.m_value -= static_cast<NativeInt>((GetD(prod) >> n + 7) * mv);
        if (a.m_value >= mv)
            a.m_value -= mv;
    }

    template <typename T = NativeInt>
    static void ModMu(typeD& prod, NativeIntegerT& a, const T& mv, const T& mu, int64_t n,
                      typename std::enable_if_t<std::is_same_v<T, DNativeInt>, bool> = true) {
        prod = {0, a.m_value};
        MultD(RShiftD(prod, n), mu, prod);
        MultD(RShiftD(prod, n + 7), mv, prod);
        a.m_value -= prod.lo;
        if (a.m_value >= mv)
            a.m_value -= mv;
    }
};

// helper template to stream vector contents provided T has an stream operator<<
template <typename T>
std::ostream& operator<<(std::ostream& os, const std::vector<T>& v) {
    os << "[";
    //    for (const auto& i : v)
    for (auto&& i : v)
        os << " " << i;
    os << " ]";
    return os;
}
// to stream internal representation
template std::ostream& operator<< <uint64_t>(std::ostream& os, const std::vector<uint64_t>& v);

}  // namespace intnat

#endif  // LBCRYPTO_MATH_HAL_INTNAT_UBINTNAT_H
