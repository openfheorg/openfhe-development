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
  This file contains the main class for unsigned big integers: ubint. Big integers are
  represented as arrays of machine native unsigned integers. The native integer type is
  supplied as a template parameter. Currently implementation based on uint32_t and uint64_t is
  supported. a native double the base integer size is also needed.
 */

#include "config_core.h"
#ifdef WITH_BE4

    #ifndef LBCRYPTO_MATH_HAL_BIGINTDYN_UBINTDYN_H
        #define LBCRYPTO_MATH_HAL_BIGINTDYN_UBINTDYN_H

        #include "math/hal/basicint.h"
        #include "math/hal/integer.h"
        #include "math/nbtheory.h"

        #include "utils/exception.h"
        #include "utils/inttypes.h"
        #include "utils/serializable.h"
        #include "utils/utilities.h"

        // #include <fstream>
        #include <functional>
        #include <iostream>
        #include <limits>
        // #include <memory>
        #include <string>
        #include <type_traits>
        // #include <typeinfo>
        #include <utility>
        #include <vector>

        // clang-format off
        // TODO: fix shifting issue when limb_t == Dlimb_t
        #if (NATIVEINT >= 64 && defined(HAVE_INT128))
            using expdtype = uint64_t;
        #else
            using expdtype = uint32_t;
        #endif
    // clang-format on

        #define _SECURE_SCL 0  // to speed up VS
        #define NO_BARRETT     // currently barrett is slower than mod

namespace bigintdyn {

template <typename limb_t>
class ubint;

/** Define the mapping for ExpBigInteger (experimental) */
using xubint     = ubint<expdtype>;
using BigInteger = xubint;

template <class ubint_el_t>
class mubintvec;

/**
 * @brief Struct to find log 2 value of N.
 * Used in preprocessing of ubint to determine bitwidth.
 */
template <usint N>
struct Log2 {
    static constexpr usint value = 1 + Log2<N / 2>::value;
};
template <>
struct Log2<2> {
    static constexpr usint value = 1;
};

// @brief A pre-computed constant of Log base 2 of 10.
// constexpr double LOG2_10 = 3.32192809489;

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

template <typename limb_t>
class ubint final : public lbcrypto::BigIntegerInterface<ubint<limb_t>> {
private:
    // variable that stores the MOST SIGNIFICANT BIT position in the
    usint m_MSB{0};
    // vector storing the native integers. stored little endian
    std::vector<limb_t> m_value{0};
    // variable to store the maximum value of the limb data type
    static constexpr limb_t m_MaxLimb{std::numeric_limits<limb_t>::max()};
    // variable to store the bitlength of the limb data type
    static constexpr usint m_limbBitLength{sizeof(limb_t) * 8};
    // variable to store the log2 of the number of bits in the limb data type
    static constexpr usint m_log2LimbBitLength{Log2<sizeof(limb_t) * 8>::value};

    friend class mubintvec<ubint<limb_t>>;

public:
    using Integer  = limb_t;
    using Slimb_t  = typename DataTypes<limb_t>::SignedType;
    using Dlimb_t  = typename DataTypes<limb_t>::DoubleType;
    using SDlimb_t = typename DataTypes<limb_t>::SignedDoubleType;

    ubint() = default;

    explicit operator bool() noexcept {
        return m_MSB != 0;
    }

    /**
   * Copy constructor.
   * @param &val is the ubint to be copied.
   */
    ubint(const ubint& val) noexcept : m_MSB{val.m_MSB}, m_value{val.m_value} {}

    ubint(const std::vector<limb_t>& v) noexcept : m_value{v} {
        this->ubint::NormalizeLimbs();
    }

    /**
   * Move constructor.
   * @param &&val is the ubint to be copied.
   */
    ubint(ubint&& val) noexcept : m_MSB{std::move(val.m_MSB)}, m_value{std::move(val.m_value)} {}

    ubint(std::vector<limb_t>&& v) noexcept : m_value{std::move(v)} {
        this->ubint::NormalizeLimbs();
    }

    /**
   * Constructor from a string.
   * @param &strval is the initial integer represented as a string.
   */
    explicit ubint(const std::string& strval) {
        this->ubint::SetValue(strval);
    }
    explicit ubint(const char* strval) {
        this->ubint::SetValue(std::string(strval));
    }
    explicit ubint(const char strval) : ubint(limb_t(strval - '0')) {}

    /**
   * Constructor from an unsigned integer.
   * @param val is the initial integer represented as a uint64_t.
   */
    template <typename T, std::enable_if_t<std::is_integral_v<T>, bool> = true>
    ubint(T val) : m_MSB{lbcrypto::GetMSB(val)}, m_value{limb_t(val)} {
        if constexpr (sizeof(T) > sizeof(limb_t)) {
            if ((val >>= m_limbBitLength) > 0) {
                m_value.resize(ubint::MSBToLimbs(m_MSB));
                for (size_t i{1}; i < m_value.size(); ++i, val >>= m_limbBitLength)
                    m_value[i] = limb_t(val);
            }
        }
    }

    template <typename T, std::enable_if_t<std::is_floating_point_v<T>, bool> = true>
    ubint(T val) = delete;

    template <typename T, std::enable_if_t<!std::is_integral_v<T> && !std::is_floating_point_v<T>, bool> = true>
    ubint(T val) : ubint(BasicInteger(val)) {}

    /**
   * Copy assignment operator
   *
   * @param &val is the ubint to be assigned from.
   * @return assigned ubint ref.
   */
    ubint& operator=(const ubint& val) noexcept {
        m_MSB   = val.m_MSB;
        m_value = val.m_value;
        return *this;
    }

    ubint& operator=(const limb_t& val) noexcept {
        m_MSB = lbcrypto::GetMSB(val);
        m_value.resize(1);
        m_value[0] = val;
        return *this;
    }

    ubint& operator=(ubint&& val) noexcept {
        if (this != &val) {
            m_MSB   = std::move(val.m_MSB);
            m_value = std::move(val.m_value);
        }
        return *this;
    }

    /**
   * Assignment operator for all other types that have not already got their own
   * assignment operators.
   * @param &val is the value to be assign from
   * @return the assigned BigInteger ref.
   */
    template <typename T, std::enable_if_t<!std::is_same_v<T, const ubint>, bool> = true>
    ubint& operator=(T val) {
        return *this = ubint(val);
    }

    /**
   * Basic set method for setting the value of a ubint
   * @param strval is the string representation of the ubint to be copied.
   */
    void SetValue(const std::string& strval);

    /**
   * Basic set method for setting the value of a ubint
   * @param val is the ubint representation of the ubint to be assigned.
   */
    void SetValue(const ubint& val) noexcept {
        m_MSB   = val.m_MSB;
        m_value = val.m_value;
    }

    void SetIdentity() noexcept {
        m_MSB = 1;
        m_value.resize(1);
        m_value[0] = 1;
    }

    /**
   * Addition operation.
   *
   * @param &b is the value to add.
   * @return result of the addition operation.
   */
    ubint Add(const ubint& b) const;
    ubint& AddEq(const ubint& b);

    /**
   * Subtraction operation.
   *
   * @param &b is the value to subtract.
   * @return is the result of the subtraction operation.
   */
    ubint Sub(const ubint& b) const;
    ubint& SubEq(const ubint& b);

    // this is a negation operator which really doesn't make sense for ubint
    // TODO: returns zero due to saturated subtraction
    ubint operator-() const {
        // return ubint().Sub(*this);
        return ubint();
    }

    /**
   * Multiplication operation.
   *
   * @param &b is the value to multiply with.
   * @return is the result of the multiplication operation.
   */
    ubint Mul(const ubint& b) const;
    ubint& MulEq(const ubint& b) {
        return *this = this->ubint::Mul(b);
    }

    /**
   * Division operation.
   *
   * @param &b is the value to divide by.
   * @return is the result of the division operation.
   */
    ubint DividedBy(const ubint& b) const;
    ubint& DividedByEq(const ubint& b);

    /**
   * Exponentiation operation. Returns x^p.
   *
   * @param p the exponent.
   * @return is the result of the exponentiation operation.
   */
    ubint Exp(usint p) const;
    ubint& ExpEq(usint p) {
        return *this = this->ubint::Exp(p);
    }

    /**
   * Multiply and Rounding operation. Returns [x*p/q] where [] is the rounding
   * operation.
   *
   * @param &p is the numerator to be multiplied.
   * @param &q is the denominator to be divided.
   * @return is the result of multiply and round operation.
   */
    ubint MultiplyAndRound(const ubint& p, const ubint& q) const;
    ubint& MultiplyAndRoundEq(const ubint& p, const ubint& q) {
        return *this = this->ubint::MultiplyAndRound(p, q);
    }

    /**
   * Divide and Rounding operation. Returns [x/q] where [] is the rounding
   * operation.
   *
   * @param &q is the denominator to be divided.
   * @return is the result of divide and round operation.
   */
    ubint DivideAndRound(const ubint& q) const;
    ubint& DivideAndRoundEq(const ubint& q) {
        return *this = this->ubint::DivideAndRound(q);
    }

    /**
   * Naive modulus operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus operation.
   */
    ubint Mod(const ubint& modulus) const;
    ubint& ModEq(const ubint& modulus);

    /**
   * Pre-computes the mu factor that is used in Barrett modulo reduction
   *
   * @return the value of mu
   */
    ubint ComputeMu() const {
        return (ubint(1) << (2 * m_MSB + 3)).DividedBy(*this);
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
    template <typename T = limb_t>
    ubint Mod(const ubint& modulus, const ubint& mu,
              typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) const {
        return this->ubint::Mod(modulus);
    }

    template <typename T = limb_t>
    ubint Mod(const ubint& modulus, const ubint& mu,
              typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) const {
        if (*this < modulus)
            return *this;
        int n(modulus.m_MSB);
        int alpha(n + 3);
        int beta(-2);
        ubint q(mu * this->ubint::RShift(n + beta));
        q >>= alpha - beta;
        ubint z(this->ubint::Sub(q * modulus));
        if (z >= modulus)
            return z.Sub(modulus);
        return z;
    }

    template <typename T = limb_t>
    ubint& ModEq(const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) {
        return this->ubint::ModEq(modulus);
    }

    template <typename T = limb_t>
    ubint& ModEq(const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) {
        if (*this < modulus)
            return *this;
        int n(modulus.m_MSB);
        int alpha(n + 3);
        int beta(-2);
        ubint q(mu * this->ubint::RShift(n + beta));
        q >>= alpha - beta;
        this->ubint::SubEq(q * modulus);
        if (*this >= modulus)
            return this->ubint::SubEq(modulus);
        return *this;
    }

    /**
   * Modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    ubint ModAdd(const ubint& b, const ubint& modulus) const;
    ubint& ModAddEq(const ubint& b, const ubint& modulus);

    /**
   * Modulus addition where operands are < modulus.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus addition operation.
   */
    ubint ModAddFast(const ubint& b, const ubint& modulus) const;
    ubint& ModAddFastEq(const ubint& b, const ubint& modulus);

    /**
   * Barrett modulus addition operation.
   *
   * @param &b is the scalar to add.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus addition operation.
   */
    template <typename T = limb_t>
    ubint ModAdd(const ubint& b, const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) const {
        return b.ModAdd(*this, modulus);
    }

    template <typename T = limb_t>
    ubint ModAdd(const ubint& b, const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) const {
        return b.Add(*this).Mod(modulus, mu);
    }

    template <typename T = limb_t>
    ubint& ModAddEq(const ubint& b, const ubint& modulus, const ubint& mu,
                    typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) {
        return this->ubint::ModAddEq(b, modulus);
    }

    template <typename T = limb_t>
    ubint& ModAddEq(const ubint& b, const ubint& modulus, const ubint& mu,
                    typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) {
        return *this = b.Add(*this).Mod(modulus, mu);
    }

    /**
   * Modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    ubint ModSub(const ubint& b, const ubint& modulus) const;
    ubint& ModSubEq(const ubint& b, const ubint& modulus);

    /**
   * Modulus subtraction where operands are < modulus.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus subtraction operation.
   */
    ubint ModSubFast(const ubint& b, const ubint& modulus) const;
    ubint& ModSubFastEq(const ubint& b, const ubint& modulus);

    /**
   * Barrett modulus subtraction operation.
   *
   * @param &b is the scalar to subtract.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus subtraction operation.
   */
    template <typename T = limb_t>
    ubint ModSub(const ubint& b, const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) const {
        return this->ubint::ModSub(b, modulus);
    }

    template <typename T = limb_t>
    ubint ModSub(const ubint& b, const ubint& modulus, const ubint& mu,
                 typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) const {
        auto bv(b);
        auto av(*this);
        if (bv >= modulus)
            bv.ModEq(modulus, mu);
        if (av >= modulus)
            av.ModEq(modulus, mu);
        if (av < bv)
            av = modulus.Add(av);
        return av.SubEq(bv);
    }

    template <typename T = limb_t>
    ubint& ModSubEq(const ubint& b, const ubint& modulus, const ubint& mu,
                    typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) {
        return this->ubint::ModSubEq(b, modulus);
    }

    template <typename T = limb_t>
    ubint& ModSubEq(const ubint& b, const ubint& modulus, const ubint& mu,
                    typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) {
        auto bv(b);
        if (bv >= modulus)
            bv.ModEq(modulus, mu);
        if (*this >= modulus)
            this->ubint::ModEq(modulus, mu);
        if (*this < bv)
            *this = modulus.Add(*this);
        return this->ubint::SubEq(bv);
    }

    /**
   * Modulus multiplication operation.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    template <typename T = limb_t>
    ubint ModMul(const ubint& b, const ubint& modulus,
                 typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) const {
        auto bv(b);
        auto av(*this);
        if (bv >= modulus)
            bv.ModEq(modulus);
        if (av >= modulus)
            av.ModEq(modulus);
        return av.ModMulFast(bv, modulus);
    }

    template <typename T = limb_t>
    ubint ModMul(const ubint& b, const ubint& modulus,
                 typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) const {
        return b.ModMul(*this, modulus, modulus.ComputeMu());
    }

    template <typename T = limb_t>
    ubint& ModMulEq(const ubint& b, const ubint& modulus,
                    typename std::enable_if_t<!std::is_same_v<T, Dlimb_t>, bool> = true) {
        auto bv(b);
        if (bv >= modulus)
            bv.ModEq(modulus);
        if (*this >= modulus)
            this->ubint::ModEq(modulus);
        return *this = bv.ModMulFast(*this, modulus);
    }

    template <typename T = limb_t>
    ubint& ModMulEq(const ubint& b, const ubint& modulus,
                    typename std::enable_if_t<std::is_same_v<T, Dlimb_t>, bool> = true) {
        return *this = b.ModMul(*this, modulus, modulus.ComputeMu());
    }

    /**
   * Barrett modulus multiplication.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    ubint ModMul(const ubint& b, const ubint& modulus, const ubint& mu) const {
        auto bv(b);
        auto av(*this);
        if (bv >= modulus)
            bv.ModEq(modulus, mu);
        if (av >= modulus)
            av.ModEq(modulus, mu);
        return av.Mul(bv).Mod(modulus, mu);
    }

    ubint& ModMulEq(const ubint& b, const ubint& modulus, ubint& mu) {
        auto bv(b);
        if (bv >= modulus)
            bv.ModEq(modulus, mu);
        if (*this >= modulus)
            this->ubint::ModEq(modulus, mu);
        return *this = bv.Mul(*this).Mod(modulus, mu);
    }

    /**
   * Modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus multiplication operation.
   */
    ubint ModMulFast(const ubint& b, const ubint& modulus) const;
    ubint& ModMulFastEq(const ubint& b, const ubint& modulus) {
        return *this = this->ubint::ModMulFast(b, modulus);
    }

    /**
   * Barrett modulus multiplication that assumes the operands are < modulus.
   *
   * @param &b is the scalar to multiply.
   * @param &modulus is the modulus to perform operations with.
   * @param &mu is the Barrett value.
   * @return is the result of the modulus multiplication operation.
   */
    ubint ModMulFast(const ubint& b, const ubint& modulus, const ubint& mu) const {
        return b.Mul(*this).Mod(modulus, mu);
    }

    ubint& ModMulFastEq(const ubint& b, const ubint& modulus, const ubint& mu) {
        return *this = b.Mul(*this).Mod(modulus, mu);
    }

    ubint ModMulFastConst(const ubint& b, const ubint& modulus, const ubint& bInv) const {
        OPENFHE_THROW("ModMulFastConst is not implemented for backend 4");
    }
    ubint& ModMulFastConstEq(const ubint& b, const ubint& modulus, const ubint& bInv) {
        OPENFHE_THROW("ModMulFastConstEq is not implemented for backend 4");
    }

    /**
   * Modulus exponentiation operation. Square-and-multiply algorithm is used.
   *
   * @param &b is the scalar to exponentiate at all locations.
   * @param &modulus is the modulus to perform operations with.
   * @return is the result of the modulus exponentiation operation.
   */
    ubint ModExp(const ubint& b, const ubint& modulus) const;
    ubint& ModExpEq(const ubint& b, const ubint& modulus) {
        return *this = this->ubint::ModExp(b, modulus);
    }

    /**
   * Modulus inverse operation.
   *
   * @param &modulus is the modulus to perform.
   * @return is the result of the modulus inverse operation.
   */
    ubint ModInverse(const ubint& modulus) const;
    ubint& ModInverseEq(const ubint& modulus) {
        return *this = this->ubint::ModInverse(modulus);
    }

    /**
   * Left shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    ubint LShift(usshort shift) const;
    ubint& LShiftEq(usshort shift);

    /**
   * Right shift operation.
   *
   * @param shift # of bits.
   * @return result of the shift operation.
   */
    ubint RShift(usshort shift) const;
    ubint& RShiftEq(usshort shift);

    /**
   * Compares the current ubint to ubint a.
   *
   * @param a is the ubint to be compared with.
   * @return  -1 for strictly less than, 0 for equal to and 1 for strictly
   * greater than conditons.
   */
    int Compare(const ubint& a) const noexcept {
        if (m_MSB < a.m_MSB)
            return -1;
        if (m_MSB > a.m_MSB)
            return 1;
        for (int i = m_value.size() - 1; i >= 0; --i) {
            if (m_value[i] < a.m_value[i])
                return -1;
            if (m_value[i] > a.m_value[i])
                return 1;
        }
        return 0;
    }

    template <typename T = BasicInteger>
    T ConvertToInt() const noexcept {
        constexpr usint limblen{sizeof(T) * 8};
        if constexpr (m_limbBitLength >= limblen) {
            return static_cast<T>(m_value[0]);
        }
        if constexpr (m_limbBitLength < limblen) {
            auto ceilInt = MSBToLimbs(limblen > m_MSB ? m_MSB : limblen);
            auto result  = static_cast<T>(m_value[0]);
            for (usint i{1}; i < ceilInt; ++i)
                result |= static_cast<T>(m_value[i]) << (i * m_limbBitLength);
            return result;
        }
    }

    /**
   * Converts the value to a float
   * if the ubint is uninitialized error is thrown
   * if the ubint is larger than the max value representable
   * or if conversion fails, and error is reported to cerr
   */
    float ConvertToFloat() const;
    double ConvertToDouble() const;
    long double ConvertToLongDouble() const;

    /**
   * Convert a string representation of a binary number to a ubint.
   * @param bitString the binary num in string.
   * @return the  number represented as a ubint.
   */
    static ubint FromBinaryString(const std::string& bitString);

    /**
   * Returns the MSB location of the value.
   * @return the index of the most significant bit.
   */
    usint GetMSB() const {
        return m_MSB;
    }

    /**
   * Returns the size of the underlying vector of Limbs
   * @return the size
   */
    size_t GetNumberOfLimbs() const {
        return m_value.size();
    }

    /**
   * Tests whether the ubint is a power of 2.
   *
   * @param x is the value to check.
   * @return true if the input is a power of 2, false otherwise.
   */
    /*
    static bool isPowerOfTwo(const ubint& x) {
        if (x.m_MSB == 0)
            return false;
        const size_t limbs{x.m_value.size() - 1};
        for (size_t i = 0; i < limbs; ++i) {
            if (0 != x.m_value[i])
                return false;
        }
        auto msb{lbcrypto::GetMSB(x.m_value[limbs]) - 1};
        auto mask{(1 << msb) - 1};
        return (0 == (x.m_value[limbs] & mask));
    }
*/

    /**
   * Get the number of digits using a specific base - support for arbitrary base
   * may be needed.
   *
   * @param base is the base with which to determine length in.
   * @return the length of the representation in a specific base.
   */

    // TODO hardcoded for base 2?
    usint GetLengthForBase(usint base) const {
        return GetMSB();
    }

    /**
   * Get the number of digits using a specific base.
   * Warning: only power-of-2 bases are currently supported.
   * Example: for number 83, index 2 and base 4 we have:
   *
   *                         index:0,1,2,3
   * 83 --base 4 decomposition--> (3,0,1,1) --at index 2--> 1
   *
   * The return number is 1.
   *
   * @param index is the location to return value from in the specific base.
   * @param base is the base with which to determine length in.
   * @return the length of the representation in a specific base.
   */
    usint GetDigitAtIndexForBase(usint index, usint base) const;

    /**
   * Gets the bit at the specified index.
   *
   * @param index is the index of the bit to get.
   * @return resulting bit.
   */
    uschar GetBitAtIndex(usint index) const;

    /**
   * A zero allocator that is called by the Matrix class. It is used to
   * initialize a Matrix of ubint objects.
   */
    static ubint Allocator() noexcept {
        return ubint();
    }

    // STRINGS & STREAMS

    /**
   * Stores the based 10 equivalent/Decimal value of the ubint in a string
   * object and returns it.
   *
   * @return value of this ubint in base 10 represented as a string.
   */
    const std::string ToString() const;

    static const std::string IntegerTypeName() {
        if constexpr (std::is_same_v<limb_t, uint32_t>)
            return "UBDYNINT_32";
        if constexpr (std::is_same_v<limb_t, uint64_t>)
            return "UBDYNINT_64";
        if constexpr (std::is_same_v<limb_t, uint128_t>)
            return "UBDYNINT_128";
        static_assert(true, "Configuration Error: ubintdyn.h");
    }

    /**
   * Delivers value of the internal limb storage
   * Used primarily for debugging
   * @return STL vector of uint_type
   */
    std::string GetInternalRepresentation() const {
        std::string ret{};
        for (size_t i = 0; i < m_value.size(); i++) {
            ret += std::to_string(m_value[i]);
            if (i < (m_value.size() - 1)) {
                ret += " ";
            }
        }
        return ret;
    }

    /**
   * ostream output << operator
   * Algorithm used is double and add
   * http://www.wikihow.com/Convert-from-Binary-to-Decimal
   *
   * @param os is the std ostream object.
   * @param ptr_obj is ubint to be printed.
   * @return is the returned ostream object.
   */
    friend std::ostream& operator<<(std::ostream& os, const ubint& ptr_obj) {
        os << ptr_obj.ToString();
        return os;
    }

    /**
   * documentation function, prints sizes of constats.
   */
    static void PrintIntegerConstants() {
        std::cout << "sizeof UINT8_C  " << sizeof(UINT8_C(1)) << std::endl;
        std::cout << "sizeof UINT16_C " << sizeof(UINT16_C(1)) << std::endl;
        std::cout << "sizeof UINT32_C " << sizeof(UINT32_C(1)) << std::endl;
        std::cout << "sizeof UINT64_C " << sizeof(UINT64_C(1)) << std::endl;
        std::cout << "sizeof uint8_t  " << sizeof(uint8_t) << std::endl;
        std::cout << "sizeof uint16_t " << sizeof(uint16_t) << std::endl;
        std::cout << "sizeof uint32_t " << sizeof(uint32_t) << std::endl;
        std::cout << "sizeof uint64_t " << sizeof(uint64_t) << std::endl;
        #if defined(HAVE_INT128)
        // std::cout << "sizeof UINT128_C "<< sizeof (UINT128_C(1)) << std::endl;
        // dbc commented out  unsupported on some machines
        std::cout << "sizeof uint128_t " << sizeof(uint128_t) << std::endl;
        #endif
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("v", m_value));
        ar(::cereal::make_nvp("m", m_MSB));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("v", m_value));
        ar(::cereal::make_nvp("m", m_MSB));
    }

    std::string SerializedObjectName() const {
        return "DYNInteger";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    /**
   * Sets the MSB to the correct value as computed from the internal value.
   */
    void SetMSB() {
        m_MSB = m_limbBitLength * static_cast<usint>(m_value.size() - 1);
        m_MSB += lbcrypto::GetMSB(m_value.back());
    }

    /**
   * Normalize limb storage of the ubint by making sure the most
   * significant limb is non-zero (all higher zero limbs are
   * removed).
   *
   * @return resulting bit.
   */
    void NormalizeLimbs() {
        auto size = m_value.size() - 1;
        while (size > 0 && m_value[size--] == 0)
            m_value.pop_back();
        m_MSB = m_limbBitLength * static_cast<usint>(m_value.size() - 1);
        m_MSB += lbcrypto::GetMSB(m_value.back());
    }

    /**
   * helper function for Div
   * @param defined in ubint.cpp
   */
    void divqr_vect(ubint& q, ubint& r, const ubint& u, const ubint& v) const noexcept;
    void divq_vect(ubint& q, const ubint& u, const ubint& v) const noexcept;
    void divr_vect(ubint& r, const ubint& u, const ubint& v) const noexcept;

    /**
   * function to return the ceiling of the input number divided by
   * the number of bits in the limb data type.  DBC this is to
   * determine how many limbs are needed for an input bitsize.
   * @param Number is the number to be divided.
   * @return the ceiling of Number/(bits in the limb data type)
   */
    static constexpr usint MSBToLimbs(usint msb) noexcept {
        constexpr usint mask{m_limbBitLength - 1};
        if (msb == 0)
            return 1;
        return (msb >> m_log2LimbBitLength) + ((msb & mask) != 0);
    }
};

        #if 0
// stream helper function for vector of objects
template <typename limb_t>
std::ostream &operator<<(std::ostream& os, const std::vector<limb_t>& v) {
  os << "[";
  for (auto&& itr : v)
    os << " " << itr;
  os << " ]";
  return os;
}
        #endif

}  // namespace bigintdyn

    #endif  // LBCRYPTO_MATH_HAL_BIGINTDYN_UBINTDYN_H
#endif
