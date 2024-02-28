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
  This file contains the main class for unsigned big integers: ubint. Big integers are represented as arrays of
  machine native unsigned integers. The native integer type is supplied as a template parameter.
  Currently implementation based on uint32_t and uint64_t is supported. a native double the base integer size is also needed.
 */

#include "config_core.h"
#ifdef WITH_BE4

    #include "math/math-hal.h"

    #include "utils/exception.h"
    #include "utils/inttypes.h"
    #include "utils/serializable.h"

    #include <iostream>
    #include <string>
    #include <vector>

namespace bigintdyn {

// Sum and Carry algorithm with radix 2^m_bitLength.
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Add(const ubint& b) const {
    const ubint* A = this;
    auto sizeA     = m_value.size();
    const ubint* B = &b;
    auto sizeB     = b.m_value.size();
    if (sizeA < sizeB) {
        std::swap(A, B);
        std::swap(sizeA, sizeB);
    }

    if (B->m_MSB == 0)
        return *A;

    std::vector<limb_t> r(sizeA + 1);
    Dlimb_t c{0};
    for (size_t i = 0; i < sizeA; ++i, c >>= m_limbBitLength) {
        auto av = static_cast<Dlimb_t>(A->m_value[i]);
        auto bv = static_cast<Dlimb_t>(i < sizeB ? B->m_value[i] : 0);
        r[i]    = static_cast<limb_t>(c += av + bv);
    }
    r[sizeA] = static_cast<limb_t>(c);
    return ubint(std::move(r));
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::AddEq(const ubint& b) {
    const ubint* A = this;
    auto sizeA     = m_value.size();
    const ubint* B = &b;
    auto sizeB     = B->m_value.size();
    if (sizeA < sizeB) {
        std::swap(A, B);
        std::swap(sizeA, sizeB);
    }

    if (B->m_MSB == 0)
        return *this = *A;

    std::vector<limb_t> r(sizeA + 1);
    Dlimb_t c{0};
    for (size_t i = 0; i < sizeA; ++i, c >>= m_limbBitLength) {
        auto av = static_cast<Dlimb_t>(A->m_value[i]);
        auto bv = static_cast<Dlimb_t>(i < sizeB ? B->m_value[i] : 0);
        r[i]    = static_cast<limb_t>(c += av + bv);
    }
    r[sizeA] = static_cast<limb_t>(c);
    m_value  = std::move(r);
    ubint<limb_t>::NormalizeLimbs();
    return *this;
}

// TODO: convert to vector constructor method
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Sub(const ubint& b) const {
    // return 0 if b is higher than *this as there is no support for negative numbers
    if (*this <= b)
        return ubint();
    ubint result(*this);
    for (size_t i = 0; i < b.m_value.size(); ++i) {
        if (result.m_value[i] < b.m_value[i]) {  // carryover condition need to
                                                 // borrow from higher limbs.
            size_t cntr{i};
            result.m_value[cntr] += (m_MaxLimb - b.m_value[cntr]) + 1;
            // set all the zero limbs to all FFs (propagate the 1)
            while (0 == result.m_value[++cntr])
                result.m_value[cntr] = m_MaxLimb;
            // and eventually borrow 1 from the first nonzero limb we find
            result.m_value[cntr]--;
        }
        else {  // usual subtraction condition
            result.m_value[i] -= b.m_value[i];
        }
    }
    result.NormalizeLimbs();
    return result;
}

// TODO: convert to vector constructor method
template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::SubEq(const ubint& b) {
    if (*this <= b) {
        m_MSB      = 0;
        m_value[0] = 0;
        m_value.resize(1);
        return *this;
    }
    for (size_t i = 0; i < b.m_value.size(); ++i) {
        if (m_value[i] < b.m_value[i]) {
            size_t cntr{i};
            m_value[cntr] += (m_MaxLimb - b.m_value[cntr]) + 1;
            while (0 == m_value[++cntr])
                m_value[cntr] = m_MaxLimb;
            m_value[cntr]--;
        }
        else {
            m_value[i] -= b.m_value[i];
        }
    }
    ubint<limb_t>::NormalizeLimbs();
    return *this;
}

// Multiply operation: usual school book shift and add after multiplication
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Mul(const ubint& b) const {
    if (m_MSB == 0 || b.m_MSB == 0)
        return ubint();
    if (b.m_MSB == 1)
        return *this;
    if (m_MSB == 1)
        return b;

    const ubint* A = this;
    auto aSize     = m_value.size();
    const ubint* B = &b;
    auto bSize     = b.m_value.size();
    if (aSize < bSize) {
        std::swap(A, B);
        std::swap(aSize, bSize);
    }

    ubint ans;
    for (size_t i = 0; i < bSize; ++i) {
        std::vector<limb_t> c(i + aSize + 1);
        Dlimb_t limbb = static_cast<Dlimb_t>(B->m_value[i]);
        Dlimb_t ofl{0};
        for (size_t j = 0; j < aSize; ++j, ofl >>= m_limbBitLength)
            c[i + j] = static_cast<limb_t>(ofl += limbb * A->m_value[j]);
        c[i + aSize] = static_cast<limb_t>(ofl);

        ans = std::move(ans.Add(ubint(std::move(c))));
    }
    return ans;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::DividedBy(const ubint& b) const {
    if (b.m_MSB == 0)
        OPENFHE_THROW("Divisor is zero");
    if (b.m_MSB > m_MSB)
        return ubint();
    if ((b.m_MSB == m_MSB) && (b.m_value.back() == m_value.back()))
        return ubint(1);
    ubint ans;
    divq_vect(ans, *this, b);
    return ans;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::DividedByEq(const ubint& b) {
    if (b.m_MSB == 0)
        OPENFHE_THROW("Divisor is zero");
    if (b.m_MSB > m_MSB) {
        m_MSB = 0;
        m_value.resize(1);
        m_value[0] = 0;
        return *this;
    }
    if ((b.m_MSB == m_MSB) && (b.m_value.back() == m_value.back())) {
        m_MSB = 1;
        m_value.resize(1);
        m_value[0] = 1;
        return *this;
    }
    ubint ans;
    divq_vect(ans, *this, b);
    return *this = std::move(ans);
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Exp(usint p) const {
    if (p == 0)
        return ubint(1);
    if (p == 1)
        return *this;
    ubint tmp{ubint<limb_t>::Exp(p >> 1)};
    tmp = tmp.Mul(tmp);
    if (p & 0x1)
        return tmp.Mul(*this);
    return tmp;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::MultiplyAndRound(const ubint& p, const ubint& q) const {
    if (q.m_MSB == 0)
        OPENFHE_THROW("MultiplyAndRound() Divisor is zero");
    auto t{ubint<limb_t>::Mul(p)};
    ubint halfQ(q >> 1);
    if (t <= halfQ)
        return ubint();
    if ((t.m_MSB == halfQ.m_MSB) || ((t.m_MSB == q.m_MSB) && (t.m_value.back() < q.m_value.back())))
        return ubint(1);
    ubint ans, rv;
    divqr_vect(ans, rv, t, q);
    if (rv > halfQ)
        return ans.Add(ubint(1));
    return ans;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::DivideAndRound(const ubint& q) const {
    if (q.m_MSB == 0)
        OPENFHE_THROW("DivideAndRound() Divisor is zero");
    ubint halfQ(q >> 1);
    if (*this <= halfQ)
        return ubint();
    if ((m_MSB == halfQ.m_MSB) || ((m_MSB == q.m_MSB) && (m_value.back() < q.m_value.back())))
        return ubint(1);
    ubint ans, rv;
    divqr_vect(ans, rv, *this, q);
    if (rv > halfQ)
        return ans.Add(ubint(1));
    return ans;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::Mod(const ubint& modulus) const {
    if (modulus.m_MSB == 0)
        OPENFHE_THROW("Mod() using zero modulus");
    if (*this < modulus)
        return *this;
    if (modulus.m_MSB == 2 && modulus.m_value[0] == 2)
        return ubint(m_value[0] & 0x1);
    ubint ans;
    divr_vect(ans, *this, modulus);
    return ans;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::ModEq(const ubint& modulus) {
    if (modulus.m_MSB == 0)
        OPENFHE_THROW("Mod() using zero modulus");
    if (*this < modulus)
        return *this;
    if (modulus.m_MSB == 2 && modulus.m_value[0] == 2) {
        m_value.resize(1);
        m_value[0] &= 0x1;
        m_MSB = m_value[0];
        return *this;
    }
    ubint ans;
    divr_vect(ans, *this, modulus);
    return *this = std::move(ans);
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModAdd(const ubint& b, const ubint& modulus) const {
    ubint bv(b);
    if (bv >= modulus)
        bv.ModEq(modulus);
    ubint av(*this);
    if (av >= modulus)
        av.ModEq(modulus);
    av = av.Add(bv);
    if (av >= modulus)
        return av.Sub(modulus);
    return av;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::ModAddEq(const ubint& b, const ubint& modulus) {
    ubint bv(b);
    if (bv >= modulus)
        bv.ModEq(modulus);
    if (*this >= modulus)
        ubint<limb_t>::ModEq(modulus);
    *this = bv.Add(*this);
    if (*this >= modulus)
        return ubint<limb_t>::SubEq(modulus);
    return *this;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModAddFast(const ubint& b, const ubint& modulus) const {
    ubint ans(b.Add(*this));
    if (ans >= modulus)
        return ans.Sub(modulus);
    return ans;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::ModAddFastEq(const ubint& b, const ubint& modulus) {
    *this = b.Add(*this);
    if (*this >= modulus)
        return ubint<limb_t>::SubEq(modulus);
    return *this;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModSub(const ubint& b, const ubint& modulus) const {
    auto av(*this);
    auto bv(b);
    if (bv >= modulus)
        bv.ModEq(modulus);
    if (av >= modulus)
        av.ModEq(modulus);
    if (av < bv)
        av = modulus.Add(av);
    return av.Sub(bv);
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::ModSubEq(const ubint& b, const ubint& modulus) {
    auto bv(b);
    if (bv >= modulus)
        bv.ModEq(modulus);
    if (*this >= modulus)
        ubint<limb_t>::ModEq(modulus);
    if (*this < bv)
        *this = modulus.Add(*this);
    return ubint<limb_t>::SubEq(bv);
}

template <typename limb_t>
inline ubint<limb_t> ubint<limb_t>::ModSubFast(const ubint& b, const ubint& modulus) const {
    if (*this < b)
        return modulus.Add(*this).Sub(b);
    return ubint<limb_t>::Sub(b);
}

template <typename limb_t>
inline ubint<limb_t>& ubint<limb_t>::ModSubFastEq(const ubint& b, const ubint& modulus) {
    if (*this < b)
        return *this = std::move(modulus.Add(*this).Sub(b));
    return ubint<limb_t>::SubEq(b);
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModMulFast(const ubint& b, const ubint& modulus) const {
    if (m_MSB == 0 || b.m_MSB == 0)
        return ubint();
    if (b.m_MSB == 1)
        return *this;
    if (m_MSB == 1)
        return b;

    const ubint* A = this;
    auto aSize     = m_value.size();
    const ubint* B = &b;
    auto bSize     = b.m_value.size();
    if (aSize < bSize) {
        std::swap(A, B);
        std::swap(aSize, bSize);
    }

    ubint ans;
    for (size_t i = 0; i < bSize; ++i) {
        std::vector<limb_t> c(i + aSize + 1);
        Dlimb_t limbb = static_cast<Dlimb_t>(B->m_value[i]);
        Dlimb_t ofl{0};
        for (size_t j = 0; j < aSize; ++j, ofl >>= m_limbBitLength)
            c[i + j] = static_cast<limb_t>(ofl += limbb * A->m_value[j]);
        c[i + aSize] = static_cast<limb_t>(ofl);

        ans = std::move(ans.Add(ubint(std::move(c))));
    }
    if (ans >= modulus)
        return ans.Mod(modulus);
    return ans;
}

// Extended Euclid algorithm used to find the multiplicative inverse
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModInverse(const ubint& modulus) const {
    if (m_MSB == 0)
        OPENFHE_THROW("Zero has no inverse");

    ubint second(*this);
    if (second >= modulus)
        second = second.Mod(modulus);
    if (second.m_MSB == 1)
        return second;

    // NORTH ALGORITHM
    ubint first(modulus);
    std::vector<ubint> quotient;
    quotient.reserve(8);  // TODO

    ubint q, mod_back;
    divqr_vect(q, mod_back, first, second);
    quotient.emplace_back(std::move(q));

    if (mod_back.m_MSB == 0) {
        std::string msg = ubint<limb_t>::ToString() + " does not have a ModInverse using " + modulus.ToString();
        OPENFHE_THROW(msg);
    }

    // max number of iterations should be < 2^k where k == min(bitsize(inputs))
    // TODO: consider breaking out of the loop if this limit exceeded.
    //       loop counter would need to be a ubint.
    while (mod_back.m_MSB != 1) {
        first  = second;
        second = mod_back;

        ubint q;
        divqr_vect(q, mod_back, first, second);
        quotient.emplace_back(std::move(q));
    }

    // SOUTH ALGORITHM
    first  = ubint();
    second = ubint(1);
    for (auto it = quotient.rbegin(); it != quotient.rend(); ++it) {
        mod_back = *it * second + first;
        first    = second;
        second   = mod_back;
    }
    if (quotient.size() & 0x1)
        return modulus - mod_back;
    return mod_back;
}

// Modular Exponentiation using Square and Multiply Algorithm
// reference:http://guan.cse.nsysu.edu.tw/note/expn.pdf
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::ModExp(const ubint& b, const ubint& modulus) const {
    ubint t(this->Mod(modulus));
    ubint p(b);
    ubint r(1);
    if (p.m_value[0] & 0x1)
        r = r.ModMulFast(t, modulus);
    while ((p >>= 1).m_MSB) {
        t = t.ModMulFast(t, modulus);
        if (p.m_value[0] & 0x1)
            r = r.ModMulFast(t, modulus);
    }
    return r;
}

template <typename limb_t>
ubint<limb_t> ubint<limb_t>::LShift(usshort shift) const {
    static constexpr usshort mask{m_limbBitLength - 1};
    if (m_MSB == 0)
        return ubint();
    auto ans(*this);
    ans.m_MSB += shift;
    size_t shiftByLimb{static_cast<size_t>(shift) >> m_log2LimbBitLength};
    shift &= mask;
    if (shift) {
        Dlimb_t ofl{0};
        for (auto& v : ans.m_value) {
            ofl |= static_cast<Dlimb_t>(v) << shift;
            v = static_cast<limb_t>(ofl);
            ofl >>= m_limbBitLength;
        }
        if (ofl)
            ans.m_value.push_back(static_cast<limb_t>(ofl));
    }
    if (shiftByLimb) {
        size_t j = ans.m_value.size();
        size_t i = j + shiftByLimb;
        ans.m_value.resize(i);
        while (i > 0)
            ans.m_value[--i] = (j > 0) ? ans.m_value[--j] : 0;
    }
    return ans;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::LShiftEq(usshort shift) {
    static constexpr usshort mask{m_limbBitLength - 1};
    if (m_MSB == 0)
        return *this;
    m_MSB += shift;
    size_t shiftByLimb{static_cast<size_t>(shift) >> m_log2LimbBitLength};
    shift &= mask;
    if (shift) {
        Dlimb_t ofl{0};
        for (auto& v : m_value) {
            ofl |= static_cast<Dlimb_t>(v) << shift;
            v = static_cast<limb_t>(ofl);
            ofl >>= m_limbBitLength;
        }
        if (ofl)
            m_value.push_back(static_cast<limb_t>(ofl));
    }
    if (shiftByLimb) {
        size_t j = m_value.size();
        size_t i = j + shiftByLimb;
        m_value.resize(i);
        while (i > 0)
            m_value[--i] = (j > 0) ? m_value[--j] : 0;
    }
    return *this;
}

/**Right Shift is done by splitting the number of shifts into
 *1. Multiple of the bit length of limb data type.
 *  Shifting is done by the shifting the limb type numbers in the array to
 *the right.
 *2. Shifts between 1 to bit length of limb data type.
 *   Shifting is done by using bit shift operations and carry over propagation.
 */
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::RShift(usshort shift) const {
    static constexpr usshort mask{m_limbBitLength - 1};
    if (m_MSB <= shift)
        return ubint(0);
    ubint ans(*this);
    ans.m_MSB -= shift;
    size_t shiftByLimb{static_cast<size_t>(shift) >> m_log2LimbBitLength};
    shift &= mask;
    Dlimb_t tmp{ans.m_value[shiftByLimb++] >> shift};
    usint lshift{m_limbBitLength - shift};
    size_t size{ans.m_value.size() - shiftByLimb};
    for (size_t i = 0; i < size; ++i, tmp >>= m_limbBitLength) {
        tmp |= static_cast<Dlimb_t>(ans.m_value[i + shiftByLimb]) << lshift;
        ans.m_value[i] = static_cast<limb_t>(tmp);
    }
    ans.m_value.resize(size);
    if (tmp)
        ans.m_value.push_back(static_cast<limb_t>(tmp));
    return ans;
}

template <typename limb_t>
ubint<limb_t>& ubint<limb_t>::RShiftEq(usshort shift) {
    static constexpr usshort mask{m_limbBitLength - 1};
    if (m_MSB <= shift) {
        m_MSB = 0;
        m_value.resize(1);
        m_value[0] = 0;
        return *this;
    }
    m_MSB -= shift;
    size_t shiftByLimb{static_cast<size_t>(shift) >> m_log2LimbBitLength};
    shift &= mask;
    Dlimb_t tmp{m_value[shiftByLimb++] >> shift};
    usint lshift{m_limbBitLength - shift};
    size_t size{m_value.size() - shiftByLimb};
    for (size_t i = 0; i < size; ++i, tmp >>= m_limbBitLength) {
        tmp |= static_cast<Dlimb_t>(m_value[i + shiftByLimb]) << lshift;
        m_value[i] = static_cast<limb_t>(tmp);
    }
    m_value.resize(size);
    if (tmp)
        m_value.push_back(static_cast<limb_t>(tmp));
    return *this;
}

// Converts the ubint to float using the std library functions.
template <typename limb_t>
float ubint<limb_t>::ConvertToFloat() const {
    float ans{-1.0f};
    try {
        ans = std::stof(ubint<limb_t>::ToString());
    }
    catch (const std::exception& e) {
        OPENFHE_THROW("ConvertToFloat() parse error converting to float");
    }
    return ans;
}

template <typename limb_t>
double ubint<limb_t>::ConvertToDouble() const {
    double ans{-1.0};
    try {
        // ans = std::stod(this->ToString());
        usint ceilInt = MSBToLimbs(m_MSB);
        double factor = pow(2, m_limbBitLength);
        double power  = 1.0;

        ans = 0.0;
        for (usint i = 0; i < ceilInt; ++i, power *= factor)
            ans += power * m_value[i];
    }
    catch (const std::exception& e) {
        OPENFHE_THROW("ConvertToDouble() parse error converting to double");
    }
    return ans;
}

// Converts the ubint to long double using the std library functions.
template <typename limb_t>
long double ubint<limb_t>::ConvertToLongDouble() const {
    long double ans{-1.0};
    try {
        ans = std::stold(ubint<limb_t>::ToString());
    }
    catch (const std::exception& e) {
        OPENFHE_THROW("ConvertToLongDouble() parse error converting to long double");
    }
    return ans;
}

// TODO
// Splits binary string to equi sized chunks then populates internal array values
template <typename limb_t>
ubint<limb_t> ubint<limb_t>::FromBinaryString(const std::string& vin) {
    std::string v = vin;
    // v.erase(0, v.find_first_not_of(' '));
    v.erase(0, v.find_first_not_of('0'));
    if (v.size() == 0)
        return ubint();
    ubint value;
    value.m_value.clear();
    usint len  = v.length();
    usint cntr = MSBToLimbs(len);
    std::string val;
    Dlimb_t partial_value = 0;
    for (usint i = 0; i < cntr; i++) {
        if (len > ((i + 1) * m_limbBitLength)) {
            val = v.substr((len - (i + 1) * m_limbBitLength), m_limbBitLength);
        }
        else {
            val = v.substr(0, len % m_limbBitLength);
        }
        for (usint j = 0; j < val.length(); j++) {
            partial_value += std::stoi(val.substr(j, 1));
            partial_value <<= 1;
        }
        partial_value >>= 1;
        value.m_value.push_back((limb_t)partial_value);
        partial_value = 0;
    }
    value.SetMSB();
    return value;
}

// TODO: * i to << i
template <typename limb_t>
usint ubint<limb_t>::GetDigitAtIndexForBase(usint index, usint base) const {
    usint DigitLen = ceil(log2(base));
    usint digit    = 0;
    usint newIndex = 1 + (index - 1) * DigitLen;
    for (usint i = 1; i < base; i <<= 1) {
        digit += GetBitAtIndex(newIndex++) * i;
    }
    return digit;
}

template <typename limb_t>
const std::string ubint<limb_t>::ToString() const {
    std::vector<uschar> val{0};
    val.reserve(m_MSB >> 1);
    for (usint i = m_MSB; i > 0; --i) {
        auto ofl = GetBitAtIndex(i);  // TODO: needlessly expensive here
        for (auto& a : val) {
            a = (a << 1) + ofl;
            if ((ofl = (a > 9)))
                a -= 10;
        }
        if (ofl)
            val.push_back(1);
    }
    for (auto& a : val)
        a += '0';
    return std::string(val.rbegin(), val.rend());
}

/* q[0], r[0], u[0], and v[0] contain the LEAST significant words.
 (The sequence is in little-endian order).

 This is a fairly precise implementation of Knuth's Algorithm D, for a
 binary computer with base b = 2**(32|64). The caller supplies:
 1. Space q for the quotient, m - n + 1 words (at least one).
 2. Space r for the remainder (optional), n words.
 3. The dividend u, m words, m >= 1.
 4. The divisor v, n words, n >= 2.
 The most significant digit of the divisor, v[n-1], must be nonzero.  The
 dividend u may have leading zeros; this just makes the algorithm take
 longer and makes the quotient contain more leading zeros.  A value of
 nullptr may be given for the address of the remainder to signify that the
 caller does not want the remainder.
 The program does not alter the input parameters u and v.
 The quotient and remainder returned may have leading zeros.  The
 function itself returns a value of 0 for success and 1 for invalid
 parameters (e.g., division by 0).
 For now, we must have m >= n.  Knuth's Algorithm D also requires
 that the dividend be at least as long as the divisor.  (In his terms,
 m >= 0 (unstated).  Therefore m+n >= n.) */

template <typename limb_t>
void ubint<limb_t>::divqr_vect(ubint& qin, ubint& rin, const ubint& uin, const ubint& vin) const noexcept {
    auto& u = uin.m_value;
    int m   = u.size();
    auto& v = vin.m_value;
    int n   = v.size();
    auto& q = qin.m_value;
    q.resize(m - n + 1);
    auto& r = rin.m_value;
    Dlimb_t ofl{0};

    if (n == 1) {
        for (int i = m - 1; i >= 0; --i) {
            ofl  = (ofl << m_limbBitLength) | u[i];
            q[i] = static_cast<limb_t>(ofl / v[0]);
            ofl %= v[0];
        }
        qin.NormalizeLimbs();

        r.resize(1);
        r[0]      = static_cast<limb_t>(ofl);
        rin.m_MSB = lbcrypto::GetMSB(r[0]);
        return;
    }

    // Normalize by shifting v left just enough so that its high-order
    // bit is set, and shift u left the same amount. We may have to append a
    // high-order digit on the dividend; we do that unconditionally.

    auto sl{m_limbBitLength - lbcrypto::GetMSB(v.back())};
    std::vector<limb_t> vn(n);
    ofl = 0;
    for (int i = 0; i < n; ++i, ofl >>= m_limbBitLength) {
        ofl |= static_cast<Dlimb_t>(v[i]) << sl;
        vn[i] = static_cast<limb_t>(ofl);
    }
    std::vector<limb_t> un(m + 1);
    ofl = 0;
    for (int i = 0; i < m; ++i, ofl >>= m_limbBitLength) {
        ofl |= static_cast<Dlimb_t>(u[i]) << sl;
        un[i] = static_cast<limb_t>(ofl);
    }
    un[m] = static_cast<limb_t>(ofl);
    Dlimb_t qhat, rhat, p;
    for (int j = m - n; j >= 0; --j) {
        ofl  = (static_cast<Dlimb_t>(un[j + n]) << m_limbBitLength) | un[j + n - 1];
        qhat = ofl / vn[n - 1];
        rhat = ofl % vn[n - 1];
        while ((qhat >> m_limbBitLength) || ((qhat * vn[n - 2]) > ((rhat << m_limbBitLength) | un[j + n - 2]))) {
            qhat -= 1;
            rhat += vn[n - 1];
            if (rhat >> m_limbBitLength)
                break;
        }
        SDlimb_t k{0}, t;
        for (int i = 0; i < n; ++i) {
            p         = qhat * vn[i];
            t         = un[i + j] - k - (p & m_MaxLimb);
            un[i + j] = static_cast<limb_t>(t);
            k         = (p >> m_limbBitLength) - (t >> m_limbBitLength);
        }
        t         = un[j + n] - k;
        un[j + n] = static_cast<limb_t>(t);
        q[j]      = qhat;
        if (t < 0) {
            q[j] -= 1;
            k = 0;
            for (int i = 0; i < n; ++i) {
                t         = static_cast<Dlimb_t>(un[i + j]) + vn[i] + k;
                un[i + j] = static_cast<limb_t>(t);
                k         = t >> m_limbBitLength;
            }
            un[j + n] += k;
        }
    }
    qin.NormalizeLimbs();

    ofl = un[0] >> sl;
    auto sr{m_limbBitLength - sl};
    r.resize(n--);
    for (int i = 0; i < n; ++i, ofl >>= m_limbBitLength) {
        ofl |= static_cast<Dlimb_t>(un[i + 1]) << sr;
        r[i] = static_cast<limb_t>(ofl);
    }
    r[n] = un[n] >> sl;
    rin.NormalizeLimbs();
}

template <typename limb_t>
void ubint<limb_t>::divq_vect(ubint& qin, const ubint& uin, const ubint& vin) const noexcept {
    auto& u = uin.m_value;
    int m   = u.size();
    auto& v = vin.m_value;
    int n   = v.size();
    auto& q = qin.m_value;
    q.resize(m - n + 1);
    Dlimb_t ofl{0};

    if (n == 1) {
        for (int i = m - 1; i >= 0; --i) {
            ofl  = (ofl << m_limbBitLength) | u[i];
            q[i] = static_cast<limb_t>(ofl / v[0]);
            ofl %= v[0];
        }
        qin.NormalizeLimbs();
        return;
    }

    auto sl{m_limbBitLength - lbcrypto::GetMSB(v.back())};
    std::vector<limb_t> vn(n);
    ofl = 0;
    for (int i = 0; i < n; ++i, ofl >>= m_limbBitLength) {
        ofl |= static_cast<Dlimb_t>(v[i]) << sl;
        vn[i] = static_cast<limb_t>(ofl);
    }
    std::vector<limb_t> un(m + 1);
    ofl = 0;
    for (int i = 0; i < m; ++i, ofl >>= m_limbBitLength) {
        ofl |= static_cast<Dlimb_t>(u[i]) << sl;
        un[i] = static_cast<limb_t>(ofl);
    }
    un[m] = static_cast<limb_t>(ofl);
    Dlimb_t qhat, rhat, p;
    for (int j = m - n; j >= 0; --j) {
        ofl  = (static_cast<Dlimb_t>(un[j + n]) << m_limbBitLength) | un[j + n - 1];
        qhat = ofl / vn[n - 1];
        rhat = ofl % vn[n - 1];
        while ((qhat >> m_limbBitLength) || ((qhat * vn[n - 2]) > ((rhat << m_limbBitLength) | un[j + n - 2]))) {
            qhat -= 1;
            rhat += vn[n - 1];
            if (rhat >> m_limbBitLength)
                break;
        }
        SDlimb_t k{0}, t;
        for (int i = 0; i < n; ++i) {
            p         = qhat * vn[i];
            t         = un[i + j] - k - (p & m_MaxLimb);
            un[i + j] = static_cast<limb_t>(t);
            k         = (p >> m_limbBitLength) - (t >> m_limbBitLength);
        }
        t         = un[j + n] - k;
        un[j + n] = static_cast<limb_t>(t);
        q[j]      = qhat;
        if (t < 0) {
            q[j] -= 1;
            k = 0;
            for (int i = 0; i < n; ++i) {
                t         = static_cast<Dlimb_t>(un[i + j]) + vn[i] + k;
                un[i + j] = static_cast<limb_t>(t);
                k         = t >> m_limbBitLength;
            }
            un[j + n] += k;
        }
    }
    qin.NormalizeLimbs();
}

template <typename limb_t>
void ubint<limb_t>::divr_vect(ubint& rin, const ubint& uin, const ubint& vin) const noexcept {
    auto& u = uin.m_value;
    int m   = u.size();
    auto& v = vin.m_value;
    int n   = v.size();
    auto& r = rin.m_value;
    Dlimb_t ofl{0};

    if (n == 1) {
        std::vector<limb_t> q(m - n + 1);
        for (int i = m - 1; i >= 0; --i) {
            ofl  = (ofl << m_limbBitLength) | u[i];
            q[i] = static_cast<limb_t>(ofl / v[0]);
            ofl %= v[0];
        }
        r[0]      = static_cast<limb_t>(ofl);
        rin.m_MSB = lbcrypto::GetMSB(r[0]);
        return;
    }

    auto sl{m_limbBitLength - lbcrypto::GetMSB(v.back())};
    std::vector<limb_t> vn(n);
    ofl = 0;
    for (int i = 0; i < n; ++i, ofl >>= m_limbBitLength) {
        ofl |= static_cast<Dlimb_t>(v[i]) << sl;
        vn[i] = static_cast<limb_t>(ofl);
    }
    std::vector<limb_t> un(m + 1);
    ofl = 0;
    for (int i = 0; i < m; ++i, ofl >>= m_limbBitLength) {
        ofl |= static_cast<Dlimb_t>(u[i]) << sl;
        un[i] = static_cast<limb_t>(ofl);
    }
    un[m] = static_cast<limb_t>(ofl);
    Dlimb_t qhat, rhat, p;
    for (int j = m - n; j >= 0; --j) {
        ofl  = (static_cast<Dlimb_t>(un[j + n]) << m_limbBitLength) | un[j + n - 1];
        qhat = ofl / vn[n - 1];
        rhat = ofl % vn[n - 1];
        while ((qhat >> m_limbBitLength) || ((qhat * vn[n - 2]) > ((rhat << m_limbBitLength) | un[j + n - 2]))) {
            qhat -= 1;
            rhat += vn[n - 1];
            if (rhat >> m_limbBitLength)
                break;
        }
        SDlimb_t k{0}, t;
        for (int i = 0; i < n; ++i) {
            p         = qhat * vn[i];
            t         = un[i + j] - k - (p & m_MaxLimb);
            un[i + j] = static_cast<limb_t>(t);
            k         = (p >> m_limbBitLength) - (t >> m_limbBitLength);
        }
        t         = un[j + n] - k;
        un[j + n] = static_cast<limb_t>(t);
        if (t < 0) {
            k = 0;
            for (int i = 0; i < n; ++i) {
                t         = static_cast<Dlimb_t>(un[i + j]) + vn[i] + k;
                un[i + j] = static_cast<limb_t>(t);
                k         = t >> m_limbBitLength;
            }
            un[j + n] += k;
        }
    }

    r.resize(n--);
    ofl = un[0] >> sl;
    auto sr{m_limbBitLength - sl};
    for (int i = 0; i < n; ++i, ofl >>= m_limbBitLength) {
        ofl |= static_cast<Dlimb_t>(un[i + 1]) << sr;
        r[i] = static_cast<limb_t>(ofl);
    }
    r[n] = un[n] >> sl;
    rin.NormalizeLimbs();
}

// Initializes the vector of limbs from the string equivalent of ubint
// Algorithm used is repeated division by 2
// Reference:http://pctechtips.org/convert-from-decimal-to-binary-with-recursion-in-java/
template <typename limb_t>
void ubint<limb_t>::SetValue(const std::string& vin) {
    std::string v{vin};
    // v.erase(0, v.find_first_not_of(' '));
    v.erase(0, v.find_first_not_of('0'));
    if (v.size() == 0)
        v = "0";

    size_t arrSize = v.length() - 1;
    for (size_t i = 0; i <= arrSize; ++i)
        v[i] -= '0';

    m_value.clear();
    //    m_value.reserve(MSBToLimbs(arrSize << 2));
    usint cnt{0};
    limb_t val{0};
    size_t zptr{0};
    while (zptr <= arrSize) {
        val |= static_cast<limb_t>(v[arrSize] & 0x1) << cnt++;
        for (size_t i = zptr; i < arrSize; ++i) {
            v[i + 1] += (v[i] & 0x1) * 10;
            v[i] >>= 1;
        }
        v[arrSize] >>= 1;
        if (v[zptr] == 0)
            zptr++;

        if ((cnt == m_limbBitLength) || (zptr > arrSize)) {
            m_value.push_back(val);
            cnt = val = 0;
        }
    }
    ubint<limb_t>::NormalizeLimbs();
}

template <typename limb_t>
uschar ubint<limb_t>::GetBitAtIndex(usint index) const {
    constexpr usint mask{m_limbBitLength - 1};
    if (index > m_MSB)
        return 0;
    size_t idx{MSBToLimbs(index) - 1};
    index &= mask;
    return static_cast<uschar>((m_value[idx] >> (index ? index - 1 : mask)) & 0x1);
}

template class bigintdyn::ubint<expdtype>;

    #if 0
// to stream internal representation
template std::ostream& operator<<<expdtype>(std::ostream& os, const std::vector<expdtype>& v);
    #endif

}  // namespace bigintdyn
#endif
