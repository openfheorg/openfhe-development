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
  This code provides basic arithmetic functionality for vectors of native integers
 */

#include "math/hal.h"
#include "math/hal/intnat/mubintvecnat.h"
#include "math/nbtheory-impl.h"

#include "utils/exception.h"

namespace intnat {

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(usint length, const IntegerType& modulus)
    : m_data(length), m_modulus{modulus} {
    if (modulus.GetMSB() > MAX_MODULUS_SIZE) {
        OPENFHE_THROW(lbcrypto::not_available_error,
                      "Modulus size " + std::to_string(modulus.GetMSB()) +
                          " is too large. NativeVectorT supports only modulus size <=  " +
                          std::to_string(MAX_MODULUS_SIZE) + " bits");
    }
}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(usint length, const IntegerType& modulus,
                                          std::initializer_list<std::string> rhs) noexcept
    : m_data(length), m_modulus{modulus} {
    const size_t len = (rhs.size() < m_data.size()) ? rhs.size() : m_data.size();
    for (size_t i = 0; i < len; ++i)
        m_data[i] = *(rhs.begin() + i) % m_modulus;
}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(usint length, const IntegerType& modulus,
                                          std::initializer_list<uint64_t> rhs) noexcept
    : m_data(length), m_modulus(modulus) {
    const size_t len = (rhs.size() < m_data.size()) ? rhs.size() : m_data.size();
    for (size_t i = 0; i < len; ++i)
        m_data[i].m_value = BasicInt(*(rhs.begin() + i)) % m_modulus.m_value;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(const NativeVectorT& rhs) noexcept {
    m_modulus = rhs.m_modulus;
    if (rhs.m_data.size() > m_data.size()) {
        m_data = rhs.m_data;
        return *this;
    }
    std::copy(rhs.m_data.begin(), rhs.m_data.end(), m_data.begin());
    if (m_data.size() > rhs.m_data.size())
        m_data.resize(rhs.m_data.size());
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(NativeVectorT&& rhs) noexcept {
    if (this != &rhs) {
        m_data    = std::move(rhs.m_data);
        m_modulus = std::move(rhs.m_modulus);
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(std::initializer_list<std::string> rhs) noexcept {
    const size_t len = rhs.size();
    if (m_data.size() < len)
        m_data.resize(len);
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (i < len) {
            m_data[i] = *(rhs.begin() + i);
            if (m_modulus.m_value != 0)
                m_data[i].m_value %= m_modulus.m_value;
        }
        else {
            m_data[i].m_value = 0;
        }
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(std::initializer_list<uint64_t> rhs) noexcept {
    const size_t len = rhs.size();
    if (m_data.size() < len)
        m_data.resize(len);
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (i < len) {
            m_data[i].m_value = BasicInt(*(rhs.begin() + i));
            if (m_modulus.m_value != 0)
                m_data[i].m_value %= m_modulus.m_value;
        }
        else {
            m_data[i].m_value = 0;
        }
    }
    return *this;
}

template <class IntegerType>
void NativeVectorT<IntegerType>::SetModulus(const IntegerType& value) {
    if (value.GetMSB() > MAX_MODULUS_SIZE) {
        OPENFHE_THROW(lbcrypto::not_available_error,
                      "NativeVectorT supports only modulus size <=  " + std::to_string(MAX_MODULUS_SIZE) + " bits");
    }
    m_modulus.m_value = value.m_value;
}

/**Switches the integers in the vector to values corresponding to the new
 * modulus.
 * Algorithm: Integer i, Old Modulus om, New Modulus nm,
 * delta = abs(om-nm):
 *  Case 1: om < nm
 *    if i > om/2
 *      i' = i + delta
 *  Case 2: om > nm
 *    i > om/2 i' = i-delta
 */
template <class IntegerType>
void NativeVectorT<IntegerType>::SwitchModulus(const IntegerType& modulus) {
#if 0    // (0.37, 1.5, 9.83) (1.5, 3.6, 20.8)
    auto size(m_data.size());
    auto halfQ(m_modulus >> 1);
    if (modulus > m_modulus) {
        auto diff(modulus - m_modulus);
        for (size_t i = 0; i < size; ++i) {
            if (m_data[i] > halfQ)
                m_data[i] += diff;
        }
    }
    else {
        auto diff(m_modulus - modulus);
        for (size_t i = 0; i < size; ++i) {
            m_data[i].ModSubEq(((m_data[i] > halfQ) ? diff : 0), modulus);
        }
    }
#elif 1  // (0.37, 1.96, 6.56) (1.5, 4.56, 14.2)
    auto size{m_data.size()};
    auto halfQ{m_modulus.m_value >> 1};
    if (modulus.m_value > m_modulus.m_value) {
        auto diff{modulus.m_value - m_modulus.m_value};
        for (size_t i = 0; i < size; ++i) {
            if (m_data[i].m_value > halfQ)
                m_data[i].m_value += diff;
        }
    }
    else {
        auto diff{modulus.m_value - (m_modulus.m_value % modulus.m_value)};
        for (size_t i = 0; i < size; ++i) {
            if (m_data[i].m_value > halfQ)
                m_data[i].m_value += diff;
            if (m_data[i].m_value >= modulus.m_value)
                m_data[i].m_value %= modulus.m_value;
        }
    }
#elif 0  // (1.2, 2.4, 6.54) (2.9, 5.2, 14.2)
    auto size(m_data.size());
    auto halfQ(m_modulus >> 1);
    auto diff(modulus - (m_modulus % modulus));
    for (size_t i = 0; i < size; ++i) {
        if (m_data[i] > halfQ)
            m_data[i] += diff;
        if (m_data[i] >= modulus)
            m_data[i] %= modulus;
    }
#elif 0  // 1.62
    auto halfQ(m_modulus >> 1);
    if (modulus > m_modulus) {
        auto diff(modulus - m_modulus);
        for (auto& x : m_data)
            if (x > halfQ)
                x += diff;
    }
    else {
        auto diff(m_modulus - modulus);
        for (auto& x : m_data)
            x.ModSubEq((x > halfQ ? diff : 0), modulus);
    }
#elif 0  // 2.0
    const auto halfQ(m_modulus >> 1);
    const auto diff(modulus - (m_modulus % modulus));
    if (modulus > m_modulus) {
        for (auto& x : m_data) {
            if (x > halfQ)
                x += diff;
        }
    }
    else {
        for (auto& x : m_data) {
            if (x > halfQ)
                x += diff;
            if (x >= modulus)
                x %= modulus;
        }
    }
#else    // 2.3  5.5
    const auto halfQ(m_modulus >> 1);
    const auto diff(modulus - (m_modulus % modulus));
    for (auto& x : m_data) {
        if (x > halfQ)
            x += diff;
        if (x >= modulus)
            x %= modulus;
    }
#endif
    this->SetModulus(modulus);
}

// MODULAR ARITHMETIC OPERATIONS

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::Mod(const IntegerType& modulus) const {
    auto ans(*this);
    if (modulus.m_value == 2)
        return ans.ModByTwoEq();
    auto size{ans.m_data.size()};
    auto halfQ{m_modulus.m_value >> 1};
    if (modulus.m_value > m_modulus.m_value) {
        auto diff{modulus.m_value - m_modulus.m_value};
        for (size_t i = 0; i < size; ++i) {
            if (ans.m_data[i].m_value > halfQ)
                ans.m_data[i].m_value += diff;
        }
    }
    else {
        auto diff{modulus.m_value - (m_modulus.m_value % modulus.m_value)};
        for (size_t i = 0; i < size; ++i) {
            if (ans.m_data[i].m_value > halfQ)
                ans.m_data[i].m_value += diff;
            if (ans.m_data[i].m_value >= modulus.m_value)
                ans.m_data[i].m_value %= modulus.m_value;
        }
    }
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModEq(const IntegerType& modulus) {
    // TODO: #ifdef NATIVEINT_BARRET_MOD

    if (modulus.m_value == 2)
        return this->NativeVectorT::ModByTwoEq();
    auto size{m_data.size()};
    auto halfQ{m_modulus.m_value >> 1};
    if (modulus.m_value > m_modulus.m_value) {
        auto diff{modulus.m_value - m_modulus.m_value};
        for (size_t i = 0; i < size; ++i) {
            if (m_data[i].m_value > halfQ)
                m_data[i].m_value += diff;
        }
    }
    else {
        auto diff{modulus.m_value - (m_modulus.m_value % modulus.m_value)};
        for (size_t i = 0; i < size; ++i) {
            if (m_data[i].m_value > halfQ)
                m_data[i].m_value += diff;
            if (m_data[i].m_value >= modulus.m_value)
                m_data[i].m_value %= modulus.m_value;
        }
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModAdd(const IntegerType& b) const {
    auto mv{m_modulus};
    auto bv{b};
    auto ans(*this);
    if (bv.m_value >= mv.m_value)
        bv.ModEq(mv);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans.m_data[i].ModAddFastEq(bv, mv);
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModAddEq(const IntegerType& b) {
    auto mv{m_modulus};
    auto bv{b};
    if (bv.m_value >= mv.m_value)
        bv.ModEq(mv);
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModAddFastEq(bv, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModAddAtIndex(size_t i, const IntegerType& b) const {
    auto ans(*this);
    ans.at(i).ModAddEq(b, m_modulus);
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModAddAtIndexEq(size_t i, const IntegerType& b) {
    this->NativeVectorT::at(i).ModAddEq(b, m_modulus);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModAdd(const NativeVectorT& b) const {
    if (m_data.size() != b.m_data.size() || m_modulus != b.m_modulus)
        OPENFHE_THROW(lbcrypto::math_error, "ModAdd called on NativeVectorT's with different parameters.");
    auto mv{m_modulus};
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans.m_data[i].ModAddFastEq(b[i], mv);
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModAddEq(const NativeVectorT& b) {
    if (m_data.size() != b.m_data.size() || m_modulus != b.m_modulus)
        OPENFHE_THROW(lbcrypto::math_error, "ModAddEq called on NativeVectorT's with different parameters.");
    auto mv{m_modulus};
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModAddFastEq(b[i], mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModSub(const IntegerType& b) const {
    auto mv{m_modulus};
    auto bv{b};
    auto ans(*this);
    if (bv.m_value >= mv.m_value)
        bv.ModEq(mv);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans.m_data[i].ModSubFastEq(bv, mv);
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModSubEq(const IntegerType& b) {
    auto mv{m_modulus};
    auto bv{b};
    if (bv.m_value >= mv.m_value)
        bv.ModEq(mv);
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModSubFastEq(bv, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModSub(const NativeVectorT& b) const {
    if (m_data.size() != b.m_data.size() || m_modulus != b.m_modulus)
        OPENFHE_THROW(lbcrypto::math_error, "ModSub called on NativeVectorT's with different parameters.");
    auto mv{m_modulus};
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans.m_data[i].ModSubFastEq(b[i], mv);
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModSubEq(const NativeVectorT& b) {
    if (m_data.size() != b.m_data.size() || m_modulus != b.m_modulus)
        OPENFHE_THROW(lbcrypto::math_error, "ModSubEq called on NativeVectorT's with different parameters.");
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModSubFastEq(b[i], m_modulus);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModMul(const IntegerType& b) const {
    auto mv{m_modulus};
    auto bv{b};
    auto ans(*this);
    if (bv.m_value >= mv.m_value)
        bv.ModEq(mv);
    auto bconst{bv.PrepModMulConst(mv)};
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans.m_data[i].ModMulFastConstEq(bv, mv, bconst);
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModMulEq(const IntegerType& b) {
    auto mv{m_modulus};
    auto bv{b};
    if (bv.m_value >= mv.m_value)
        bv.ModEq(mv);
    auto bconst{bv.PrepModMulConst(mv)};
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModMulFastConstEq(bv, mv, bconst);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModMul(const NativeVectorT& b) const {
    if (m_data.size() != b.m_data.size() || m_modulus != b.m_modulus)
        OPENFHE_THROW(lbcrypto::math_error, "ModMul called on NativeVectorT's with different parameters.");
#ifdef NATIVEINT_BARRET_MOD
    auto mu{m_modulus.ComputeMu()};
    auto mv{m_modulus};
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans.m_data[i].ModMulFastEq(b[i], mv, mu);
    return std::move(ans);
#else
    auto mv{m_modulus};
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans.m_data[i].ModMulFastEq(b[i], mv);
    return std::move(ans);
#endif
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModMulEq(const NativeVectorT& b) {
    if (m_data.size() != b.m_data.size() || m_modulus != b.m_modulus)
        OPENFHE_THROW(lbcrypto::math_error, "ModMulEq called on NativeVectorT's with different parameters.");
#ifdef NATIVEINT_BARRET_MOD
    auto mu{m_modulus.ComputeMu()};
    auto mv{m_modulus};
    auto size{m_data.size()};
    for (size_t i = 0; i < size; ++i)
        m_data[i].ModMulFastEq(b[i], mv, mu);
    return *this;
#else
    auto mv{m_modulus};
    auto size{m_data.size()};
    for (size_t i = 0; i < size; ++i)
        m_data[i].ModMulFastEq(b[i], mv);
    return *this;
#endif
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModByTwo() const {
    auto halfQ{m_modulus.m_value >> 1};
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans.m_data[i].m_value = 0x1 & (ans.m_data[i].m_value ^ (ans.m_data[i].m_value > halfQ));
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModByTwoEq() {
    auto halfQ{m_modulus.m_value >> 1};
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].m_value = 0x1 & (m_data[i].m_value ^ (m_data[i].m_value > halfQ));
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModExp(const IntegerType& b) const {
    auto mv{m_modulus};
    auto bv{b};
    auto ans(*this);
    if (bv.m_value >= mv.m_value)
        bv.ModEq(mv);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i] = ans[i].ModExp(bv, mv);
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModExpEq(const IntegerType& b) {
    auto mv{m_modulus};
    auto bv{b};
    if (bv.m_value >= mv.m_value)
        bv.ModEq(mv);
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i] = m_data[i].ModExp(bv, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModInverse() const {
    auto mv{m_modulus};
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i] = ans[i].ModInverse(mv);
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModInverseEq() {
    auto mv{m_modulus};
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i] = m_data[i].ModInverse(mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::MultWithOutMod(const NativeVectorT& b) const {
    if (m_data.size() != b.m_data.size() || m_modulus != b.m_modulus)
        OPENFHE_THROW(lbcrypto::math_error, "ModMul called on NativeVectorT's with different parameters.");
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].m_value = ans[i].m_value * b[i].m_value;
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::MultiplyAndRound(const IntegerType& p,
                                                                        const IntegerType& q) const {
    auto halfQ{m_modulus.m_value >> 1};
    auto mv{m_modulus};
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i) {
        if (ans[i].m_value > halfQ) {
            auto tmp = mv - ans[i];
            ans[i]   = mv - tmp.MultiplyAndRound(p, q);
        }
        else {
            ans[i] = ans[i].MultiplyAndRound(p, q).Mod(mv);
        }
    }
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::MultiplyAndRoundEq(const IntegerType& p, const IntegerType& q) {
    auto halfQ{m_modulus.m_value >> 1};
    auto mv{m_modulus};
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (m_data[i].m_value > halfQ) {
            auto tmp  = mv - m_data[i];
            m_data[i] = mv - tmp.MultiplyAndRound(p, q);
        }
        else {
            m_data[i] = m_data[i].MultiplyAndRound(p, q).Mod(mv);
        }
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::DivideAndRound(const IntegerType& q) const {
    auto halfQ{m_modulus.m_value >> 1};
    auto mv{m_modulus};
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i) {
        if (ans[i].m_value > halfQ) {
            auto tmp = mv - ans[i];
            ans[i]   = mv - tmp.DivideAndRound(q);
        }
        else {
            ans[i] = ans[i].DivideAndRound(q);
        }
    }
    return std::move(ans);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::DivideAndRoundEq(const IntegerType& q) {
    auto halfQ{m_modulus.m_value >> 1};
    auto mv{m_modulus};
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (m_data[i].m_value > halfQ) {
            auto tmp  = mv - m_data[i];
            m_data[i] = mv - tmp.DivideAndRound(q);
        }
        else {
            m_data[i] = m_data[i].DivideAndRound(q);
        }
    }
    return *this;
}

// OTHER FUNCTIONS

// Gets the ind
template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::GetDigitAtIndexForBase(usint index, usint base) const {
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].m_value = static_cast<BasicInt>(ans[i].GetDigitAtIndexForBase(index, base));
    return std::move(ans);
}

template class NativeVectorT<NativeInteger>;

}  // namespace intnat
