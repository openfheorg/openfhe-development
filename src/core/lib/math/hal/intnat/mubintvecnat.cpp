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

#include "math/math-hal.h"
#include "math/hal/intnat/mubintvecnat.h"
#include "math/nbtheory-impl.h"

#include "utils/exception.h"

namespace intnat {

#if defined(__GNUC__) && !defined(__clang__) && __GNUC__ < 12
    #define OPENFHE_COMPARE_SELECT_LANES 1
#endif

template <typename T>
static inline T topBitMask(T x) {
    return static_cast<T>(0) - static_cast<T>(x >> (sizeof(T) * 8 - 1));
}

template <typename T>
static inline T modAddLane(T a, T b, T m) {
#if defined(OPENFHE_COMPARE_SELECT_LANES) || defined(__clang__)
    T t = a + b;
    return t >= m ? t - m : t;
#else
    T t = a + b - m;
    return t + (m & topBitMask(t));
#endif
}

template <typename T>
static inline T modSubLane(T a, T b, T m) {
#ifdef OPENFHE_COMPARE_SELECT_LANES
    T t = a - b;
    return a < b ? t + m : t;
#else
    T t = a - b;
    return t + (m & topBitMask(t));
#endif
}

template <typename T>
static inline T centeredCorrectionLane(T v, T halfQ, T diff) {
#ifdef OPENFHE_COMPARE_SELECT_LANES
    return v > halfQ ? diff : static_cast<T>(0);
#else
    return diff & topBitMask(halfQ - v);
#endif
}

template <class IntegerType>
void NativeVectorT<IntegerType>::GeneralShrinkLoop(IntegerType* dst, const IntegerType* src, size_t size, BasicInt ov,
                                                   BasicInt nv) {
    using DInt = typename IntegerType::DNativeInt;
    const BasicInt halfQ{ov >> 1};
    const BasicInt diffR{static_cast<BasicInt>((ov - nv) % nv)};
    if constexpr (sizeof(DInt) > sizeof(BasicInt)) {
        // e >= 1 is what bounds the quotient estimate to a single correction below
        const int64_t e{static_cast<int64_t>(lbcrypto::GetMSB(nv)) - 2};
        if (e >= 1) {
            // mu = floor(2^(W+e) / nv) fits a word because nv >= 2^(e+1), which is also
            // DivD's hi < divisor precondition; the estimate never exceeds the true
            // quotient and falls short of it by at most one
            const BasicInt mu{IntegerType::DivD(BasicInt(1) << e, 0, nv)};
            for (size_t i = 0; i < size; ++i) {
                const BasicInt v{src[i].m_value};
                BasicInt av{v};
                // kept as a branch, not folded into the reduction: callers are uniform in
                // which way it goes (a near-equal shrink skips every element, a deep one
                // reduces every element), so it predicts and the near-equal case pays nothing
                if (av >= nv) {
                    av -= static_cast<BasicInt>(IntegerType::MultDHi(v, mu) >> e) * nv;
                    if (av >= nv)
                        av -= nv;
                }
                dst[i].m_value = modSubLane(av, centeredCorrectionLane(v, halfQ, diffR), nv);
            }
            return;
        }
    }
    for (size_t i = 0; i < size; ++i) {
        const BasicInt v{src[i].m_value};
        BasicInt av{v};
        if (av >= nv)
            av %= nv;
        dst[i].m_value = modSubLane(av, centeredCorrectionLane(v, halfQ, diffR), nv);
    }
}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(uint32_t length, const IntegerType& modulus,
                                          std::initializer_list<std::string> rhs) noexcept
    : m_modulus{modulus}, m_data(length) {
    const uint32_t vlen = (rhs.size() < m_data.size()) ? rhs.size() : m_data.size();
    for (uint32_t i = 0; i < vlen; ++i)
        m_data[i] = *(rhs.begin() + i) % m_modulus;
}

template <class IntegerType>
NativeVectorT<IntegerType>::NativeVectorT(uint32_t length, const IntegerType& modulus,
                                          std::initializer_list<uint64_t> rhs) noexcept
    : m_modulus{modulus}, m_data(length) {
    const uint32_t vlen = (rhs.size() < m_data.size()) ? rhs.size() : m_data.size();
    for (uint32_t i = 0; i < vlen; ++i)
        m_data[i].m_value = BasicInt(*(rhs.begin() + i)) % m_modulus.m_value;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(std::initializer_list<std::string> rhs) noexcept {
    const size_t vlen = rhs.size();
    if (m_data.size() < vlen)
        m_data.resize(vlen);
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (i < vlen) {
            m_data[i] = *(rhs.begin() + i);
            if (m_modulus.m_value != 0)
                m_data[i].m_value = m_data[i].m_value % m_modulus.m_value;
        }
        else {
            m_data[i].m_value = 0;
        }
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::operator=(std::initializer_list<uint64_t> rhs) noexcept {
    const size_t vlen = rhs.size();
    if (m_data.size() < vlen)
        m_data.resize(vlen);
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (i < vlen) {
            m_data[i].m_value = BasicInt(*(rhs.begin() + i));
            if (m_modulus.m_value != 0)
                m_data[i].m_value = m_data[i].m_value % m_modulus.m_value;
        }
        else {
            m_data[i].m_value = 0;
        }
    }
    return *this;
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
NativeVectorT<IntegerType>::NativeVectorT(const NativeVectorT& v, const IntegerType& modulus) noexcept
    : m_data(v.m_data.size()) {
    // same three branches as SwitchModulus below, reading from v instead of in place
    this->SetModulus(modulus);
    const auto ov{v.m_modulus.m_value};
    const auto nv{modulus.m_value};
    const auto halfQ{ov >> 1};
    const size_t size{m_data.size()};
    if (nv > ov) {
        const auto diff{nv - ov};
        for (size_t i = 0; i < size; ++i) {
            const auto x{v.m_data[i].m_value};
            m_data[i].m_value = x + centeredCorrectionLane(x, halfQ, diff);
        }
    }
    else if (nv > halfQ) {
        const auto diff{ov - nv};
        for (size_t i = 0; i < size; ++i) {
            const auto x{v.m_data[i].m_value};
            m_data[i].m_value = x - centeredCorrectionLane(x, halfQ, diff);
        }
    }
    else {
        GeneralShrinkLoop(m_data.data(), v.m_data.data(), size, ov, nv);
    }
}

template <class IntegerType>
void NativeVectorT<IntegerType>::SwitchModulus(const IntegerType& modulus) {
    const auto ov{m_modulus.m_value};
    const auto nv{modulus.m_value};
    const auto halfQ{ov >> 1};
    const size_t size{m_data.size()};
    if (nv > ov) {
        const auto diff{nv - ov};
        for (size_t i = 0; i < size; ++i)
            m_data[i].m_value += centeredCorrectionLane(m_data[i].m_value, halfQ, diff);
    }
    else if (nv > halfQ) {
        // new modulus within 2x of the old one: a single conditional subtract fully
        // reduces every value (v <= halfQ < nv, and v > halfQ maps into [0, nv))
        const auto diff{ov - nv};
        for (size_t i = 0; i < size; ++i)
            m_data[i].m_value -= centeredCorrectionLane(m_data[i].m_value, halfQ, diff);
    }
    else {
        GeneralShrinkLoop(m_data.data(), m_data.data(), size, ov, nv);
    }
    this->SetModulus(modulus);
}

template <class IntegerType>
void NativeVectorT<IntegerType>::LazySwitchModulus(const IntegerType& modulus) {
    for (auto& v : m_data)
        v.ModEq(modulus);
    this->SetModulus(modulus);
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::MultAccEqNoCheck(const NativeVectorT& V, const IntegerType& I) {
    auto iv{I};
    auto mv{m_modulus};
    if (iv.m_value >= mv.m_value)
        iv.ModEq(mv);
    auto iinv{iv.PrepModMulConst(mv)};
    const uint32_t ringdm = m_data.size();
    for (uint32_t i = 0; i < ringdm; ++i)
        m_data[i].ModAddFastEq(V.m_data[i].ModMulFastConst(iv, mv, iinv), mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::Mod(const IntegerType& modulus) const {
    auto ans(*this);
    ans.ModEq(modulus);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModEq(const IntegerType& modulus) {
    if (modulus.m_value == 2)
        return this->NativeVectorT::ModByTwoEq();
    const auto ov{m_modulus.m_value};
    const auto nv{modulus.m_value};
    const auto halfQ{ov >> 1};
    const size_t size{m_data.size()};
    if (nv > ov) {
        const auto diff{nv - ov};
        for (size_t i = 0; i < size; ++i)
            m_data[i].m_value += centeredCorrectionLane(m_data[i].m_value, halfQ, diff);
    }
    else if (nv > halfQ) {
        // new modulus within 2x of the old one: every value is below ov by the class
        // invariant, so a single conditional subtract fully reduces it
        const auto diff{ov - nv};
        for (size_t i = 0; i < size; ++i)
            m_data[i].m_value -= centeredCorrectionLane(m_data[i].m_value, halfQ, diff);
    }
    else {
        GeneralShrinkLoop(m_data.data(), m_data.data(), size, ov, nv);
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModReduceEq() {
    const auto mv{m_modulus.m_value};
    const size_t size{m_data.size()};
    using DInt = typename IntegerType::DNativeInt;
    if constexpr (sizeof(DInt) > sizeof(BasicInt)) {
        const int64_t e{static_cast<int64_t>(lbcrypto::GetMSB(mv)) - 2};
        if (e >= 1) {
            const BasicInt mu{IntegerType::DivD(BasicInt(1) << e, 0, mv)};
            for (size_t i = 0; i < size; ++i) {
                const BasicInt v{m_data[i].m_value};
                if (v < mv)
                    continue;
                BasicInt av{v - static_cast<BasicInt>(IntegerType::MultDHi(v, mu) >> e) * mv};
                m_data[i].m_value = (av >= mv) ? av - mv : av;
            }
            return *this;
        }
    }
    for (size_t i = 0; i < size; ++i) {
        if (m_data[i].m_value >= mv)
            m_data[i].m_value %= mv;
    }
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModAdd(const IntegerType& b) const {
    auto ans(*this);
    ans.ModAddEq(b);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModAddEq(const IntegerType& b) {
    auto mv{m_modulus.m_value};
    auto bv{b};
    if (bv.m_value >= mv)
        bv.ModEq(m_modulus);
    const size_t size{m_data.size()};
    for (size_t i = 0; i < size; ++i)
        m_data[i].m_value = modAddLane(m_data[i].m_value, bv.m_value, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModAddAtIndex(size_t i, const IntegerType& b) const {
    auto ans(*this);
    ans.at(i).ModAddEq(b, m_modulus);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModAddAtIndexEq(size_t i, const IntegerType& b) {
    this->NativeVectorT::at(i).ModAddEq(b, m_modulus);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModAdd(const NativeVectorT& b) const {
    auto ans(*this);
    ans.ModAddEq(b);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModAddEq(const NativeVectorT& b) {
    if (m_data.size() != b.m_data.size() || m_modulus != b.m_modulus)
        OPENFHE_THROW("Called on NativeVectorT's with different parameters.");
    const auto mv{m_modulus.m_value};
    const size_t size{m_data.size()};
    for (size_t i = 0; i < size; ++i)
        m_data[i].m_value = modAddLane(m_data[i].m_value, b.m_data[i].m_value, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModSub(const IntegerType& b) const {
    auto ans(*this);
    ans.ModSubEq(b);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModSubEq(const IntegerType& b) {
    auto mv{m_modulus.m_value};
    auto bv{b};
    if (bv.m_value >= mv)
        bv.ModEq(m_modulus);
    const size_t size{m_data.size()};
    for (size_t i = 0; i < size; ++i)
        m_data[i].m_value = modSubLane(m_data[i].m_value, bv.m_value, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModSub(const NativeVectorT& b) const {
    auto ans(*this);
    ans.ModSubEq(b);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModSubEq(const NativeVectorT& b) {
    if (m_data.size() != b.m_data.size() || m_modulus != b.m_modulus)
        OPENFHE_THROW("Called on NativeVectorT's with different parameters.");
    const auto mv{m_modulus.m_value};
    const size_t size{m_data.size()};
    for (size_t i = 0; i < size; ++i)
        m_data[i].m_value = modSubLane(m_data[i].m_value, b.m_data[i].m_value, mv);
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
        ans[i].ModMulFastConstEq(bv, mv, bconst);
    return ans;
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
        OPENFHE_THROW("Called on NativeVectorT's with different parameters.");
    auto ans(*this);
    BarrettModMulLoop(ans.m_data.data(), b.m_data.data(), ans.m_data.size(), m_modulus);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModMulEq(const NativeVectorT& b) {
    if (m_data.size() != b.m_data.size() || m_modulus != b.m_modulus)
        OPENFHE_THROW("Called on NativeVectorT's with different parameters.");
    BarrettModMulLoop(m_data.data(), b.m_data.data(), m_data.size(), m_modulus);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::ModByTwo() const {
    auto ans(*this);
    auto halfQ{m_modulus.m_value >> 1};
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].m_value = 0x1 & (ans[i].m_value ^ (ans[i].m_value > halfQ));
    return ans;
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
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i] = ans[i].ModExp(bv, mv);
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::ModExpEq(const IntegerType& b) {
    auto mv{m_modulus};
    auto bv{b};
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i] = m_data[i].ModExp(bv, mv);
    return *this;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::MultWithOutMod(const NativeVectorT& b) const {
    if (m_data.size() != b.m_data.size() || m_modulus != b.m_modulus)
        OPENFHE_THROW("Called on NativeVectorT's with different parameters.");
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].m_value = ans[i].m_value * b[i].m_value;
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::MultiplyAndRound(const IntegerType& p,
                                                                        const IntegerType& q) const {
    auto halfQ{m_modulus.m_value >> 1};
    auto mv{m_modulus};
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i) {
        if (ans[i].m_value > halfQ) {
            auto&& tmp{mv - ans[i]};
            ans[i] = mv - tmp.MultiplyAndRound(p, q);
        }
        else {
            ans[i] = ans[i].MultiplyAndRound(p, q).Mod(mv);
        }
    }
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::MultiplyAndRoundEq(const IntegerType& p, const IntegerType& q) {
    auto halfQ{m_modulus.m_value >> 1};
    auto mv{m_modulus};
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (m_data[i].m_value > halfQ) {
            auto&& tmp{mv - m_data[i]};
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
            auto&& tmp{mv - ans[i]};
            ans[i] = mv - tmp.DivideAndRound(q);
        }
        else {
            ans[i] = ans[i].DivideAndRound(q);
        }
    }
    return ans;
}

template <class IntegerType>
NativeVectorT<IntegerType>& NativeVectorT<IntegerType>::DivideAndRoundEq(const IntegerType& q) {
    auto halfQ{m_modulus.m_value >> 1};
    auto mv{m_modulus};
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (m_data[i].m_value > halfQ) {
            auto&& tmp{mv - m_data[i]};
            m_data[i] = mv - tmp.DivideAndRound(q);
        }
        else {
            m_data[i] = m_data[i].DivideAndRound(q);
        }
    }
    return *this;
}

template <class IntegerType>
std::vector<NativeVectorT<IntegerType>> NativeVectorT<IntegerType>::BaseDecompose(uint32_t digitLen) const {
    const BasicInt q  = m_modulus.m_value;
    const uint32_t nW = (m_modulus.GetMSB() + digitLen - 1) / digitLen;
    const auto mask   = static_cast<BasicInt>((uint64_t{1} << digitLen) - 1);
    const uint32_t n  = m_data.size();
    std::vector<NativeVectorT> result;
    result.reserve(nW);

    if (nW * digitLen + 1 > IntegerType::MaxBits() || q <= 1) {
        // not enough headroom for the bias: plain unsigned digit windows
        for (uint32_t w = 0; w < nW; ++w) {
            NativeVectorT d(n, m_modulus);
            const uint32_t shift = w * digitLen;
            for (uint32_t i = 0; i < n; ++i)
                d[i].m_value = (m_data[i].m_value >> shift) & mask;
            result.push_back(std::move(d));
        }
        return result;
    }

    // bias by H (gHalf in every digit position) once; every balanced digit is then an
    // independent window: digit_w = (((x~ + H) >> w*digitLen) & mask) - h, x~ centered.
    const BasicInt h     = BasicInt{1} << (digitLen - 1);
    const BasicInt qHalf = q >> 1;
    BasicInt H{0};
    for (uint32_t i = 0; i < nW; ++i)
        H += h << (i * digitLen);
    std::vector<BasicInt> biased(n);
    for (uint32_t i = 0; i < n; ++i) {
        // borrow of (qHalf - x) is 1 exactly when x > qHalf, i.e. x is negative centered
        const BasicInt borrow = (qHalf - m_data[i].m_value) >> (IntegerType::MaxBits() - 1);
        biased[i]             = m_data[i].m_value + H - (q & (0 - borrow));
    }

    for (uint32_t w = 0; w < nW; ++w) {
        NativeVectorT d(n, m_modulus);
        const uint32_t shift = w * digitLen;
        if (w + 1 < nW) {
            for (uint32_t i = 0; i < n; ++i) {
                const BasicInt v    = (biased[i] >> shift) & mask;
                const BasicInt addq = q & ((v >> (digitLen - 1)) - 1);  // q exactly when v < h
                d[i].m_value        = v - h + addq;
            }
        }
        else {  // the top window is unmasked so it absorbs the remaining quotient (v < 3h)
            for (uint32_t i = 0; i < n; ++i) {
                const BasicInt v    = biased[i] >> shift;
                BasicInt s          = v >> (digitLen - 1);  // in {0, 1, 2}
                s                   = (s | (s >> 1)) & 0x1;
                const BasicInt addq = q & (s - 1);
                d[i].m_value        = v - h + addq;
            }
        }
        result.push_back(std::move(d));
    }
    return result;
}

template <class IntegerType>
NativeVectorT<IntegerType> NativeVectorT<IntegerType>::GetDigitAtIndexForBase(uint32_t index, uint32_t base) const {
    auto digitLen = lbcrypto::GetMSB(base - 1);  // == ceil(log2(base))
    uint32_t shift{(index - 1) * digitLen};
    if (shift >= IntegerType::MaxBits())
        return NativeVectorT(m_data.size(), m_modulus);
    auto ans(*this);
    const auto mask = static_cast<BasicInt>((uint64_t{1} << digitLen) - 1);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].m_value = (ans[i].m_value >> shift) & mask;
    return ans;
}

template class NativeVectorT<NativeInteger>;

}  // namespace intnat
