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
  This file contains the cpp implementation of  mubintvec, a <vector> of ubint, with associated math operators
 */

#include "config_core.h"
#ifdef WITH_BE4

    #include "math/math-hal.h"
    #include "math/hal/bigintdyn/mubintvecdyn.h"

    #include "utils/exception.h"
    #include "utils/inttypes.h"
    #include "utils/serializable.h"

//    #include "time.h"
//    #include <chrono>
    #include <initializer_list>
    #include <string>
    #include <vector>

namespace bigintdyn {

template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(usint length, const ubint_el_t& modulus,
                                 std::initializer_list<std::string> rhs) noexcept
    : m_modulus{modulus}, m_modulus_state{State::INITIALIZED}, m_data(length) {
    const size_t len = (rhs.size() < m_data.size()) ? rhs.size() : m_data.size();
    for (size_t i = 0; i < len; ++i)
        m_data[i] = ubint_el_t(*(rhs.begin() + i)) % m_modulus;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(usint length, const ubint_el_t& modulus, std::initializer_list<uint64_t> rhs) noexcept
    : m_modulus{modulus}, m_modulus_state{State::INITIALIZED}, m_data(length) {
    const size_t len = (rhs.size() < m_data.size()) ? rhs.size() : m_data.size();
    for (size_t i = 0; i < len; ++i)
        m_data[i] = ubint_el_t(*(rhs.begin() + i)) % m_modulus;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const std::vector<std::string>& s, const ubint_el_t& modulus) noexcept
    : m_modulus{modulus}, m_modulus_state{State::INITIALIZED}, m_data(s.size()) {
    for (size_t i = 0; i < s.size(); ++i)
        m_data[i] = ubint_el_t(s[i]) % m_modulus;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>::mubintvec(const std::vector<std::string>& s, const std::string& modulus) noexcept
    : m_modulus{modulus}, m_modulus_state{State::INITIALIZED}, m_data(s.size()) {
    for (size_t i = 0; i < s.size(); ++i)
        m_data[i] = ubint_el_t(s[i]) % m_modulus;
}

// if two vectors are different sized, then it will resize target vector
// will overwrite target modulus
template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(const mubintvec& rhs) noexcept {
    m_modulus       = rhs.m_modulus;
    m_modulus_state = rhs.m_modulus_state;
    if (rhs.m_data.size() > m_data.size()) {
        m_data = rhs.m_data;
        return *this;
    }
    std::copy(rhs.m_data.begin(), rhs.m_data.end(), m_data.begin());
    if (m_data.size() > rhs.m_data.size())
        m_data.resize(rhs.m_data.size());
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(std::initializer_list<std::string> rhs) noexcept {
    const size_t len = rhs.size();
    if (m_data.size() < len)
        m_data.resize(len);
    const auto reduce = (m_modulus_state == State::INITIALIZED && m_modulus);
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (i < len) {
            m_data[i] = ubint_el_t(*(rhs.begin() + i));
            if (reduce)
                m_data[i].ModEq(m_modulus);
        }
        else {
            m_data[i] = 0;
        }
    }
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::operator=(std::initializer_list<uint64_t> rhs) noexcept {
    const size_t len = rhs.size();
    if (m_data.size() < len)
        m_data.resize(len);
    const auto reduce = (m_modulus_state == State::INITIALIZED && m_modulus);
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (i < len) {
            m_data[i] = ubint_el_t(*(rhs.begin() + i));
            if (reduce)
                m_data[i].ModEq(m_modulus);
        }
        else {
            m_data[i] = 0;
        }
    }
    return *this;
}

/**Switches the integers in the vector to values corresponding to the new
 * modulus Algorithm: Integer i, Old Modulus om, New Modulus nm, delta =
 * abs(om-nm): Case 1: om < nm if i > i > om/2 i' = i + delta Case 2: om > nm i
 * > om/2 i' = i-delta
 */
template <class ubint_el_t>
void mubintvec<ubint_el_t>::SwitchModulus(const ubint_el_t& modulus) {
    auto size{m_data.size()};
    auto halfQ{m_modulus >> 1};
    if (modulus > m_modulus) {
        auto diff{modulus - m_modulus};
        for (size_t i = 0; i < size; ++i) {
            if (m_data[i] > halfQ)
                m_data[i] += diff;
        }
    }
    else {
        auto diff{modulus - (m_modulus % modulus)};
        for (size_t i = 0; i < size; ++i) {
            if (m_data[i] > halfQ)
                m_data[i] += diff;
            if (m_data[i] >= modulus)
                m_data[i] %= modulus;
        }
    }
    this->SetModulus(modulus);
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::Mod(const ubint_el_t& modulus) const {
    auto ans(*this);
    if (modulus == 2)
        return ans.ModByTwoEq();
    auto size{m_data.size()};
    auto halfQ{m_modulus >> 1};
    if (modulus > m_modulus) {
        auto diff{modulus - m_modulus};
        for (size_t i = 0; i < size; ++i) {
            if (ans.m_data[i] > halfQ)
                ans.m_data[i] += diff;
        }
    }
    else {
        auto diff{modulus - (m_modulus % modulus)};
        for (size_t i = 0; i < size; ++i) {
            if (ans.m_data[i] > halfQ)
                ans.m_data[i] += diff;
            if (ans.m_data[i] >= modulus)
                ans.m_data[i] %= modulus;
        }
    }
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModEq(const ubint_el_t& modulus) {
    if (modulus == 2)
        return this->ModByTwoEq();
    auto size{m_data.size()};
    auto halfQ{m_modulus >> 1};
    if (modulus > m_modulus) {
        auto diff{modulus - m_modulus};
        for (size_t i = 0; i < size; ++i) {
            if (m_data[i] > halfQ)
                m_data[i] += diff;
        }
    }
    else {
        auto diff{modulus - (m_modulus % modulus)};
        for (size_t i = 0; i < size; ++i) {
            if (m_data[i] > halfQ)
                m_data[i] += diff;
            if (m_data[i] >= modulus)
                m_data[i] %= modulus;
        }
    }
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAdd(const ubint_el_t& b) const {
    auto ans(*this);
    auto modulus(m_modulus);
    auto bLocal(b);
    if (bLocal >= modulus)
        bLocal.ModEq(modulus);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].ModAddFastEq(bLocal, modulus);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModAddEq(const ubint_el_t& b) {
    auto modulus{m_modulus};
    auto bLocal{b};
    if (bLocal >= modulus)
        bLocal.ModEq(modulus);
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModAddFastEq(bLocal, modulus);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAddAtIndex(size_t i, const ubint_el_t& b) const {
    auto ans(*this);
    ans.at(i).ModAddEq(b, m_modulus);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModAddAtIndexEq(size_t i, const ubint_el_t& b) {
    this->mubintvec::at(i).ModAddEq(b, m_modulus);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModAdd(const mubintvec& b) const {
    if (m_modulus != b.m_modulus)
        OPENFHE_THROW("mubintvec adding vectors of different moduli");
    if (m_data.size() != b.m_data.size())
        OPENFHE_THROW("mubintvec adding vectors of different lengths");
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].ModAddEq(b.m_data[i], ans.m_modulus);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModAddEq(const mubintvec& b) {
    if (m_modulus != b.m_modulus)
        OPENFHE_THROW("mubintvec adding vectors of different moduli");
    if (m_data.size() != b.m_data.size())
        OPENFHE_THROW("mubintvec adding vectors of different lengths");
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModAddEq(b.m_data[i], m_modulus);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModAddNoCheckEq(const mubintvec& b) {
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModAddEq(b.m_data[i], m_modulus);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModSub(const ubint_el_t& b) const {
    auto ans(*this);
    auto modulus{m_modulus};
    auto bLocal{b};
    if (bLocal >= modulus)
        bLocal.ModEq(modulus);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].ModSubFastEq(bLocal, modulus);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModSubEq(const ubint_el_t& b) {
    auto modulus{m_modulus};
    auto bLocal{b};
    if (bLocal >= modulus)
        bLocal.ModEq(modulus);
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModSubFastEq(bLocal, modulus);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModSub(const mubintvec& b) const {
    if (m_modulus != b.m_modulus)
        OPENFHE_THROW("mubintvec subtractiong vectors of different moduli");
    if (m_data.size() != b.m_data.size())
        OPENFHE_THROW("mubintvec subtractiong vectors of different lengths");
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].ModSubEq(b.m_data[i], ans.m_modulus);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModSubEq(const mubintvec& b) {
    if (m_modulus != b.m_modulus)
        OPENFHE_THROW("mubintvec subtractiong vectors of different moduli");
    if (m_data.size() != b.m_data.size())
        OPENFHE_THROW("mubintvec subtractiong vectors of different lengths");
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModSubEq(b.m_data[i], m_modulus);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModMul(const ubint_el_t& b) const {
    auto ans(*this);
    auto bLocal{b};
    if (bLocal >= ans.m_modulus)
        bLocal.ModEq(ans.m_modulus);
    #ifdef NO_BARRETT
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].ModMulFastEq(bLocal, ans.m_modulus);
    #else
    auto mu(ans.m_modulus.ComputeMu());
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].ModMulFastEq(bLocal, ans.m_modulus, mu);
    #endif
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModMulEq(const ubint_el_t& b) {
    auto bLocal(b);
    if (bLocal >= m_modulus)
        bLocal.ModEq(m_modulus);
    #ifdef NO_BARRETT
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModMulFastEq(bLocal, m_modulus);
    #else
    auto mu(m_modulus.ComputeMu());
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModMulFastEq(bLocal, m_modulus, mu);
    #endif
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModMul(const mubintvec& b) const {
    if (m_modulus != b.m_modulus)
        OPENFHE_THROW("mubintvec multiplying vectors of different moduli");
    if (m_data.size() != b.m_data.size())
        OPENFHE_THROW("mubintvec multiplying vectors of different lengths");
    auto ans(*this);
    #ifdef NO_BARRETT
    for (size_t i = 0; i < m_data.size(); ++i)
        ans[i].ModMulFastEq(b[i], ans.m_modulus);
    #else
    auto mu(ans.m_modulus.ComputeMu());
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].ModMulFastEq(b[i], ans.m_modulus, mu);
    #endif
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModMulEq(const mubintvec& b) {
    if (m_modulus != b.m_modulus)
        OPENFHE_THROW("mubintvec multiplying vectors of different moduli");
    if (m_data.size() != b.m_data.size())
        OPENFHE_THROW("mubintvec multiplying vectors of different lengths");
    #ifdef NO_BARRETT
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModMulFastEq(b[i], m_modulus);
    #else
    auto mu(m_modulus.ComputeMu());
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModMulFastEq(b[i], m_modulus, mu);
    #endif
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModMulNoCheckEq(const mubintvec& b) {
    #ifdef NO_BARRETT
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModMulFastEq(b[i], m_modulus);
    #else
    auto mu(m_modulus.ComputeMu());
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModMulFastEq(b[i], m_modulus, mu);
    #endif
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModExp(const ubint_el_t& b) const {
    auto ans(*this);
    auto modulus{m_modulus};
    auto bLocal{b};
    if (bLocal >= modulus)
        bLocal.ModEq(modulus);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].ModExpEq(bLocal, modulus);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModExpEq(const ubint_el_t& b) {
    auto modulus{m_modulus};
    auto bLocal{b};
    if (bLocal >= modulus)
        bLocal.ModEq(modulus);
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModExpEq(bLocal, modulus);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModInverse() const {
    auto ans(*this);
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i].ModInverseEq(ans.m_modulus);
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModInverseEq() {
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i].ModInverseEq(m_modulus);
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::ModByTwo() const {
    auto ans(*this);
    auto halfQ{m_modulus >> 1};
    for (size_t i = 0; i < ans.m_data.size(); ++i)
        ans[i] = ubint_el_t((ans[i].m_value[0] & 0x1) ^ (ans[i] > halfQ));
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::ModByTwoEq() {
    auto halfQ{m_modulus >> 1};
    for (size_t i = 0; i < m_data.size(); ++i)
        m_data[i] = ubint_el_t((m_data[i].m_value[0] & 0x1) ^ (m_data[i] > halfQ));
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::MultiplyAndRound(const ubint_el_t& p, const ubint_el_t& q) const {
    auto ans(*this);
    auto mv(m_modulus);
    auto halfQ{m_modulus >> 1};
    for (size_t i = 0; i < ans.m_data.size(); ++i) {
        if (ans.m_data[i] > halfQ) {
            auto&& tmp{mv - ans[i]};
            ans[i] = mv - tmp.MultiplyAndRound(p, q);
        }
        else {
            ans[i] = ans[i].MultiplyAndRound(p, q).Mod(mv);
        }
    }
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::MultiplyAndRoundEq(const ubint_el_t& p, const ubint_el_t& q) {
    auto mv{m_modulus};
    auto halfQ{m_modulus >> 1};
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (m_data[i] > halfQ) {
            auto&& tmp{mv - m_data[i]};
            m_data[i] = mv - tmp.MultiplyAndRound(p, q);
        }
        else {
            m_data[i] = m_data[i].MultiplyAndRound(p, q).Mod(mv);
        }
    }
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::DivideAndRound(const ubint_el_t& q) const {
    auto ans(*this);
    auto mv{m_modulus};
    auto halfQ{m_modulus >> 1};
    for (size_t i = 0; i < ans.m_data.size(); ++i) {
        if (ans[i] > halfQ) {
            auto&& tmp{mv - ans[i]};
            ans[i] = mv - tmp.DivideAndRound(q);
        }
        else {
            ans[i] = ans[i].DivideAndRoundEq(q);
        }
    }
    return ans;
}

template <class ubint_el_t>
mubintvec<ubint_el_t>& mubintvec<ubint_el_t>::DivideAndRoundEq(const ubint_el_t& q) {
    auto mv{m_modulus};
    auto halfQ{m_modulus >> 1};
    for (size_t i = 0; i < m_data.size(); ++i) {
        if (m_data[i] > halfQ) {
            auto&& tmp{mv - m_data[i]};
            m_data[i] = mv - tmp.DivideAndRound(q);
        }
        else {
            m_data[i] = m_data[i].DivideAndRound(q);
        }
    }
    return *this;
}

template <class ubint_el_t>
mubintvec<ubint_el_t> mubintvec<ubint_el_t>::GetDigitAtIndexForBase(usint index, usint base) const {
    auto ans(*this);
    for (size_t i = 0; i < m_data.size(); ++i)
        ans[i] = static_cast<ubint_el_t>(ans[i].GetDigitAtIndexForBase(index, base));
    return ans;
}

template class mubintvec<BigInteger>;

}  // namespace bigintdyn

#endif
