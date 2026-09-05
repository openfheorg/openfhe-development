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

#include "rgsw-cryptoparameters.h"

namespace lbcrypto {

const std::vector<NativeInteger>& RingGSWCryptoParams::PrecomputeGPower(uint32_t baseG) {
    auto it = m_Gpower_map.find(baseG);
    if (it != m_Gpower_map.end())
        return it->second;

    auto digitsG{DigitsForBase(m_Q, baseG)};
    NativeInteger vTemp{1};
    std::vector<NativeInteger> tempvec(digitsG);
    for (uint32_t i = 0; i < digitsG; ++i) {
        tempvec[i] = vTemp;
        vTemp      = vTemp.ModMulFast(NativeInteger(baseG), m_Q);
    }
    return m_Gpower_map.emplace(baseG, std::move(tempvec)).first->second;
}

void RingGSWCryptoParams::PreCompute(bool signEval) {
    // Computes baseR^i (only for AP bootstrapping)
    if (m_method == BINFHE_METHOD::AP) {
        auto digitCountR{GetDigitCount(m_q.ConvertToInt(), m_baseR)};
        m_digitsR.clear();
        m_digitsR.reserve(digitCountR);
        BasicInteger value{1};
        for (size_t i = 0; i < digitCountR; ++i, value *= m_baseR)
            m_digitsR.emplace_back(value);
    }

    // Computes baseG^i. The context's own base is always precomputed: sign evaluation adds
    // the three bases Change_BaseG switches between, it does not replace the base in use.
    PrecomputeGPower(m_baseG);
    for (const auto& item : m_baseG_map)
        PrecomputeGPower(item.first);
    if (signEval) {
        for (uint32_t baseG : {1 << 14, 1 << 18, 1 << 27})
            PrecomputeGPower(baseG);
    }
    m_Gpower = m_Gpower_map.at(m_baseG);

    // Sets the gate constants for supported binary operations
    m_gateConst = {
        NativeInteger(5) * (m_q >> 3),   // OR
        NativeInteger(7) * (m_q >> 3),   // AND
        NativeInteger(1) * (m_q >> 3),   // NOR
        NativeInteger(3) * (m_q >> 3),   // NAND
        NativeInteger(6) * (m_q >> 3),   // XOR
        NativeInteger(2) * (m_q >> 3),   // XNOR
        NativeInteger(7) * (m_q >> 3),   // MAJORITY
        NativeInteger(11) * (m_q / 12),  // AND3
        NativeInteger(7) * (m_q / 12),   // OR3
        NativeInteger(15) * (m_q >> 4),  // AND4
        NativeInteger(9) * (m_q >> 4),   // OR4
        NativeInteger(6) * (m_q >> 3),   // XOR_FAST
        NativeInteger(2) * (m_q >> 3)    // XNOR_FAST
    };

    // Computes polynomials X^m - 1 that are needed in the accumulator for the
    // CGGI bootstrapping
    if (m_method == BINFHE_METHOD::GINX)
        BuildMonomials();

    // expand the base map into one entry per LWE index. Digit counts are computed here,
    // once per distinct base, instead of per call in the accumulator.
    m_baseGByIndex.clear();
    if (!m_baseG_map.empty()) {
        uint32_t total{0};
        for (const auto& [baseG, count] : m_baseG_map)
            total += count;
        m_baseGByIndex.reserve(total);
        for (const auto& [baseG, count] : m_baseG_map) {
            auto it = m_Gpower_map.find(baseG);
            if (it == m_Gpower_map.end())
                OPENFHE_THROW("No GPower found for the requested gadget base.");
            m_baseGByIndex.insert(m_baseGByIndex.end(), count,
                                  BaseGParams{baseG, DigitsForBase(m_Q, baseG), GetMSB(baseG) - 1, &it->second});
        }
    }

    if (m_method == LMKCDEY) {
        constexpr uint32_t gen{5};
        m_logGen.clear();
        uint32_t M{2 * m_N};
        m_logGen.resize(M);
        uint32_t gPow{1};
        m_logGen[M - gPow] = M;  // for -1
        for (uint32_t i = 1; i < m_N / 2; ++i) {
            gPow               = (gPow * gen) % M;
            m_logGen[gPow]     = i;
            m_logGen[M - gPow] = -i;
        }

        // EvalAcc only ever rotates by gen^k for k in [1, numAutoKeys] and by M - gen
        m_autoMap.clear();
        auto addMap = [this](uint32_t idx) {
            auto& v = m_autoMap[idx];
            v.resize(m_N);
            PrecomputeAutoMap(m_N, idx, &v);
        };
        addMap(M - gen);
        uint32_t idx{1};
        for (uint32_t k = 1; k <= m_numAutoKeys; ++k) {
            idx = (idx * gen) % M;
            addMap(idx);
        }
    }
}

#if NATIVEINT != 32
const std::shared_ptr<ILNativeParams32>& RingGSWCryptoParams::GetPolyParams32() {
    if (m_polyParams32 == nullptr) {
        m_polyParams32 = std::make_shared<ILNativeParams32>(
            2 * m_N, NativeInteger32(m_Q.ConvertToInt<uint32_t>()),
            NativeInteger32(m_polyParams->GetRootOfUnity().ConvertToInt<uint32_t>()));
    }
    return m_polyParams32;
}

const std::shared_ptr<const std::vector<NativePoly32>>& RingGSWCryptoParams::GetMonomials32() {
    if (m_monomials32 == nullptr) {
        const auto& pp = GetPolyParams32();
        // X^m - 1 built natively at 32 bits: the NTT mod Q is width-independent, so the table is
        // identical to narrowing the 64-bit one, which therefore need not exist
        NativeInteger32 Q32(m_Q.ConvertToInt<uint32_t>());
        constexpr NativeInteger32 one{1};
        auto monomials = std::make_shared<std::vector<NativePoly32>>();
        monomials->reserve(2 * m_N);
        for (uint32_t i = 0; i < 2 * m_N; ++i) {
            NativePoly32 aPoly(pp, Format::COEFFICIENT, true);
            aPoly[0].ModSubFastEq(one, Q32);  // -1
            if (i < m_N)
                aPoly[i].ModAddFastEq(one, Q32);  // X^m
            else
                aPoly[i - m_N].ModSubFastEq(one, Q32);  // -X^m
            aPoly.SetFormat(Format::EVALUATION);
            monomials->push_back(std::move(aPoly));
        }
        m_monomials32 = std::move(monomials);
    }
    return m_monomials32;
}

const std::shared_ptr<const std::vector<NativeVector32>>& RingGSWCryptoParams::GetMonomialsPrecon32() {
    if (m_monomialsPrecon32 == nullptr) {
        const auto& monomials = *GetMonomials32();
        NativeInteger32 Q32(m_Q.ConvertToInt<uint32_t>());
        auto precon = std::make_shared<std::vector<NativeVector32>>();
        precon->reserve(monomials.size());
        for (const auto& m : monomials) {
            const auto& mv = m.GetValues();
            NativeVector32 p(mv.GetLength(), Q32);
            for (size_t k = 0; k < mv.GetLength(); ++k)
                p[k] = mv[k].PrepModMulConst(Q32);
            precon->push_back(std::move(p));
        }
        m_monomialsPrecon32 = std::move(precon);
    }
    return m_monomialsPrecon32;
}
#endif  // NATIVEINT != 32

void RingGSWCryptoParams::BuildMonomials() {
    constexpr NativeInteger one{1};
    m_monomials.clear();
    m_monomials.reserve(2 * m_N);
    for (uint32_t i = 0; i < m_N; ++i) {
        NativePoly aPoly(m_polyParams, Format::COEFFICIENT, true);
        aPoly[0].ModSubFastEq(one, m_Q);  // -1
        aPoly[i].ModAddFastEq(one, m_Q);  // X^m
        aPoly.SetFormat(Format::EVALUATION);
        m_monomials.push_back(std::move(aPoly));
    }
    for (uint32_t i = 0; i < m_N; ++i) {
        NativePoly aPoly(m_polyParams, Format::COEFFICIENT, true);
        aPoly[0].ModSubFastEq(one, m_Q);  // -1
        aPoly[i].ModSubFastEq(one, m_Q);  // -X^m
        aPoly.SetFormat(Format::EVALUATION);
        m_monomials.push_back(std::move(aPoly));
    }
}

};  // namespace lbcrypto
