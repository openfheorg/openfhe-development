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

#include "rgsw-acckey32.h"

#include "utils/exception.h"

#include <utility>
#include <vector>

namespace lbcrypto {

#if NATIVEINT != 32

bool RingGSWACCKey32Impl::Fits(const RingGSWCryptoParams& params) {
    auto method = params.GetMethod();
    if (method != BINFHE_METHOD::GINX && method != BINFHE_METHOD::AP && method != BINFHE_METHOD::LMKCDEY)
        return false;
    if (params.GetQ().GetMSB() > MAX_MODULUS_SIZE32)
        return false;
    uint64_t Q{params.GetQ().ConvertToInt<uint64_t>()};
    auto ok = [Q](const RingGSWCryptoParams::BaseGParams& bp) {
        // excess-H headroom: the biased value must stay inside a 32-bit word
        if (bp.digitsG * bp.gBits + 1 > 32)
            return false;
        // uint64 headroom for the lazy inner product: digitsG2 * (Q-1)^2 < 2^64
        uint64_t d2{static_cast<uint64_t>((bp.digitsG - 1) << 1)};
        return d2 <= static_cast<uint64_t>(-1) / ((Q - 1) * (Q - 1));
    };
    const auto& byIndex = params.GetBaseGByIndex();
    if (byIndex.empty())
        return ok(params.GetDefaultBaseGParams());
    for (const auto& bp : byIndex)
        if (!ok(bp))
            return false;
    // the LMKCDEY automorphism key switch uses the default base regardless of the per-index map
    if (method == BINFHE_METHOD::LMKCDEY && !ok(params.GetDefaultBaseGParams()))
        return false;
    return true;
}

RingGSWACCKey32Impl::RingGSWACCKey32Impl(const std::shared_ptr<RingGSWCryptoParams>& params,
                                         const RingGSWACCKeyImpl& ek) {
    const auto& src = ek.GetElements();
    if (src.empty() || src[0].empty() || src[0][0].empty())
        OPENFHE_THROW("RingGSWACCKey32Impl: empty accumulator key");
    Init(params);
    m_key.assign(src.size(),
                 std::vector<std::vector<EvalKey32>>(src[0].size(), std::vector<EvalKey32>(src[0][0].size())));
    for (size_t i = 0; i < src.size(); ++i)
        for (size_t j = 0; j < src[i].size(); ++j)
            for (size_t k = 0; k < src[i][j].size(); ++k)
                if (src[i][j][k] != nullptr)
                    SetEvalKey(i, j, k, *src[i][j][k]);
}

RingGSWACCKey32Impl::RingGSWACCKey32Impl(const std::shared_ptr<RingGSWCryptoParams>& params, uint32_t d1, uint32_t d2,
                                         uint32_t d3) {
    Init(params);
    m_key.assign(d1, std::vector<std::vector<EvalKey32>>(d2, std::vector<EvalKey32>(d3)));
}

// shared setup for both constructors
void RingGSWACCKey32Impl::Init(const std::shared_ptr<RingGSWCryptoParams>& params) {
    if (!Fits(*params))
        OPENFHE_THROW("parameters do not qualify for the 32-bit internal path");

    m_N          = params->GetN();
    m_polyParams = params->GetPolyParams32();
    // force the lazy monomial build now: construction is single-threaded, gates may not be
    if (params->GetMethod() == BINFHE_METHOD::GINX)
        params->GetMonomialsPrecon32();
}

void RingGSWACCKey32Impl::SetEvalKey(uint32_t i, uint32_t j, uint32_t k, const RingGSWEvalKeyImpl& ek) {
    const auto& el = ek.GetElements();
    auto& dst      = m_key[i][j][k];
    dst.resize(el.size());
    for (size_t d = 0; d < el.size(); ++d) {
        dst[d].clear();
        dst[d].reserve(el[d].size());
        for (size_t col = 0; col < el[d].size(); ++col)
            dst[d].push_back(NarrowPoly32(el[d][col], m_polyParams));
    }
}

RingGSWACCKey RingGSWACCKey32Impl::Widen(const std::shared_ptr<RingGSWCryptoParams>& params) const {
    const auto& polyParams = params->GetPolyParams();
    auto ek                = std::make_shared<RingGSWACCKeyImpl>(m_key.size(), m_key[0].size(), m_key[0][0].size());
    for (size_t i = 0; i < m_key.size(); ++i) {
        for (size_t j = 0; j < m_key[i].size(); ++j) {
            for (size_t k = 0; k < m_key[i][j].size(); ++k) {
                const auto& src = m_key[i][j][k];
                if (src.empty())
                    continue;
                auto dst = std::make_shared<RingGSWEvalKeyImpl>(static_cast<uint32_t>(src.size()), 2);
                for (size_t d = 0; d < src.size(); ++d) {
                    for (size_t col = 0; col < src[d].size(); ++col) {
                        NativePoly p(polyParams, src[d][col].GetFormat(), true);
                        WidenPoly32Into(src[d][col], p);
                        (*dst)[d][col] = std::move(p);
                    }
                }
                (*ek)[i][j][k] = std::move(dst);
            }
        }
    }
    return ek;
}

uint64_t RingGSWACCKey32Impl::KeyBytes() const {
    uint64_t polys = 0;
    for (const auto& i : m_key)
        for (const auto& j : i)
            for (const auto& k : j)
                for (const auto& d : k)
                    polys += d.size();
    return polys * static_cast<uint64_t>(m_N) * sizeof(uint32_t);
}

#endif  // NATIVEINT != 32

}  // namespace lbcrypto
