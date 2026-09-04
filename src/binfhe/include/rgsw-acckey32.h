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

#ifndef _RGSW_ACCKEY32_H_
#define _RGSW_ACCKEY32_H_

#include "rgsw-acckey.h"
#include "rgsw-cryptoparameters.h"

#include <memory>
#include <utility>
#include <vector>

namespace lbcrypto {

#if NATIVEINT != 32

class RingGSWACCKey32Impl;
using RingGSWACCKey32      = std::shared_ptr<RingGSWACCKey32Impl>;
using ConstRingGSWACCKey32 = const std::shared_ptr<const RingGSWACCKey32Impl>;

// exact conversions between the two widths: every value is below 2^28, so 32 -> 64 -> 32 is the
// identity and the two representations agree bit for bit
inline NativePoly32 NarrowPoly32(const NativePoly& src, const std::shared_ptr<ILNativeParams32>& params) {
    const auto& v{src.GetValues()};
    uint32_t n = v.GetLength();
    NativeVector32 out(n, params->GetModulus());
    for (uint32_t i = 0; i < n; ++i)
        out[i] = NativeInteger32(static_cast<uint32_t>(v[i].ConvertToInt()));
    NativePoly32 dst(params, src.GetFormat(), false);
    dst.SetValues(std::move(out), src.GetFormat());
    return dst;
}

inline void WidenPoly32Into(const NativePoly32& src, NativePoly& dst) {
    const auto& v{src.GetValues()};
    uint32_t n = v.GetLength();
    for (uint32_t i = 0; i < n; ++i)
        dst[i] = NativeInteger(static_cast<uint64_t>(v[i].ConvertToInt()));
}

inline std::vector<NativePoly32> NarrowAcc32(const std::shared_ptr<ILNativeParams32>& params,
                                             const std::vector<NativePoly>& acc) {
    std::vector<NativePoly32> out;
    out.reserve(acc.size());
    for (const auto& p : acc)
        out.push_back(NarrowPoly32(p, params));
    return out;
}

inline void WidenAcc32Into(const std::vector<NativePoly32>& acc32, std::vector<NativePoly>& acc) {
    for (size_t i = 0; i < acc.size(); ++i) {
        acc[i].SetFormat(acc32[i].GetFormat());
        WidenPoly32Into(acc32[i], acc[i]);
    }
}

/**
 * @brief 32-bit internal form of a refreshing key (GINX, AP, LMKCDEY).
 *
 * Pure storage plus width conversions, mirroring RingGSWACCKeyImpl's three-dimensional layout so
 * each method indexes it exactly as its accumulator indexes the 64-bit key; the blind rotation
 * itself lives on the RingGSWAccumulator classes as EvalAcc32. Every stored value is a residue
 * below 2^28, so the key holds in half the memory of the 64-bit form and evaluation at either
 * width produces bit-identical results.
 */
class RingGSWACCKey32Impl {
public:
    // one RGSW eval key: [digit][column]
    using EvalKey32 = std::vector<std::vector<NativePoly32>>;

    // The complete qualification predicate: a false return means KeyGen falls back to the
    // 64-bit key; construction never throws on a params object this accepted.
    static bool Fits(const RingGSWCryptoParams& params);

    // Narrow an existing 64-bit key of any method's shape. Peak memory holds both forms; the
    // released pages come back only after AllocTrim(). Prefer the incremental form below.
    RingGSWACCKey32Impl(const std::shared_ptr<RingGSWCryptoParams>& params, const RingGSWACCKeyImpl& ek);

    // Incremental construction: size the 32-bit store up front (d1 x d2 x d3, matching the
    // method's 64-bit key shape), then hand it one 64-bit eval key at a time. The caller lets
    // each 64-bit key die immediately, so the full 64-bit refreshing key is never materialised.
    RingGSWACCKey32Impl(const std::shared_ptr<RingGSWCryptoParams>& params, uint32_t d1, uint32_t d2, uint32_t d3);
    void SetEvalKey(uint32_t i, uint32_t j, uint32_t k, const RingGSWEvalKeyImpl& ek);

    // native 32-bit form, for key generation that never materialises a 64-bit key
    void SetEvalKey(uint32_t i, uint32_t j, uint32_t k, EvalKey32&& ek) {
        m_key[i][j][k] = std::move(ek);
    }

    // the 64-bit key's [d1][d2][d3] layout; entries the method leaves unset stay empty
    const std::vector<std::vector<std::vector<EvalKey32>>>& GetElements() const {
        return m_key;
    }

    const std::vector<std::vector<EvalKey32>>& operator[](uint32_t i) const {
        return m_key[i];
    }

    // exact 64-bit copy for serialization
    RingGSWACCKey Widen(const std::shared_ptr<RingGSWCryptoParams>& params) const;

    // resident bytes of key material, for the halved-key measurement
    uint64_t KeyBytes() const;

private:
    void Init(const std::shared_ptr<RingGSWCryptoParams>& params);

    std::shared_ptr<ILNativeParams32> m_polyParams;
    std::vector<std::vector<std::vector<EvalKey32>>> m_key;
    uint32_t m_N{0};
};

#endif  // NATIVEINT != 32

}  // namespace lbcrypto

#endif  // _RGSW_ACCKEY32_H_
