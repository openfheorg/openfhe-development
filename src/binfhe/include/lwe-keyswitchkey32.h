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

#ifndef _LWE_KEYSWITCHKEY32_H_
#define _LWE_KEYSWITCHKEY32_H_

#include "lwe-cryptoparameters.h"
#include "lwe-keyswitchkey-fwd.h"

#include <cstdint>
#include <memory>
#include <vector>

namespace lbcrypto {

#if NATIVEINT != 32

class LWESwitchingKey32Impl;
using LWESwitchingKey32      = std::shared_ptr<LWESwitchingKey32Impl>;
using ConstLWESwitchingKey32 = const std::shared_ptr<const LWESwitchingKey32Impl>;

/**
 * @brief 32-bit internal form of the LWE key switching key.
 *
 * Every stored value is a residue mod qKS, so when qKS fits a 32-bit word the key stores in half
 * the memory of the 64-bit form -- and it is by far the largest key object. Storage is two flat
 * arrays indexed by (LWE index i, digit value, digit position): rows of n words in m_keyA and one
 * word each in m_keyB, replacing the nested vector-of-vectors layout. The key switch itself
 * accumulates rows in uint64 and reduces once per output coefficient, which yields the same
 * residues as the 64-bit path, so results are bit-identical.
 */
class LWESwitchingKey32Impl {
public:
    // storage is uint32, and the key switch accumulates N*digitCount unreduced rows in uint64
    static bool Fits(const LWECryptoParams& params) {
        const auto& qKS = params.GetqKS();
        if (qKS.GetMSB() > 32)
            return false;
        uint64_t rows{static_cast<uint64_t>(params.GetN()) * params.GetDigitCountKS()};
        return rows <= static_cast<uint64_t>(-1) / qKS.ConvertToInt<uint64_t>();
    }

    LWESwitchingKey32Impl(uint32_t N, uint32_t baseKS, uint32_t digitCount, uint32_t n)
        : m_N(N),
          m_m(baseKS),
          m_d(digitCount),
          m_n(n),
          m_keyA(static_cast<uint64_t>(N) * baseKS * digitCount * n),
          m_keyB(static_cast<uint64_t>(N) * baseKS * digitCount) {}

    // Narrow an existing 64-bit key. Peak memory holds both forms; the released pages come back
    // only after AllocTrim(). Prefer KeySwitchGen32, which never materialises the 64-bit key.
    LWESwitchingKey32Impl(const LWECryptoParams& params, const LWESwitchingKeyImpl& K);

    // exact 64-bit copy for serialization: every value fits, so 32 -> 64 -> 32 is the identity
    LWESwitchingKey Widen(const LWECryptoParams& params) const;

    uint32_t* RowA(uint32_t i, uint32_t val, uint32_t pos) {
        return m_keyA.data() + ((static_cast<uint64_t>(i) * m_m + val) * m_d + pos) * m_n;
    }

    const uint32_t* RowA(uint32_t i, uint32_t val, uint32_t pos) const {
        return m_keyA.data() + ((static_cast<uint64_t>(i) * m_m + val) * m_d + pos) * m_n;
    }

    uint32_t& B(uint32_t i, uint32_t val, uint32_t pos) {
        return m_keyB[(static_cast<uint64_t>(i) * m_m + val) * m_d + pos];
    }

    uint32_t B(uint32_t i, uint32_t val, uint32_t pos) const {
        return m_keyB[(static_cast<uint64_t>(i) * m_m + val) * m_d + pos];
    }

    uint32_t GetN() const {
        return m_N;
    }

    uint32_t GetBaseKS() const {
        return m_m;
    }

    uint32_t GetDigitCount() const {
        return m_d;
    }

    uint32_t Getn() const {
        return m_n;
    }

    uint64_t KeyBytes() const {
        return (m_keyA.size() + m_keyB.size()) * sizeof(uint32_t);
    }

private:
    uint32_t m_N{0};
    uint32_t m_m{0};
    uint32_t m_d{0};
    uint32_t m_n{0};
    std::vector<uint32_t> m_keyA;
    std::vector<uint32_t> m_keyB;
};

#endif  // NATIVEINT != 32

}  // namespace lbcrypto

#endif  // _LWE_KEYSWITCHKEY32_H_
