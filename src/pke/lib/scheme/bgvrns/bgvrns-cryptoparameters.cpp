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
BGV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/bgvrns/bgvrns-cryptoparameters.h"

namespace lbcrypto {

// Precomputation of CRT tables encryption, decryption, and  homomorphic
// multiplication
void CryptoParametersBGVRNS::PrecomputeCRTTables(KeySwitchTechnique ksTech, ScalingTechnique scalTech,
                                                 EncryptionTechnique encTech, MultiplicationTechnique multTech,
                                                 uint32_t numPartQ, uint32_t auxBits, uint32_t extraBits) {
    CryptoParametersRNS::PrecomputeCRTTables(ksTech, scalTech, encTech, multTech, numPartQ, auxBits, extraBits);

    size_t sizeQ = GetElementParams()->GetParams().size();

    std::vector<NativeInteger> moduliQ(sizeQ);
    std::vector<NativeInteger> rootsQ(sizeQ);

    for (size_t i = 0; i < sizeQ; i++) {
        moduliQ[i] = GetElementParams()->GetParams()[i]->GetModulus();
        rootsQ[i]  = GetElementParams()->GetParams()[i]->GetRootOfUnity();
    }

    NativeInteger t(GetPlaintextModulus());

    if (m_ksTechnique == HYBRID) {
        size_t sizeP = GetParamsP()->GetParams().size();
        std::vector<NativeInteger> moduliP(sizeP);
        for (size_t j = 0; j < sizeP; j++) {
            moduliP[j] = GetParamsP()->GetParams()[j]->GetModulus();
        }

        // Pre-compute values [t^{-1}]_{q_i}, precomputations for  [t]_{q_i}
        m_tInvModq.resize(sizeQ);
        m_tInvModqPrecon.resize(sizeQ);
        for (usint i = 0; i < sizeQ; i++) {
            m_tInvModq[i]       = t.ModInverse(moduliQ[i]);
            m_tInvModqPrecon[i] = m_tInvModq[i].PrepModMulConst(moduliQ[i]);
        }

        // Pre-compute values [t^{-1}]_{p_i}, precomputations for [t]_{q_i}
        m_tInvModp.resize(sizeP);
        m_tInvModpPrecon.resize(sizeP);
        for (usint j = 0; j < sizeP; j++) {
            m_tInvModp[j]       = t.ModInverse(moduliP[j]);
            m_tInvModpPrecon[j] = m_tInvModp[j].PrepModMulConst(moduliP[j]);
        }
    }

    m_negtInvModq.resize(sizeQ);
    m_negtInvModqPrecon.resize(sizeQ);
    m_tModqPrecon.resize(sizeQ);
    m_qlInvModq.resize(sizeQ);
    m_qlInvModqPrecon.resize(sizeQ);
    for (usint i = 0; i < sizeQ; i++) {
        m_negtInvModq[i]       = moduliQ[i] - t.ModInverse(moduliQ[i]);
        m_negtInvModqPrecon[i] = m_negtInvModq[i].PrepModMulConst(moduliQ[i]);
        NativeInteger tModQi   = t.Mod(moduliQ[i]);
        m_tModqPrecon[i]       = tModQi.PrepModMulConst(moduliQ[i]);
        m_qlInvModq[i].resize(i);
        m_qlInvModqPrecon[i].resize(i);
        for (usint j = 0; j < i; ++j) {
            m_qlInvModq[i][j]       = moduliQ[i].ModInverse(moduliQ[j]);
            m_qlInvModqPrecon[i][j] = m_qlInvModq[i][j].PrepModMulConst(moduliQ[j]);
        }
    }

    if (m_scalTechnique == FLEXIBLEAUTO || m_scalTechnique == FLEXIBLEAUTOEXT) {
        m_scalingFactorsInt.resize(sizeQ);
        m_scalingFactorsInt[0]     = moduliQ[sizeQ - 1] % t;
        uint32_t isFlexibleAutoExt = (m_scalTechnique == FLEXIBLEAUTOEXT) ? 1 : 0;
        if (isFlexibleAutoExt) {
            m_scalingFactorsInt[1] = moduliQ[sizeQ - 2] % t;
        }
        for (uint32_t k = 1 + isFlexibleAutoExt; k < sizeQ - isFlexibleAutoExt; k++) {
            NativeInteger prevSF   = m_scalingFactorsInt[k - 1];
            NativeInteger qInv     = moduliQ[sizeQ - k].ModInverse(t);
            m_scalingFactorsInt[k] = prevSF.ModMul(prevSF, t).ModMul(qInv, t);
        }

        m_scalingFactorsIntBig.resize(sizeQ - 1);

        if (m_scalingFactorsIntBig.size() > 0) {
            if (m_scalTechnique == FLEXIBLEAUTO) {
                m_scalingFactorsIntBig[0] = m_scalingFactorsInt[0].ModMul(m_scalingFactorsInt[0], t);
            }
            else {
                m_scalingFactorsIntBig[0] = m_scalingFactorsInt[0].ModMul(m_scalingFactorsInt[1], t);
            }
            for (uint32_t k = 1; k < sizeQ - 1; k++) {
                m_scalingFactorsIntBig[k] = m_scalingFactorsInt[k].ModMul(m_scalingFactorsInt[k], t);
            }
        }

        // Moduli mod t
        m_qModt.resize(sizeQ);
        for (usint i = 0; i < sizeQ; i++) {
            m_qModt[i] = moduliQ[i].Mod(t);
        }
    }

    if (m_ksTechnique == HYBRID) {
        const auto BarrettBase128Bit(BigInteger(1).LShiftEq(128));
        m_modqBarrettMu.resize(sizeQ);
        for (uint32_t i = 0; i < sizeQ; i++) {
            m_modqBarrettMu[i] = (BarrettBase128Bit / BigInteger(moduliQ[i])).ConvertToInt<DoubleNativeInt>();
        }
    }
}

uint64_t CryptoParametersBGVRNS::FindAuxPrimeStep() const {
    size_t n               = GetElementParams()->GetRingDimension();
    usint plaintextModulus = GetPlaintextModulus();
    usint cyclOrder        = 2 * n;
    usint pow2ptm          = 1;

    // The largest power of 2 dividing ptm
    // Check whether it is larger than cyclOrder or not
    while (plaintextModulus % 2 == 0) {
        plaintextModulus >>= 1;
        pow2ptm <<= 1;
    }

    if (pow2ptm < cyclOrder)
        pow2ptm = cyclOrder;

    return static_cast<uint64_t>(pow2ptm) * plaintextModulus;
}

}  // namespace lbcrypto
