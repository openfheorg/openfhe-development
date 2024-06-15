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
CKKS implementation. See https://eprint.iacr.org/2020/1118 for details.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"

namespace lbcrypto {

// Precomputation of CRT tables encryption, decryption, and  homomorphic
// multiplication
void CryptoParametersCKKSRNS::PrecomputeCRTTables(KeySwitchTechnique ksTech, ScalingTechnique scalTech,
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

    BigInteger modulusQ = GetElementParams()->GetModulus();
    // Pre-compute values for rescaling
    // modulusQ holds Q^(l) = \prod_{i=0}^{i=l}(q_i).
    m_QlQlInvModqlDivqlModq.resize(sizeQ - 1);
    m_QlQlInvModqlDivqlModqPrecon.resize(sizeQ - 1);
    m_qlInvModq.resize(sizeQ - 1);
    m_qlInvModqPrecon.resize(sizeQ - 1);
    for (size_t k = 0; k < sizeQ - 1; k++) {
        size_t l = sizeQ - (k + 1);
        modulusQ = modulusQ / BigInteger(moduliQ[l]);
        m_QlQlInvModqlDivqlModq[k].resize(l);
        m_QlQlInvModqlDivqlModqPrecon[k].resize(l);
        m_qlInvModq[k].resize(l);
        m_qlInvModqPrecon[k].resize(l);
        BigInteger QlInvModql = modulusQ.ModInverse(moduliQ[l]);
        BigInteger result     = (QlInvModql * modulusQ) / BigInteger(moduliQ[l]);
        for (usint i = 0; i < l; i++) {
            m_QlQlInvModqlDivqlModq[k][i]       = result.Mod(moduliQ[i]).ConvertToInt();
            m_QlQlInvModqlDivqlModqPrecon[k][i] = m_QlQlInvModqlDivqlModq[k][i].PrepModMulConst(moduliQ[i]);
            m_qlInvModq[k][i]                   = moduliQ[l].ModInverse(moduliQ[i]);
            m_qlInvModqPrecon[k][i]             = m_qlInvModq[k][i].PrepModMulConst(moduliQ[i]);
        }
    }

    // Pre-compute scaling factors for each level (used in EXACT scaling technique)
    if (m_scalTechnique == FLEXIBLEAUTO || m_scalTechnique == FLEXIBLEAUTOEXT) {
        m_scalingFactorsReal.resize(sizeQ);
        m_scalingFactorsReal[0] = moduliQ[sizeQ - 1].ConvertToDouble();

        if (extraBits == 0) {
            for (uint32_t k = 1; k < sizeQ; k++) {
                double prevSF           = m_scalingFactorsReal[k - 1];
                m_scalingFactorsReal[k] = prevSF * prevSF / moduliQ[sizeQ - k].ConvertToDouble();
                double ratio            = m_scalingFactorsReal[k] / m_scalingFactorsReal[0];

                if (ratio <= 0.5 || ratio >= 2.0)
                    OPENFHE_THROW(
                        "CryptoParametersCKKSRNS::PrecomputeCRTTables "
                        "- FLEXIBLEAUTO cannot support this "
                        "number of levels in this parameter setting. Please use "
                        "FIXEDMANUAL.");
            }
        }
        else {
            m_scalingFactorsReal[1] = moduliQ[sizeQ - 2].ConvertToDouble();
            for (uint32_t k = 2; k < sizeQ; k++) {
                double prevSF           = m_scalingFactorsReal[k - 1];
                m_scalingFactorsReal[k] = prevSF * prevSF / moduliQ[sizeQ - k].ConvertToDouble();
                double ratio            = m_scalingFactorsReal[k] / m_scalingFactorsReal[1];

                if (ratio <= 0.5 || ratio >= 2.0)
                    OPENFHE_THROW(
                        "CryptoParametersCKKSRNS::PrecomputeCRTTables "
                        "- FLEXIBLEAUTO cannot support this "
                        "number of levels in this parameter setting. Please use "
                        "FIXEDMANUAL.");
            }
        }

        m_scalingFactorsRealBig.resize(sizeQ - 1);

        if (m_scalingFactorsRealBig.size() > 0) {
            if (extraBits == 0) {
                m_scalingFactorsRealBig[0] = m_scalingFactorsReal[0] * m_scalingFactorsReal[0];
            }
            else {
                m_scalingFactorsRealBig[0] = m_scalingFactorsReal[0] * m_scalingFactorsReal[1];
            }
            for (uint32_t k = 1; k < sizeQ - 1; k++) {
                m_scalingFactorsRealBig[k] = m_scalingFactorsReal[k] * m_scalingFactorsReal[k];
            }
        }

        // Moduli as real
        m_dmoduliQ.resize(sizeQ);
        for (uint32_t i = 0; i < sizeQ; ++i) {
            m_dmoduliQ[i] = moduliQ[i].ConvertToDouble();
        }
    }
    else {
        const auto p = GetPlaintextModulus();
        m_approxSF   = pow(2, p);
    }
    if (m_ksTechnique == HYBRID) {
        const auto BarrettBase128Bit(BigInteger(1).LShiftEq(128));
        m_modqBarrettMu.resize(sizeQ);
        for (uint32_t i = 0; i < sizeQ; i++) {
            m_modqBarrettMu[i] = (BarrettBase128Bit / BigInteger(moduliQ[i])).ConvertToInt<DoubleNativeInt>();
        }
    }
}

uint64_t CryptoParametersCKKSRNS::FindAuxPrimeStep() const {
    size_t n = GetElementParams()->GetRingDimension();
    return static_cast<uint64_t>(2 * n);
}

}  // namespace lbcrypto
