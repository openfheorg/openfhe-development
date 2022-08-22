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

#include "rgsw-cryptoparameters.h"

namespace lbcrypto {

void RingGSWCryptoParams::PreCompute(bool signEval) {
    // Computes baseR^i (only for AP bootstrapping)
    if (m_method == AP) {
        uint32_t digitCountR =
            (uint32_t)std::ceil(log(static_cast<double>(m_q.ConvertToInt())) / log(static_cast<double>(m_baseR)));
        // Populate digits
        NativeInteger value = 1;
        for (uint32_t i = 0; i < digitCountR; i++) {
            m_digitsR.push_back(value);
            value *= m_baseR;
        }
    }

    // Computes baseG^i
    if (signEval) {
        uint32_t baseGlist[3] = {1 << 14, 1 << 18, 1 << 27};
        for (size_t j = 0; j < 3; j++) {
            NativeInteger vTemp = NativeInteger(1);
            auto tempdigits = (uint32_t)std::ceil(log(m_Q.ConvertToDouble()) / log(static_cast<double>(baseGlist[j])));
            std::vector<NativeInteger> tempvec(tempdigits);
            for (uint32_t i = 0; i < tempdigits; i++) {
                tempvec[i] = vTemp;
                vTemp      = vTemp.ModMul(NativeInteger(baseGlist[j]), m_Q);
            }
            m_Gpower_map[baseGlist[j]] = tempvec;
            if (m_baseG == baseGlist[j])
                m_Gpower = tempvec;
        }
    }
    else {
        NativeInteger vTemp = NativeInteger(1);
        for (uint32_t i = 0; i < m_digitsG; i++) {
            m_Gpower.push_back(vTemp);
            vTemp = vTemp.ModMul(NativeInteger(m_baseG), m_Q);
        }
    }

    // Sets the gate constants for supported binary operations
    m_gateConst = {
        NativeInteger(5) * (m_q >> 3),  // OR
        NativeInteger(7) * (m_q >> 3),  // AND
        NativeInteger(1) * (m_q >> 3),  // NOR
        NativeInteger(3) * (m_q >> 3),  // NAND
        NativeInteger(5) * (m_q >> 3),  // XOR_FAST
        NativeInteger(1) * (m_q >> 3)   // XNOR_FAST
    };

    // Computes polynomials X^m - 1 that are needed in the accumulator for the
    // GINX bootstrapping
    if (m_method == GINX) {
        // loop for positive values of m
        for (uint32_t i = 0; i < m_N; i++) {
            NativePoly aPoly = NativePoly(m_polyParams, Format::COEFFICIENT, true);
            aPoly[i].ModAddEq(NativeInteger(1), m_Q);  // X^m
            aPoly[0].ModSubEq(NativeInteger(1), m_Q);  // -1
            aPoly.SetFormat(Format::EVALUATION);
            m_monomials.push_back(aPoly);
        }

        // loop for negative values of m
        for (uint32_t i = 0; i < m_N; i++) {
            NativePoly aPoly = NativePoly(m_polyParams, Format::COEFFICIENT, true);
            aPoly[i].ModSubEq(NativeInteger(1), m_Q);  // -X^m
            aPoly[0].ModSubEq(NativeInteger(1), m_Q);  // -1
            aPoly.SetFormat(Format::EVALUATION);
            m_monomials.push_back(aPoly);
        }
    }

    // #if defined(BINFHE_DEBUG)
    //    std::cerr << "base_g = " << m_baseG << std::endl;
    //    std::cerr << "m_digitsG = " << m_digitsG << std::endl;
    //    std::cerr << "m_digitsG2 = " << m_digitsG2 << std::endl;
    //    std::cerr << "m_baseR = " << m_baseR << std::endl;
    //    std::cerr << "m_digitsR = " << m_digitsR << std::endl;
    //    std::cerr << "m_Gpower = " << m_Gpower << std::endl;
    //    std::cerr << "n = " << m_LWEParams->Getn() << std::endl;
    //    std::cerr << "N = " << m_LWEParams->GetN() << std::endl;
    //    std::cerr << "q = " << m_LWEParams->Getq() << std::endl;
    //    std::cerr << "Q = " << m_LWEParams->GetQ() << std::endl;
    //    std::cerr << "baseKS = " << m_LWEParams->GetBaseKS() << std::endl;
    //    std::cerr << "digitsKS = " << m_LWEParams->GetDigitsKS() << std::endl;
    // #endif
}

};  // namespace lbcrypto
