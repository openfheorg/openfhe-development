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

#include <cstdint>

#include "ciphertext.h"
#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "utils/parallel.h"

namespace lbcrypto {

template <>
void CiphertextImpl<DCRTPoly>::SetLevel(size_t level) {
    m_level = level;

    // check if the multiplication depth value is sufficient in SetLevel() as it always gets called
    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
            CryptoObject<DCRTPoly>::GetCryptoContext()->GetCryptoParameters());
    // the multDepth check applies only to CKKS, when cryptoParams is of type CryptoParametersCKKSRNS.
    if (cryptoParams) {
        uint32_t limbNum = m_elements[0].GetNumOfElements();
        if (limbNum < GetNoiseScaleDeg()) {
            uint32_t multDepth = cryptoParams->GetMultiplicativeDepth();
            OPENFHE_THROW("The current multiplicative depth [" + std::to_string(multDepth) +
                          "] is insufficient; increase it.");
        }
    }
}

template <>
Ciphertext<DCRTPoly> CiphertextImpl<DCRTPoly>::Clone() const {
    auto ct = this->CloneEmpty();
    const uint32_t sizeCv = m_elements.size();
    const uint32_t numTowers = (sizeCv > 0) ? m_elements[0].GetNumOfElements() : 0;
    const uint32_t numTasks = sizeCv * numTowers;
    bool sameTowers = true;
    for (const auto& element : m_elements)
        sameTowers = sameTowers && (element.GetNumOfElements() == numTowers);
    if (!sameTowers || numTasks < 2 || ParallelControls::InParallelRegion() ||
        static_cast<uint64_t>(numTasks) * m_elements[0].GetRingDimension() < (uint64_t{1} << 16)) {
        ct->m_elements = m_elements;
        return ct;
    }

    auto& elements = ct->m_elements;
    elements.reserve(sizeCv);
    for (const auto& element : m_elements)
        elements.emplace_back(element.GetParams(), element.GetFormat(), false);
    const uint32_t width =
            (numTasks < static_cast<uint32_t>(OpenFHEParallelControls.GetNumThreads())) ? numTasks : numTowers;
#pragma omp parallel for num_threads(OpenFHEParallelControls.GetThreadLimit(width))
    for (uint32_t task = 0; task < numTasks; ++task) {
        const uint32_t k = task / numTowers;
        const uint32_t i = task % numTowers;
        elements[k].GetAllElements()[i] = m_elements[k].GetElementAtIndex(i);
    }
    return ct;
}

template class CiphertextImpl<Poly>;
template class CiphertextImpl<NativePoly>;
template class CiphertextImpl<DCRTPoly>;

}  // namespace lbcrypto
