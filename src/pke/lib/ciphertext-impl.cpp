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

#include "ciphertext.h"
#include "cryptocontext.h"

namespace lbcrypto {

template <>
void CiphertextImpl<DCRTPoly>::SetLevel(size_t level) {
    m_level = level;
    // check if the multiplication depth value is sufficient. The check should be in this function as
    // SetLevel() gets always called
    uint32_t limbNum = m_elements[0].GetNumOfElements();

    const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(
        CryptoObject<DCRTPoly>::GetCryptoContext()->GetCryptoParameters());
    if (!cryptoParams) {
        OPENFHE_THROW("dynamic_pointer_cast<CryptoParametersRNS> failed");
    }

    uint32_t multDepth = cryptoParams->GetMultiplicativeDepth();
    // std::cout << "level: " << level << "; limbNum: " << limbNum << "; multDepth: " << multDepth << std::endl;

    if (limbNum > multDepth) {
        OPENFHE_THROW("The multiplicative depth of [" + std::to_string(multDepth) +
                      "] is insufficient for ciphertext with " + std::to_string(limbNum) + " limbs.");
    }
}

template class CiphertextImpl<Poly>;
template class CiphertextImpl<NativePoly>;
template class CiphertextImpl<DCRTPoly>;

}  // namespace lbcrypto
