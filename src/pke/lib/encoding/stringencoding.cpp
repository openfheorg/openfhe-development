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
  Represents and defines string-encoded plaintext objects in OpenFHE
 */

#include "encoding/stringencoding.h"

namespace lbcrypto {

static const size_t charPtm      = (1 << 8);
static const uint32_t CHARMARKER = (1 << 7);

bool StringEncoding::Encode() {
    if (m_isEncoded)
        return true;
    auto mod = m_encodingParams->GetPlaintextModulus();

    if (mod != 256) {
        OPENFHE_THROW("Plaintext modulus must be " + std::to_string(charPtm) + " for string encoding");
    }

    if (m_typeFlag == IsNativePoly) {
        m_encodedNativeVector.SetValuesToZero();
        size_t i = 0;
        for (; i < m_ptx.size() && i < m_encodedNativeVector.GetLength(); i++) {
            m_encodedNativeVector[i] = static_cast<uint32_t>(m_ptx[i]);
        }
        for (; i < m_encodedNativeVector.GetLength(); i++) {
            m_encodedNativeVector[i] = CHARMARKER;
        }
    }
    else {
        m_encodedVector.SetValuesToZero();
        size_t i = 0;
        for (; i < m_ptx.size() && i < m_encodedVector.GetLength(); i++) {
            m_encodedVector[i] = static_cast<uint32_t>(m_ptx[i]);
        }
        for (; i < m_encodedVector.GetLength(); i++) {
            m_encodedVector[i] = CHARMARKER;
        }
    }

    if (m_typeFlag == IsDCRTPoly) {
        m_encodedVectorDCRT = m_encodedVector;
        m_encodedVectorDCRT.SetFormat(Format::EVALUATION);
    }

    m_isEncoded = true;
    return true;
}

template <typename P>
static void fillPlaintext(const P& poly, std::string& str, const PlaintextModulus& mod) {
    str.clear();
    for (size_t i = 0; i < poly.GetLength(); i++) {
        uint32_t ch = (poly[i].ConvertToInt() % mod) & 0xff;
        if (ch == CHARMARKER)
            break;
        str += static_cast<char>(ch);
    }
}

bool StringEncoding::Decode() {
    auto mod = m_encodingParams->GetPlaintextModulus();

    if (m_typeFlag == IsNativePoly) {
        fillPlaintext(m_encodedNativeVector, m_ptx, mod);
        // clears the values containing information about the noise
        m_encodedNativeVector.SetValuesToZero();
    }
    else {
        fillPlaintext(m_encodedVector, m_ptx, mod);
        // clears the values containing information about the noise
        m_encodedVector.SetValuesToZero();
    }

    return true;
}

} /* namespace lbcrypto */
