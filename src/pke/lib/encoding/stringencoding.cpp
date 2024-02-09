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
    if (this->isEncoded)
        return true;
    auto mod = this->encodingParams->GetPlaintextModulus();

    if (mod != 256) {
        OPENFHE_THROW("Plaintext modulus must be " + std::to_string(charPtm) + " for string encoding");
    }

    if (this->typeFlag == IsNativePoly) {
        this->encodedNativeVector.SetValuesToZero();
        size_t i = 0;
        for (; i < ptx.size() && i < this->encodedNativeVector.GetLength(); i++) {
            this->encodedNativeVector[i] = static_cast<uint32_t>(ptx[i]);
        }
        for (; i < this->encodedNativeVector.GetLength(); i++) {
            this->encodedNativeVector[i] = CHARMARKER;
        }
    }
    else {
        this->encodedVector.SetValuesToZero();
        size_t i = 0;
        for (; i < ptx.size() && i < this->encodedVector.GetLength(); i++) {
            this->encodedVector[i] = static_cast<uint32_t>(ptx[i]);
        }
        for (; i < this->encodedVector.GetLength(); i++) {
            this->encodedVector[i] = CHARMARKER;
        }
    }

    if (this->typeFlag == IsDCRTPoly) {
        this->encodedVectorDCRT = this->encodedVector;
    }

    this->isEncoded = true;
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
    auto mod = this->encodingParams->GetPlaintextModulus();

    if (this->typeFlag == IsNativePoly)
        fillPlaintext(this->encodedNativeVector, this->ptx, mod);
    else
        fillPlaintext(this->encodedVector, this->ptx, mod);

    return true;
}

} /* namespace lbcrypto */
