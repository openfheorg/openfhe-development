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
  Manufactures plaintext objects in OpenFHE
 */

#ifndef SRC_CORE_LIB_ENCODING_PLAINTEXTFACTORY_H_
#define SRC_CORE_LIB_ENCODING_PLAINTEXTFACTORY_H_

#include "encoding/encodings.h"
#include "scheme/scheme-id.h"

#include <memory>
#include <string>
#include <vector>

// TODO: when the parms are polymorphic, reduce the tuple of methods to a
// single one

namespace lbcrypto {

class PlaintextFactory {
    PlaintextFactory() = delete;  // never construct one!

public:
    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                      std::is_same<T, NativePoly::Params>::value ||
                                                      std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    static Plaintext MakePlaintext(PlaintextEncodings encoding, std::shared_ptr<T> vp, EncodingParams ep,
                                   SCHEME schemeID = SCHEME::INVALID_SCHEME) {
        switch (encoding) {
            case COEF_PACKED_ENCODING:
                return std::make_shared<CoefPackedEncoding>(vp, ep, schemeID);
            case PACKED_ENCODING:
                return std::make_shared<PackedEncoding>(vp, ep);
            case STRING_ENCODING:
                return std::make_shared<StringEncoding>(vp, ep);
            case CKKS_PACKED_ENCODING:
                return std::make_shared<CKKSPackedEncoding>(vp, ep);
            default:
                OPENFHE_THROW("Unknown plaintext encoding type in MakePlaintext");
        }
    }

    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                      std::is_same<T, NativePoly::Params>::value ||
                                                      std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    static Plaintext MakePlaintext(const std::vector<int64_t>& value, PlaintextEncodings encoding,
                                   std::shared_ptr<T> vp, EncodingParams ep, SCHEME schemeID = SCHEME::INVALID_SCHEME,
                                   size_t noiseScaleDeg = 1, uint32_t level = 0, NativeInteger scalingFactor = 1) {
        // Check if plaintext has got enough slots for data (value)
        usint ringDim    = vp->GetRingDimension();
        size_t valueSize = value.size();
        if (isCKKS(schemeID) && valueSize > ringDim / 2) {
            OPENFHE_THROW("The size [" + std::to_string(valueSize) +
                          "] of the vector with values should not be greater than ringDim/2 [" +
                          std::to_string(ringDim / 2) + "] if the scheme is CKKS");
        }
        else if (valueSize > ringDim) {
            OPENFHE_THROW("The size [" + std::to_string(valueSize) +
                          "] of the vector with values should not be greater than ringDim [" + std::to_string(ringDim) +
                          "] if the scheme is NOT CKKS");
        }
        Plaintext pt = MakePlaintext(encoding, vp, ep, schemeID);
        pt->SetIntVectorValue(value);
        pt->SetNoiseScaleDeg(noiseScaleDeg);
        pt->SetLevel(level);
        pt->SetScalingFactorInt(scalingFactor);
        pt->Encode();
        return pt;
    }

    template <typename T, typename std::enable_if<std::is_same<T, Poly::Params>::value ||
                                                      std::is_same<T, NativePoly::Params>::value ||
                                                      std::is_same<T, DCRTPoly::Params>::value,
                                                  bool>::type = true>
    static Plaintext MakePlaintext(const std::string& value, PlaintextEncodings encoding, std::shared_ptr<T> vp,
                                   EncodingParams ep, SCHEME schemeID = SCHEME::INVALID_SCHEME,
                                   size_t noiseScaleDeg = 1, uint32_t level = 0, NativeInteger scalingFactor = 1) {
        // Check if plaintext has got enough slots for data (value)
        usint ringDim    = vp->GetRingDimension();
        size_t valueSize = value.size();
        if (isCKKS(schemeID) && valueSize > ringDim / 2) {
            OPENFHE_THROW("The size [" + std::to_string(valueSize) +
                          "] of the vector with values should not be greater than ringDim/2 [" +
                          std::to_string(ringDim / 2) + "] if the scheme is CKKS");
        }
        else if (valueSize > ringDim) {
            OPENFHE_THROW("The size [" + std::to_string(valueSize) +
                          "] of the vector with values should not be greater than ringDim [" + std::to_string(ringDim) +
                          "] if the scheme is NOT CKKS");
        }
        Plaintext pt = MakePlaintext(encoding, vp, ep, schemeID);
        pt->SetStringValue(value);
        pt->SetNoiseScaleDeg(noiseScaleDeg);
        pt->SetLevel(level);
        pt->SetScalingFactorInt(scalingFactor);
        pt->Encode();
        return pt;
    }
};

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_ENCODING_PLAINTEXTFACTORY_H_ */
