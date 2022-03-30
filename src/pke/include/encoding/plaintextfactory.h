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

#include <memory>
#include <string>
#include <vector>

#include "encoding/encodings.h"

// TODO: when the parms are polymorphic, reduce the tuple of methods to a
// single one

namespace lbcrypto {

class PlaintextFactory {
  PlaintextFactory() {}  // never construct one!

 public:
  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 std::shared_ptr<Poly::Params> vp,
                                 EncodingParams ep) {
    Plaintext pt;

    switch (encoding) {
      case Unknown:
        OpenFHE_THROW(type_error,
                       "Unknown plaintext encoding type in MakePlaintext");
        break;
      case CoefPacked:
        pt = std::make_shared<CoefPackedEncoding>(vp, ep);
        break;
      case Packed:
        pt = std::make_shared<PackedEncoding>(vp, ep);
        break;
      case String:
        pt = std::make_shared<StringEncoding>(vp, ep);
        break;
      case CKKSPacked:
        pt = std::make_shared<CKKSPackedEncoding>(vp, ep);
        break;
    }

    return pt;
  }

  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 std::shared_ptr<NativePoly::Params> vp,
                                 EncodingParams ep) {
    Plaintext pt;

    switch (encoding) {
      case Unknown:
        OpenFHE_THROW(type_error,
                       "Unknown plaintext encoding type in MakePlaintext");
        break;
      case CoefPacked:
        pt = std::make_shared<CoefPackedEncoding>(vp, ep);
        break;
      case Packed:
        pt = std::make_shared<PackedEncoding>(vp, ep);
        break;
      case String:
        pt = std::make_shared<StringEncoding>(vp, ep);
        break;
      case CKKSPacked:
        pt = std::make_shared<CKKSPackedEncoding>(vp, ep);
        break;
    }

    return pt;
  }

  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 std::shared_ptr<DCRTPoly::Params> vp,
                                 EncodingParams ep) {
    Plaintext pt;

    switch (encoding) {
      case Unknown:
        OpenFHE_THROW(type_error,
                       "Unknown plaintext encoding type in MakePlaintext");
        break;
      case CoefPacked:
        pt = std::make_shared<CoefPackedEncoding>(vp, ep);
        break;
      case Packed:
        pt = std::make_shared<PackedEncoding>(vp, ep);
        break;
      case String:
        pt = std::make_shared<StringEncoding>(vp, ep);
        break;
      case CKKSPacked:
        pt = std::make_shared<CKKSPackedEncoding>(vp, ep);
        break;
    }

    return pt;
  }

  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 std::shared_ptr<Poly::Params> vp, EncodingParams ep,
                                 const std::vector<int64_t>& value) {
    Plaintext pt = MakePlaintext(encoding, vp, ep);
    pt->SetIntVectorValue(value);
    pt->Encode();
    return pt;
  }

  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 std::shared_ptr<NativePoly::Params> vp,
                                 EncodingParams ep,
                                 const std::vector<int64_t>& value) {
    Plaintext pt = MakePlaintext(encoding, vp, ep);
    pt->SetIntVectorValue(value);
    pt->Encode();
    return pt;
  }

  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 std::shared_ptr<DCRTPoly::Params> vp,
                                 EncodingParams ep,
                                 const std::vector<int64_t>& value) {
    Plaintext pt = MakePlaintext(encoding, vp, ep);
    pt->SetIntVectorValue(value);
    pt->Encode();
    return pt;
  }

  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 std::shared_ptr<Poly::Params> vp, EncodingParams ep,
                                 const std::string& value) {
    Plaintext pt = MakePlaintext(encoding, vp, ep);
    pt->SetStringValue(value);
    pt->Encode();
    return pt;
  }

  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 std::shared_ptr<NativePoly::Params> vp,
                                 EncodingParams ep, const std::string& value) {
    Plaintext pt = MakePlaintext(encoding, vp, ep);
    pt->SetStringValue(value);
    pt->Encode();
    return pt;
  }

  static Plaintext MakePlaintext(PlaintextEncodings encoding,
                                 std::shared_ptr<DCRTPoly::Params> vp,
                                 EncodingParams ep, const std::string& value) {
    Plaintext pt = MakePlaintext(encoding, vp, ep);
    pt->SetStringValue(value);
    pt->Encode();
    return pt;
  }
};

} /* namespace lbcrypto */

#endif /* SRC_CORE_LIB_ENCODING_PLAINTEXTFACTORY_H_ */
