// @file coefpackedencoding.cpp Represents and defines packing integers of
// plaintext objects into polynomial coefficients in Palisade.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "encoding/coefpackedencoding.h"

namespace lbcrypto {

template <typename P>
inline static void encodeVec(P& poly, const PlaintextModulus& mod, int64_t lb,
                             int64_t ub, const vector<int64_t>& value) {
  poly.SetValuesToZero();

  const typename P::Integer& q = poly.GetModulus();

  for (size_t i = 0; i < value.size() && i < poly.GetLength(); i++) {
    if (value[i] > INT32_MAX || value[i] < INT32_MIN) {
      PALISADE_THROW(config_error,
                     "Cannot encode a coefficient larger than 32 bits");
    }

    if (value[i] <= lb || value[i] > ub)
      PALISADE_THROW(config_error,
                     "Cannot encode integer " + std::to_string(value[i]) +
                         " at position " + std::to_string(i) +
                         " because it is out of range of plaintext modulus " +
                         std::to_string(mod));

    typename P::Integer entry = value[i];

    if (value[i] < 0) {
      // It is more efficient to encode negative numbers using the ciphertext
      // modulus no noise growth occurs
      entry = q - typename P::Integer(llabs(value[i]));
    }

    poly[i] = entry;
  }
}

bool CoefPackedEncoding::Encode() {
  if (this->isEncoded) return true;
  PlaintextModulus mod = this->encodingParams->GetPlaintextModulus();

  if (this->typeFlag == IsNativePoly) {
    encodeVec(this->encodedNativeVector, mod, LowBound(), HighBound(),
              this->value);
  } else {
    encodeVec(this->encodedVector, mod, LowBound(), HighBound(), this->value);
  }

  if (this->typeFlag == IsDCRTPoly) {
    this->encodedVectorDCRT = this->encodedVector;
  }

  this->isEncoded = true;
  return true;
}

template <typename P>
inline static void fillVec(const P& poly, const PlaintextModulus& mod,
                           vector<int64_t>& value) {
  value.clear();

  int64_t half = int64_t(mod) / 2;
  const typename P::Integer& q = poly.GetModulus();
  typename P::Integer qHalf = q >> 1;

  for (size_t i = 0; i < poly.GetLength(); i++) {
    int64_t val;
    if (poly[i] > qHalf)
      val = (-(q - poly[i]).ConvertToInt());
    else
      val = poly[i].ConvertToInt();
    if (val > half) val -= mod;
    value.push_back(val);
  }
}

bool CoefPackedEncoding::Decode() {
  PlaintextModulus mod = this->encodingParams->GetPlaintextModulus();

  if (this->typeFlag == IsNativePoly) {
    fillVec(this->encodedNativeVector, mod, this->value);
  } else {
    fillVec(this->encodedVector, mod, this->value);
  }

  return true;
}

} /* namespace lbcrypto */
