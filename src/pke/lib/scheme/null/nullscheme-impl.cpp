// @file nullscheme-impl.cpp - template instantiations and methods for the NULL
// scheme
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

#include "cryptocontext.h"
#include "scheme/null/nullscheme.h"

namespace lbcrypto {

template <>
Ciphertext<Poly> LPAlgorithmSHENull<Poly>::EvalMult(
    ConstCiphertext<Poly> ciphertext1,
    ConstCiphertext<Poly> ciphertext2) const {
  Ciphertext<Poly> newCiphertext = ciphertext1->CloneEmpty();

  const Poly& c1 = ciphertext1->GetElement();
  const Poly& c2 = ciphertext2->GetElement();

  const auto ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

  Poly cResult = ElementNullSchemeMultiply(c1, c2, ptm);

  newCiphertext->SetElement(cResult);

  return newCiphertext;
}

template <>
Ciphertext<Poly> LPAlgorithmSHENull<Poly>::EvalMult(
    ConstCiphertext<Poly> ciphertext1, ConstPlaintext plaintext) const {
  Ciphertext<Poly> newCiphertext = ciphertext1->CloneEmpty();

  const Poly& c1 = ciphertext1->GetElement();
  const Poly& c2 = plaintext->GetElement<Poly>();

  const auto ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

  Poly cResult = ElementNullSchemeMultiply(c1, c2, ptm);

  newCiphertext->SetElement(cResult);

  return newCiphertext;
}

template class LPCryptoParametersNull<Poly>;
template class LPPublicKeyEncryptionSchemeNull<Poly>;
template class LPAlgorithmNull<Poly>;
template class LPAlgorithmParamsGenNull<Poly>;
template class LPAlgorithmSHENull<Poly>;
template class LPLeveledSHEAlgorithmNull<Poly>;

template <>
Ciphertext<NativePoly> LPAlgorithmSHENull<NativePoly>::EvalMult(
    ConstCiphertext<NativePoly> ciphertext1,
    ConstCiphertext<NativePoly> ciphertext2) const {
  Ciphertext<NativePoly> newCiphertext = ciphertext1->CloneEmpty();

  const NativePoly& c1 = ciphertext1->GetElement();
  const NativePoly& c2 = ciphertext2->GetElement();

  const auto ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

  NativePoly cResult = ElementNullSchemeMultiply(c1, c2, ptm);

  newCiphertext->SetElement(cResult);

  return newCiphertext;
}

template <>
Ciphertext<NativePoly> LPAlgorithmSHENull<NativePoly>::EvalMult(
    ConstCiphertext<NativePoly> ciphertext1, ConstPlaintext plaintext) const {
  Ciphertext<NativePoly> newCiphertext = ciphertext1->CloneEmpty();

  const NativePoly& c1 = ciphertext1->GetElement();
  const NativePoly& c2 = plaintext->GetElement<NativePoly>();

  const auto ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

  NativePoly cResult = ElementNullSchemeMultiply(c1, c2, ptm);

  newCiphertext->SetElement(cResult);

  return newCiphertext;
}

template class LPCryptoParametersNull<NativePoly>;
template class LPPublicKeyEncryptionSchemeNull<NativePoly>;
template class LPAlgorithmNull<NativePoly>;
template class LPAlgorithmParamsGenNull<NativePoly>;
template class LPAlgorithmSHENull<NativePoly>;
template class LPLeveledSHEAlgorithmNull<NativePoly>;

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHENull<DCRTPoly>::EvalMult(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  Ciphertext<DCRTPoly> newCiphertext = ciphertext1->CloneEmpty();

  const DCRTPoly& c1 = ciphertext1->GetElement();
  const DCRTPoly& c2 = ciphertext2->GetElement();

  const vector<PolyType>& c1e = c1.GetAllElements();
  const vector<PolyType>& c2e = c2.GetAllElements();

  const auto ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

  vector<PolyType> mResults;

  for (size_t i = 0; i < c1.GetNumOfElements(); i++) {
    PolyType v = ElementNullSchemeMultiply(c1e.at(i), c2e.at(i), ptm);
    mResults.push_back(std::move(v));
  }

  DCRTPoly cResult(mResults);

  newCiphertext->SetElement(std::move(cResult));

  return newCiphertext;
}

template <>
Ciphertext<DCRTPoly> LPAlgorithmSHENull<DCRTPoly>::EvalMult(
    ConstCiphertext<DCRTPoly> ciphertext1, ConstPlaintext plaintext) const {
  Ciphertext<DCRTPoly> newCiphertext = ciphertext1->CloneEmpty();

  const DCRTPoly& c1 = ciphertext1->GetElement();
  const DCRTPoly& c2 = plaintext->GetElement<DCRTPoly>();

  const vector<PolyType>& c1e = c1.GetAllElements();
  const vector<PolyType>& c2e = c2.GetAllElements();

  const auto ptm = ciphertext1->GetCryptoParameters()->GetPlaintextModulus();

  vector<PolyType> mResults;

  for (size_t i = 0; i < c1.GetNumOfElements(); i++) {
    PolyType v = ElementNullSchemeMultiply(c1e.at(i), c2e.at(i), ptm);
    mResults.push_back(std::move(v));
  }

  DCRTPoly cResult(mResults);

  newCiphertext->SetElement(std::move(cResult));

  return newCiphertext;
}

template class LPCryptoParametersNull<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeNull<DCRTPoly>;
template class LPAlgorithmNull<DCRTPoly>;
template class LPAlgorithmParamsGenNull<DCRTPoly>;
template class LPAlgorithmSHENull<DCRTPoly>;
template class LPLeveledSHEAlgorithmNull<DCRTPoly>;

}  // namespace lbcrypto
