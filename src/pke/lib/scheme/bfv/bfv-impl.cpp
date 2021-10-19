// @file bfv-impl.cpp - template instantiations and methods for the BFV scheme
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

#include "bfv.cpp"

namespace lbcrypto {

template <>
LPPublicKeyEncryptionSchemeBFV<Poly>::LPPublicKeyEncryptionSchemeBFV()
    : LPPublicKeyEncryptionScheme<Poly>() {
  this->m_algorithmParamsGen =
      std::make_shared<LPAlgorithmParamsGenBFV<Poly>>();
}

template <>
LPPublicKeyEncryptionSchemeBFV<NativePoly>::LPPublicKeyEncryptionSchemeBFV()
    : LPPublicKeyEncryptionScheme<NativePoly>() {
  this->m_algorithmParamsGen =
      std::make_shared<LPAlgorithmParamsGenBFV<NativePoly>>();
}

template class LPCryptoParametersBFV<Poly>;
template class LPPublicKeyEncryptionSchemeBFV<Poly>;
template class LPAlgorithmBFV<Poly>;
template class LPAlgorithmParamsGenBFV<Poly>;
template class LPAlgorithmPREBFV<Poly>;
template class LPAlgorithmSHEBFV<Poly>;

template class LPCryptoParametersBFV<NativePoly>;
template class LPPublicKeyEncryptionSchemeBFV<NativePoly>;
template class LPAlgorithmBFV<NativePoly>;
template class LPAlgorithmParamsGenBFV<NativePoly>;
template class LPAlgorithmPREBFV<NativePoly>;
template class LPAlgorithmSHEBFV<NativePoly>;

template <>
LPCryptoParametersBFV<DCRTPoly>::LPCryptoParametersBFV() {
  std::string errMsg = "BFV does not support DCRTPoly. Use Poly instead.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
LPCryptoParametersBFV<DCRTPoly>::LPCryptoParametersBFV(
    const LPCryptoParametersBFV &rhs) {
  std::string errMsg = "BFV does not support DCRTPoly. Use Poly instead.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
LPCryptoParametersBFV<DCRTPoly>::LPCryptoParametersBFV(
    shared_ptr<ParmType> params, const PlaintextModulus &plaintextModulus,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, const BigInteger &delta, MODE mode,
    const BigInteger &bigModulus, const BigInteger &bigRootOfUnity,
    const BigInteger &bigModulusArb, const BigInteger &bigRootOfUnityArb,
    int depth, int maxDepth) {
  std::string errMsg = "BFV does not support DCRTPoly. Use Poly instead.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
LPCryptoParametersBFV<DCRTPoly>::LPCryptoParametersBFV(
    shared_ptr<ParmType> params, EncodingParams encodingParams,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, const BigInteger &delta, MODE mode,
    const BigInteger &bigModulus, const BigInteger &bigRootOfUnity,
    const BigInteger &bigModulusArb, const BigInteger &bigRootOfUnityArb,
    int depth, int maxDepth) {
  std::string errMsg = "BFV does not support DCRTPoly. Use Poly instead.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template <>
LPPublicKeyEncryptionSchemeBFV<DCRTPoly>::LPPublicKeyEncryptionSchemeBFV() {
  std::string errMsg = "BFV does not support DCRTPoly. Use Poly instead.";
  PALISADE_THROW(not_implemented_error, errMsg);
}

template class LPCryptoParametersBFV<DCRTPoly>;
template class LPPublicKeyEncryptionSchemeBFV<DCRTPoly>;
template class LPAlgorithmBFV<DCRTPoly>;
template class LPAlgorithmParamsGenBFV<DCRTPoly>;
template class LPAlgorithmPREBFV<DCRTPoly>;
template class LPAlgorithmSHEBFV<DCRTPoly>;

}  // namespace lbcrypto
