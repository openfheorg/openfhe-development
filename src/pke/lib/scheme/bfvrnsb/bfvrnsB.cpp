// @file bfvrnsB.cpp - implementation of the BEHZ variant of BFVrns.
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
/*
Description:

This code implements a RNS variant of the Brakerski-Fan-Vercauteren (BFV)
homomorphic encryption scheme.  This scheme is also referred to as the FV
scheme.

The BFV scheme is introduced in the following papers:
   - Zvika Brakerski (2012). Fully Homomorphic Encryption without Modulus
Switching from Classical GapSVP. Cryptology ePrint Archive, Report 2012/078.
(https://eprint.iacr.org/2012/078)
   - Junfeng Fan and Frederik Vercauteren (2012). Somewhat Practical Fully
Homomorphic Encryption.  Cryptology ePrint Archive, Report 2012/144.
(https://eprint.iacr.org/2012/144.pdf)

 Our implementation builds from the designs here:
   - Lepoint T., Naehrig M. (2014) A Comparison of the Homomorphic Encryption
Schemes FV and YASHE. In: Pointcheval D., Vergnaud D. (eds) Progress in
Cryptology – AFRICACRYPT 2014. AFRICACRYPT 2014. Lecture Notes in Computer
Science, vol 8469. Springer, Cham. (https://eprint.iacr.org/2014/062.pdf)
   - Jean-Claude Bajard and Julien Eynard and Anwar Hasan and Vincent Zucca
(2016). A Full RNS Variant of FV like Somewhat Homomorphic Encryption Schemes.
Cryptology ePrint Archive, Report 2016/510. (https://eprint.iacr.org/2016/510)
   - Ahmad Al Badawi and Yuriy Polyakov and Khin Mi Mi Aung and Bharadwaj
Veeravalli and Kurt Rohloff (2018). Implementation and Performance Evaluation of
RNS Variants of the BFV Homomorphic Encryption Scheme. Cryptology ePrint
Archive, Report 2018/589. {https://eprint.iacr.org/2018/589}
 */

#ifndef LBCRYPTO_CRYPTO_BFVRNS_B_C
#define LBCRYPTO_CRYPTO_BFVRNS_B_C

#include <fstream>
#include <iostream>
#include "scheme/bfvrnsb/bfvrnsB.h"

namespace lbcrypto {

template <class Element>
LPCryptoParametersBFVrnsB<Element>::LPCryptoParametersBFVrnsB()
    : LPCryptoParametersRLWE<Element>(),
      m_numq(0),
      m_numb(0),
      m_negQInvModmtilde(0) {}

template <class Element>
LPCryptoParametersBFVrnsB<Element>::LPCryptoParametersBFVrnsB(
    const LPCryptoParametersBFVrnsB &rhs)
    : LPCryptoParametersRLWE<Element>(rhs),
      m_numq(0),
      m_numb(0),
      m_negQInvModmtilde(0) {}

template <class Element>
LPCryptoParametersBFVrnsB<Element>::LPCryptoParametersBFVrnsB(
    shared_ptr<ParmType> params, const PlaintextModulus &plaintextModulus,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth)
    : LPCryptoParametersRLWE<Element>(
          params,
          EncodingParams(
              std::make_shared<EncodingParamsImpl>(plaintextModulus)),
          distributionParameter, assuranceMeasure, securityLevel, relinWindow,
          depth, maxDepth, mode),
      m_numq(0),
      m_numb(0),
      m_negQInvModmtilde(0) {}

template <class Element>
LPCryptoParametersBFVrnsB<Element>::LPCryptoParametersBFVrnsB(
    shared_ptr<ParmType> params, EncodingParams encodingParams,
    float distributionParameter, float assuranceMeasure, float securityLevel,
    usint relinWindow, MODE mode, int depth, int maxDepth)
    : LPCryptoParametersRLWE<Element>(
          params, encodingParams, distributionParameter, assuranceMeasure,
          securityLevel, relinWindow, depth, maxDepth, mode),
      m_numq(0),
      m_numb(0),
      m_negQInvModmtilde(0) {}

template <class Element>
LPCryptoParametersBFVrnsB<Element>::LPCryptoParametersBFVrnsB(
    shared_ptr<ParmType> params, EncodingParams encodingParams,
    float distributionParameter, float assuranceMeasure,
    SecurityLevel securityLevel, usint relinWindow, MODE mode, int depth,
    int maxDepth)
    : LPCryptoParametersRLWE<Element>(
          params, encodingParams, distributionParameter, assuranceMeasure,
          securityLevel, relinWindow, depth, maxDepth, mode),
      m_numq(0),
      m_numb(0),
      m_negQInvModmtilde(0) {}

// Enable for LPPublicKeyEncryptionSchemeBFVrnsB
template <class Element>
void LPPublicKeyEncryptionSchemeBFVrnsB<Element>::Enable(
    PKESchemeFeature feature) {
  switch (feature) {
    case ENCRYPTION:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBFVrnsB<Element>>();
      break;
    case SHE:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBFVrnsB<Element>>();
      if (this->m_algorithmSHE == nullptr)
        this->m_algorithmSHE =
            std::make_shared<LPAlgorithmSHEBFVrnsB<Element>>();
      break;
    case PRE:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBFVrnsB<Element>>();
      if (this->m_algorithmSHE == nullptr)
        this->m_algorithmSHE =
            std::make_shared<LPAlgorithmSHEBFVrnsB<Element>>();
      if (this->m_algorithmPRE == nullptr)
        this->m_algorithmPRE =
            std::make_shared<LPAlgorithmPREBFVrnsB<Element>>();
      break;
    case MULTIPARTY:
      if (this->m_algorithmEncryption == nullptr)
        this->m_algorithmEncryption =
            std::make_shared<LPAlgorithmBFVrnsB<Element>>();
      if (this->m_algorithmPRE == nullptr)
        this->m_algorithmPRE =
            std::make_shared<LPAlgorithmPREBFVrnsB<Element>>();
      if (this->m_algorithmSHE == nullptr)
        this->m_algorithmSHE =
            std::make_shared<LPAlgorithmSHEBFVrnsB<Element>>();
      if (this->m_algorithmMultiparty == nullptr)
        this->m_algorithmMultiparty =
            std::make_shared<LPAlgorithmMultipartyBFVrnsB<Element>>();
      break;
    case FHE:
      PALISADE_THROW(not_implemented_error,
                     "FHE feature not supported for BFVrnsB scheme");
    case LEVELEDSHE:
      PALISADE_THROW(not_implemented_error,
                     "LEVELEDSHE feature not supported for BFVrnsB scheme");
    case ADVANCEDSHE:
      PALISADE_THROW(not_implemented_error,
                     "ADVANCEDSHE feature not supported for BFVrnsB scheme");
  }
}

template <class Element>
LPPublicKeyEncryptionSchemeBFVrnsB<
    Element>::LPPublicKeyEncryptionSchemeBFVrnsB()
    : LPPublicKeyEncryptionScheme<Element>() {
  this->m_algorithmParamsGen =
      std::make_shared<LPAlgorithmParamsGenBFVrnsB<Element>>();
}

template <class Element>
LPEvalKey<Element> LPAlgorithmPREBFVrnsB<Element>::ReKeyGen(
    const LPPublicKey<Element> newPK,
    const LPPrivateKey<Element> origPrivateKey) const {
  return LPAlgorithmPREBFV<Element>::ReKeyGen(newPK, origPrivateKey);
}

template <class Element>
Ciphertext<Element> LPAlgorithmPREBFVrnsB<Element>::ReEncrypt(
    const LPEvalKey<Element> EK, ConstCiphertext<Element> ciphertext,
    const LPPublicKey<Element> publicKey) const {
  return LPAlgorithmPREBFV<Element>::ReEncrypt(EK, ciphertext, publicKey);
}

}  // namespace lbcrypto

#endif
