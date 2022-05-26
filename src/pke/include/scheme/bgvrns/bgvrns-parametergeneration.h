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

#ifndef LBCRYPTO_CRYPTO_BGVRNS_PARAMETERGENERATION_H
#define LBCRYPTO_CRYPTO_BGVRNS_PARAMETERGENERATION_H

#include "schemerns/rns-parametergeneration.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class ParameterGenerationBGVRNS : public ParameterGenerationRNS {
public:
  virtual ~ParameterGenerationBGVRNS() {}

  /*
   * Method that generates parameters for the BGV RNS scheme.
   *
   * @param cryptoParams contains parameters input by the user
   * @param evalAddCount is the maximum number of additions per level.
   * @param keySwitchCount is the maximum number of key switches per level.
   * @param cyclOrder is the cyclotomic order, which is twice the ring dimension.
   * @param ptm is the plaintext modulus.
   * @param numPrimes Number of CRT moduli.
   * @param relinWindow The bit size of the base for BV key relinearization.
   * @param mode
   * @param firstModSize is the approximate bit size of the first CRT modulus.
   * @param dcrtBits is the approximate bit size of the remaining CRT moduli.
   * @param numPartQ is 
   * @param multihopQBound 
   * @param ksTech is the key switching technique used, BV or Hybrid.
   * @param rsTech is the rescaling technique used.
   * @param encTech is the encryption technique used.
   * @param multTech is the multiplication technique used (BFV) only.
   * @return A boolean.
   */
  bool ParamsGenBGVRNS(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                 int32_t evalAddCount, int32_t keySwitchCount,
                 usint cyclOrder, usint ptm, usint numPrimes, usint relinWindow,
                 MODE mode,
                 usint firstModSize,
                 usint dcrtBits,
                 uint32_t numPartQ,
                 usint multihopQBound,
                 enum KeySwitchTechnique ksTech,
                 enum RescalingTechnique rsTech,
                 enum EncryptionTechnique encTech,
                 enum MultiplicationTechnique multTech) const override;

  std::vector<NativeInteger> computeModuli(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                     uint32_t ringDimension,
                     int32_t evalAddCount,
                     int32_t keySwitchCount,
                     usint relinWindow,
                     uint32_t auxBits,
                     enum KeySwitchTechnique ksTech,
                     enum RescalingTechnique rsTech,
                     usint numPrimes) const;

  /////////////////////////////////////
  // SERIALIZATION
  /////////////////////////////////////


  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {}

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {}

  std::string SerializedObjectName() const {
    return "ParameterGenerationBGVRNS";
  }
};

}  // namespace lbcrypto

#endif
