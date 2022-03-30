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

#ifndef LBCRYPTO_CRYPTO_CKKSRNS_CRYPTOPARAMETERS_H
#define LBCRYPTO_CRYPTO_CKKSRNS_CRYPTOPARAMETERS_H

#include "schemerns/rns-cryptoparameters.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class CryptoParametersCKKSRNS : public CryptoParametersRNS {
  using ParmType = typename DCRTPoly::Params;

public:

  CryptoParametersCKKSRNS()
  : CryptoParametersRNS() {}

  CryptoParametersCKKSRNS(const CryptoParametersCKKSRNS &rhs)
      : CryptoParametersRNS(rhs) {}

  CryptoParametersCKKSRNS(std::shared_ptr<ParmType> params,
                       const PlaintextModulus &plaintextModulus,
                       float distributionParameter, float assuranceMeasure,
                       float securityLevel, usint relinWindow, MODE mode,
                       int depth = 1, int maxDepth = 2,
                       KeySwitchTechnique ksTech = BV,
                       RescalingTechnique rsTech = FIXEDMANUAL,
                       EncryptionTechnique encTech = STANDARD,
                       MultiplicationTechnique multTech = HPS)
      : CryptoParametersRNS(params, plaintextModulus, distributionParameter,
          assuranceMeasure, securityLevel, relinWindow, mode, depth, maxDepth,
          ksTech, rsTech, encTech, multTech) {}

  CryptoParametersCKKSRNS(std::shared_ptr<ParmType> params,
                       EncodingParams encodingParams,
                       float distributionParameter, float assuranceMeasure,
                       float securityLevel, usint relinWindow, MODE mode,
                       int depth = 1, int maxDepth = 2,
                       KeySwitchTechnique ksTech = BV,
                       RescalingTechnique rsTech = FIXEDMANUAL,
                       EncryptionTechnique encTech = STANDARD,
                       MultiplicationTechnique multTech = HPS)
      : CryptoParametersRNS(
            params, encodingParams, distributionParameter, assuranceMeasure,
            securityLevel, relinWindow, mode, depth, maxDepth,
            ksTech, rsTech, encTech, multTech) {}

  virtual ~CryptoParametersCKKSRNS() {}

  virtual void PrecomputeCRTTables(
      KeySwitchTechnique ksTech = BV,
      RescalingTechnique rsTech = FIXEDMANUAL,
      EncryptionTechnique encTech = STANDARD,
      MultiplicationTechnique multTech = HPS,
      uint32_t numPartQ = 0,
      uint32_t auxBits = 0,
      uint32_t extraBits = 0) override;

  virtual uint64_t FindAuxPrimeStep() const override;

  /////////////////////////////////////
  // SERIALIZATION
  /////////////////////////////////////

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(cereal::base_class<CryptoParametersRNS>(this));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      OpenFHE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(cereal::base_class<CryptoParametersRNS>(this));

    PrecomputeCRTTables(m_ksTechnique, m_rsTechnique, m_encTechnique, m_multTechnique,
                        m_numPartQ, m_auxBits, m_extraBits);
  }

  std::string SerializedObjectName() const override { return "SchemeParametersCKKSRNS"; }
  static uint32_t SerializedVersion() { return 1; }
};

}  // namespace lbcrypto

#endif
