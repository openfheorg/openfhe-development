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

  /*
   * Struct that keeps track of all noise estimates necessary to compute moduli.
   *
   * @param Berr is the bound on the error distribution
   * @param Bkey is the bound on the key distribution
   * @param expansionFactor is the expansion factor of the ring
   * @param freshEncryptionNoise is the noise after encryption
   * @param keySwitchingNoise is the noise after key switching
   * @param modSwitchingNoise is the noise after modulus switching
   * @param noisePerLevel is the noise we wish to maintain at each level
   */
  struct BGVNoiseEstimates {
    const double Berr;
    const double Bkey;
    const double expansionFactor;
    const double freshEncryptionNoise;
    const double keySwitchingNoise;
    const double modSwitchingNoise;
    const double noisePerLevel;

    BGVNoiseEstimates(
        const double Berr0,
        const double Bkey0,
        const double expansionFactor0,
        const double freshEncryptionNoise0,
        const double keySwitchingNoise0,
        const double modSwitchingNoise0,
        double noisePerLevel0) :
        Berr(Berr0),
        Bkey(Bkey0),
        expansionFactor(expansionFactor0),
        freshEncryptionNoise(freshEncryptionNoise0),
        keySwitchingNoise(keySwitchingNoise0),
        modSwitchingNoise(modSwitchingNoise0),
        noisePerLevel(noisePerLevel0) {}
  };

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
   * @param digitSize The bit size of the base for BV key relinearization.
   * @param secretKeyDist
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
  bool ParamsGenBGVRNS(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, int32_t evalAddCount,
                       int32_t keySwitchCount, usint cyclOrder, usint numPrimes,
                       usint firstModSize, usint dcrtBits, uint32_t numPartQ, usint multihopQBound) const override;

  /*
   * Method that computes a security-compliant ring dimension.
   *
   * @param cryptoParams contains parameters input by the user
   * @param qBound is the upper bound on the number of bits in the ciphertext modulus
   * @param cyclOrder is the cyclotomic order, which is twice the ring dimension.
   * @return The ring dimension.
   */
  uint32_t computeRingDimension(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                                uint32_t qBound, usint cyclOrder) const;

  BGVNoiseEstimates computeNoiseEstimates(
            std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
            uint32_t ringDimension,
            int32_t evalAddCount, int32_t keySwitchCount, uint32_t auxBits,
            usint numPrimes) const;

  uint64_t getCyclicOrder(const uint32_t ringDimension,
                          const int plainModulus,
                          const RescalingTechnique rsTech) const;

  /*
   * Method that generates moduli for FLEXIBLEAUTOEXT mode for the BGV RNS scheme.
   *
   * @param cryptoParams contains parameters input by the user
   * @param ringDimension is the dimension of the ring (n)
   * @param evalAddCount is the maximum number of additions per level.
   * @param keySwitchCount is the maximum number of key switches per level.
   * @param digitSize The bit size of the base for BV key relinearization.
   * @param auxBits is the size of the additional modulus P, used for hybrid key-switching.
   * @param ksTech is the key switching technique used, BV or Hybrid.
   * @param rsTech is the rescaling technique used.
   * @param numPrimes Number of CRT moduli.
   * @return A pair containing: 1) a vector with the CRT moduli and 2) the total modulus size to be used for ensuring security compliance.
   */
  std::pair<std::vector<NativeInteger>, uint32_t> computeModuli(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                     uint32_t ringDimension,
                     int32_t evalAddCount,
                     int32_t keySwitchCount,
                     uint32_t auxBits,
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
