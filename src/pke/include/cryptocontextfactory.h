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
  Control for encryption operations
 */

#ifndef SRC_PKE_CRYPTOCONTEXTFACTORY_H_
#define SRC_PKE_CRYPTOCONTEXTFACTORY_H_

#include "utils/serial.h"
#include "scheme/allscheme.h"

namespace lbcrypto {

template <typename Element>
class CryptoContextImpl;

// Backend-specific settings for CKKS
#if NATIVEINT == 128
const size_t FIRSTMODSIZE = 105;
const enum RescalingTechnique DEFAULTRSTECH = FIXEDAUTO;
#else
const size_t FIRSTMODSIZE = 60;
const enum RescalingTechnique DEFAULTRSTECH = FLEXIBLEAUTO;
#endif

/**
 * @brief CryptoContextFactory
 *
 * A class that contains static methods to generate new crypto contexts from
 * user parameters
 *
 */
template <typename Element>
class CryptoContextFactory {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;

 protected:
  static std::vector<CryptoContext<Element>> AllContexts;

 public:
  static void ReleaseAllContexts();

  static int GetContextCount();

  static CryptoContext<Element> GetSingleContext();

  static CryptoContext<Element> GetContext(
      std::shared_ptr<CryptoParametersBase<Element>> params,
      std::shared_ptr<SchemeBase<Element>> scheme, const std::string& schemeId = "Not");

  static CryptoContext<Element> GetContextForPointer(
      CryptoContextImpl<Element>* cc);

  static const std::vector<CryptoContext<Element>>& GetAllContexts();


  /**
   * construct a OpenFHE CryptoContextImpl for the BFVrns Scheme using the
   * scheme's ParamsGen methods
   * @param plaintextModulus plaintext modulus
   * @param securityLevel root Hermite factor (lattice security parameter)
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow the key switching window (bits in the base for digits)
   * used for digit decomposition (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrns(
      const PlaintextModulus plaintextModulus, float securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0,
      MultiplicationTechnique multTech = HPS);

  /**
   * construct a OpenFHE CryptoContextImpl for the BFVrns Scheme using the
   * scheme's ParamsGen methods
   * @param plaintextModulus plaintext modulus
   * @param securityLevel standard secuirity level
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow the key switching window (bits in the base for digits)
   * used for digit decomposition (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrns(
      const PlaintextModulus plaintextModulus, SecurityLevel securityLevel,
      float dist, unsigned int numAdds, unsigned int numMults,
      unsigned int numKeyswitches, MODE mode = OPTIMIZED, int maxDepth = 2,
      uint32_t relinWindow = 0, size_t dcrtBits = 60, uint32_t n = 0,
      MultiplicationTechnique multTech = HPS);

  /**
   * construct a OpenFHE CryptoContextImpl for the BFVrns Scheme using the
   * scheme's ParamsGen methods
   * @param encodingParams plaintext encoding parameters
   * @param securityLevel root Hermite factor (lattice security parameter)
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow  the key switching window used for digit decomposition
   * (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrns(
      EncodingParams encodingParams, float securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0,
      MultiplicationTechnique multTech = HPS);

  /**
   * construct a OpenFHE CryptoContextImpl for the BFVrns Scheme using the
   * scheme's ParamsGen methods
   * @param encodingParams plaintext encoding parameters
   * @param securityLevel standard security level
   * @param dist distribution parameter for Gaussian noise generation
   * @param numAdds additive depth for homomorphic computations (assumes
   * numMults and numKeySwitches are set to zero)
   * @param numMults multiplicative depth for homomorphic computations (assumes
   * numAdds and numKeySwitches are set to zero)
   * @param numKeyswitches  key-switching depth for homomorphic computations
   * (assumes numAdds and numMults are set to zero)
   * @param mode secret key distribution mode (RLWE [Gaussian noise] or
   * OPTIMIZED [ternary uniform distribution])
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated (by default, it is 2); setting it to a
   * value larger than 2 adds support for homomorphic multiplication w/o
   * relinearization
   * @param relinWindow  the key switching window used for digit decomposition
   * (0 - means to use only CRT decomposition)
   * @param dcrtBits size of "small" CRT moduli
   * @param n ring dimension in case the user wants to use a custom ring
   * dimension
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBFVrns(
      EncodingParams encodingParams, SecurityLevel securityLevel, float dist,
      unsigned int numAdds, unsigned int numMults, unsigned int numKeyswitches,
      MODE mode = OPTIMIZED, int maxDepth = 2, uint32_t relinWindow = 0,
      size_t dcrtBits = 60, uint32_t n = 0,
      MultiplicationTechnique multTech = HPS);

  /**
   * construct a OpenFHE CryptoContextImpl for the BGVrns Scheme
   * @param plaintextmodulus
   * @param ringdim
   * @param modulus
   * @param rootOfUnity
   * @param relinWindow
   * @param stDev
   * @param mode
   * @param depth
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param ksTech key switching technique to use (e.g., GHS or BV)
   * @param msMethod mod switch method
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBGVrns(
      std::shared_ptr<ParmType> params, const PlaintextModulus plaintextmodulus,
      usint relinWindow, float stDev, MODE mode = RLWE, int depth = 1,
      int maxDepth = 2, KeySwitchTechnique ksTech = BV,
      enum RescalingTechnique rsTech = FIXEDMANUAL);

  /**
   * construct a OpenFHE CryptoContextImpl for the BGVrns Scheme
   * @param encodingParams
   * @param ringdim
   * @param modulus
   * @param rootOfUnity
   * @param relinWindow
   * @param stDev
   * @param mode
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param ksTech key switching technique to use (e.g., GHS or BV)
   * @param msMethod mod switch method
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBGVrns(
      std::shared_ptr<ParmType> params, EncodingParams encodingParams,
      usint relinWindow, float stDev, MODE mode = RLWE, int depth = 1,
      int maxDepth = 2, enum KeySwitchTechnique ksTech = BV,
      enum RescalingTechnique rsTech = FIXEDMANUAL);

  /**
   * Automatically generate the moduli chain and construct a OpenFHE
   * CryptoContextImpl for the BGVrns Scheme with it.
   *
   * @param cyclOrder the cyclotomic order M
   * @param numPrimes the number of towers/primes to use when building the
   * moduli chain
   * @param ptm the plaintext modulus
   * @param mode RLWE or OPTIMIZED
   * @param depth
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param firstModSize the bit-length of the first modulus
   * @param dcrtrBits the size of the moduli in bits
   * @param ksTech key switching technique to use (e.g., GHS or BV)
   * @param numLargeDigits the number of big digits to use in HYBRID key
   * switching
   * @param batchSize the number of slots being used in the ciphertext
   * @param msMethod mod switch method
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBGVrnsWithParamsGen(
      usint cyclOrder, usint numPrimes, usint ptm, usint relinWindow, MODE mode,
      int depth = 1, int maxDepth = 2, enum KeySwitchTechnique ksTech = BV,
      usint firstModSize = 0, usint dcrtBits = 0, uint32_t numLargeDigits = 4,
      usint batchSize = 0, enum RescalingTechnique rsTech = FIXEDMANUAL,
      usint multihopQBound = 0);

  /**
   * Construct a OpenFHE CryptoContextImpl for the BGVrns Scheme.
   *
   * @param multiplicativeDepth the depth of multiplications supported by the
   * scheme (equal to number of towers - 1)
   * @param ptm the plaintext modulus
   * @param stdLevel the standard security level we want the scheme to satisfy
   * @param stdDev sigma - distribution parameter for error distribution
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param mode RLWE (gaussian distribution) or OPTIMIZED (ternary
   * distribution)
   * @param ksTech key switching technique to use (e.g., HYBRID, GHS or BV)
   * @param ringDim the ring dimension (if not specified selected automatically
   * based on stdLevel)
   * @param numLargeDigits the number of big digits to use in HYBRID key
   * switching
   * @param firstModSize the bit-length of the first modulus
   * @param dcrtrBits the size of the moduli in bits
   * @param relinWindow the relinearization windows (used in BV key switching,
   * use 0 for RNS decomposition)
   * @param batchSize the number of slots being used in the ciphertext
   * @param msMethod mod switch method
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextBGVrns(
      usint multiplicativeDepth, usint ptm,
      SecurityLevel stdLevel = HEStd_128_classic, float stdDev = 3.19,
      int maxDepth = 2, MODE mode = OPTIMIZED,
      enum KeySwitchTechnique ksTech = HYBRID, usint ringDim = 0,
      uint32_t numLargeDigits = 0, usint firstModSize = 0, usint dcrtBits = 0,
      usint relinWindow = 0, usint batchSize = 0,
      enum RescalingTechnique rsTech = FIXEDAUTO, usint multihopQBound = 0);


  /**
   * construct a OpenFHE CryptoContextImpl for the CKKS Scheme
   * @param encodingParams
   * @param ringdim
   * @param modulus
   * @param rootOfUnity
   * @param relinWindow
   * @param stDev
   * @param mode
   * @param maxDepth the maximum power of secret key for which the
   * relinearization key is generated
   * @param ksTech key switching technique to use (e.g., GHS or BV)
   * @param rsTech rescaling technique to use (e.g., FIXEDMANUAL or
   * FLEXIBLEAUTO)
   * @return new context
   */
  static CryptoContext<Element> genCryptoContextCKKSrns(
      std::shared_ptr<ParmType> params, EncodingParams encodingParams,
      usint relinWindow, float stDev, MODE mode = RLWE, int depth = 1,
      int maxDepth = 2, enum KeySwitchTechnique ksTech = BV,
      RescalingTechnique rsTech = FIXEDMANUAL);

};
}

#endif
