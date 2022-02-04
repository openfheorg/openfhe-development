// @file ciphertextgen.h -- Generator for crypto contexts.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
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

#ifndef SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_
#define SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_

#include <memory>
#include <string>

#include "cryptocontextfactory.h"
#include "scheme/ckksrns/cryptocontext-ckksrns.h"
#include "gen-cryptocontext.h"
#include "lattice/elemparamfactory.h"
#include "utils/parmfactory.h"

using namespace lbcrypto;

static const usint DefaultQbits = 59;
static const usint DefaultT = 3;

template <typename Element>
inline CryptoContext<Element> GenCryptoContextBFVrns(PlaintextModulus ptm,
                                                     MODE mode = RLWE,
                                                     uint32_t batchSize = 0,
                                                     MultiplicationTechnique multTech = HPS);

template <>
inline CryptoContext<DCRTPoly> GenCryptoContextBFVrns(PlaintextModulus ptm,
                                                      MODE mode,
                                                      uint32_t batchSize,
                                                      MultiplicationTechnique multTech) {
  EncodingParams encodingParams(std::make_shared<EncodingParamsImpl>(ptm));
  encodingParams->SetBatchSize(batchSize);
  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBFVrns(
          encodingParams, HEStd_128_classic, 3.2, 0, 2, 0, mode, 2, 20, 60, 0, multTech);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(PRE);
  cc->Enable(LEVELEDSHE);
  cc->Enable(MULTIPARTY);
  return cc;
}

template <typename Element>
inline CryptoContext<Element> GenCryptoContextCKKSrns(
    usint cyclOrder, usint numPrimes, usint scaleExp, usint relinWindow,
    usint batchSize, MODE mode, KeySwitchTechnique ksTech,
    RescalingTechnique rsTech);

/* *
 * Generate a CryptoContext for the CKKS scheme.
 *
 * @param m Cyclotomic order. Must be a power of 2.
 * @param init_size Number of co-primes comprising the ciphertext modulus.
 * 			  It is equal to the desired depth of the computation.
 * @param scaleExp (dcrtBits) Size of each co-prime in bits. Should fit into a
 * 			 machine word, i.e., less than 64.
 * @param p Scaling parameter 2^p. p should usually be equal to (dcrtBits).
 * @param relinWin The bit decomposition count used in relinearization.
 * 			 Use 0 to go with max possible. Use small values (3-4?)
 * 			 if you need rotations before any multiplications.
 * @param batchSize The length of the packed vectors to be used with CKKS.
 * @param mode (e.g., RLWE or OPTIMIZED)
 * @param ksTech key switching technique to use (e.g., GHS or BV)
 * @param rsTech rescaling technique to use (e.g., FIXEDMANUAL or
 * FLEXIBLEAUTO)
 */
template <>
inline CryptoContext<DCRTPoly> GenCryptoContextCKKSrns(
    usint cyclOrder, usint numPrimes, usint scaleExp, usint relinWindow,
    usint batchSize, MODE mode, KeySwitchTechnique ksTech,
    RescalingTechnique rsTech) {

    CCParams<CryptoContextCKKSRNS> parameters;
    parameters.SetMultiplicativeDepth(numPrimes - 1);
    parameters.SetScalingFactorBits(scaleExp);
    parameters.SetBatchSize(batchSize);
    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(cyclOrder / 2);
    parameters.SetRescalingTechnique(rsTech);
    parameters.SetKeySwitchTechnique(ksTech);
    parameters.SetRelinWindow(relinWindow);
    parameters.SetMode(mode);

    CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);

    cc->Enable(PKE);
    cc->Enable(KEYSWITCH);
    cc->Enable(LEVELEDSHE);
    cc->Enable(MULTIPARTY);
    return cc;
}

/* *
 * Generate a CryptoContext for the BGVrns scheme.
 *
 * @param m Cyclotomic order. Must be a power of 2.
 * @param init_size Number of co-primes comprising the ciphertext modulus.
 * 			  It is equal to the desired depth of the computation.
 * @param dcrtBits Size of each co-prime in bits. Should fit into a
 * 			 machine word, i.e., less than 64.
 * @param ptm the plaintext modulus.
 * @param relinWin The bit decomposition count used in relinearization.
 * 			 Use 0 to go with max possible. Use small values (3-4?)
 * 			 if you need rotations before any multiplications.
 * @param mode (e.g., RLWE or OPTIMIZED)
 * @param ksTech key switching technique to use (e.g., GHS or BV)
 * @param batchSize The length of the packed vectors to be used with CKKS.
 * @param msMethod mod switching method
 */

template <typename Element>
inline CryptoContext<Element> GenCryptoContextBGVrns(
    usint cyclOrder, usint numPrimes, usint dcrtBits, usint ptm,
    usint relinWindow, MODE mode, KeySwitchTechnique ksTech, usint batchSize,
    RescalingTechnique rsTech);

template <>
inline CryptoContext<DCRTPoly> GenCryptoContextBGVrns(
    usint cyclOrder, usint numPrimes, usint dcrtBits, usint ptm,
    usint relinWindow, MODE mode, KeySwitchTechnique ksTech, usint batchSize,
    RescalingTechnique rsTech) {
  usint n = cyclOrder / 2;
  usint relinWin = relinWindow;
  float stdDev = 3.2;

  CryptoContext<DCRTPoly> cc =
      CryptoContextFactory<DCRTPoly>::genCryptoContextBGVrns(
          numPrimes - 1, ptm, HEStd_NotSet, stdDev, 1, /* maxDepth */
          mode, ksTech, n,                             /*ringDimension*/
          0,                                           /*numLargeDigits*/
          60,                                          /*firstMod*/
          dcrtBits, relinWin, batchSize, rsTech);

  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(PRE);
  cc->Enable(LEVELEDSHE);
  cc->Enable(MULTIPARTY);
  return cc;
}

inline CryptoContext<DCRTPoly> GenTestCryptoContext(
    const string& name, usint ORDER, PlaintextModulus ptm,
    usint bits = DefaultQbits, usint towers = DefaultT, usint relinWin = 0,
    usint batchSize = 16, KeySwitchTechnique ksTech = BV,
    RescalingTechnique rsTech = FIXEDMANUAL, usint dummy = 0) {

  using Element = DCRTPoly;

  shared_ptr<typename Element::Params> p =
      ElemParamFactory::GenElemParams<typename Element::Params>(ORDER, bits,
                                                                towers);

  CryptoContext<Element> cc;

  if (name == "BFVrns_rlwe") {
    cc = GenCryptoContextBFVrns<Element>(ptm, RLWE, batchSize, HPS);
  } else if (name == "BFVrns_opt") {
    cc = GenCryptoContextBFVrns<Element>(ptm, OPTIMIZED, batchSize, HPS);
  } else if (name == "BFVrnsB_rlwe") {
    cc = GenCryptoContextBFVrns<Element>(ptm, RLWE, batchSize, BEHZ);
  } else if (name == "BFVrnsB_opt") {
    cc = GenCryptoContextBFVrns<Element>(ptm, OPTIMIZED, batchSize, BEHZ);
  } else if (name == "CKKS_sparse") {
    cc = GenCryptoContextCKKSrns<Element>(ORDER, towers, ptm, relinWin, batchSize,
                                       SPARSE, ksTech, rsTech);
  } else if (name == "CKKS") {
    cc = GenCryptoContextCKKSrns<Element>(ORDER, towers, ptm, relinWin, batchSize,
                                       OPTIMIZED, ksTech, rsTech);
  } else if (name == "BGVrns_rlwe") {
    cc = GenCryptoContextBGVrns<Element>(ORDER, towers, bits, ptm, relinWin,
                                         RLWE, ksTech, batchSize, rsTech);
  } else if ((name == "BGVrns_opt") || (name == "BGVrns")) {
    cc =
        GenCryptoContextBGVrns<Element>(ORDER, towers, bits, ptm, relinWin,
                                        OPTIMIZED, ksTech, batchSize, rsTech);
  } else if (name == "BGVrns_sparse") {
    cc = GenCryptoContextBGVrns<Element>(ORDER, towers, bits, ptm, relinWin,
                                         SPARSE, ksTech, batchSize, rsTech);
  } else {
    std::cout << "nothing for " << name << std::endl;
    PALISADE_THROW(not_available_error, "No generator for " + name);
  }

  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(PRE);
  cc->Enable(LEVELEDSHE);

  return cc;
}

#endif /* SRC_PKE_LIB_CRYPTOCONTEXTGEN_H_ */
