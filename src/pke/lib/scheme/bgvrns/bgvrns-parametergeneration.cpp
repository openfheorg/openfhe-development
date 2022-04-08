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
Description:

This code implements RNS variants of the Cheon-Kim-Kim-Song scheme.

The CKKS scheme is introduced in the following paper:
- Jung Hee Cheon, Andrey Kim, Miran Kim, and Yongsoo Song. Homomorphic
encryption for arithmetic of approximate numbers. Cryptology ePrint Archive,
Report 2016/421, 2016. https://eprint.iacr.org/2016/421.

 Our implementation builds from the designs here:
 - Marcelo Blatt, Alexander Gusev, Yuriy Polyakov, Kurt Rohloff, and Vinod
Vaikuntanathan. Optimized homomorphic encryption solution for secure genomewide
association studies. Cryptology ePrint Archive, Report 2019/223, 2019.
https://eprint.iacr.org/2019/223.
 - Andrey Kim, Antonis Papadimitriou, and Yuriy Polyakov. Approximate
homomorphic encryption with reduced approximation error. Cryptology ePrint
Archive, Report 2020/1118, 2020. https://eprint.iacr.org/2020/
1118.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/bgvrns/bgvrns-cryptoparameters.h"
#include "scheme/bgvrns/bgvrns-parametergeneration.h"

namespace lbcrypto {

bool ParameterGenerationBGVRNS::ParamsGenBGVRNS(
    std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, usint cyclOrder,
    usint ptm, usint numPrimes, usint relinWindow, MODE mode,
    usint firstModSize, usint dcrtBits,
    uint32_t numPartQ, usint multihopQBound,
    enum KeySwitchTechnique ksTech,
    enum RescalingTechnique rsTech,
    enum EncryptionTechnique encTech,
    enum MultiplicationTechnique multTech) const {
  const auto cryptoParamsBGVRNS =
      std::static_pointer_cast<CryptoParametersBGVRNS>(cryptoParams);

  // Select the size of moduli according to the plaintext modulus (TODO:
  // optimized the bounds).
  if (dcrtBits == 0) {
    dcrtBits = 28 + GetMSB64(ptm);
    if (dcrtBits > 60) {
      dcrtBits = 60;
    }
  }

  // Select firstModSize to be dcrtBits if no indicated otherwise
  if (firstModSize == 0) firstModSize = dcrtBits;

  //// HE Standards compliance logic/check
  SecurityLevel stdLevel = cryptoParamsBGVRNS->GetStdLevel();
  uint32_t auxBits = 60;

  uint32_t n = cyclOrder / 2;
  uint32_t qBound = 0;
  // Estimate ciphertext modulus Q bound (in case of GHS/HYBRID P*Q)
  qBound = firstModSize + (numPrimes - 1) * dcrtBits;
  if (ksTech == HYBRID)
    qBound +=
        ceil(ceil(static_cast<double>(qBound) / numPartQ) / auxBits) *
        auxBits;

  // Note this code is not executed if multihopQBound == 0 so it is backwards
  // compatable
  if (qBound < multihopQBound) {
    // need to increase qBound to multihopQBound
    qBound = multihopQBound;

    // need to increase numPrimes to support new larger qBound
    numPrimes = (unsigned int)((qBound - firstModSize) / ((float)dcrtBits) + 1);
  }

  // RLWE security constraint
  DistributionType distType =
      (cryptoParamsBGVRNS->GetMode() == RLWE) ? HEStd_error : HEStd_ternary;
  auto nRLWE = [&](usint q) -> uint32_t {
    return StdLatticeParm::FindRingDim(distType, stdLevel, q);
  };

  // Case 1: SecurityLevel specified as HEStd_NotSet -> Do nothing
  if (stdLevel != HEStd_NotSet) {
    if (n == 0) {
      // Case 2: SecurityLevel specified, but ring dimension not specified

      // Choose ring dimension based on security standards
      n = nRLWE(qBound);
      cyclOrder = 2 * n;
    } else {  // if (n!=0)
      // Case 3: Both SecurityLevel and ring dimension specified

      // Check whether particular selection is standards-compliant
      auto he_std_n = nRLWE(qBound);
      if (he_std_n > n) {
        PALISADE_THROW(
            math_error,
            "The specified ring dimension (" + std::to_string(n) +
                ") does not comply with HE standards recommendation (" +
                std::to_string(he_std_n) + ").");
      }
    }
  } else if (n == 0) {
    PALISADE_THROW(
        math_error,
        "Please specify the ring dimension or desired security level.");
  }
  //// End HE Standards compliance logic/check

  std::vector<NativeInteger> moduliQ(numPrimes);
  std::vector<NativeInteger> rootsQ(numPrimes);

  // For ModulusSwitching to work we need the moduli to be also congruent to 1
  // modulo ptm
  usint plaintextModulus = ptm;
  usint pow2ptm = 1;  // The largest power of 2 dividing ptm (check whether it
                      // is larger than cyclOrder or not)
  while (plaintextModulus % 2 == 0) {
    plaintextModulus >>= 1;
    pow2ptm <<= 1;
  }

  if (pow2ptm < cyclOrder) pow2ptm = cyclOrder;

  uint64_t lcmCyclOrderPtm = (uint64_t)pow2ptm * plaintextModulus;

  // Get the largest prime with size less or equal to firstModSize bits.
  NativeInteger firstInteger =
      FirstPrime<NativeInteger>(firstModSize, lcmCyclOrderPtm);

  while (firstInteger > ((uint64_t)1 << firstModSize))
    firstInteger = PreviousPrime<NativeInteger>(firstInteger, lcmCyclOrderPtm);

  moduliQ[0] = PreviousPrime<NativeInteger>(firstInteger, lcmCyclOrderPtm);
  rootsQ[0] = RootOfUnity<NativeInteger>(cyclOrder, moduliQ[0]);

  if (numPrimes > 1) {
    NativeInteger q = (firstModSize != dcrtBits)
                          ? FirstPrime<NativeInteger>(dcrtBits, lcmCyclOrderPtm)
                          : moduliQ[0];

    moduliQ[1] = PreviousPrime<NativeInteger>(q, lcmCyclOrderPtm);
    rootsQ[1] = RootOfUnity<NativeInteger>(cyclOrder, moduliQ[1]);

    for (size_t i = 2; i < numPrimes; i++) {
      moduliQ[i] =
          PreviousPrime<NativeInteger>(moduliQ[i - 1], lcmCyclOrderPtm);
      rootsQ[i] = RootOfUnity<NativeInteger>(cyclOrder, moduliQ[i]);
    }
  }

  auto paramsDCRT =
      std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliQ, rootsQ);

  ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootsQ, cyclOrder,
                                                          moduliQ);

  cryptoParamsBGVRNS->SetElementParams(paramsDCRT);

  const EncodingParams encodingParams = cryptoParamsBGVRNS->GetEncodingParams();
  if (encodingParams->GetBatchSize() > n)
    PALISADE_THROW(config_error,
                   "The batch size cannot be larger than the ring dimension.");

  // if no batch size was specified compute a default value
  if (encodingParams->GetBatchSize() == 0) {
    // Check whether ptm and cyclOrder are coprime
    usint a, b, gcd;
    if (cyclOrder > ptm) {
      a = cyclOrder;
      b = ptm;
    } else {
      b = cyclOrder;
      a = ptm;
    }

    gcd = b;
    while (b != 0) {
      gcd = b;
      b = a % b;
      a = gcd;
    }

    // if ptm and CyclOrder are not coprime we set batchSize = n by default (for
    // full packing)
    uint32_t batchSize;
    if (gcd != 1) {
      batchSize = n;
    } else {  // set batchsize to the actual batchsize i.e. n/d where d is the
              // order of ptm mod CyclOrder
      a = (uint64_t)ptm % cyclOrder;
      b = 1;
      while (a != 1) {
        a = ((uint64_t)(a * ptm)) % cyclOrder;
        b++;
      }

      if (n % b != 0)
        PALISADE_THROW(math_error,
                       "BGVrns.ParamsGen: something went wrong when computing "
                       "the batchSize");

      batchSize = n / b;
    }

    EncodingParams encodingParamsNew(std::make_shared<EncodingParamsImpl>(
        encodingParams->GetPlaintextModulus(), batchSize));
    cryptoParamsBGVRNS->SetEncodingParams(encodingParamsNew);
  }

  cryptoParamsBGVRNS->PrecomputeCRTTables(ksTech, rsTech, encTech, multTech, numPartQ, auxBits, 0);

  return true;
}

} //namespace lbcrypto
