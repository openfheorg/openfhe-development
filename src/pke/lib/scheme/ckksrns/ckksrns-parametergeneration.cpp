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
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-parametergeneration.h"

namespace lbcrypto {

bool ParameterGenerationCKKSRNS::ParamsGenCKKSRNS(
          std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, usint cyclOrder,
          usint numPrimes, usint scaleExp, usint relinWindow, MODE mode,
          usint firstModSize,
          uint32_t numPartQ,
          KeySwitchTechnique ksTech,
          RescalingTechnique rsTech,
          EncryptionTechnique encTech,
          MultiplicationTechnique multTech) const {

  usint extraModSize = 0;
  if (rsTech == FLEXIBLEAUTOEXT) {
    // TODO: Allow the user to specify this?
    extraModSize = 20;
  }

  const auto cryptoParamsCKKSRNS =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(cryptoParams);

  //// HE Standards compliance logic/check
  SecurityLevel stdLevel = cryptoParamsCKKSRNS->GetStdLevel();
  uint32_t auxBits = 60;
  uint32_t n = cyclOrder / 2;
  uint32_t qBound = 0;
  // Estimate ciphertext modulus Q bound (in case of GHS/HYBRID P*Q)
  if (ksTech == BV) {
    qBound = firstModSize + (numPrimes - 1) * scaleExp + extraModSize;
  } else if (ksTech == HYBRID) {
    qBound = firstModSize + (numPrimes - 1) * scaleExp + extraModSize;
    qBound +=
        ceil(ceil(static_cast<double>(qBound) / numPartQ) / auxBits) *
        auxBits;
  }

  uint32_t qBoundExact = 0;
  uint32_t auxBitsExact = 0;

  if (rsTech == FLEXIBLEAUTOEXT) {
      qBoundExact = firstModSize + (numPrimes - 1) * scaleExp;
    if (ksTech == BV) {
      qBoundExact += ceil(static_cast<double>(qBoundExact) / auxBits) * auxBits;
    } else if (ksTech == HYBRID) {
      auxBitsExact = ceil(ceil(static_cast<double>(qBoundExact) / numPartQ) /
	       auxBits);
      qBoundExact += ceil(ceil(static_cast<double>(qBoundExact) / numPartQ) /
	       auxBits) * auxBits;
    }

  }
  // RLWE security constraint
  DistributionType distType =
      (cryptoParamsCKKSRNS->GetMode() == RLWE) ? HEStd_error : HEStd_ternary;
  auto nRLWE = [&](usint q) -> uint32_t {
    return StdLatticeParm::FindRingDim(distType, stdLevel, q);
  };

  // Case 1: SecurityLevel specified as HEStd_NotSet -> Do nothing
  if (stdLevel != HEStd_NotSet) {
    if (n == 0) {
      // Case 2: SecurityLevel specified, but ring dimension not specified

      // Choose ring dimension based on security standards
      n = nRLWE(qBound);
      if (extraModSize > 0) {
        usint nExact = nRLWE(qBoundExact);
        //std::cerr << "n = " << n << std::endl;
        //std::cerr << "nExact = " << nExact << std::endl;
        while (n > nExact) {
            qBound = firstModSize + (numPrimes - 1) * scaleExp + extraModSize;
            usint PBound = qBoundExact - qBound;
            auxBits = (uint32_t)std::floor(PBound / auxBitsExact);
            qBound += auxBitsExact * auxBits;
            n = nRLWE(qBound);
        }
      }
      cyclOrder = 2 * n;
    } else {  // if (n!=0)
      // Case 3: Both SecurityLevel and ring dimension specified

      // Check whether particular selection is standards-compliant
      auto he_std_n = nRLWE(qBound);
      if (he_std_n > n) {
        OPENFHE_THROW(
            config_error,
            "The specified ring dimension (" + std::to_string(n) +
                ") does not comply with HE standards recommendation (" +
                std::to_string(he_std_n) + ").");
      }
    }
  } else if (n == 0) {
    OPENFHE_THROW(
        config_error,
        "Please specify the ring dimension or desired security level.");
  }
  //// End HE Standards compliance logic/check

  usint dcrtBits = scaleExp;

  std::vector<NativeInteger> moduliQ;
  std::vector<NativeInteger> rootsQ;
  if (extraModSize == 0) {
    moduliQ.resize(numPrimes);
    rootsQ.resize(numPrimes);
  } else {
    moduliQ.resize(numPrimes + 1);
    rootsQ.resize(numPrimes + 1);
  }
  NativeInteger q = FirstPrime<NativeInteger>(dcrtBits, cyclOrder);
  moduliQ[numPrimes - 1] = q;
  rootsQ[numPrimes - 1] = RootOfUnity(cyclOrder, moduliQ[numPrimes - 1]);

  NativeInteger qNext = q;
  NativeInteger qPrev = q;
  if (numPrimes > 1) {
    if (rsTech != FLEXIBLEAUTO) {
      uint32_t cnt = 0;
      for (usint i = numPrimes - 2; i >= 1; i--) {
        if ((cnt % 2) == 0) {
          qPrev = lbcrypto::PreviousPrime(qPrev, cyclOrder);
          q = qPrev;
        } else {
          qNext = lbcrypto::NextPrime(qNext, cyclOrder);
          q = qNext;
        }

        moduliQ[i] = q;
        rootsQ[i] = RootOfUnity(cyclOrder, moduliQ[i]);
        cnt++;
      }
    } else {  // FLEXIBLEAUTO
      /* Scaling factors in FLEXIBLEAUTO are a bit fragile,
       * in the sense that once one scaling factor gets far enough from the
       * original scaling factor, subsequent level scaling factors quickly
       * diverge to either 0 or infinity. To mitigate this problem to a certain
       * extend, we have a special prime selection process in place. The goal is
       * to maintain the scaling factor of all levels as close to the original
       * scale factor of level 0 as possible.
       */

      double sf = moduliQ[numPrimes - 1].ConvertToDouble();
      uint32_t cnt = 0;
      for (usint i = numPrimes - 2; i >= 1; i--) {
        sf = static_cast<double>(pow(sf, 2) / moduliQ[i + 1].ConvertToDouble());
        if ((cnt % 2) == 0) {
          NativeInteger sfInt = std::llround(sf);
          NativeInteger sfRem = sfInt.Mod(cyclOrder);
          NativeInteger qPrev =
              sfInt - NativeInteger(cyclOrder) - sfRem + NativeInteger(1);

          bool hasSameMod = true;
          while (hasSameMod) {
            hasSameMod = false;
            qPrev = lbcrypto::PreviousPrime(qPrev, cyclOrder);
            for (uint32_t j = i + 1; j < numPrimes; j++) {
              if (qPrev == moduliQ[j]) {
                hasSameMod = true;
              }
            }
          }
          moduliQ[i] = qPrev;

        } else {
          NativeInteger sfInt = std::llround(sf);
          NativeInteger sfRem = sfInt.Mod(cyclOrder);
          NativeInteger qNext =
              sfInt + NativeInteger(cyclOrder) - sfRem + NativeInteger(1);
          bool hasSameMod = true;
          while (hasSameMod) {
            hasSameMod = false;
            qNext = lbcrypto::NextPrime(qNext, cyclOrder);
            for (uint32_t j = i + 1; j < numPrimes; j++) {
              if (qNext == moduliQ[j]) {
                hasSameMod = true;
              }
            }
          }
          moduliQ[i] = qNext;
        }

        rootsQ[i] = RootOfUnity(cyclOrder, moduliQ[i]);
        cnt++;
      }
    }
  }

  if (firstModSize == dcrtBits) {  // this requires dcrtBits < 60
    moduliQ[0] = PreviousPrime<NativeInteger>(qPrev, cyclOrder);
  } else {
    NativeInteger firstInteger =
        FirstPrime<NativeInteger>(firstModSize, cyclOrder);
    moduliQ[0] = PreviousPrime<NativeInteger>(firstInteger, cyclOrder);
  }
  rootsQ[0] = RootOfUnity(cyclOrder, moduliQ[0]);

  if (rsTech == FLEXIBLEAUTOEXT) {
    if (extraModSize == dcrtBits || extraModSize == firstModSize) {
      moduliQ[numPrimes] = PreviousPrime<NativeInteger>(moduliQ[0], cyclOrder);
    } else {
      NativeInteger extraInteger =
          FirstPrime<NativeInteger>(extraModSize, cyclOrder);
      moduliQ[numPrimes] =
          PreviousPrime<NativeInteger>(extraInteger, cyclOrder);
    }
    rootsQ[numPrimes] = RootOfUnity(cyclOrder, moduliQ[numPrimes]);
  }

  auto paramsDCRT =
      std::make_shared<ILDCRTParams<BigInteger>>(cyclOrder, moduliQ, rootsQ);

  cryptoParamsCKKSRNS->SetElementParams(paramsDCRT);

  const EncodingParams encodingParams = cryptoParamsCKKSRNS->GetEncodingParams();
  if (encodingParams->GetBatchSize() > n / 2)
    OPENFHE_THROW(config_error,
                   "The batch size cannot be larger than ring dimension / 2.");

  // if no batch size was specified, we set batchSize = n/2 by default (for full
  // packing)
  if (encodingParams->GetBatchSize() == 0) {
    uint32_t batchSize = n / 2;
    EncodingParams encodingParamsNew(std::make_shared<EncodingParamsImpl>(
        encodingParams->GetPlaintextModulus(), batchSize));
    cryptoParamsCKKSRNS->SetEncodingParams(encodingParamsNew);
  }

  cryptoParamsCKKSRNS->PrecomputeCRTTables(ksTech, rsTech, encTech, multTech, numPartQ, auxBits, extraModSize);

  return true;
}

}  // namespace lbcrypto
