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
BFV implementation. See https://eprint.iacr.org/2021/204 for details.
 */

#define PROFILE

#include "cryptocontext.h"
#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "scheme/bfvrns/bfvrns-parametergeneration.h"
#include "scheme/scheme-utils.h"

namespace lbcrypto {

bool ParameterGenerationBFVRNS::ParamsGenBFVRNS(
    std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
    int32_t evalAddCount, int32_t multiplicativeDepth,
    int32_t keySwitchCount, size_t dcrtBits,
    uint32_t nCustom,
    uint32_t numDigits) const {
  if (!cryptoParams)
    OPENFHE_THROW(not_available_error,
                   "No crypto parameters are supplied to BFVrns ParamsGen");

  if ((dcrtBits < DCRT_MODULUS::MIN_SIZE) || (dcrtBits > DCRT_MODULUS::MAX_SIZE))
    OPENFHE_THROW(math_error,
                   "BFVrns.ParamsGen: Number of bits in CRT moduli should be "
                   "in the range from 30 to 60");

  const auto cryptoParamsBFVRNS =
      std::static_pointer_cast<CryptoParametersBFVRNS>(cryptoParams);

  KeySwitchTechnique ksTech = cryptoParamsBFVRNS->GetKeySwitchTechnique();
  ScalingTechnique scalTech = cryptoParamsBFVRNS->GetScalingTechnique();
  EncryptionTechnique encTech = cryptoParamsBFVRNS->GetEncryptionTechnique();
  MultiplicationTechnique multTech = cryptoParamsBFVRNS->GetMultiplicationTechnique();

  double sigma = cryptoParamsBFVRNS->GetDistributionParameter();
  double alpha = cryptoParamsBFVRNS->GetAssuranceMeasure();
  double p = static_cast<double>(cryptoParamsBFVRNS->GetPlaintextModulus());
  uint32_t digitSize = cryptoParamsBFVRNS->GetDigitSize();
  SecurityLevel stdLevel = cryptoParamsBFVRNS->GetStdLevel();

  // Bound of the Gaussian error polynomial
  double Berr = sigma * sqrt(alpha);

  // Bound of the key polynomial
  double Bkey;

  DistributionType distType;

  // supports both discrete Gaussian (GAUSSIAN) and ternary uniform distribution
  // (UNIFORM_TERNARY) cases
  if (cryptoParamsBFVRNS->GetSecretKeyDist() == GAUSSIAN) {
    Bkey = sigma * sqrt(alpha);
    distType = HEStd_error;
  } else {
    Bkey = 1;
    distType = HEStd_ternary;
  }

  // expansion factor delta
  auto delta = [](uint32_t n) -> double { return (2. * sqrt(n)); };

  // norm of fresh ciphertext polynomial (for EXTENDED the noise is reduced to modulus switching noise)
  auto Vnorm = [&](uint32_t n) -> double {
	if (encTech == EXTENDED)
	  return (1. + delta(n) * Bkey)/2.;
	else
      return Berr * (1. + 2. * delta(n) * Bkey);
  };

  // GAUSSIAN security constraint
  auto nRLWE = [&](double logq) -> double {
    if (stdLevel == HEStd_NotSet) {
      return 0;
    } else {
      return static_cast<double>(StdLatticeParm::FindRingDim(
          distType, stdLevel, static_cast<long>(ceil(logq / log(2)))));
    }
  };

  auto noiseKS = [&](uint32_t n, double logqPrev, double w, bool mult) -> double {
	if ((ksTech == HYBRID) && (!mult))
      return  (delta(n) * Berr + delta(n) * Bkey + 1.0 )/2;
	else if ((ksTech == HYBRID) && (mult))
	// conservative estimate for HYBRID to avoid the use of method of
	// iterative approximations; we do not know the number
	// of moduli at this point and use an upper bound for numDigits
      return  (multiplicativeDepth + 1) * delta(n) * Berr;
	else
	  return delta(n) *
              (floor(logqPrev / (log(2) * dcrtBits)) + 1) * w * Berr;
  };

  // initial values
  uint32_t n = (nCustom > 0) ? nCustom : 512;

  double logq = 0.;

  // only public key encryption and EvalAdd (optional when evalAddCount = 0)
  // operations are supported the correctness constraint from section 3.5 of
  // https://eprint.iacr.org/2014/062.pdf is used
  // optimization (noise reduction) from Section 3.1 of https://eprint.iacr.org/2021/204.pdf
  // is also applied
  if ((multiplicativeDepth == 0) && (keySwitchCount == 0)) {
    // Correctness constraint
    auto logqBFV = [&](uint32_t n) -> double {
      return log(p *
                 (4 * ((evalAddCount + 1) * Vnorm(n) + evalAddCount) + p));
    };

    // initial value
    logq = logqBFV(n);

    if ((nRLWE(logq) > n) && (nCustom > 0))
      OPENFHE_THROW(config_error,
                     "Ring dimension n specified by the user does not meet the "
                     "security requirement. Please increase it.");

    while (nRLWE(logq) > n) {
      n = 2 * n;
      logq = logqBFV(n);
    }

    // this code updates n and q to account for the discrete size of CRT moduli
    // = dcrtBits

    int32_t k =
        static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));

    double logqCeil = k * dcrtBits * log(2);

    while (nRLWE(logqCeil) > n) {
      n = 2 * n;
      logq = logqBFV(n);
      k = static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));
      logqCeil = k * dcrtBits * log(2);
    }
  } else if ((multiplicativeDepth == 0) && (keySwitchCount > 0) && (evalAddCount == 0)) {
    // this case supports automorphism w/o any other operations
    // base for relinearization

    double w = digitSize == 0 ? pow(2, dcrtBits) : pow(2, digitSize);

    // Correctness constraint
    auto logqBFV = [&](uint32_t n, double logqPrev) -> double {
      return log(
          p * (4 * (Vnorm(n) + keySwitchCount * noiseKS(n, logqPrev, w, false)) +
               p));
    };

    // initial values
    double logqPrev = 6 * log(10);
    logq = logqBFV(n, logqPrev);
    logqPrev = logq;

    if ((nRLWE(logq) > n) && (nCustom > 0))
      OPENFHE_THROW(config_error,
                     "Ring dimension n specified by the user does not meet the "
                     "security requirement. Please increase it.");

    // this "while" condition is needed in case the iterative solution for q
    // changes the requirement for n, which is rare but still theoretically
    // possible
    while (nRLWE(logq) > n) {
      while (nRLWE(logq) > n) {
        n = 2 * n;
        logq = logqBFV(n, logqPrev);
        logqPrev = logq;
      }

      logq = logqBFV(n, logqPrev);

      while (fabs(logq - logqPrev) > log(1.001)) {
        logqPrev = logq;
        logq = logqBFV(n, logqPrev);
      }

      // this code updates n and q to account for the discrete size of CRT
      // moduli = dcrtBits

      int32_t k =
          static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));

      double logqCeil = k * dcrtBits * log(2);
      logqPrev = logqCeil;

      while (nRLWE(logqCeil) > n) {
        n = 2 * n;
        logq = logqBFV(n, logqPrev);
        k = static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));
        logqCeil = k * dcrtBits * log(2);
        logqPrev = logqCeil;
      }
    }
  } else if ((evalAddCount == 0) && (multiplicativeDepth > 0) && (keySwitchCount == 0)) {
    // Only EvalMult operations are used in the correctness constraint
    // the correctness constraint from Section 3.1 of https://eprint.iacr.org/2021/204.pdf
	// is used

    // base for relinearization
    double w = digitSize == 0 ? pow(2, dcrtBits) : pow(2, digitSize);

    // function used in the EvalMult constraint
    auto C1 = [&](uint32_t n) -> double {
      return delta(n) * delta(n) * p * Bkey;
    };

    // function used in the EvalMult constraint
    auto C2 = [&](uint32_t n, double logqPrev) -> double {
      return delta(n) * delta(n) * Bkey * Bkey / 2.0 +
    		  noiseKS(n, logqPrev, w, true);
    };

    // main correctness constraint
    auto logqBFV = [&](uint32_t n, double logqPrev) -> double {
      return log(4 * p) + (multiplicativeDepth - 1) * log(C1(n)) +
             log(C1(n) * Vnorm(n) + multiplicativeDepth * C2(n, logqPrev));
    };

    // initial values
    double logqPrev = 6. * log(10);
    logq = logqBFV(n, logqPrev);
    logqPrev = logq;

    if ((nRLWE(logq) > n) && (nCustom > 0))
      OPENFHE_THROW(config_error,
                     "Ring dimension n specified by the user does not meet the "
                     "security requirement. Please increase it.");

    // this "while" condition is needed in case the iterative solution for q
    // changes the requirement for n, which is rare but still theoretically
    // possible
    while (nRLWE(logq) > n) {
      while (nRLWE(logq) > n) {
        n = 2 * n;
        logq = logqBFV(n, logqPrev);
        logqPrev = logq;
      }

      logq = logqBFV(n, logqPrev);

      while (fabs(logq - logqPrev) > log(1.001)) {
        logqPrev = logq;
        logq = logqBFV(n, logqPrev);
      }

      // this code updates n and q to account for the discrete size of CRT
      // moduli = dcrtBits

      int32_t k =
          static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));

      double logqCeil = k * dcrtBits * log(2);
      logqPrev = logqCeil;

      while (nRLWE(logqCeil) > n) {
        n = 2 * n;
        logq = logqBFV(n, logqPrev);
        k = static_cast<int32_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));
        logqCeil = k * dcrtBits * log(2);
        logqPrev = logqCeil;
      }
    }
  }

  const size_t sizeQ =
      static_cast<size_t>(ceil((ceil(logq / log(2)) + 1.0) / dcrtBits));
  if (sizeQ < 1)
    OPENFHE_THROW(config_error, "sizeQ must be greater than 0.");

  std::vector<NativeInteger> moduliQ(sizeQ);
  std::vector<NativeInteger> rootsQ(sizeQ);

  // makes sure the first integer is less than 2^60-1 to take advantage of NTL
  // optimizations
  NativeInteger firstInteger = FirstPrime<NativeInteger>(dcrtBits, 2 * n);

  moduliQ[0] = PreviousPrime<NativeInteger>(firstInteger, 2 * n);
  rootsQ[0] = RootOfUnity<NativeInteger>(2 * n, moduliQ[0]);

  for (size_t i = 1; i < sizeQ; i++) {
    moduliQ[i] = PreviousPrime<NativeInteger>(moduliQ[i - 1], 2 * n);
    rootsQ[i] = RootOfUnity<NativeInteger>(2 * n, moduliQ[i]);
  }

  auto params =
      std::make_shared<ILDCRTParams<BigInteger>>(2 * n, moduliQ, rootsQ);

  ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootsQ, 2 * n,
                                                          moduliQ);

  cryptoParamsBFVRNS->SetElementParams(params);

  const EncodingParams encodingParams = cryptoParamsBFVRNS->GetEncodingParams();
  if (encodingParams->GetBatchSize() > n)
    OPENFHE_THROW(config_error,
                   "The batch size cannot be larger than the ring dimension.");
  // if no batch size was specified, we set batchSize = n by default (for full
  // packing)
  if (encodingParams->GetBatchSize() == 0) {
    uint32_t batchSize = n;
    EncodingParams encodingParamsNew(std::make_shared<EncodingParamsImpl>(
        encodingParams->GetPlaintextModulus(), batchSize));
    cryptoParamsBFVRNS->SetEncodingParams(encodingParamsNew);
  }

  uint32_t numPartQ = ComputeNumLargeDigits(numDigits, sizeQ - 1);

  cryptoParamsBFVRNS->PrecomputeCRTTables(ksTech, scalTech, encTech, multTech, numPartQ, 60, 0);

  return true;
}

} //namespace lbcrypto
