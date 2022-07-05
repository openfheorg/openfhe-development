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

#define PROFILE

#include "math/dftransform.h"

#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "utils/polynomials.h"
#include "utils/caller_info.h"

namespace lbcrypto {

//------------------------------------------------------------------------------
// Bootstrap Wrapper
//------------------------------------------------------------------------------

void FHECKKSRNS::EvalBootstrapSetup(
    const CryptoContextImpl<DCRTPoly> &cc,
    std::vector<uint32_t> levelBudget,
    std::vector<uint32_t> dim1, uint32_t numSlots) {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          cc.GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
      OPENFHE_THROW(config_error, "CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT==128
    if (cryptoParams->GetRescalingTechnique() == FLEXIBLEAUTO)
      OPENFHE_THROW(config_error, "128-bit CKKS Bootstrapping is not supported for the FLEXIBLEAUTO method.");
#endif

  uint32_t M = cc.GetCyclotomicOrder();
  uint32_t slots = (numSlots == 0) ? M/4 : numSlots;

  m_bootPrecomMap[slots] = std::make_shared<CKKSBootstrapPrecom>();
  std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap[slots];

  precom->m_slots = slots;
  precom->m_dim1 = dim1[0];

  double logSlots = std::log2(slots);
  // Perform some checks on the level budget and compute parameters
  std::vector<uint32_t> newBudget = levelBudget;

  if (levelBudget[0] > logSlots) {
    std::cerr << "\nWarning, the level budget for encoding cannot be this large. The budget was changed to " << uint32_t(logSlots) << std::endl;
    newBudget[0] = uint32_t(logSlots);
  }
  if (levelBudget[0] < 1) {
    std::cerr << "\nWarning, the level budget for encoding has to be at least 1. The budget was changed to " << 1 << std::endl;
    newBudget[0] = 1;
  }

  if (levelBudget[1] > logSlots) {
    std::cerr << "\nWarning, the level budget for decoding cannot be this large. The budget was changed to " << uint32_t(logSlots) << std::endl;
    newBudget[1] = uint32_t(logSlots);
  }
  if (levelBudget[1] < 1) {
    std::cerr << "\nWarning, the level budget for decoding has to be at least 1. The budget was changed to " << 1 << std::endl;
    newBudget[1] = 1;
  }

  precom->m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] = newBudget[0];
  if (newBudget[0] > 1) {
    precom->m_paramsEnc = GetCollapsedFFTParams(slots, newBudget[0], dim1[0]);
  }

  precom->m_paramsDec[FFT_PARAMS::LEVEL_BUDGET] = newBudget[1];
  if (newBudget[1] > 1) {
    precom->m_paramsDec = GetCollapsedFFTParams(slots, newBudget[1], dim1[1]);
  }

  uint32_t m = 4 * slots;
  bool isSparse = (M != m) ? true : false;

  // computes indices for all primitive roots of unity
  std::vector<uint32_t> rotGroup(slots);
  uint32_t fivePows = 1;
  for (uint32_t i = 0; i < slots; ++i) {
    rotGroup[i] = fivePows;
    fivePows *= 5;
    fivePows %= m;
  }

  // computes all powers of a primitive root of unity exp(2 * M_PI/m)
  std::vector<std::complex<double>> ksiPows(m + 1);
  for (uint32_t j = 0; j < m; ++j) {
          double angle = 2.0 * M_PI * j / m;
          ksiPows[j].real(cos(angle));
          ksiPows[j].imag(sin(angle));
  }
  ksiPows[m] = ksiPows[0];

  // Extract the modulus prior to bootstrapping
  NativeInteger q = cryptoParams->GetElementParams()->GetParams()[0]->GetModulus().ConvertToInt();
  double qDouble = q.ConvertToDouble();

  unsigned __int128 factor = ((unsigned __int128)1 << ((uint32_t)std::round(std::log2(qDouble))));
  double pre = qDouble / factor;
  double k = (cryptoParams->GetMode() == SPARSE) ? K_SPARSE : 1.0;
  double scaleEnc = pre / k;
  double scaleDec = 1 / pre;

  uint32_t approxModDepth = 8;
  if (cryptoParams->GetMode() == OPTIMIZED) {
    approxModDepth += R - 1;
//    if (cryptoParams->GetRescalingTechnique() == FIXEDMANUAL) {
//      approxModDepth += R - 1;
//    } else {
//      approxModDepth += R;
//    }
  }

  uint32_t depthBT = approxModDepth + 1 +
      precom->m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] +
      precom->m_paramsDec[FFT_PARAMS::LEVEL_BUDGET];

  // compute # of levels to remain when encoding the coefficients
  uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size();
  uint32_t lEnc = L0 - precom->m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] - 1;
  uint32_t lDec = L0 - depthBT;

  if (precom->m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] == 1) {
    std::vector<std::vector<std::complex<double>>> U0hatT(slots, std::vector<std::complex<double>>(slots));
    for (size_t i = 0; i < slots; i++) {
      for (size_t j = 0; j < slots; j++) {
        U0hatT[j][i] = std::conj(ksiPows[(j * rotGroup[i]) % m]);
      }
    }
    if (!isSparse) {
      precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, scaleEnc, lEnc);
    } else {
      std::vector<std::vector<std::complex<double>>> U1hatT(slots, std::vector<std::complex<double>>(slots));
      for (size_t i = 0; i < slots; i++) {
        for (size_t j = 0; j < slots; j++) {
          U1hatT[j][i] = std::conj(std::complex<double>(0, 1) * ksiPows[(j * rotGroup[i]) % m]);
        }
      }
      precom->m_U0hatTPre = EvalLinearTransformPrecompute(cc, U0hatT, U1hatT, 0, scaleEnc, lEnc);
    }
  } else {
    precom->m_U0hatTPreFFT = EvalCoeffsToSlotsPrecompute(cc, ksiPows, rotGroup, false, scaleEnc, lEnc);
  }

  if (precom->m_paramsDec[FFT_PARAMS::LEVEL_BUDGET] == 1) {
    std::vector<std::vector<std::complex<double>>> U0(slots, std::vector<std::complex<double>>(slots));
    for (size_t i = 0; i < slots; i++) {
      for (size_t j = 0; j < slots; j++) {
        U0[i][j] = ksiPows[(j * rotGroup[i]) % m];
      }
    }
    if (!isSparse) {
      precom->m_U0Pre = EvalLinearTransformPrecompute(cc, U0, scaleDec, lDec);
    } else {
      std::vector<std::vector<std::complex<double>>> U1(slots, std::vector<std::complex<double>>(slots));
      for (size_t i = 0; i < slots; i++) {
        for (size_t j = 0; j < slots; j++) {
          U1[i][j] = std::complex<double>(0, 1) * ksiPows[(j * rotGroup[i]) % m];
        }
      }
      precom->m_U0Pre = EvalLinearTransformPrecompute(cc, U0, U1, 1, scaleDec, lDec);
    }
  } else {
    precom->m_U0PreFFT = EvalSlotsToCoeffsPrecompute(cc, ksiPows, rotGroup, false, scaleDec, lDec);
  }
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> FHECKKSRNS::EvalBootstrapKeyGen(
    const PrivateKey<DCRTPoly> privateKey, uint32_t slots) {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          privateKey->GetCryptoParameters());

    if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
      OPENFHE_THROW(config_error, "CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT==128
    if (cryptoParams->GetRescalingTechnique() == FLEXIBLEAUTO)
      OPENFHE_THROW(config_error, "128-bit CKKS Bootstrapping is not supported for the FLEXIBLEAUTO method.");
#endif
    auto cc = privateKey->GetCryptoContext();
    uint32_t M = cc->GetCyclotomicOrder();

  if (slots == 0) slots = M/4;
  // computing all indices for baby-step giant-step procedure
  auto algo = cc->GetScheme();
  auto evalKeys = algo->EvalAtIndexKeyGen(nullptr, privateKey,
      FindBootstrapRotationIndices(slots, M));

  auto conjKey = ConjugateKeyGen(privateKey);
  (*evalKeys)[M - 1] = conjKey;

  return evalKeys;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrap(ConstCiphertext<DCRTPoly> ciphertext) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  if (cryptoParams->GetKeySwitchTechnique() != HYBRID)
      OPENFHE_THROW(config_error, "CKKS Bootstrapping is only supported for the Hybrid key switching method.");
#if NATIVEINT==128
    if (cryptoParams->GetRescalingTechnique() == FLEXIBLEAUTO)
      OPENFHE_THROW(config_error, "128-bit CKKS Bootstrapping is not supported for the FLEXIBLEAUTO method.");
#endif

#ifdef BOOTSTRAPTIMING
  TimeVar t;
  double timeEncode(0.0);
  double timeModReduce(0.0);
  double timeDecode(0.0);
#endif

  uint32_t slots = ciphertext->GetSlots();
  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);

  auto cc = ciphertext->GetCryptoContext();
  uint32_t M = cc->GetCyclotomicOrder();
  size_t N = cc->GetRingDimension();

  auto elementParams = cryptoParams->GetElementParams();
  NativeInteger q = elementParams->GetParams()[0]->GetModulus().ConvertToInt();
  double qDouble = q.ConvertToDouble();

  const auto p = cryptoParams->GetPlaintextModulus();
  double powP = pow(2, p);

  double deg = std::round(std::log2(qDouble / powP));
  double correction = 9.0 - deg;
  double post = std::pow(2, deg);

  double pre = 1. / post;
  uint64_t scalar = std::llround(post);

  //------------------------------------------------------------------------------
  // RAISING THE MODULUS
  //------------------------------------------------------------------------------

  // In FLEXIBLEAUTO, raising the ciphertext to a larger number
  // of towers is a bit more complex, because we need to adjust
  // it's scaling factor to the one that corresponds to the level
  // it's being raised to.
  // Increasing the modulus

  Ciphertext<DCRTPoly> raised = ciphertext->Clone();
  auto algo = cc->GetScheme();
  algo->ModReduceInternalInPlace(raised, raised->GetDepth() - 1);

  AdjustCiphertext(raised, correction);
  auto ctxtDCRT = raised->GetElements();

  // We only use the level 0 ciphertext here. All other towers are automatically ignored to make
  // CKKS bootstrapping faster.
  for (size_t i = 0; i < ctxtDCRT.size(); i++) {
    DCRTPoly temp(elementParams, COEFFICIENT);
    ctxtDCRT[i].SetFormat(COEFFICIENT);
    temp = ctxtDCRT[i].GetElementAtIndex(0);
    temp.SetFormat(EVALUATION);
    ctxtDCRT[i] = temp;
  }

  raised->SetElements(ctxtDCRT);
  raised->SetLevel(elementParams->GetParams().size() - ctxtDCRT[0].GetNumOfElements());

#ifdef BOOTSTRAPTIMING
  std::cerr << "\nNumber of levels at the beginning of bootstrapping: " << raised->GetElements()[0].GetNumOfElements() - 1 << std::endl;
#endif

  //------------------------------------------------------------------------------
  // SETTING PARAMETERS FOR APPROXIMATE MODULAR REDUCTION
  //------------------------------------------------------------------------------

  // Coefficients of the Chebyshev series interpolating 1/(2 Pi) Sin(2 Pi K x)
  std::vector<double> coefficients;
  double k = 0;

  if (cryptoParams->GetMode() == SPARSE) {
    coefficients = g_coefficientsSparse;
    //k = K_SPARSE;
    k = 1.0; //do not divide by k as we already did it during precomputation
  } else {
    coefficients = g_coefficientsUniform;
    k = K_UNIFORM;
  }

  double constantEvalMult = pre * (1.0 / (k * N));

  cc->EvalMultInPlace(raised, constantEvalMult);

  // no linear transformations are needed for Chebyshev series as the range has been normalized to [-1,1]
  double coeffLowerBound = -1;
  double coeffUpperBound = 1;

  Ciphertext<DCRTPoly> ctxtDec;

  if (slots == M/4) {
    //------------------------------------------------------------------------------
    // FULLY PACKED CASE
    //------------------------------------------------------------------------------

#ifdef BOOTSTRAPTIMING
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running CoeffToSlot
    //------------------------------------------------------------------------------

    // need to call internal modular reduction so it also works for FLEXIBLEAUTO
    algo->ModReduceInternalInPlace(raised);

    // only one linear transform is needed as the other one can be derived
    auto ctxtEnc = (precom->m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] == 1) ?
      EvalLinearTransform(precom->m_U0hatTPre, raised) :
      EvalCoeffsToSlots(precom->m_U0hatTPreFFT, raised);

    auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag());
    auto conj = Conjugate(ctxtEnc, evalKeyMap);
    auto ctxtEncI = cc->EvalSub(ctxtEnc, conj);
    cc->EvalAddInPlace(ctxtEnc, conj);
    algo->MultByMonomialInPlace(ctxtEncI, 3 * M / 4);

    if (cryptoParams->GetRescalingTechnique() == FIXEDMANUAL) {
      while(ctxtEnc->GetDepth() > 1) {
        cc->ModReduceInPlace(ctxtEnc);
        cc->ModReduceInPlace(ctxtEncI);
      }
    } else {
      if (ctxtEnc->GetDepth() == 2) {
        algo->ModReduceInternalInPlace(ctxtEnc);
        algo->ModReduceInternalInPlace(ctxtEncI);
      }
    }

    //------------------------------------------------------------------------------
    // Running Approximate Mod Reduction
    //------------------------------------------------------------------------------

    // Evaluate Chebyshev series for the sine wave
    ctxtEnc = cc->EvalChebyshevSeries(ctxtEnc, coefficients, coeffLowerBound, coeffUpperBound);
    ctxtEncI = cc->EvalChebyshevSeries(ctxtEncI, coefficients, coeffLowerBound, coeffUpperBound);

    // Double-angle iterations are applied in the case of OPTIMIZED/uniform secrets
    if (cryptoParams->GetMode() == OPTIMIZED) {
      if (cryptoParams->GetRescalingTechnique() != FIXEDMANUAL) {
        algo->ModReduceInternalInPlace(ctxtEnc);
        algo->ModReduceInternalInPlace(ctxtEncI);
      }
      ApplyDoubleAngleIterations(ctxtEnc);
      ApplyDoubleAngleIterations(ctxtEncI);
    }

    algo->MultByMonomialInPlace(ctxtEncI, M / 4);
    cc->EvalAddInPlace(ctxtEnc, ctxtEncI);

    // scale the message back up after Chebyshev interpolation
    algo->MultByIntegerInPlace(ctxtEnc, scalar);

#ifdef BOOTSTRAPTIMING
    timeModReduce = TOC(t);

     std::cerr << "Approximate modular reduction time: " << timeModReduce/1000.0 << " s" << std::endl;

    // Running SlotToCoeff

    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running SlotToCoeff
    //------------------------------------------------------------------------------

    // In the case of FLEXIBLEAUTO, we need one extra tower
    // TODO: See if we can remove the extra level in FLEXIBLEAUTO
    if (cryptoParams->GetRescalingTechnique() != FIXEDMANUAL) {
      algo->ModReduceInternalInPlace(ctxtEnc);
    }

    // Only one linear transform is needed
    ctxtDec = (precom->m_paramsDec[FFT_PARAMS::LEVEL_BUDGET] == 1) ?
      EvalLinearTransform(precom->m_U0Pre, ctxtEnc) :
      EvalSlotsToCoeffs(precom->m_U0PreFFT, ctxtEnc);
  } else {

    //------------------------------------------------------------------------------
    // SPARSELY PACKED CASE
    //------------------------------------------------------------------------------

    //------------------------------------------------------------------------------
    // Running PartialSum
    //------------------------------------------------------------------------------

    for (uint32_t j = 1; j < N/(2*slots); j <<= 1) {
      auto temp = cc->EvalRotate(raised, j * slots);
      cc->EvalAddInPlace(raised, temp);
    }

#ifdef BOOTSTRAPTIMING
    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running CoeffsToSlots
    //------------------------------------------------------------------------------

    algo->ModReduceInternalInPlace(raised);

    auto ctxtEnc = (precom->m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] == 1) ?
      EvalLinearTransform(precom->m_U0hatTPre, raised) :
      EvalCoeffsToSlots(precom->m_U0hatTPreFFT, raised);

    auto evalKeyMap = cc->GetEvalAutomorphismKeyMap(ctxtEnc->GetKeyTag());
    auto conj = Conjugate(ctxtEnc, evalKeyMap);
    cc->EvalAddInPlace(ctxtEnc, conj);

    if (cryptoParams->GetRescalingTechnique() == FIXEDMANUAL) {
      while(ctxtEnc->GetDepth() > 1) {
        cc->ModReduceInPlace(ctxtEnc);
      }
    } else {
      if (ctxtEnc->GetDepth() == 2) {
        algo->ModReduceInternalInPlace(ctxtEnc);
      }
    }

#ifdef BOOTSTRAPTIMING
    timeEncode = TOC(t);

    std::cerr << "\nEncoding time: " << timeEncode/1000.0 << " s" << std::endl;

    // Running Approximate Mod Reduction

    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running Approximate Mod Reduction
    //------------------------------------------------------------------------------

    // Evaluate Chebyshev series for the sine wave
    ctxtEnc = cc->EvalChebyshevSeries(ctxtEnc, coefficients, coeffLowerBound, coeffUpperBound);

    // Double-angle iterations are applied in the case of OPTIMIZED/uniform secrets
    if (cryptoParams->GetMode() == OPTIMIZED) {
      if (cryptoParams->GetRescalingTechnique() != FIXEDMANUAL) {
        algo->ModReduceInternalInPlace(ctxtEnc);
      }
      ApplyDoubleAngleIterations(ctxtEnc);
    }

    // scale the message back up after Chebyshev interpolation
    algo->MultByIntegerInPlace(ctxtEnc, scalar);

#ifdef BOOTSTRAPTIMING
    timeModReduce = TOC(t);

    std::cerr << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s" << std::endl;

    // Running SlotToCoeff

    TIC(t);
#endif

    //------------------------------------------------------------------------------
    // Running SlotsToCoeffs
    //------------------------------------------------------------------------------

    // In the case of FLEXIBLEAUTO, we need one extra tower
    // TODO: See if we can remove the extra level in FLEXIBLEAUTO
    if (cryptoParams->GetRescalingTechnique() != FIXEDMANUAL) {
      algo->ModReduceInternalInPlace(ctxtEnc);
    }

    // linear transform for decoding
    ctxtDec = (precom->m_paramsDec[FFT_PARAMS::LEVEL_BUDGET] == 1) ?
      EvalLinearTransform(precom->m_U0Pre, ctxtEnc) :
      EvalSlotsToCoeffs(precom->m_U0PreFFT, ctxtEnc);

    cc->EvalAddInPlace(ctxtDec, cc->EvalRotate(ctxtDec, slots));
  }


#if NATIVEINT!=128
  // 64-bit only: scale back the message to its original scale.
  uint64_t corFactor = (uint64_t)1 << std::llround(correction);
  algo->MultByIntegerInPlace(ctxtDec, corFactor);
#endif

#ifdef BOOTSTRAPTIMING
    timeDecode = TOC(t);

  std::cout << "Decoding time: " << timeDecode / 1000.0 << " s" << std::endl;
#endif

  return ctxtDec;
}

//------------------------------------------------------------------------------
// Find Rotation Indices
//------------------------------------------------------------------------------

std::vector<int32_t> FHECKKSRNS::FindBootstrapRotationIndices(
    uint32_t slots, uint32_t M) {
  std::vector<int32_t> fullIndexList;

  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);

  if (precom->m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] == 1) {
    std::vector<int32_t> indexList = FindLinearTransformRotationIndices(slots, M);
    fullIndexList.insert(fullIndexList.end(), indexList.begin(), indexList.end());
  } else {
    std::vector<int32_t> indexList = FindCoeffsToSlotsRotationIndices(slots, M);
    fullIndexList.insert(fullIndexList.end(), indexList.begin(), indexList.end());
  }

  if (precom->m_paramsDec[FFT_PARAMS::LEVEL_BUDGET] == 1) {
    if (precom->m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] != 1) {
      std::vector<int32_t> indexList = FindLinearTransformRotationIndices(slots, M);
      fullIndexList.insert(fullIndexList.end(), indexList.begin(), indexList.end());
      // Remove possible duplicates
      sort(fullIndexList.begin(), fullIndexList.end());
      fullIndexList.erase(unique(fullIndexList.begin(), fullIndexList.end()), fullIndexList.end());
    }
  } else {
    std::vector<int32_t> indexList = FindSlotsToCoeffsRotationIndices(slots, M);
    fullIndexList.insert(fullIndexList.end(), indexList.begin(), indexList.end());
  }

  // Remove possible duplicates
  sort(fullIndexList.begin(), fullIndexList.end());
  fullIndexList.erase(unique(fullIndexList.begin(), fullIndexList.end()), fullIndexList.end());

  //remove automorphisms corresponding to 0
  fullIndexList.erase(std::remove(fullIndexList.begin(), fullIndexList.end(), 0), fullIndexList.end());
  fullIndexList.erase(std::remove(fullIndexList.begin(), fullIndexList.end(), M/4), fullIndexList.end());

  return fullIndexList;
}

std::vector<int32_t> FHECKKSRNS::FindLinearTransformRotationIndices(uint32_t slots, uint32_t M) {
  std::vector<int32_t> indexList;
  // precom.m_slots and precom.m_dim1 are not available when we call solely EvalLT
  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);

  // Computing the baby-step g and the giant-step h.
  int g = (precom->m_dim1 == 0) ? ceil(sqrt(slots)) : precom->m_dim1;
  int h =  ceil((double)slots/g);

  // computing all indices for baby-step giant-step procedure
  // ATTN: resize() is used as indexListEvalLT may be empty here
  indexList.reserve(g + h - 2);
  for (int i = 0; i < g; i++) {
    indexList.emplace_back(i + 1);
  }
  for (int i = 2; i < h; i++) {
    indexList.emplace_back(g * i);
  }

  uint32_t m = slots * 4;
  // additional automorphisms are needed for sparse bootstrapping
  if (m != M) {
    for (uint32_t j = 1; j < M/m; j <<= 1) {
      indexList.emplace_back(j * slots);
    }
  }
  // Remove possible duplicates
  sort(indexList.begin(), indexList.end());
  indexList.erase(unique(indexList.begin(), indexList.end()), indexList.end());

  //remove automorphisms corresponding to 0
  indexList.erase(std::remove(indexList.begin(), indexList.end(), 0), indexList.end());
  indexList.erase(std::remove(indexList.begin(), indexList.end(), M/4), indexList.end());

  return indexList;
}

std::vector<int32_t> FHECKKSRNS::FindCoeffsToSlotsRotationIndices(
    uint32_t slots, uint32_t M) {
  std::vector<int32_t> indexList;

  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);

  int32_t levelBudget = precom->m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET];
  int32_t layersCollapse = precom->m_paramsEnc[FFT_PARAMS::LAYERS_COLL];
  int32_t remCollapse = precom->m_paramsEnc[FFT_PARAMS::LAYERS_REM];
  int32_t numRotations = precom->m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS];
  int32_t b = precom->m_paramsEnc[FFT_PARAMS::BABY_STEP];
  int32_t g = precom->m_paramsEnc[FFT_PARAMS::GIANT_STEP];
  int32_t numRotationsRem = precom->m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS_REM];
  int32_t bRem = precom->m_paramsEnc[FFT_PARAMS::BABY_STEP_REM];
  int32_t gRem = precom->m_paramsEnc[FFT_PARAMS::GIANT_STEP_REM];

  int32_t stop;
  int32_t flagRem;
  if (remCollapse == 0) {
    stop = -1;
    flagRem = 0;
  } else {
    stop = 0;
    flagRem = 1;
  }

  // Computing all indices for baby-step giant-step procedure for encoding and decoding
  if (flagRem == 0) {
    indexList.reserve(b + g - 2 + 1);
  } else {
    indexList.reserve(b + g - 2 + bRem + gRem - 2 + 1);
  }

  for (int32_t s = int32_t(levelBudget) - 1; s > stop; s--) {
    for (int32_t j = 0; j < g; j++) {
      indexList.emplace_back(ReduceRotation(
          (j - int32_t((numRotations + 1)/2) + 1) * (1 << ((s - flagRem) * layersCollapse + remCollapse)), slots));
    }

    for (int32_t i = 0; i < b; i++) {
      indexList.emplace_back(ReduceRotation(
          (g * i) * (1 << ((s - flagRem) * layersCollapse + remCollapse)), M/4));
    }
  }

  if (flagRem) {
    for (int32_t j = 0; j < gRem; j++) {
      indexList.emplace_back(ReduceRotation(
          (j - int32_t((numRotationsRem + 1)/2) + 1), slots));
    }
    for (int32_t i = 0; i < bRem; i++) {
      indexList.emplace_back(ReduceRotation(
          gRem * i, M/4));
    }
  }

  uint32_t m = slots * 4;
  // additional automorphisms are needed for sparse bootstrapping
  if (m != M) {
    for (uint32_t j = 1; j < M/m; j <<= 1) {
      indexList.emplace_back(j * slots);
    }
  }

  // Remove possible duplicates
  sort(indexList.begin(), indexList.end());
  indexList.erase(unique(indexList.begin(), indexList.end()), indexList.end());

  //remove automorphisms corresponding to 0
  indexList.erase(std::remove(indexList.begin(), indexList.end(), 0), indexList.end());
  indexList.erase(std::remove(indexList.begin(), indexList.end(), M/4), indexList.end());

  return indexList;
}

std::vector<int32_t> FHECKKSRNS::FindSlotsToCoeffsRotationIndices(
    uint32_t slots, uint32_t M) {
  std::vector<int32_t> indexList;
  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);

  int32_t levelBudget = precom->m_paramsDec[FFT_PARAMS::LEVEL_BUDGET];
  int32_t layersCollapse = precom->m_paramsDec[FFT_PARAMS::LAYERS_COLL];
  int32_t remCollapse = precom->m_paramsDec[FFT_PARAMS::LAYERS_REM];
  int32_t numRotations = precom->m_paramsDec[FFT_PARAMS::NUM_ROTATIONS];
  int32_t b = precom->m_paramsDec[FFT_PARAMS::BABY_STEP];
  int32_t g = precom->m_paramsDec[FFT_PARAMS::GIANT_STEP];
  int32_t numRotationsRem = precom->m_paramsDec[FFT_PARAMS::NUM_ROTATIONS_REM];
  int32_t bRem = precom->m_paramsDec[FFT_PARAMS::BABY_STEP_REM];
  int32_t gRem = precom->m_paramsDec[FFT_PARAMS::GIANT_STEP_REM];

  int32_t flagRem;
  if (remCollapse == 0) {
    flagRem = 0;
  } else {
    flagRem = 1;
  }

  // Computing all indices for baby-step giant-step procedure for encoding and decoding
  if (flagRem == 0) {
    indexList.reserve(b + g - 2 + 1);
  } else {
    indexList.reserve(b + g - 2 + bRem + gRem - 2 + 1);
  }

  for(int32_t s = 0; s < int32_t(levelBudget); s++){
    for(int32_t j = 0; j < g; j++) {
      indexList.emplace_back(ReduceRotation(
          (j - (numRotations + 1)/2 + 1) * (1 <<(s * layersCollapse)), M/4));
    }
    for(int32_t i = 0; i < b; i++) {
      indexList.emplace_back(ReduceRotation(
          (g * i) * (1 << (s * layersCollapse)), M/4));
    }
  }

  if (flagRem) {
    int32_t s = int32_t(levelBudget) - flagRem;
    for (int32_t j = 0; j < gRem; j++) {
      indexList.emplace_back(ReduceRotation(
          (j - (numRotationsRem + 1)/2 + 1) * (1 << (s * layersCollapse)), M/4));
    }
    for (int32_t i = 0; i < bRem; i++) {
      indexList.emplace_back(ReduceRotation(
          (gRem * i) * (1 << (s * layersCollapse)), M/4));
    }
  }

  uint32_t m = slots * 4;
  // additional automorphisms are needed for sparse bootstrapping
  if (m != M) {
    for (uint32_t j = 1; j < M/m; j <<= 1) {
      indexList.emplace_back(j * slots);
    }
  }

  // Remove possible duplicates
  sort(indexList.begin(), indexList.end());
  indexList.erase(unique(indexList.begin(), indexList.end()), indexList.end());

  //remove automorphisms corresponding to 0
  indexList.erase(std::remove(indexList.begin(), indexList.end(), 0), indexList.end());
  indexList.erase(std::remove(indexList.begin(), indexList.end(), M/4), indexList.end());

  return indexList;
}

//------------------------------------------------------------------------------
// Precomputations for CoeffsToSlots and SlotsToCoeffs
//------------------------------------------------------------------------------

std::vector<ConstPlaintext> FHECKKSRNS::EvalLinearTransformPrecompute(
    const CryptoContextImpl<DCRTPoly> &cc,
    const std::vector<std::vector<std::complex<double>>>& A,
    double scale, uint32_t L) const {
  if (A[0].size() != A.size()) {
    OPENFHE_THROW(math_error,
        "The matrix passed to EvalLTPrecompute is not square");
  }

  uint32_t slots = A.size();
  uint32_t M = cc.GetCyclotomicOrder();

  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);
  // Computing the baby-step bStep and the giant-step gStep.
  int bStep = (precom->m_dim1 == 0) ? ceil(sqrt(slots)) : precom->m_dim1;
  int gStep = ceil(static_cast<double>(slots) / bStep);

  // make sure the plaintext is created only with the necessary amount of moduli

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          cc.GetCryptoParameters());

  ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());

  uint32_t towersToDrop = 0;
  if (L != 0) {
    towersToDrop = elementParams.GetParams().size() - L - 1;
    for (uint32_t i = 0; i < towersToDrop; i++) elementParams.PopLastParam();
  }

  auto paramsQ = elementParams.GetParams();
  usint sizeQ = paramsQ.size();
  auto paramsP = cryptoParams->GetParamsP()->GetParams();
  usint sizeP = paramsP.size();

  std::vector<NativeInteger> moduli(sizeQ + sizeP);
  std::vector<NativeInteger> roots(sizeQ + sizeP);

  for (size_t i = 0; i < sizeQ; i++) {
    moduli[i] = paramsQ[i]->GetModulus();
    roots[i] = paramsQ[i]->GetRootOfUnity();
  }

  for (size_t i = 0; i < sizeP; i++) {
      moduli[sizeQ + i] = paramsP[i]->GetModulus();
      roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
  }

  auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);
//  auto elementParamsPtr2 = std::dynamic_pointer_cast<typename DCRTPoly::Params>(elementParamsPtr);

  std::vector<ConstPlaintext> result(slots);
#pragma omp parallel for
  for (int j = 0; j < gStep; j++) {
      int offset = -bStep * j;
      for (int i = 0; i < bStep; i++) {
      if (bStep*j + i < static_cast<int>(slots)) {
        auto diag = ExtractShiftedDiagonal(A, bStep*j + i);
        for (uint32_t k = 0; k < diag.size(); k++) diag[k] *= scale;

        result[bStep * j + i] =
            MakeAuxPlaintext(cc, elementParamsPtr,
                Rotate(diag, offset), 1, towersToDrop, diag.size());
      }
    }
  }
  return result;
}

std::vector<ConstPlaintext> FHECKKSRNS::EvalLinearTransformPrecompute(
    const CryptoContextImpl<DCRTPoly> &cc,
    const std::vector<std::vector<std::complex<double>>>& A,
    const std::vector<std::vector<std::complex<double>>>& B,
    uint32_t orientation, double scale, uint32_t L) const {
  uint32_t slots = A.size();
  uint32_t M = cc.GetCyclotomicOrder();

  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);

  // Computing the baby-step bStep and the giant-step gStep.
  int bStep = (precom->m_dim1 == 0) ? ceil(sqrt(slots)) : precom->m_dim1;
  int gStep = ceil(static_cast<double>(slots) / bStep);

  // make sure the plaintext is created only with the necessary amount of moduli

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          cc.GetCryptoParameters());

  auto elementParams = *(cryptoParams->GetElementParams());

  uint32_t towersToDrop = 0;
  if (L != 0) {
    towersToDrop = elementParams.GetParams().size() - L - 1;
    for (uint32_t i = 0; i < towersToDrop; i++) elementParams.PopLastParam();
  }

  auto paramsQ = elementParams.GetParams();
  usint sizeQ = paramsQ.size();
  auto paramsP = cryptoParams->GetParamsP()->GetParams();
  usint sizeP = paramsP.size();

  std::vector<NativeInteger> moduli(sizeQ + sizeP);
  std::vector<NativeInteger> roots(sizeQ + sizeP);
  for (size_t i = 0; i < sizeQ; i++) {
    moduli[i] = paramsQ[i]->GetModulus();
    roots[i] = paramsQ[i]->GetRootOfUnity();
  }

  for (size_t i = 0; i < sizeP; i++) {
    moduli[sizeQ + i] = paramsP[i]->GetModulus();
    roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
  }

  auto elementParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(M, moduli, roots);
//  auto elementParamsPtr2 = std::dynamic_pointer_cast<typename DCRTPoly::Params>(elementParamsPtr);

  std::vector<ConstPlaintext> result(slots);

  if (orientation == 0) {
    // vertical concatenation - used during homomorphic encoding
    // #pragma omp parallel for
    for (int j = 0; j < gStep; j++) {
      int offset = -bStep * j;
      for (int i = 0; i < bStep; i++) {
        if (bStep * j + i < static_cast<int>(slots)) {
          auto vecA = ExtractShiftedDiagonal(A, bStep * j + i);
          auto vecB = ExtractShiftedDiagonal(B, bStep * j + i);

          vecA.insert(vecA.end(), vecB.begin(), vecB.end());
          for (uint32_t k = 0; k < vecA.size(); k++) vecA[k] *= scale;

          result[bStep * j + i] =
              MakeAuxPlaintext(cc, elementParamsPtr,
                Rotate(vecA, offset), 1, towersToDrop, vecA.size());
        }
      }
    }
  } else {
    // horizontal concatenation - used during homomorphic decoding
    std::vector<std::vector<std::complex<double>>> newA(slots);

    //  A and B are concatenated horizontally
    for (uint32_t i = 0; i < A.size(); i++) {
      auto vecA = A[i];
      auto vecB = B[i];
      vecA.insert(vecA.end(), vecB.begin(), vecB.end());
      newA[i] = vecA;
    }

#pragma omp parallel for
    for (int j = 0; j < gStep; j++) {
        int offset = -bStep * j;
        for (int i = 0; i < bStep; i++) {
        if (bStep*j + i < static_cast<int>(slots)) {
          // shifted diagonal is computed for rectangular map newA of dimension
          // slots x 2*slots
          auto vec = ExtractShiftedDiagonal(newA, bStep * j + i);
          for (uint32_t k = 0; k < vec.size(); k++) vec[k] *= scale;

          result[bStep * j + i] =
              MakeAuxPlaintext(cc, elementParamsPtr,
                  Rotate(vec, offset), 1, towersToDrop, vec.size());
        }
      }
    }
  }

  return result;
}

std::vector<std::vector<ConstPlaintext>> FHECKKSRNS::EvalCoeffsToSlotsPrecompute(
    const CryptoContextImpl<DCRTPoly> &cc,
    const std::vector<std::complex<double>> &A,
    const std::vector<uint32_t> &rotGroup,
    bool flag_i, double scale, uint32_t L) const {

  uint32_t slots = rotGroup.size();
  uint32_t M = cc.GetCyclotomicOrder();

  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);

  int32_t levelBudget = precom->m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET];
  int32_t layersCollapse = precom->m_paramsEnc[FFT_PARAMS::LAYERS_COLL];
  int32_t remCollapse = precom->m_paramsEnc[FFT_PARAMS::LAYERS_REM];
  int32_t numRotations = precom->m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS];
  int32_t b = precom->m_paramsEnc[FFT_PARAMS::BABY_STEP];
  int32_t g = precom->m_paramsEnc[FFT_PARAMS::GIANT_STEP];
  int32_t numRotationsRem = precom->m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS_REM];
  int32_t bRem = precom->m_paramsEnc[FFT_PARAMS::BABY_STEP_REM];
  int32_t gRem = precom->m_paramsEnc[FFT_PARAMS::GIANT_STEP_REM];

  int32_t stop = -1;
  int32_t flagRem = 0;

  if (remCollapse != 0) {
    stop = 0;
    flagRem = 1;
  }

  // result is the rotated plaintext version of the coefficients
  std::vector<std::vector<ConstPlaintext>> result(levelBudget);
  for (uint32_t i = 0; i < uint32_t(levelBudget); i++) {
    if (flagRem == 1 && i == 0) {
      // remainder corresponds to index 0 in encoding and to last index in decoding
      result[i] = std::vector<ConstPlaintext>(numRotationsRem);
    } else {
      result[i] = std::vector<ConstPlaintext>(numRotations);
    }
  }

  // make sure the plaintext is created only with the necessary amount of moduli

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          cc.GetCryptoParameters());

  auto elementParams = *(cryptoParams->GetElementParams());

  uint32_t towersToDrop = 0;

  if (L != 0) {
    towersToDrop = elementParams.GetParams().size() - L - levelBudget;
    for (uint32_t i = 0; i < towersToDrop; i++) {
      elementParams.PopLastParam();
    }
  }

  uint32_t level0 = towersToDrop + levelBudget - 1;

  auto paramsQ = elementParams.GetParams();
  usint sizeQ = paramsQ.size();
  auto paramsP = cryptoParams->GetParamsP()->GetParams();
  usint sizeP = paramsP.size();

  std::vector<NativeInteger> moduli(sizeQ + sizeP);
  std::vector<NativeInteger> roots(sizeQ + sizeP);
  for (size_t i = 0; i < sizeQ; i++) {
    moduli[i] = paramsQ[i]->GetModulus();
    roots[i] = paramsQ[i]->GetRootOfUnity();
  }

  for (size_t i = 0; i < sizeP; i++) {
    moduli[sizeQ + i] = paramsP[i]->GetModulus();
    roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
  }

  // we need to pre-compute the plaintexts in the extended basis P*Q
  std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> paramsVector(levelBudget - stop);
  for (int32_t s = levelBudget - 1; s >= stop; s--) {
      paramsVector[s - stop] = std::make_shared<ILDCRTParams<BigInteger>>(M, moduli, roots);
      moduli.erase(moduli.begin() + sizeQ - 1);
      roots.erase(roots.begin() + sizeQ - 1);
      sizeQ--;
  }

  if (slots == M/4) {
    //------------------------------------------------------------------------------
    // fully-packed mode
    //------------------------------------------------------------------------------

    auto coeff = CoeffEncodingCollapse(A, rotGroup, levelBudget, flag_i);

    for (int32_t s = levelBudget - 1; s > stop; s--) {
      for (int32_t i = 0; i < b; i++) {

#pragma omp parallel for
        for (int32_t j = 0; j < g; j++) {
          if (g * i + j != int32_t(numRotations)) {
            uint32_t rot = ReduceRotation(
                -g * i * (1 << ((s - flagRem) * layersCollapse + remCollapse)), slots);
            if ((flagRem == 0) && (s == stop + 1)) {
              // do the scaling only at the last set of coefficients
              for (uint32_t k = 0; k < slots; k++) {
                coeff[s][g * i + j][k] *= scale;
              }
            }

            auto rotateTemp = Rotate(coeff[s][g * i + j], rot);

            result[s][g * i + j] = MakeAuxPlaintext(
                cc, paramsVector[s - stop], rotateTemp, 1, level0 - s, rotateTemp.size());
          }
        }
      }
    }

    if (flagRem) {
      for (int32_t i = 0; i < bRem; i++) {

#pragma omp parallel for
        for (int32_t j=0; j < gRem; j++) {
          if (gRem * i + j != int32_t(numRotationsRem)) {
            uint32_t rot = ReduceRotation(
                -gRem * i,slots);
            for (uint32_t k=0; k < slots; k++) {
              coeff[stop][gRem * i + j][k] *= scale;
            }

            auto rotateTemp = Rotate(coeff[stop][gRem * i + j], rot);
            result[stop][gRem * i + j] = MakeAuxPlaintext(
                cc, paramsVector[0],
                rotateTemp, 1, level0, rotateTemp.size());
          }
        }
      }
    }
  } else {
    //------------------------------------------------------------------------------
    //sparsely-packed mode
    //------------------------------------------------------------------------------

    auto coeff = CoeffEncodingCollapse(A, rotGroup, levelBudget, false);
    auto coeffi = CoeffEncodingCollapse(A, rotGroup, levelBudget, true);

    for (int32_t s = levelBudget - 1; s > stop; s--) {
      for (int32_t i = 0; i < b; i++) {

#pragma omp parallel for
        for (int32_t j = 0; j < g; j++) {
          if (g*i + j != int32_t(numRotations)) {
            uint32_t rot = ReduceRotation(
                -g * i * (1 << ((s - flagRem) * layersCollapse + remCollapse)), M/4);
            // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
            auto clearTemp = coeff[s][g * i + j];
            auto clearTempi = coeffi[s][g * i + j];
            clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
            if ((flagRem == 0) && (s == stop + 1)) {
              // do the scaling only at the last set of coefficients
              for (uint32_t k = 0; k < clearTemp.size(); k++) {
                clearTemp[k] *= scale;
              }
            }

            auto rotateTemp = Rotate(clearTemp, rot);
            result[s][g * i + j] = MakeAuxPlaintext(
                cc, paramsVector[s - stop],
                rotateTemp, 1, level0 - s, rotateTemp.size());
          }
        }
      }
    }

    if (flagRem) {
      for (int32_t i = 0; i < bRem; i++) {

#pragma omp parallel for
        for (int32_t j=0; j < gRem; j++) {
          if (gRem * i + j != int32_t(numRotationsRem)) {
            uint32_t rot = ReduceRotation(
                -gRem * i, M/4);
            // concatenate the coefficients on their third dimension, which corresponds to the # of slots
            auto clearTemp = coeff[stop][gRem * i + j];
            auto clearTempi = coeffi[stop][gRem * i + j];
            clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
            for (uint32_t k = 0; k < clearTemp.size(); k++) {
              clearTemp[k] *= scale;
            }

            auto rotateTemp = Rotate(clearTemp, rot);
            result[stop][gRem * i + j] = MakeAuxPlaintext(
                cc, paramsVector[0], rotateTemp, 1, level0, rotateTemp.size());
          }
        }
      }
    }
  }
  return result;
}

std::vector<std::vector<ConstPlaintext>> FHECKKSRNS::EvalSlotsToCoeffsPrecompute(
    const CryptoContextImpl<DCRTPoly> &cc,
    const std::vector<std::complex<double>> &A,
    const std::vector<uint32_t> &rotGroup,
    bool flag_i, double scale, uint32_t L) const {

  uint32_t slots = rotGroup.size();
  uint32_t M = cc.GetCyclotomicOrder();

  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);

  int32_t levelBudget = precom->m_paramsDec[FFT_PARAMS::LEVEL_BUDGET];
  int32_t layersCollapse = precom->m_paramsDec[FFT_PARAMS::LAYERS_COLL];
  int32_t remCollapse = precom->m_paramsDec[FFT_PARAMS::LAYERS_REM];
  int32_t numRotations = precom->m_paramsDec[FFT_PARAMS::NUM_ROTATIONS];
  int32_t b = precom->m_paramsDec[FFT_PARAMS::BABY_STEP];
  int32_t g = precom->m_paramsDec[FFT_PARAMS::GIANT_STEP];
  int32_t numRotationsRem = precom->m_paramsDec[FFT_PARAMS::NUM_ROTATIONS_REM];
  int32_t bRem = precom->m_paramsDec[FFT_PARAMS::BABY_STEP_REM];
  int32_t gRem = precom->m_paramsDec[FFT_PARAMS::GIANT_STEP_REM];

  int32_t flagRem = 0;

  if (remCollapse != 0) {
    flagRem = 1;
  }

  // result is the rotated plaintext version of coeff
  std::vector<std::vector<ConstPlaintext>> result(levelBudget);
  for (uint32_t i = 0; i < uint32_t(levelBudget); i++) {
    if (flagRem == 1 && i == uint32_t(levelBudget - 1)) {
      // remainder corresponds to index 0 in encoding and to last index in decoding
      result[i] = std::vector<ConstPlaintext>(numRotationsRem);
    } else {
      result[i] = std::vector<ConstPlaintext>(numRotations);
    }
  }

  // make sure the plaintext is created only with the necessary amount of moduli

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          cc.GetCryptoParameters());

  auto elementParams = *(cryptoParams->GetElementParams());

  uint32_t towersToDrop = 0;

  if (L != 0) {
    towersToDrop = elementParams.GetParams().size() - L - levelBudget;
    for (uint32_t i = 0; i < towersToDrop; i++) {
      elementParams.PopLastParam();
    }
  }

  uint32_t level0 = towersToDrop;

  auto paramsQ = elementParams.GetParams();
  usint sizeQ = paramsQ.size();
  auto paramsP = cryptoParams->GetParamsP()->GetParams();
  usint sizeP = paramsP.size();

  std::vector<NativeInteger> moduli(sizeQ + sizeP);
  std::vector<NativeInteger> roots(sizeQ + sizeP);
  for (size_t i = 0; i < sizeQ; i++) {
    moduli[i] = paramsQ[i]->GetModulus();
    roots[i] = paramsQ[i]->GetRootOfUnity();
  }

  for (size_t i = 0; i < sizeP; i++) {
    moduli[sizeQ + i] = paramsP[i]->GetModulus();
    roots[sizeQ + i] = paramsP[i]->GetRootOfUnity();
  }

  // we need to pre-compute the plaintexts in the extended basis P*Q
  std::vector<std::shared_ptr<ILDCRTParams<BigInteger>>> paramsVector(levelBudget - flagRem + 1);
  for (int32_t s = 0; s < levelBudget - flagRem + 1; s++) {
      paramsVector[s] = std::make_shared<ILDCRTParams<BigInteger>>(M, moduli, roots);
      moduli.erase(moduli.begin() + sizeQ - 1);
      roots.erase(roots.begin() + sizeQ - 1);
      sizeQ--;
  }

  if (slots == M/4) {
    // fully-packed
    auto coeff = CoeffDecodingCollapse(A, rotGroup, levelBudget, flag_i);

    for (int32_t s = 0; s < levelBudget - flagRem; s++) {
      for (int32_t i = 0; i < b; i++) {

#pragma omp parallel for
        for (int32_t j = 0; j < g; j++) {
          if (g * i + j != int32_t(numRotations)) {
            uint32_t rot = ReduceRotation(
                -g * i * (1 << (s * layersCollapse)), slots);
            if ((flagRem == 0) && (s == levelBudget - flagRem - 1)) {
              // do the scaling only at the last set of coefficients
              for (uint32_t k = 0; k < slots; k++) {
                coeff[s][g * i + j][k] *= scale;
              }
            }

            auto rotateTemp = Rotate(coeff[s][g * i + j], rot);
            result[s][g * i + j] = MakeAuxPlaintext(
                cc, paramsVector[s],
                rotateTemp, 1, level0 + s, rotateTemp.size());
          }
        }
      }
    }

    if (flagRem) {
      int32_t s = levelBudget - flagRem;
      for (int32_t i = 0; i < bRem; i++) {

#pragma omp parallel for
        for (int32_t j = 0; j < gRem; j++) {
          if (gRem * i + j != int32_t(numRotationsRem)) {
            uint32_t rot = ReduceRotation(
                -gRem * i * (1 << (s * layersCollapse)), slots);
            for (uint32_t k = 0; k < slots; k++) {
              coeff[s][gRem * i + j][k] *= scale;
            }

            auto rotateTemp = Rotate(coeff[s][gRem * i + j], rot);
            result[s][gRem * i + j] = MakeAuxPlaintext(
                cc, paramsVector[s],
                rotateTemp, 1, level0 + s, rotateTemp.size());
          }
        }
      }
    }
  } else {

    //------------------------------------------------------------------------------
    // sparsely-packed mode
    //------------------------------------------------------------------------------

    auto coeff = CoeffDecodingCollapse(A, rotGroup, levelBudget, false);
    auto coeffi = CoeffDecodingCollapse(A, rotGroup, levelBudget, true);

    for (int32_t s = 0; s < levelBudget - flagRem; s++) {
      for (int32_t i = 0; i < b; i++) {

#pragma omp parallel for
        for (int32_t j = 0; j < g; j++) {
          if (g*i + j != int32_t(numRotations)) {
            uint32_t rot = ReduceRotation(
                -g * i * (1 << (s * layersCollapse)), M/4);
            // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
            auto clearTemp = coeff[s][g * i + j];
            auto clearTempi = coeffi[s][g * i + j];
            clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
            if ((flagRem == 0) && (s == levelBudget - flagRem - 1)) {
              // do the scaling only at the last set of coefficients
              for (uint32_t k = 0; k < clearTemp.size(); k++) {
                clearTemp[k] *= scale;
              }
            }

            auto rotateTemp = Rotate(clearTemp, rot);
            result[s][g * i + j] = MakeAuxPlaintext(
                cc, paramsVector[s],
                rotateTemp, 1, level0 + s, rotateTemp.size());
          }
        }
      }
    }

    if (flagRem) {
      int32_t s = levelBudget - flagRem;
      for (int32_t i = 0; i < bRem; i++) {

#pragma omp parallel for
        for (int32_t j = 0; j < gRem; j++) {
          if (gRem * i + j != int32_t(numRotationsRem)) {
            uint32_t rot = ReduceRotation(
                -gRem * i * (1 << (s * layersCollapse)), M/4);
            // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
            auto clearTemp = coeff[s][gRem * i + j];
            auto clearTempi = coeffi[s][gRem * i + j];
            clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
            for (uint32_t k = 0; k < clearTemp.size(); k++) {
              clearTemp[k] *= scale;
            }

            auto rotateTemp = Rotate(clearTemp, rot);
            result[s][gRem * i + j] = MakeAuxPlaintext(
                cc, paramsVector[s],
                rotateTemp, 1, level0 + s, rotateTemp.size());
          }
        }
      }
    }
  }
  return result;
}

//------------------------------------------------------------------------------
// EVALUATION: CoeffsToSlots and SlotsToCoeffs
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> FHECKKSRNS::EvalLinearTransform(
    const std::vector<ConstPlaintext>& A,
    ConstCiphertext<DCRTPoly> ct) const {
  auto cc = ct->GetCryptoContext();
  uint32_t slots = A.size();

  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);

  // Computing the baby-step bStep and the giant-step gStep.
  uint32_t bStep = (precom->m_dim1 == 0) ? ceil(sqrt(slots)) : precom->m_dim1;
  uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

  uint32_t M = cc->GetCyclotomicOrder();
  uint32_t N = cc->GetRingDimension();

  // computes the NTTs for each CRT limb (for the hoisted automorphisms used
  // later on)
  auto digits = cc->EvalFastRotationPrecompute(ct);

  std::vector<Ciphertext<DCRTPoly>> fastRotation(bStep - 1);

  // hoisted automorphisms
#pragma omp parallel for
  for (uint32_t j = 1; j < bStep; j++) {
    fastRotation[j - 1] = cc->EvalFastRotationExt(ct, j, digits, true);
  }

  Ciphertext<DCRTPoly> result;
  DCRTPoly first;

  for (uint32_t j = 0; j < gStep; j++) {
    Ciphertext<DCRTPoly> inner =
        EvalMultExt(cc->KeySwitchExt(ct, true), A[bStep * j]);
    for (uint32_t i = 1; i < bStep; i++) {
      if (bStep * j + i < slots) {
        EvalAddExtInPlace(inner, EvalMultExt(fastRotation[i - 1], A[bStep * j + i]));
      }
    }

    if (j == 0) {
      first = cc->KeySwitchDownFirstElement(inner);
      auto elements = inner->GetElements();
      elements[0].SetValuesToZero();
      inner->SetElements(elements);
      result = inner;
    } else {
      inner = cc->KeySwitchDown(inner);
      // Find the automorphism index that corresponds to rotation index index.
      usint autoIndex = FindAutomorphismIndex2nComplex(bStep * j, M);
      std::vector<usint> map(N);
      PrecomputeAutoMap(N, autoIndex, &map);
      DCRTPoly firstCurrent = inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
      first += firstCurrent;

      auto innerDigits = cc->EvalFastRotationPrecompute(inner);
      EvalAddExtInPlace(result,
          cc->EvalFastRotationExt(inner, bStep * j, innerDigits, false));
    }
  }

  result = cc->KeySwitchDown(result);
  auto elements = result->GetElements();
  elements[0] += first;
  result->SetElements(elements);

  return result;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalCoeffsToSlots(
    const std::vector<std::vector<ConstPlaintext>> &A, ConstCiphertext<DCRTPoly> ctxt) const {

  auto cc = ctxt->GetCryptoContext();
  uint32_t M = cc->GetCyclotomicOrder();
  uint32_t N = cc->GetRingDimension();

  uint32_t slots = ctxt->GetSlots();
  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);

  int32_t levelBudget = precom->m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET];
  int32_t layersCollapse = precom->m_paramsEnc[FFT_PARAMS::LAYERS_COLL];
  int32_t remCollapse = precom->m_paramsEnc[FFT_PARAMS::LAYERS_REM];
  int32_t numRotations = precom->m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS];
  int32_t b = precom->m_paramsEnc[FFT_PARAMS::BABY_STEP];
  int32_t g = precom->m_paramsEnc[FFT_PARAMS::GIANT_STEP];
  int32_t numRotationsRem = precom->m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS_REM];
  int32_t bRem = precom->m_paramsEnc[FFT_PARAMS::BABY_STEP_REM];
  int32_t gRem = precom->m_paramsEnc[FFT_PARAMS::GIANT_STEP_REM];

  int32_t stop = -1;
  int32_t flagRem = 0;

  auto algo = cc->GetScheme();

  if (remCollapse!=0) {
    stop = 0;
    flagRem = 1;
  }

  // precompute the inner and outer rotations
  std::vector<std::vector<int32_t>> rot_in(levelBudget);
  for(uint32_t i = 0; i < uint32_t(levelBudget); i++){
    if (flagRem == 1 && i == 0) {
      // remainder corresponds to index 0 in encoding and to last index in decoding
      rot_in[i] = std::vector<int32_t>(numRotationsRem + 1);
    } else {
      rot_in[i] = std::vector<int32_t>(numRotations + 1);
    }
  }

  std::vector<std::vector<int32_t>> rot_out(levelBudget);
  for(uint32_t i = 0; i < uint32_t(levelBudget); i++) {
    rot_out[i] = std::vector<int32_t>(b + bRem);
  }

  for (int32_t s = levelBudget - 1; s > stop; s--) {
    for (int32_t j = 0; j < g; j++) {
      rot_in[s][j] = ReduceRotation(
          (j - int32_t((numRotations + 1)/2) + 1) *
          (1 << ((s - flagRem) * layersCollapse + remCollapse)), slots);
    }

    for (int32_t i = 0; i < b; i++) {
      rot_out[s][i] = ReduceRotation(
          (g * i) *
          (1 << ((s - flagRem) * layersCollapse + remCollapse)), M/4);
    }
  }

  if (flagRem) {
    for (int32_t j = 0; j < gRem; j++) {
      rot_in[stop][j] = ReduceRotation(
          (j - int32_t((numRotationsRem + 1)/2) + 1), slots);
    }

    for (int32_t i = 0; i < bRem; i++) {
      rot_out[stop][i] = ReduceRotation(
          (gRem * i), M/4);
    }
  }

  Ciphertext<DCRTPoly> result = ctxt->Clone();

  // hoisted automorphisms
  for (int32_t s = levelBudget -  1; s > stop; s--) {
    if (s != levelBudget -  1) {
      algo->ModReduceInternalInPlace(result);
    }

    // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc->EvalFastRotationPrecompute(result);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(g);
#pragma omp parallel for
    for (int32_t j = 0; j < g; j++) {
      if (rot_in[s][j] != 0) {
        fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[s][j], digits, true);
      } else {
        fastRotation[j] = cc->KeySwitchExt(result, true);
      }
    }

    Ciphertext<DCRTPoly> outer;
    DCRTPoly first;
    for (int32_t i = 0; i < b; i++) {
      // for the first iteration with j=0:
      int32_t G = g * i;
      Ciphertext<DCRTPoly> inner = EvalMultExt(fastRotation[0], A[s][G]);
      // continue the loop
      for (int32_t j = 1; j < g; j++) {
        if ((G + j) != int32_t(numRotations)) {
          EvalAddExtInPlace(inner,
              EvalMultExt(fastRotation[j], A[s][G + j]));
        }
      }

      if (i == 0) {
        first = cc->KeySwitchDownFirstElement(inner);
        auto elements = inner->GetElements();
        elements[0].SetValuesToZero();
        inner->SetElements(elements);
        outer = inner;
      } else {
        if (rot_out[s][i] != 0) {
          inner = cc->KeySwitchDown(inner);
          // Find the automorphism index that corresponds to rotation index index.
          usint autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], M);
          std::vector<usint> map(N);
          PrecomputeAutoMap(N, autoIndex, &map);
          first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
          auto innerDigits = cc->EvalFastRotationPrecompute(inner);
          EvalAddExtInPlace(outer,
              cc->EvalFastRotationExt(inner, rot_out[s][i], innerDigits, false));
        } else {
          first += cc->KeySwitchDownFirstElement(inner);
          auto elements = inner->GetElements();
          elements[0].SetValuesToZero();
          inner->SetElements(elements);
          EvalAddExtInPlace(outer, inner);
        }
      }
    }
    result = cc->KeySwitchDown(outer);
    std::vector<DCRTPoly> &elements = result->GetElements();
    elements[0] += first;
  }

  if (flagRem) {
    algo->ModReduceInternalInPlace(result);

    // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc->EvalFastRotationPrecompute(result);
    std::vector<Ciphertext<DCRTPoly>> fastRotation(gRem);

#pragma omp parallel for
    for (int32_t j = 0; j < gRem; j++) {
      if (rot_in[stop][j] != 0) {
        fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[stop][j], digits, true);
      } else {
        fastRotation[j] = cc->KeySwitchExt(result, true);
      }
    }

    Ciphertext<DCRTPoly> outer;
    DCRTPoly first;
    for (int32_t i = 0; i < bRem; i++) {
      Ciphertext<DCRTPoly> inner;
      // for the first iteration with j=0:
      int32_t GRem = gRem * i;
      inner = EvalMultExt(fastRotation[0], A[stop][GRem]);
      // continue the loop
      for (int32_t j = 1; j < gRem; j++) {
        if ((GRem + j) != int32_t(numRotationsRem)) {
          EvalAddExtInPlace(inner,
              EvalMultExt(fastRotation[j], A[stop][GRem+j]));
        }
      }

      if (i == 0) {
        first = cc->KeySwitchDownFirstElement(inner);
        auto elements = inner->GetElements();
        elements[0].SetValuesToZero();
        inner->SetElements(elements);
        outer = inner;
      } else {
        if (rot_out[stop][i] != 0) {
          inner = cc->KeySwitchDown(inner);
          // Find the automorphism index that corresponds to rotation index index.
          usint autoIndex = FindAutomorphismIndex2nComplex(rot_out[stop][i], M);
          std::vector<usint> map(N);
          PrecomputeAutoMap(N, autoIndex, &map);
          first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
          auto innerDigits = cc->EvalFastRotationPrecompute(inner);
          EvalAddExtInPlace(outer,
              cc->EvalFastRotationExt(inner, rot_out[stop][i], innerDigits, false));
        } else {
          first += cc->KeySwitchDownFirstElement(inner);
          auto elements = inner->GetElements();
          elements[0].SetValuesToZero();
          inner->SetElements(elements);
          EvalAddExtInPlace(outer, inner);
        }
      }
    }

    result = cc->KeySwitchDown(outer);
    std::vector<DCRTPoly> &elements = result->GetElements();
    elements[0] += first;
  }

  return result;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalSlotsToCoeffs(
    const std::vector<std::vector<ConstPlaintext>> &A,
    ConstCiphertext<DCRTPoly> ctxt) const {

  auto cc = ctxt->GetCryptoContext();

  uint32_t M = cc->GetCyclotomicOrder();
  uint32_t N = cc->GetRingDimension();
  uint32_t slots = ctxt->GetSlots();

  const std::shared_ptr<CKKSBootstrapPrecom> precom = m_bootPrecomMap.at(slots);

  int32_t levelBudget = precom->m_paramsDec[FFT_PARAMS::LEVEL_BUDGET];
  int32_t layersCollapse = precom->m_paramsDec[FFT_PARAMS::LAYERS_COLL];
  int32_t remCollapse = precom->m_paramsDec[FFT_PARAMS::LAYERS_REM];
  int32_t numRotations = precom->m_paramsDec[FFT_PARAMS::NUM_ROTATIONS];
  int32_t b = precom->m_paramsDec[FFT_PARAMS::BABY_STEP];
  int32_t g = precom->m_paramsDec[FFT_PARAMS::GIANT_STEP];
  int32_t numRotationsRem = precom->m_paramsDec[FFT_PARAMS::NUM_ROTATIONS_REM];
  int32_t bRem = precom->m_paramsDec[FFT_PARAMS::BABY_STEP_REM];
  int32_t gRem = precom->m_paramsDec[FFT_PARAMS::GIANT_STEP_REM];

  auto algo = cc->GetScheme();

  int32_t flagRem = 0;

  if(remCollapse!=0) {
    flagRem = 1;
  }

  // precompute the inner and outer rotations

  std::vector<std::vector<int32_t>> rot_in(levelBudget);
  for (uint32_t i = 0; i < uint32_t(levelBudget); i++) {
    if (flagRem == 1 && i == uint32_t(levelBudget - 1)) {
      // remainder corresponds to index 0 in encoding and to last index in decoding
      rot_in[i] = std::vector<int32_t>(numRotationsRem + 1);
    } else {
      rot_in[i] = std::vector<int32_t>(numRotations + 1);
    }
  }

  std::vector<std::vector<int32_t>> rot_out(levelBudget);
  for (uint32_t i = 0; i < uint32_t(levelBudget); i++) {
    rot_out[i] = std::vector<int32_t>(b + bRem);
  }

  for (int32_t s = 0; s < levelBudget - flagRem; s++){
    for (int32_t j = 0; j < g; j++) {
      rot_in[s][j] = ReduceRotation(
          (j - int32_t((numRotations + 1)/2) + 1) *
          (1 << (s * layersCollapse)), M/4);
    }

    for (int32_t i = 0; i < b; i++) {
      rot_out[s][i] = ReduceRotation(
          (g * i) *
          (1 << (s * layersCollapse)),M/4);
    }
  }

  if (flagRem) {
    int32_t s = levelBudget - flagRem;
    for (int32_t j = 0; j < gRem; j++) {
      rot_in[s][j] = ReduceRotation(
          (j - int32_t((numRotationsRem + 1)/2) + 1) *
          (1 << (s * layersCollapse)), M/4);
    }

    for (int32_t i = 0; i < bRem; i++) {
      rot_out[s][i] = ReduceRotation(
          (gRem * i) *
          (1 << (s * layersCollapse)), M/4);
    }
  }

  //  No need for Encrypted Bit Reverse
  Ciphertext<DCRTPoly> result = ctxt->Clone();

  // hoisted automorphisms
  for (int32_t s = 0; s < levelBudget - flagRem; s++) {
    if (s != 0) {
      algo->ModReduceInternalInPlace(result);
    }
    // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc->EvalFastRotationPrecompute(result);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(g);
#pragma omp parallel for
    for (int32_t j = 0; j < g; j++) {
      if (rot_in[s][j] != 0) {
        fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[s][j], digits, true);
      } else {
        fastRotation[j] = cc->KeySwitchExt(result, true);
      }
    }

    Ciphertext<DCRTPoly> outer;
    DCRTPoly first;
    for (int32_t i = 0; i < b; i++) {
      Ciphertext<DCRTPoly> inner;
      // for the first iteration with j=0:
      int32_t G = g * i;
      inner = EvalMultExt(fastRotation[0], A[s][G]);
      // continue the loop
      for (int32_t j = 1; j < g; j++) {
        if ((G + j) != int32_t(numRotations)) {
          EvalAddExtInPlace(inner,
              EvalMultExt(fastRotation[j], A[s][G + j]));
        }
      }

      if (i == 0) {
        first = cc->KeySwitchDownFirstElement(inner);
        auto elements = inner->GetElements();
        elements[0].SetValuesToZero();
        inner->SetElements(elements);
        outer = inner;
      } else {
        if (rot_out[s][i] != 0) {
          inner = cc->KeySwitchDown(inner);
          // Find the automorphism index that corresponds to rotation index index.
          usint autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], M);
          std::vector<usint> map(N);
          PrecomputeAutoMap(N, autoIndex, &map);
          first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
          auto innerDigits = cc->EvalFastRotationPrecompute(inner);
          EvalAddExtInPlace(outer,
              cc->EvalFastRotationExt(inner, rot_out[s][i], innerDigits, false));
        } else {
          first += cc->KeySwitchDownFirstElement(inner);
          auto elements = inner->GetElements();
          elements[0].SetValuesToZero();
          inner->SetElements(elements);
          EvalAddExtInPlace(outer, inner);
        }
      }
    }

    result = cc->KeySwitchDown(outer);
    std::vector<DCRTPoly> &elements = result->GetElements();
    elements[0] += first;
  }

  if (flagRem) {
    algo->ModReduceInternalInPlace(result);
    // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc->EvalFastRotationPrecompute(result);
    std::vector<Ciphertext<DCRTPoly>> fastRotation(gRem);

    int32_t s = levelBudget - flagRem;
#pragma omp parallel for
    for (int32_t j = 0; j < gRem; j++) {
      if (rot_in[s][j] != 0) {
        fastRotation[j] = cc->EvalFastRotationExt(result, rot_in[s][j], digits, true);
      } else {
        fastRotation[j] = cc->KeySwitchExt(result, true);
      }
    }

    Ciphertext<DCRTPoly> outer;
    DCRTPoly first;
    for (int32_t i = 0; i < bRem; i++) {
      Ciphertext<DCRTPoly> inner;
      // for the first iteration with j=0:
      int32_t GRem = gRem * i;
      inner = EvalMultExt(fastRotation[0], A[s][GRem]);
      // continue the loop
      for (int32_t j = 1; j < gRem; j++) {
        if ((GRem + j) != int32_t(numRotationsRem))
          EvalAddExtInPlace(inner,
              EvalMultExt(fastRotation[j], A[s][GRem + j]));
      }

      if (i == 0) {
        first = cc->KeySwitchDownFirstElement(inner);
        auto elements = inner->GetElements();
        elements[0].SetValuesToZero();
        inner->SetElements(elements);
        outer = inner;
      } else {
          if (rot_out[s][i] != 0) {
            inner = cc->KeySwitchDown(inner);
            // Find the automorphism index that corresponds to rotation index index.
            usint autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], M);
            std::vector<usint> map(N);
            PrecomputeAutoMap(N, autoIndex, &map);
            first += inner->GetElements()[0].AutomorphismTransform(autoIndex, map);
            auto innerDigits = cc->EvalFastRotationPrecompute(inner);
            EvalAddExtInPlace(outer,
                cc->EvalFastRotationExt(inner, rot_out[s][i], innerDigits, false));
          } else {
            first += cc->KeySwitchDownFirstElement(inner);
            auto elements = inner->GetElements();
            elements[0].SetValuesToZero();
            inner->SetElements(elements);
            EvalAddExtInPlace(outer, inner);
          }
      }
    }

    result = cc->KeySwitchDown(outer);
    std::vector<DCRTPoly> &elements = result->GetElements();
    elements[0] += first;
  }

  return result;
}

//------------------------------------------------------------------------------
// Auxiliary Bootstrap Functions
//------------------------------------------------------------------------------

void FHECKKSRNS::AdjustCiphertext(
    Ciphertext<DCRTPoly>& ciphertext,
    double correction) const {
  const auto cryptoParams =
       std::static_pointer_cast<CryptoParametersCKKSRNS>(
           ciphertext->GetCryptoParameters());

  auto cc = ciphertext->GetCryptoContext();
  auto algo = cc->GetScheme();

  if (cryptoParams->GetRescalingTechnique() == FLEXIBLEAUTO) {
    double targetSF = cryptoParams->GetScalingFactorReal(0);
    double sourceSF = ciphertext->GetScalingFactor();
    uint32_t numTowers = ciphertext->GetElements()[0].GetNumOfElements();
    double modToDrop = cryptoParams->GetElementParams()->GetParams()[numTowers - 1]->GetModulus().ConvertToDouble();

    // in the case of FLEXIBLEAUTO, we need to bring the ciphertext to the right scale using a
    // a scaling multiplication. Note the at currently FLEXIBLEAUTO is only supported for NATIVEINT = 64.
    // So the other branch is for future purposes (in case we decide to add add the FLEXIBLEAUTO support
    // for NATIVEINT = 128.
#if NATIVEINT!=128
    // Scaling down the message by a correction factor to emulate using a larger q0.
    // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
    double adjustmentFactor = (targetSF / sourceSF) * (modToDrop / sourceSF) * std::pow(2, -correction);
#else
    double adjustmentFactor = (targetSF / sourceSF) * (modToDrop / sourceSF);
#endif
    cc->EvalMultInPlace(ciphertext, adjustmentFactor);

    algo->ModReduceInternalInPlace(ciphertext);
    ciphertext->SetScalingFactor(targetSF);
  } else {
#if NATIVEINT!=128
    // Scaling down the message by a correction factor to emulate using a larger q0.
    // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
    cc->EvalMultInPlace(ciphertext, std::pow(2, -correction));
    algo->ModReduceInternalInPlace(ciphertext);
#endif
  }
}

void FHECKKSRNS::ApplyDoubleAngleIterations(
    Ciphertext<DCRTPoly>& ciphertext) const {
  auto cc = ciphertext->GetCryptoContext();

  int32_t r = R;
  for (int32_t j = 1; j < r + 1; j++) {
    cc->EvalSquareInPlace(ciphertext);
    ciphertext = cc->EvalAdd(ciphertext, ciphertext);
    double scalar = -1.0 / std::pow((2.0 * M_PI), std::pow(2.0, j - r));
    cc->EvalAddInPlace(ciphertext, scalar);
    cc->ModReduceInPlace(ciphertext);
  }
}

Plaintext FHECKKSRNS::MakeAuxPlaintext(
    const CryptoContextImpl<DCRTPoly> &cc,
    const std::shared_ptr<ParmType> params,
    const std::vector<std::complex<double>>& value,
    size_t depth, uint32_t level, usint slots) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          cc.GetCryptoParameters());

  double scFact = cryptoParams->GetScalingFactorReal(level);

  Plaintext p = Plaintext(std::make_shared<CKKSPackedEncoding>(
      params, cc.GetEncodingParams(), value, depth, level, scFact, slots));

  DCRTPoly& plainElement = p->GetElement<DCRTPoly>();

  usint N = cc.GetRingDimension();

  std::vector<std::complex<double>> inverse = value;

  inverse.resize(slots);

  DiscreteFourierTransform::FFTSpecialInv(inverse);
  double powP = scFact;

  // Compute approxFactor, a value to scale down by, in case the value exceeds a 64-bit integer.
  int32_t MAX_BITS_IN_WORD = 62;

  int32_t logc = 0;
  for (size_t i = 0; i < slots; ++i) {
    inverse[i] *= powP;
    int32_t logci = static_cast<int32_t>(ceil(log2(abs(inverse[i].real()))));
    if (logc < logci) logc = logci;
    logci = static_cast<int32_t>(ceil(log2(abs(inverse[i].imag()))));
    if (logc < logci) logc = logci;
  }
  if (logc < 0) {
    OPENFHE_THROW(math_error, "Too small scaling factor");
  }
  int32_t logValid = (logc <= MAX_BITS_IN_WORD) ? logc : MAX_BITS_IN_WORD;
  int32_t logApprox = logc - logValid;
  double approxFactor = pow(2, logApprox);

  std::vector<int64_t> temp(2 * slots);
  for (size_t i = 0; i < slots; ++i) {
    // Scale down by approxFactor in case the value exceeds a 64-bit integer.
    double dre = inverse[i].real() / approxFactor;
    double dim = inverse[i].imag() / approxFactor;

    // Check for possible overflow
    if (is64BitOverflow(dre) || is64BitOverflow(dim)) {
      DiscreteFourierTransform::FFTSpecial(inverse);

      double invLen = static_cast<double>(inverse.size());
      double factor = 2 * M_PI * i;

      double realMax = -1, imagMax = -1;
      uint32_t realMaxIdx = -1, imagMaxIdx = -1;

      for (uint32_t idx = 0; idx < inverse.size(); idx++) {
        // exp( j*2*pi*n*k/N )
        std::complex<double> expFactor = {cos((factor * idx) / invLen),
                                          sin((factor * idx) / invLen)};

        // X[k] * exp( j*2*pi*n*k/N )
        std::complex<double> prodFactor = inverse[idx] * expFactor;

        double realVal = prodFactor.real();
        double imagVal = prodFactor.imag();

        if (realVal > realMax) {
          realMax = realVal;
          realMaxIdx = idx;
        }
        if (imagVal > imagMax) {
          imagMax = imagVal;
          imagMaxIdx = idx;
        }
      }

      auto scaledInputSize = ceil(log2(dre));

      std::stringstream buffer;
      buffer
          << std::endl
          << "Overflow in data encoding - scaled input is too large to fit "
             "into a NativeInteger (60 bits). Try decreasing scaling factor."
          << std::endl;
      buffer << "Overflow at slot number " << i << std::endl;
      buffer << "- Max real part contribution from input[" << realMaxIdx
             << "]: " << realMax << std::endl;
      buffer << "- Max imaginary part contribution from input[" << imagMaxIdx
             << "]: " << imagMax << std::endl;
      buffer << "Scaling factor is " << ceil(log2(powP)) << " bits "
             << std::endl;
      buffer << "Scaled input is " << scaledInputSize << " bits "
             << std::endl;
      OPENFHE_THROW(math_error, buffer.str());
    }

    int64_t re = std::llround(dre);
    int64_t im = std::llround(dim);

    temp[i] = (re < 0) ? Max64BitValue() + re : re;
    temp[i + slots] = (im < 0) ? Max64BitValue() + im : im;
  }

  const std::shared_ptr<ILDCRTParams<BigInteger>> bigParams =
      plainElement.GetParams();
  const std::vector<std::shared_ptr<ILNativeParams>> &nativeParams =
      bigParams->GetParams();

  for (size_t i = 0; i < nativeParams.size(); i++) {
    NativeVector nativeVec(N, nativeParams[i]->GetModulus());
    FitToNativeVector(N, temp, Max64BitValue(), &nativeVec);
    NativePoly element = plainElement.GetElementAtIndex(i);
    element.SetValues(nativeVec, Format::COEFFICIENT);
    plainElement.SetElementAtIndex(i, element);
  }

  usint numTowers = nativeParams.size();
  std::vector<DCRTPoly::Integer> moduli(numTowers);
  for (usint i = 0; i < numTowers; i++) {
    moduli[i] = nativeParams[i]->GetModulus();
  }

  DCRTPoly::Integer intPowP = std::llround(powP);
  std::vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);

  auto currPowP = crtPowP;

  // We want to scale temp by 2^(pd), and the loop starts from j=2
  // because temp is already scaled by 2^p in the re/im loop above,
  // and currPowP already is 2^p.
  for (size_t i = 2; i < depth; i++) {
    currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
  }

  if (depth > 1) {
    plainElement = plainElement.Times(currPowP);
  }

  // Scale back up by the approxFactor to get the correct encoding.
  int32_t MAX_LOG_STEP = 60;
  if (logApprox > 0) {
    int32_t logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
    DCRTPoly::Integer intStep = uint64_t(1) << logStep;
    std::vector<DCRTPoly::Integer> crtApprox(numTowers, intStep);
    logApprox -= logStep;

    while (logApprox > 0) {
      int32_t logStep = (logApprox <= MAX_LOG_STEP) ? logApprox : MAX_LOG_STEP;
      DCRTPoly::Integer intStep = uint64_t(1) << logStep;
      std::vector<DCRTPoly::Integer> crtSF(numTowers, intStep);
      crtApprox = CKKSPackedEncoding::CRTMult(crtApprox, crtSF, moduli);
      logApprox -= logStep;
    }
    plainElement = plainElement.Times(crtApprox);
  }

  p->SetFormat(Format::EVALUATION);
  p->SetScalingFactor(pow(p->GetScalingFactor(), depth));

  return p;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalMultExt(
    ConstCiphertext<DCRTPoly> ciphertext,
    ConstPlaintext plaintext) const {
  Ciphertext<DCRTPoly> result = ciphertext->Clone();
  std::vector<DCRTPoly> &cv = result->GetElements();

  DCRTPoly pt = plaintext->GetElement<DCRTPoly>();
  pt.SetFormat(Format::EVALUATION);

  for (auto &c : cv) {
    c *= pt;
  }
  result->SetDepth(result->GetDepth() + plaintext->GetDepth());
  result->SetScalingFactor(result->GetScalingFactor() * plaintext->GetScalingFactor());
  return result;
}

void FHECKKSRNS::EvalAddExtInPlace(
    Ciphertext<DCRTPoly> &ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  std::vector<DCRTPoly> &cv1 = ciphertext1->GetElements();
  const std::vector<DCRTPoly> &cv2 = ciphertext2->GetElements();

  for (usint i = 0; i < cv1.size(); ++i) {
    cv1[i] += cv2[i];
  }
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalAddExt(
    ConstCiphertext<DCRTPoly> ciphertext1,
    ConstCiphertext<DCRTPoly> ciphertext2) const {
  Ciphertext<DCRTPoly> result = ciphertext1->Clone();
  EvalAddExtInPlace(result, ciphertext2);
  return result;
}

EvalKey<DCRTPoly> FHECKKSRNS::ConjugateKeyGen(
    const PrivateKey<DCRTPoly> privateKey) const {

  const auto cc = privateKey->GetCryptoContext();
  auto algo = cc->GetScheme();

  const DCRTPoly &s = privateKey->GetPrivateElement();
  usint N = s.GetRingDimension();

  PrivateKey<DCRTPoly> privateKeyPermuted =
      std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc);

  usint index =  2 * N - 1;
  std::vector<usint> vec(N);
  PrecomputeAutoMap(N, index, &vec);

  DCRTPoly sPermuted = s.AutomorphismTransform(index, vec);

  privateKeyPermuted->SetPrivateElement(sPermuted);
  privateKeyPermuted->SetKeyTag(privateKey->GetKeyTag());

  return algo->KeySwitchGen(privateKey, privateKeyPermuted);
}

Ciphertext<DCRTPoly> FHECKKSRNS::Conjugate(
    ConstCiphertext<DCRTPoly> ciphertext,
    const std::map<usint, EvalKey<DCRTPoly>> &evalKeyMap) const {
  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  usint N = cv[0].GetRingDimension();

  std::vector<usint> vec(N);
  PrecomputeAutoMap(N, 2 * N - 1, &vec);

  auto algo = ciphertext->GetCryptoContext()->GetScheme();

  Ciphertext<DCRTPoly> result = ciphertext->Clone();

  algo->KeySwitchInPlace(result, evalKeyMap.at(2 * N - 1));

  std::vector<DCRTPoly> &rcv = result->GetElements();

  rcv[0] = rcv[0].AutomorphismTransform(2 * N - 1, vec);
  rcv[1] = rcv[1].AutomorphismTransform(2 * N - 1, vec);

  return result;
}

void FHECKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<int64_t> &vec,
                                           int64_t bigBound,
                                           NativeVector *nativeVec) const {
  NativeInteger bigValueHf(bigBound >> 1);
  NativeInteger modulus(nativeVec->GetModulus());
  NativeInteger diff = bigBound - modulus;
  uint32_t dslots = vec.size();
  uint32_t gap = ringDim/dslots;
  for (usint i = 0; i < vec.size(); i++) {
    NativeInteger n(vec[i]);
    if (n > bigValueHf) {
      (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
    } else {
      (*nativeVec)[gap * i] = n.Mod(modulus);
    }
  }
}

#if NATIVEINT == 128
void FHECKKSRNS::FitToNativeVector(uint32_t ringDim, const std::vector<__int128> &vec,
                                           __int128 bigBound,
                                           NativeVector *nativeVec) const {
  NativeInteger bigValueHf((unsigned __int128)bigBound >> 1);
  NativeInteger modulus(nativeVec->GetModulus());
  NativeInteger diff = NativeInteger((unsigned __int128)bigBound) - modulus;
  uint32_t dslots = vec.size();
  uint32_t gap = ringDim/dslots;
  for (usint i = 0; i < vec.size(); i++) {
    NativeInteger n((unsigned __int128)vec[i]);
    if (n > bigValueHf) {
      (*nativeVec)[gap * i] = n.ModSub(diff, modulus);
    } else {
      (*nativeVec)[gap * i] = n.Mod(modulus);
    }
  }
}
#endif

}