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

#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-fhe.h"
#include "utils/polynomials.h"
#include "utils/caller_info.h"

namespace lbcrypto {

void FHECKKSRNS::EvalBootstrapSetup(
    const CryptoContextImpl<DCRTPoly> &cc,
    uint32_t dim1, uint32_t numSlots) {
  uint32_t m = cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();

  precom.m_slots = (numSlots == 0) ? m/4 : numSlots;

  // store the level budget
  precom.m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] = 1;
  precom.m_paramsDec[FFT_PARAMS::LEVEL_BUDGET] = 1;
  precom.m_dim1 = dim1;
}

void FHECKKSRNS::EvalBootstrapSetup(const CryptoContextImpl<DCRTPoly>& cc,
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

  // the linear method is more efficient for a level budget of 1
  if (levelBudget[0] == 1 && levelBudget[1] == 1){
    EvalBootstrapSetup( cc, dim1[0], numSlots);
  } else {
    uint32_t m = cc.GetCryptoParameters()->GetElementParams()->GetCyclotomicOrder();

    uint32_t slots = (numSlots == 0) ? m/4 : numSlots;

    // Perform some checks on the level budget and compute parameters
    std::vector<uint32_t> newBudget = levelBudget;
    // TODO Andrey: logSlots precompute here
    //    uint32_t logSlots = (uint32_t)std::log2(slots);
    if (levelBudget[0] > std::log2(slots)) {
      std::cerr << "\nWarning, the level budget for encoding cannot be this large. The budget was changed to " << std::log2(slots) << std::endl;
        newBudget[0] = std::log2(slots);
    }
    if (levelBudget[1] > std::log2(slots)){
      std::cerr << "\nWarning, the level budget for decoding cannot be this large. The budget was changed to " << std::log2(slots) << std::endl;
        newBudget[1] = std::log2(slots);
    }
    if (levelBudget[0] < 1){
      std::cerr << "\nWarning, the level budget for encoding has to be at least 1. The budget was changed to " << 1 << std::endl;
      newBudget[0] = 1;
    }
    if (levelBudget[1] < 1){
      std::cerr << "\nWarning, the level budget for decoding has to be at least 1. The budget was changed to " << 1 << std::endl;
      newBudget[1] = 1;
    }

    precom.m_paramsEnc = GetCollapsedFFTParams( slots, newBudget[0], dim1[0] );
    precom.m_paramsDec = GetCollapsedFFTParams( slots, newBudget[1], dim1[1] );

    precom.m_slots = slots;
  }

}

void FHECKKSRNS::EvalBootstrapPrecompute(const CryptoContextImpl<DCRTPoly> &cc, uint32_t debugFlag) {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          cc.GetCryptoParameters());

  uint32_t m = 4 * precom.m_slots;
  bool isSparse = (cryptoParams->GetElementParams()->GetCyclotomicOrder() != m) ? true : false;

  // computes indices for all primitive roots of unity
  std::vector<uint32_t> rotGroup(precom.m_slots);
  uint32_t fivePows = 1;
  for (uint32_t i = 0; i < precom.m_slots; ++i) {
          rotGroup[i] = fivePows;
          fivePows *= 5;
          fivePows %= m;
  }

  // computes all powers of a primitive root of unity exp(2*M_PI/m)
  std::vector<std::complex<double>> ksiPows(m+1);
  for (uint32_t j = 0; j < m; ++j) {
          double angle = 2.0 * M_PI * j / m;
          ksiPows[j].real(cos(angle));
          ksiPows[j].imag(sin(angle));
  }
  ksiPows[m] = ksiPows[0];

  // compute # of levels to remain when encoding the coefficients
  uint32_t L0 = cryptoParams->GetElementParams()->GetParams().size();

  // Extract the modulus prior to bootstrapping
  NativeInteger q = cryptoParams->GetElementParams()->GetParams()[0]->GetModulus().ConvertToInt();
  double qDouble = q.ConvertToDouble();

  unsigned __int128 factor = ((unsigned __int128)1<<((uint32_t)std::round(std::log2(qDouble))));
  double pre = qDouble/factor;
  double k = (cryptoParams->GetMode() == SPARSE) ? K_SPARSE : 1.0;
  double scaleEnc = pre/k;
  double scaleDec = 1/pre;

  if (debugFlag == 0) {
    if ((precom.m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] == 1) && (precom.m_paramsDec[FFT_PARAMS::LEVEL_BUDGET] == 1)) {
      // allocate all vectors
      std::vector<std::vector<std::complex<double>>> U0(precom.m_slots, std::vector<std::complex<double>>(precom.m_slots));
      std::vector<std::vector<std::complex<double>>> U1(precom.m_slots, std::vector<std::complex<double>>(precom.m_slots));
      std::vector<std::vector<std::complex<double>>> U0hatT(precom.m_slots, std::vector<std::complex<double>>(precom.m_slots));
      std::vector<std::vector<std::complex<double>>> U1hatT(precom.m_slots, std::vector<std::complex<double>>(precom.m_slots));

      for (size_t i = 0; i < precom.m_slots; i++) {
        for (size_t j = 0; j < precom.m_slots; j++) {
          U0[i][j] = ksiPows[(j * rotGroup[i]) % m];
          U0hatT[j][i] = std::conj(U0[i][j]);

          U1[i][j] = std::complex<double>(0, 1) * U0[i][j];
          U1hatT[j][i] = std::conj(U1[i][j]);
        }
      }

      uint32_t depthBT = GetBootstrapDepth(cc, { 1,1 });
      uint32_t lEnc = L0 - 2;
      uint32_t lDec = L0 - depthBT;

      if (!isSparse) {
        //fully-packed mode
        precom.m_U0hatTPre = cc.EvalLTPrecompute(U0hatT, precom.m_dim1, scaleEnc, lEnc);
        precom.m_U0Pre = cc.EvalLTPrecompute(U0, precom.m_dim1, scaleDec, lDec);
      } else {
        // sparse mode
        precom.m_U0hatTPre = cc.EvalLTPrecompute(U0hatT, U1hatT, precom.m_dim1, 0, scaleEnc, lEnc);
        precom.m_U0Pre = cc.EvalLTPrecompute(U0, U1, precom.m_dim1, 1, scaleDec, lDec);
      }
      // The other case is for testing only encoding and decoding, without the approx. mod. reduction.
      // In that case, the precomputations are done directly in the demo/test.
    } else {
      std::vector<uint32_t> params = { (uint32_t)precom.m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET],(uint32_t)precom.m_paramsDec[FFT_PARAMS::LEVEL_BUDGET] };
      uint32_t depthBT = GetBootstrapDepth(cc, params);
      uint32_t lEnc = L0 - precom.m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] - 1;
      uint32_t lDec = L0 - depthBT;

      precom.m_U0hatTPreFFT = EvalBootstrapPrecomputeEncoding(cc, ksiPows, rotGroup, false, scaleEnc, lEnc);
      precom.m_U0PreFFT = EvalBootstrapPrecomputeDecoding(cc, ksiPows, rotGroup, false, scaleDec, lDec);
    }
  }
}

std::vector<int32_t> FHECKKSRNS::FindBootstrapRotationIndices(int32_t bootstrapFlag, uint32_t m,
        uint32_t blockDimension) {

    uint32_t slotsFull = m/4;

    std::vector<int32_t> levelBudget = { precom.m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET], precom.m_paramsDec[FFT_PARAMS::LEVEL_BUDGET] };

    if (levelBudget[0] == 1 && levelBudget[1] == 1) {
        return FindLTRotationIndices(precom.m_dim1, bootstrapFlag, m, blockDimension);
    } else {
        std::vector<int32_t> layersCollapse = { precom.m_paramsEnc[FFT_PARAMS::LAYERS_COLL], precom.m_paramsDec[FFT_PARAMS::LAYERS_COLL] };
        std::vector<int32_t> remCollapse = { precom.m_paramsEnc[FFT_PARAMS::LAYERS_REM], precom.m_paramsDec[FFT_PARAMS::LAYERS_REM] };
        std::vector<int32_t> numRotations = { precom.m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS], precom.m_paramsDec[FFT_PARAMS::NUM_ROTATIONS] };
        std::vector<int32_t> b = { precom.m_paramsEnc[FFT_PARAMS::BABY_STEP], precom.m_paramsDec[FFT_PARAMS::BABY_STEP] };
        std::vector<int32_t> g = { precom.m_paramsEnc[FFT_PARAMS::GIANT_STEP], precom.m_paramsDec[FFT_PARAMS::GIANT_STEP] };
        std::vector<int32_t> numRotationsRem = { precom.m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS_REM], precom.m_paramsDec[FFT_PARAMS::NUM_ROTATIONS_REM] };
        std::vector<int32_t> bRem = { precom.m_paramsEnc[FFT_PARAMS::BABY_STEP_REM], precom.m_paramsDec[FFT_PARAMS::BABY_STEP_REM] };
        std::vector<int32_t> gRem = { precom.m_paramsEnc[FFT_PARAMS::GIANT_STEP_REM], precom.m_paramsDec[FFT_PARAMS::GIANT_STEP_REM] };
        std::vector<int32_t> stop = { -1,-1 };
        std::vector<int32_t> flagRem(levelBudget.size());

        for(uint32_t i=0;i<remCollapse.size();i++){
            if(remCollapse[i]==0){
                stop[i] = -1;
                flagRem[i] = 0;
            }
            else{
                stop[i] = 0;
                flagRem[i] = 1;
            }
        }

        // Computing all indices for baby-step giant-step procedure for encoding and decoding
        if(flagRem[0] == 0)
          precom.indexListEvalBT.reserve(b[0]+g[0]-2+b[1]+g[1]-2 + 1);
        else
          precom.indexListEvalBT.reserve(b[0]+g[0]-2+b[1]+g[1]-2 + bRem[0]+gRem[0]-2+bRem[1]+gRem[1]-2 + 1);

        for(int32_t s = int32_t(levelBudget[0])-1; s > stop[0]; s--){
            for(int32_t j = 0; j < g[0]; j++)
              precom.indexListEvalBT.emplace_back(ReduceRotation((j-int32_t((numRotations[0]+1)/2) + 1)*(1<<((s-flagRem[0])*layersCollapse[0] + remCollapse[0])),precom.m_slots)); // m/4
            for(int32_t i = 0; i < b[0]; i++)
              precom.indexListEvalBT.emplace_back(ReduceRotation((g[0]*i)*(1 << ((s-flagRem[0])*layersCollapse[0] + remCollapse[0])), slotsFull));
        }

        if(flagRem[0]){
            for(int32_t j = 0; j < gRem[0]; j++)
              precom.indexListEvalBT.emplace_back(ReduceRotation((j-int32_t((numRotationsRem[0]+1)/2) + 1),precom.m_slots)); //m/4
            for(int32_t i = 0; i < bRem[0]; i++)
              precom.indexListEvalBT.emplace_back(ReduceRotation(gRem[0]*i, slotsFull));
        }

        for(int32_t s = 0; s < int32_t(levelBudget[1]); s++){
            for(int32_t j = 0; j < g[1]; j++)
              precom.indexListEvalBT.emplace_back(ReduceRotation((j-(numRotations[1]+1)/2 + 1)*(1<<(s*layersCollapse[1])), slotsFull));
            for(int32_t i = 0; i < b[1]; i++)
              precom.indexListEvalBT.emplace_back(ReduceRotation((g[1]*i)*(1<<(s*layersCollapse[1])), slotsFull));
        }

        if(flagRem[1]){
            int32_t s = int32_t(levelBudget[1])-flagRem[1];
            for(int32_t j = 0; j < gRem[1]; j++)
              precom.indexListEvalBT.emplace_back(ReduceRotation((j-(numRotationsRem[1]+1)/2 + 1)*(1<<(s*layersCollapse[1])), slotsFull));
            for(int32_t i = 0; i < bRem[1]; i++)
              precom.indexListEvalBT.emplace_back(ReduceRotation((gRem[1]*i)*(1<<(s*layersCollapse[1])), slotsFull));
        }

        // additional automorphisms are needed for sparse bootstrapping
        if (bootstrapFlag == 1){
            for(int j = 0; j < int(std::log2(m/(4*precom.m_slots))); j++){
              precom.indexListEvalBT.emplace_back((1<<j)*precom.m_slots);
            }
        }

        // Remove possible duplicates
        sort(precom.indexListEvalBT.begin(), precom.indexListEvalBT.end() );
        precom.indexListEvalBT.erase( unique(precom.indexListEvalBT.begin(), precom.indexListEvalBT.end() ), precom.indexListEvalBT.end() );

        //remove automorphisms corresponding to 0
        precom.indexListEvalBT.erase(std::remove(precom.indexListEvalBT.begin(), precom.indexListEvalBT.end(), 0), precom.indexListEvalBT.end());
        precom.indexListEvalBT.erase(std::remove(precom.indexListEvalBT.begin(), precom.indexListEvalBT.end(), slotsFull), precom.indexListEvalBT.end());

        return precom.indexListEvalBT;
    }
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> FHECKKSRNS::EvalBootstrapKeyGen(
    const PrivateKey<DCRTPoly> privateKey, int32_t bootstrapFlag) {
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
  uint32_t m = cc->GetCyclotomicOrder();
    std::vector<int32_t> levelBudget = { precom.m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET], precom.m_paramsDec[FFT_PARAMS::LEVEL_BUDGET] };

    if (levelBudget[0] == 1 && levelBudget[1] == 1){
        return EvalLTKeyGen( privateKey, precom.m_dim1, bootstrapFlag, 1 ); // precom.m_dim1 was set before
    } else {
        std::vector<int32_t> indexListEvalBT = FindBootstrapRotationIndices(bootstrapFlag, m);

        auto algo = cc->GetScheme();
        auto evalKeys = algo->EvalAtIndexKeyGen(nullptr, privateKey, indexListEvalBT);

        auto conjKey = ConjugateKeyGen(privateKey);

        (*evalKeys)[m - 1] = conjKey;

        return evalKeys;
    }

}

std::vector<int32_t> FHECKKSRNS::FindLTRotationIndices(
    uint32_t dim1 = 0, int32_t bootstrapFlag = 0,
    uint32_t m = 0, uint32_t blockDimension = 0) {

  // precom.m_slots and precom.m_dim1 are not available when we call solely EvalLT
  uint32_t slots;

  if ((bootstrapFlag == 1) && (blockDimension > 0)) {
      OPENFHE_THROW(not_implemented_error, "bootstrapping with linear encoding/decoding "
   " + matrix arithmetic are not currently supported.");
  }

  if (bootstrapFlag == 0) {
    if (blockDimension > 0)
      precom.m_slots = blockDimension;
  }

if ((precom.m_slots == 0) || (precom.m_slots == m/4)) // fully-packed mode
slots = m/4;
else //sparse mode
slots = precom.m_slots;

  // Computing the baby-step g and the giant-step h.
  int g = (dim1 == 0) ? ceil(sqrt(slots)) : dim1;
  int h =  ceil((double)slots/g);

  // computing all indices for baby-step giant-step procedure
  // ATTN: resize() is used as indexListEvalLT may be empty here
  precom.indexListEvalLT.reserve(g + h - 2);
  for(int i = 0; i < g; i++)
    precom.indexListEvalLT.emplace_back(i + 1);
  for(int i = 2; i < h; i++)
    precom.indexListEvalLT.emplace_back(g*i);

  // additional automorphisms are needed for sparse bootstrapping
  if (bootstrapFlag == 1)
  {
    precom.indexListEvalLT.emplace_back(slots);

      for(int j = 0; j < int(std::log2(m/(4*slots))); j++){
        precom.indexListEvalLT.emplace_back((1<<j)*slots);
      }

      // remove any duplicate indices to avoid the generation of extra automorphism keys
      sort(precom.indexListEvalLT.begin(), precom.indexListEvalLT.end() );
      precom.indexListEvalLT.erase( std::unique(precom.indexListEvalLT.begin(), precom.indexListEvalLT.end() ), precom.indexListEvalLT.end() );
  }

  return precom.indexListEvalLT;
}

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> FHECKKSRNS::EvalLTKeyGen(
    const PrivateKey<DCRTPoly> privateKey, uint32_t dim1,
    int32_t bootstrapFlag, int32_t conjFlag ) {

  auto cc = privateKey->GetCryptoContext();

  uint32_t m = cc->GetCyclotomicOrder();

  // computing all indices for baby-step giant-step procedure
  std::vector<int32_t> indexListEvalLT = FindLTRotationIndices(dim1, bootstrapFlag, m, cc->GetBlockDimension());

  auto algo = cc->GetScheme();
  auto evalKeys = algo->EvalAtIndexKeyGen(nullptr, privateKey, indexListEvalLT);

  // Add conjugation key
  if (bootstrapFlag == 1 || conjFlag == 1){
    auto conjKey = ConjugateKeyGen(privateKey);
    (*evalKeys)[m - 1] = conjKey;
  }

  return evalKeys;
}

void FHECKKSRNS::AdjustCiphertext(Ciphertext<DCRTPoly>& ciphertext,
  const std::shared_ptr<CryptoParametersCKKSRNS> cryptoParams,
  const CryptoContext<DCRTPoly> cc,
  double correction) const {

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
  }
  else {
#if NATIVEINT!=128
    // Scaling down the message by a correction factor to emulate using a larger q0.
    // This step is needed so we could use a scaling factor of up to 2^59 with q9 ~= 2^60.
    cc->EvalMultInPlace(ciphertext, std::pow(2, -correction));
    algo->ModReduceInternalInPlace(ciphertext);
#endif
  }
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrapEncoding(const CryptoContextImpl<DCRTPoly> &cc,
    const std::vector<std::complex<double>> &A, const std::vector<uint32_t> &rotGroup,
    ConstCiphertext<DCRTPoly> ct, bool flag_i, double scale) {

  auto precomputedA = EvalBootstrapPrecomputeEncoding(cc,A,rotGroup,flag_i,scale);

  return EvalBootstrapWithPrecompEncoding(cc, precomputedA, ct);
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrapDecoding(const CryptoContextImpl<DCRTPoly> &cc,
    const std::vector<std::complex<double>> &A, const std::vector<uint32_t> &rotGroup,
    ConstCiphertext<DCRTPoly> ct, bool flag_i, double scale) {

  auto precomputedA = EvalBootstrapPrecomputeDecoding(cc,A,rotGroup,flag_i,scale);

  return EvalBootstrapWithPrecompDecoding(cc, precomputedA, ct);

}

void FHECKKSRNS::ApplyDoubleAngleIterations(CryptoContext<DCRTPoly>& cc,
  Ciphertext<DCRTPoly>& ciphertext) const {
  int32_t r = R;
  for (int32_t j = 1; j < r + 1; j++) {
    ciphertext = cc->EvalMult(ciphertext, ciphertext);
    ciphertext = cc->EvalAdd(ciphertext, ciphertext);
    double scalar = -1.0 / std::pow((2.0 * M_PI), std::pow(2.0, j - r));
    cc->EvalAddInPlace(ciphertext, scalar);
    cc->ModReduceInPlace(ciphertext);
  }
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
  CKKSBootstrapMethod method = (precom.m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET] == 1 && precom.m_paramsDec[FFT_PARAMS::LEVEL_BUDGET] == 1) ?
    EvalBTLinearMethod : EvalBTFFTMethod;

  return EvalBootstrapCore(method, ciphertext);
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrapCore(
    CKKSBootstrapMethod method, ConstCiphertext<DCRTPoly> ciphertext1) const {
  bool isEvalBTLinear = (method == EvalBTLinearMethod);

#ifdef BOOTSTRAPTIMING
  TimeVar t;
  double timeEncode(0.0);
  double timeModReduce(0.0);
  double timeDecode(0.0);
#endif

  Ciphertext<DCRTPoly> ciphertext = ciphertext1->Clone();

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  uint32_t cyclOrder = cryptoParams->GetElementParams()->GetCyclotomicOrder();
  size_t ringDim = cryptoParams->GetElementParams()->GetRingDimension();

  auto cc = ciphertext->GetCryptoContext();
  auto algo = cc->GetScheme();

  algo->ModReduceInternalInPlace(ciphertext, ciphertext->GetDepth() - 1);

  NativeInteger q = cryptoParams->GetElementParams()->GetParams()[0]->GetModulus().ConvertToInt();
  double qDouble = q.ConvertToDouble();

  const auto sf = cryptoParams->GetScalingFactorReal();

  double deg = std::round(std::log2(qDouble/sf));
  double correction = 9.0 - deg;
  double post = std::pow(2,deg);

  double pre = 1/post;
  uint64_t scalar = std::llround(post);

  // Increasing the modulus

  // In FLEXIBLEAUTO, raising the ciphertext to a larger number
  // of towers is a bit more complex, because we need to adjust
  // it's scaling factor to the one that corresponds to the level
  // it's being raised to.
  // Increasing the modulus

  Ciphertext<DCRTPoly> raised = ciphertext->CloneEmpty();
  AdjustCiphertext(ciphertext, cryptoParams, cc, correction);
  auto ctxtDCRT = ciphertext->GetElements();

  // We only use the level 0 ciphertext here. All other towers are automatically ignored to make
  // CKKS bootstrapping faster.
  for (size_t i = 0; i < ctxtDCRT.size(); i++) {
    DCRTPoly temp(cryptoParams->GetElementParams(), COEFFICIENT);
    ctxtDCRT[i].SetFormat(COEFFICIENT);
    temp = ctxtDCRT[i].GetElementAtIndex(0);
    temp.SetFormat(EVALUATION);
    ctxtDCRT[i] = temp;
  }

  raised->SetElements(ctxtDCRT);
  raised->SetDepth(ciphertext->GetDepth());
  raised->SetLevel(cryptoParams->GetElementParams()->GetParams().size() -
    ctxtDCRT[0].GetNumOfElements());
  raised->SetScalingFactor(ciphertext->GetScalingFactor());

#ifdef BOOTSTRAPTIMING
  std::cerr << "\nNumber of levels at the beginning of bootstrapping: " << raised->GetElements()[0].GetNumOfElements() - 1 << std::endl;
#endif

  // SETTING PARAMETERS FOR APPROXIMATE MODULAR REDUCTION

  // Coefficients of the Chebyshev series interpolating 1/(2 Pi) Sin(2 Pi K x)
  std::vector<double> coefficients;
  double k = 0;

  if (cryptoParams->GetMode() == SPARSE) {
    coefficients = g_coefficientsSparse;
    //k = K_SPARSE;
    k = 1.0; //do not divide by k as we already did it during precomputation
  }
  else {
    coefficients = g_coefficientsUniform;
    k = K_UNIFORM;
  }

  // scale by 1/(cyclOrder/2) for the inverse DFT and divide by Kq/2^p to scale the encrypted integers to -1 .. 1
  double constantEvalMult = 0;
  if (isEvalBTLinear || (precom.m_slots == cyclOrder / 4))
    constantEvalMult = pre * (1.0 / (k * cyclOrder / 2));
  else
    constantEvalMult = pre * (1.0 / (k * ringDim));
  cc->EvalMultInPlace(raised, constantEvalMult);

  // no linear transformations are needed for Chebyshev series as the range has been normalized to [-1,1]
  double coeffLowerBound = -1;
  double coeffUpperBound = 1;

  Ciphertext<DCRTPoly> ctxtDec;

  if (precom.m_slots == cyclOrder/4) {
    // fully-packed mode
    std::vector<Ciphertext<DCRTPoly>> ctxtEnc(2);

    // Running CoeffToSlot

#ifdef BOOTSTRAPTIMING
    TIC(t);
#endif

    // need to call internal modular reduction so it also works for FLEXIBLEAUTO
    algo->ModReduceInternalInPlace(raised);

    // only one linear transform is needed as the other one can be derived
    auto ctxtEnc0 = (isEvalBTLinear) ?
      cc->EvalLTWithPrecomp(precom.m_U0hatTPre, raised, precom.m_dim1) :
      EvalBootstrapWithPrecompEncoding(*cc,precom.m_U0hatTPreFFT,raised);
    auto evalKeys = cc->GetAllEvalRotationKeys()[ctxtEnc0->GetKeyTag()];
    auto conj = Conjugate(ctxtEnc0, *evalKeys);
    ctxtEnc[0] = cc->EvalAdd(ctxtEnc0,conj);

    auto ctxtEnc1 = cc->EvalSub(ctxtEnc0, conj);
    ctxtEnc[1] = algo->MultByMonomial(ctxtEnc1, 3 * cyclOrder / 4);

    if (isEvalBTLinear) {
      if (cryptoParams->GetRescalingTechnique() == FIXEDMANUAL) {
        for (uint32_t i = 0; i < 2; i++) {
          while (ctxtEnc[i]->GetDepth() > 1) {
            cc->ModReduceInPlace(ctxtEnc[i]); // scaling power = 1
          }
        }
      }
    }

#ifdef BOOTSTRAPTIMING
    timeEncode = TOC(t);

    std::cerr << "\nEncoding time: " << timeEncode/1000.0 << " s" << std::endl;

    // Running Approximate Modulo Reduction

    TIC(t);
#endif

    for (uint32_t i = 0; i < 2; i++) {
      // Evaluate Chebyshev series for the sine wave
      ctxtEnc[i] = cc->EvalChebyshevSeries(ctxtEnc[i], coefficients, coeffLowerBound, coeffUpperBound);

      // Double-angle iterations are applied in the case of OPTIMIZED/uniform secrets
      if (cryptoParams->GetMode() == OPTIMIZED)
        ApplyDoubleAngleIterations(cc, ctxtEnc[i]);
    }

#ifdef BOOTSTRAPTIMING
    timeModReduce = TOC(t);

     std::cerr << "Approximate modular reduction time: " << timeModReduce/1000.0 << " s" << std::endl;

    // Running SlotToCoeff

    TIC(t);
#endif

    auto ctxtMultI = algo->MultByMonomial(ctxtEnc[1], cyclOrder / 4);
    auto ctxtFused = cc->EvalAdd(ctxtEnc[0], ctxtMultI);

    // scale the message back up after Chebyshev interpolation
    algo->MultByIntegerInPlace(ctxtFused, scalar);

    // In the case of FLEXIBLEAUTO, we need one extra tower
    // TODO: See if we can remove the extra level in FLEXIBLEAUTO
    if (cryptoParams->GetRescalingTechnique() != FIXEDMANUAL) {
      algo->ModReduceInternalInPlace(ctxtFused);
    }

    // Only one linear transform is needed
    ctxtDec = (isEvalBTLinear) ?
      cc->EvalLTWithPrecomp(precom.m_U0Pre, ctxtFused, precom.m_dim1) :
      EvalBootstrapWithPrecompDecoding(*cc, precom.m_U0PreFFT, ctxtFused);
  } else {
    // sparsely-packed mode
    if(isEvalBTLinear) {
      algo->ModReduceInternalInPlace(raised);
    }

    Ciphertext<DCRTPoly> ctxt1 = raised;

    // Running PartialSum
    for(int j = 0; j < int(std::log2(ringDim/(2*precom.m_slots))); j++) {
      auto temp = cc->EvalRotate(ctxt1,(1<<j)*precom.m_slots);
      cc->EvalAddInPlace(ctxt1, temp);
    }

#ifdef BOOTSTRAPTIMING
    TIC(t);
#endif

    // Running CoeffToSlot
    if(!isEvalBTLinear) {
      algo->ModReduceInternalInPlace(ctxt1);
    }
    auto ctxtEnc0 = (isEvalBTLinear) ?
      cc->EvalLTWithPrecomp(precom.m_U0hatTPre,ctxt1,precom.m_dim1) :
      EvalBootstrapWithPrecompEncoding(*cc,precom.m_U0hatTPreFFT,ctxt1);
    auto evalKeys = cc->GetAllEvalRotationKeys()[ctxtEnc0->GetKeyTag()];
    auto ctxtEnc = cc->EvalAdd(ctxtEnc0,Conjugate(ctxtEnc0, *evalKeys));

    if(isEvalBTLinear)
      cc->ModReduceInPlace(ctxtEnc);

#ifdef BOOTSTRAPTIMING
    timeEncode = TOC(t);

    std::cerr << "\nEncoding time: " << timeEncode/1000.0 << " s" << std::endl;

    // Running Approximate Mod Reduction

    TIC(t);
#endif

    // Evaluate Chebyshev series for the sine wave
    ctxtEnc = cc->EvalChebyshevSeries(ctxtEnc,coefficients, coeffLowerBound, coeffUpperBound);

    // Double-angle iterations are applied in the case of OPTIMIZED/uniform secrets
    if (cryptoParams->GetMode() == OPTIMIZED)
      ApplyDoubleAngleIterations(cc, ctxtEnc);

    // scale the message back up after Chebyshev interpolation
    algo->MultByIntegerInPlace(ctxtEnc, scalar);

#ifdef BOOTSTRAPTIMING
    timeModReduce = TOC(t);

    std::cerr << "Approximate modular reduction time: " << timeModReduce / 1000.0 << " s" << std::endl;

    // Running SlotToCoeff

    TIC(t);
#endif

    // In the case of FLEXIBLEAUTO, we need one extra tower
    // TODO: See if we can remove the extra level in FLEXIBLEAUTO
    if (cryptoParams->GetRescalingTechnique() != FIXEDMANUAL) {
      algo->ModReduceInternalInPlace(ctxtEnc);
    }

    // linear transform for decoding
    auto ctxtDec0 = (isEvalBTLinear) ?
      cc->EvalLTWithPrecomp(precom.m_U0Pre, ctxtEnc, precom.m_dim1) :
      EvalBootstrapWithPrecompDecoding(*cc, precom.m_U0PreFFT, ctxtEnc);

    ctxtDec = cc->EvalAdd(ctxtDec0, cc->EvalRotate(ctxtDec0, precom.m_slots));
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

Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrapWithPrecompEncoding(
    const CryptoContextImpl<DCRTPoly> &cc,
    const std::vector<std::vector<ConstPlaintext>> &A, ConstCiphertext<DCRTPoly> ctxt) const {

  uint32_t m = cc.GetCyclotomicOrder();
  uint32_t n = cc.GetRingDimension();

  int32_t levelBudget = precom.m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET];
  int32_t layersCollapse = precom.m_paramsEnc[FFT_PARAMS::LAYERS_COLL];
  int32_t remCollapse = precom.m_paramsEnc[FFT_PARAMS::LAYERS_REM];
  int32_t numRotations = precom.m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS];
  int32_t b = precom.m_paramsEnc[FFT_PARAMS::BABY_STEP];
  int32_t g = precom.m_paramsEnc[FFT_PARAMS::GIANT_STEP];
  int32_t numRotationsRem = precom.m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS_REM];
  int32_t bRem = precom.m_paramsEnc[FFT_PARAMS::BABY_STEP_REM];
  int32_t gRem = precom.m_paramsEnc[FFT_PARAMS::GIANT_STEP_REM];

  int32_t stop = -1;
  int32_t flagRem = 0;

  auto algo = cc.GetScheme();

  if(remCollapse!=0){
    stop = 0;
    flagRem = 1;
  }

  Ciphertext<DCRTPoly> result =  ctxt->Clone();

  // precompute the inner and outer rotations

  std::vector<std::vector<int32_t>> rot_in(levelBudget);
  for(uint32_t i = 0; i < uint32_t(levelBudget); i++){
    if (flagRem == 1 && i == 0) // remainder corresponds to index 0 in encoding and to last index in decoding
      rot_in[i] = std::vector<int32_t>(numRotationsRem+1);
    else
      rot_in[i] = std::vector<int32_t>(numRotations+1);

  }
  std::vector<std::vector<int32_t>> rot_out(levelBudget);
  for(uint32_t i = 0; i < uint32_t(levelBudget); i++)
    rot_out[i] = std::vector<int32_t>(b + bRem);

  for (int32_t s = levelBudget-1; s > stop; s--){
    for (int32_t j=0; j < g; j++)
      rot_in[s][j] = ReduceRotation((j-int32_t((numRotations+1)/2)+1)*(1<<((s-flagRem)*layersCollapse + remCollapse)),precom.m_slots); // m/4
    for (int32_t i = 0; i < b; i++)
      rot_out[s][i] = ReduceRotation((g*i)*(1 << ((s-flagRem)*layersCollapse + remCollapse)),m/4);
  }

  if (flagRem){
    for (int32_t j=0; j < gRem; j++)
      rot_in[stop][j] = ReduceRotation((j-int32_t((numRotationsRem+1)/2)+1),precom.m_slots); // m/4
    for (int32_t i = 0; i < bRem; i++)
      rot_out[stop][i] = ReduceRotation((gRem*i),m/4);
  }

  // hoisted automorphisms
  for (int32_t s = levelBudget-1; s > stop; s--){
    // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.EvalFastRotationPrecompute(result);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(g);
#pragma omp parallel for
    for (int32_t j=0; j < g; j++) {
      if (rot_in[s][j] != 0)
        fastRotation[j] = cc.EvalFastRotationExt(result,rot_in[s][j],digits,true);
      else
        fastRotation[j] = cc.KeySwitchExt(result,true);
    }

    Ciphertext<DCRTPoly> outer;
    DCRTPoly first;
    for (int32_t i = 0; i < b; i++){

      Ciphertext<DCRTPoly> inner;
      // for the first iteration with j=0:
      int32_t G = g * i;
      inner = cc.EvalMult(fastRotation[0], A[s][G]);
      // continue the loop
      for (int32_t j=1; j < g; j++) {
        if ((G+j) != int32_t(numRotations))
          cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j],A[s][G + j]));
      }

        if (i == 0) {
          first = cc.KeySwitchDownFirstElement(inner);
          auto elements = inner->GetElements();
          elements[0].SetValuesToZero();
          inner->SetElements(elements);
          outer = inner;
      } else {
          if (rot_out[s][i] != 0) {
            inner = cc.KeySwitchDown(inner);
            // Find the automorphism index that corresponds to rotation index index.
            usint autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], m);
            std::vector<usint> map(n);
            PrecomputeAutoMap(n, autoIndex, &map);
            first += inner->GetElements()[0].AutomorphismTransform(autoIndex,map);

            auto innerDigits = cc.EvalFastRotationPrecompute(inner);
            cc.EvalAddInPlace(outer,cc.EvalFastRotationExt(inner,rot_out[s][i],innerDigits,false));
          } else {
            first += cc.KeySwitchDownFirstElement(inner);
            auto elements = inner->GetElements();
            elements[0].SetValuesToZero();
            inner->SetElements(elements);
            cc.EvalAddInPlace(outer,inner);
          }
      }
    }

    outer = cc.KeySwitchDown(outer);
    auto elements = outer->GetElements();
    elements[0]+= first;
    outer->SetElements(elements);

//    result = outer;
    result = algo->ModReduceInternal(outer);
  }

   if (flagRem) {
    // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.EvalFastRotationPrecompute(result);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(gRem);
#pragma omp parallel for
    for (int32_t j=0; j < gRem; j++) {
      if (rot_in[stop][j] != 0) {
              fastRotation[j] = cc.EvalFastRotationExt(result,rot_in[stop][j],digits,true);
      } else {
        fastRotation[j] = cc.KeySwitchExt(result,true);
      }
    }

    Ciphertext<DCRTPoly> outer;
    DCRTPoly first;
    for (int32_t i = 0; i < bRem; i++){

      Ciphertext<DCRTPoly> inner;
      // for the first iteration with j=0:
      int32_t GRem = gRem * i;
      inner = cc.EvalMult(fastRotation[0], A[stop][GRem]);
      // continue the loop
      for (int32_t j=1; j < gRem; j++) {
        if ((GRem+j) != int32_t(numRotationsRem))
          cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j],A[stop][GRem+j]));
      }

        if (i == 0) {
          first = cc.KeySwitchDownFirstElement(inner);
          auto elements = inner->GetElements();
          elements[0].SetValuesToZero();
          inner->SetElements(elements);
          outer = inner;
      } else {
          if (rot_out[stop][i] != 0) {
            inner = cc.KeySwitchDown(inner);
            // Find the automorphism index that corresponds to rotation index index.
            usint autoIndex = FindAutomorphismIndex2nComplex(rot_out[stop][i], m);
            std::vector<usint> map(n);
            PrecomputeAutoMap(n, autoIndex, &map);
            first += inner->GetElements()[0].AutomorphismTransform(autoIndex,map);

            auto innerDigits = cc.EvalFastRotationPrecompute(inner);
            cc.EvalAddInPlace(outer,cc.EvalFastRotationExt(inner,rot_out[stop][i],innerDigits,false));
          } else {
            first += cc.KeySwitchDownFirstElement(inner);
            auto elements = inner->GetElements();
            elements[0].SetValuesToZero();
            inner->SetElements(elements);
            cc.EvalAddInPlace(outer,inner);
          }
      }
    }

    outer = cc.KeySwitchDown(outer);
    auto elements = outer->GetElements();
    elements[0]+= first;
    outer->SetElements(elements);
    result = algo->ModReduceInternal(outer);
   }

//  No need for Encrypted Bit Reverse

  return result;
}

Ciphertext<DCRTPoly> FHECKKSRNS::EvalBootstrapWithPrecompDecoding(const CryptoContextImpl<DCRTPoly> &cc,
    const std::vector<std::vector<ConstPlaintext>> &A, ConstCiphertext<DCRTPoly> ctxt) const {

  uint32_t m = cc.GetCyclotomicOrder();
  uint32_t n = cc.GetRingDimension();

  int32_t levelBudget = precom.m_paramsDec[FFT_PARAMS::LEVEL_BUDGET];
  int32_t layersCollapse = precom.m_paramsDec[FFT_PARAMS::LAYERS_COLL];
  int32_t remCollapse = precom.m_paramsDec[FFT_PARAMS::LAYERS_REM];
  int32_t numRotations = precom.m_paramsDec[FFT_PARAMS::NUM_ROTATIONS];
  int32_t b = precom.m_paramsDec[FFT_PARAMS::BABY_STEP];
  int32_t g = precom.m_paramsDec[FFT_PARAMS::GIANT_STEP];
  int32_t numRotationsRem = precom.m_paramsDec[FFT_PARAMS::NUM_ROTATIONS_REM];
  int32_t bRem = precom.m_paramsDec[FFT_PARAMS::BABY_STEP_REM];
  int32_t gRem = precom.m_paramsDec[FFT_PARAMS::GIANT_STEP_REM];

  auto algo = cc.GetScheme();

  int32_t flagRem = 0;

  if(remCollapse!=0)
    flagRem = 1;

  //  No need for Encrypted Bit Reverse

  Ciphertext<DCRTPoly> result =  ctxt->Clone();

  // precompute the inner and outer rotations

  std::vector<std::vector<int32_t>> rot_in(levelBudget);
  for(uint32_t i = 0; i < uint32_t(levelBudget); i++){
    if (flagRem == 1 && i == uint32_t(levelBudget-1)) // remainder corresponds to index 0 in encoding and to last index in decoding
      rot_in[i] = std::vector<int32_t>(numRotationsRem+1);
    else
      rot_in[i] = std::vector<int32_t>(numRotations+1);
  }
  std::vector<std::vector<int32_t>> rot_out(levelBudget);
  for(uint32_t i = 0; i < uint32_t(levelBudget); i++)
    rot_out[i] = std::vector<int32_t>(b + bRem);

  for (int32_t s = 0; s < levelBudget - flagRem; s++){
    for (int32_t j=0; j < g; j++)
      rot_in[s][j] = ReduceRotation((j-int32_t((numRotations+1)/2)+1)*(1<<(s*layersCollapse)),m/4);
    for (int32_t i = 0; i < b; i++)
      rot_out[s][i] = ReduceRotation((g*i)*(1 << (s*layersCollapse)),m/4);
  }

  if (flagRem){
    int32_t s = levelBudget - flagRem;
    for (int32_t j=0; j < gRem; j++)
      rot_in[s][j] = ReduceRotation((j-int32_t((numRotationsRem+1)/2)+1)*(1<<(s*layersCollapse)),m/4);
    for (int32_t i = 0; i < bRem; i++)
      rot_out[s][i] = ReduceRotation((gRem*i)*(1<<(s*layersCollapse)),m/4);
  }

  // hoisted automorphisms
  for (int32_t s = 0; s < levelBudget - flagRem; s++){
    // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.EvalFastRotationPrecompute(result);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(g);
#pragma omp parallel for
    for (int32_t j=0; j < g; j++) {
      if (rot_in[s][j] != 0)
        fastRotation[j] = cc.EvalFastRotationExt(result,rot_in[s][j],digits,true);
      else
        fastRotation[j] = cc.KeySwitchExt(result,true);
    }

    Ciphertext<DCRTPoly> outer;
    DCRTPoly first;
    for (int32_t i = 0; i < b; i++){
      Ciphertext<DCRTPoly> inner;
      // for the first iteration with j=0:
      int32_t G = g * i;
      inner = cc.EvalMult(fastRotation[0], A[s][G]);
      // continue the loop
      for (int32_t j = 1; j < g; j++) {
        if ((G + j) != int32_t(numRotations))
          cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j], A[s][G + j]));
      }

          if (i == 0) {
          first = cc.KeySwitchDownFirstElement(inner);
          auto elements = inner->GetElements();
          elements[0].SetValuesToZero();
          inner->SetElements(elements);
          outer = inner;
      } else {
          if (rot_out[s][i] != 0) {
            inner = cc.KeySwitchDown(inner);
            // Find the automorphism index that corresponds to rotation index index.
            usint autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], m);
            std::vector<usint> map(n);
            PrecomputeAutoMap(n, autoIndex, &map);
            first += inner->GetElements()[0].AutomorphismTransform(autoIndex,map);

            auto innerDigits = cc.EvalFastRotationPrecompute(inner);
            cc.EvalAddInPlace(outer,cc.EvalFastRotationExt(inner,rot_out[s][i],innerDigits,false));
          } else {
            first += cc.KeySwitchDownFirstElement(inner);
            auto elements = inner->GetElements();
            elements[0].SetValuesToZero();
            inner->SetElements(elements);
            cc.EvalAddInPlace(outer,inner);
          }
      }
    }

    outer = cc.KeySwitchDown(outer);
    auto elements = outer->GetElements();
    elements[0]+= first;
    outer->SetElements(elements);

    result = algo->ModReduceInternal(outer);

  }

   if(flagRem){
    int32_t s = levelBudget - flagRem;
    // computes the NTTs for each CRT limb (for the hoisted automorphisms used later on)
    auto digits = cc.EvalFastRotationPrecompute(result);

    std::vector<Ciphertext<DCRTPoly>> fastRotation(gRem);
#pragma omp parallel for
    for (int32_t j=0; j < gRem; j++) {
      if (rot_in[s][j] != 0)
        fastRotation[j] = cc.EvalFastRotationExt(result,rot_in[s][j],digits,true);
      else
        fastRotation[j] = cc.KeySwitchExt(result,true);
    }

    Ciphertext<DCRTPoly> outer;
    DCRTPoly first;
    for (int32_t i = 0; i < bRem; i++){

      Ciphertext<DCRTPoly> inner;
      // for the first iteration with j=0:
      int32_t GRem = gRem * i;
      inner = cc.EvalMult(fastRotation[0], A[s][GRem]);
      // continue the loop
      for (int32_t j = 1; j < gRem; j++) {
        if ((GRem + j) != int32_t(numRotationsRem))
          cc.EvalAddInPlace(inner, cc.EvalMult(fastRotation[j], A[s][GRem + j]));
      }

          if (i == 0) {
          first = cc.KeySwitchDownFirstElement(inner);
          auto elements = inner->GetElements();
          elements[0].SetValuesToZero();
          inner->SetElements(elements);
          outer = inner;
      } else {
          if (rot_out[s][i] != 0) {
            inner = cc.KeySwitchDown(inner);
            // Find the automorphism index that corresponds to rotation index index.
            usint autoIndex = FindAutomorphismIndex2nComplex(rot_out[s][i], m);
            std::vector<usint> map(n);
            PrecomputeAutoMap(n, autoIndex, &map);
            first += inner->GetElements()[0].AutomorphismTransform(autoIndex,map);

            auto innerDigits = cc.EvalFastRotationPrecompute(inner);
            cc.EvalAddInPlace(outer,cc.EvalFastRotationExt(inner,rot_out[s][i],innerDigits,false));
          } else {
            first += cc.KeySwitchDownFirstElement(inner);
            auto elements = inner->GetElements();
            elements[0].SetValuesToZero();
            inner->SetElements(elements);
            cc.EvalAddInPlace(outer,inner);
          }
      }
    }

    outer = cc.KeySwitchDown(outer);
    auto elements = outer->GetElements();
    elements[0]+= first;
    outer->SetElements(elements);
    result = algo->ModReduceInternal(outer);
  }

  return result;
}

std::vector<std::vector<ConstPlaintext>> FHECKKSRNS::EvalBootstrapPrecomputeDecoding(
  const CryptoContextImpl<DCRTPoly> &cc, const std::vector<std::complex<double>> &A, const std::vector<uint32_t> &rotGroup,
  bool flag_i, double scale, uint32_t L) {

  uint32_t slots = rotGroup.size();
  uint32_t m = cc.GetCyclotomicOrder();

  int32_t levelBudget = precom.m_paramsDec[FFT_PARAMS::LEVEL_BUDGET];
  int32_t layersCollapse = precom.m_paramsDec[FFT_PARAMS::LAYERS_COLL];
  int32_t remCollapse = precom.m_paramsDec[FFT_PARAMS::LAYERS_REM];
  int32_t numRotations = precom.m_paramsDec[FFT_PARAMS::NUM_ROTATIONS];
  int32_t b = precom.m_paramsDec[FFT_PARAMS::BABY_STEP];
  int32_t g = precom.m_paramsDec[FFT_PARAMS::GIANT_STEP];
  int32_t numRotationsRem = precom.m_paramsDec[FFT_PARAMS::NUM_ROTATIONS_REM];
  int32_t bRem = precom.m_paramsDec[FFT_PARAMS::BABY_STEP_REM];
  int32_t gRem = precom.m_paramsDec[FFT_PARAMS::GIANT_STEP_REM];

  int32_t flagRem = 0;

  if(remCollapse!=0)
    flagRem = 1;

  // result is the rotated plaintext version of coeff
  std::vector<std::vector<ConstPlaintext>> result(levelBudget);
  for(uint32_t i = 0; i < uint32_t(levelBudget); i++){
    if (flagRem == 1 && i == uint32_t(levelBudget - 1)) // remainder corresponds to index 0 in encoding and to last index in decoding
      result[i] = std::vector<ConstPlaintext>(numRotationsRem);
    else
      result[i] = std::vector<ConstPlaintext>(numRotations);
  }

  // make sure the plaintext is created only with the necessary amount of moduli

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          cc.GetCryptoParameters());

  ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());

  uint32_t towersToDrop = 0;

  if (L != 0)
  {
    towersToDrop = elementParams.GetParams().size() - L - levelBudget;
    for (uint32_t i = 0; i < towersToDrop; i++)
      elementParams.PopLastParam();
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

  std::vector<std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>> paramsVector(levelBudget - flagRem + 1);
  for (int32_t s = 0; s < levelBudget - flagRem + 1; s++) {
      paramsVector[s] = std::make_shared<typename DCRTPoly::Params>(m, moduli, roots);
      moduli.erase(moduli.begin() + sizeQ - 1);
      roots.erase(roots.begin() + sizeQ - 1);
      sizeQ--;
  }

  if (slots == m/4) // fully-packed
  {
    auto coeff = CoeffDecodingCollapse(A,rotGroup,levelBudget,flag_i);

    for (int32_t s = 0; s < levelBudget-flagRem; s++) {
      for (int32_t i=0; i < b; i++) {
#pragma omp parallel for
        for (int32_t j=0; j < g; j++) {
          if (g*i + j != int32_t(numRotations)) {
            uint32_t rot = ReduceRotation(-g*i*(1<<(s*layersCollapse)),slots);
            if ((flagRem == 0) && (s == levelBudget-flagRem-1)) {// do the scaling only at the last set of coefficients
              for (uint32_t k=0; k < slots; k++)
                coeff[s][g*i+j][k] *= scale;
            }
            auto rotateTemp = Rotate(coeff[s][g*i+j],rot);
            Plaintext temp = cc.MakeCKKSPackedPlaintext( Fill(rotateTemp,slots), 1, level0 + s, paramsVector[s] );
            result[s][g*i+j] = temp;
          }
        }
      }
    }

    if(flagRem){

      int32_t s = levelBudget-flagRem;
      for (int32_t i=0; i < bRem; i++) {
#pragma omp parallel for
        for (int32_t j=0; j < gRem; j++) {
          if (gRem*i + j != int32_t(numRotationsRem)) {
            uint32_t rot = ReduceRotation(-gRem*i*(1<<(s*layersCollapse)),slots);
            for (uint32_t k=0; k < slots; k++)
              coeff[s][gRem*i+j][k] *= scale;
            auto rotateTemp = Rotate(coeff[s][gRem*i+j],rot);
            Plaintext temp = cc.MakeCKKSPackedPlaintext( Fill(rotateTemp,slots), 1, level0 + s, paramsVector[s] );
            result[s][gRem*i+j] = temp;
          }
        }
      }
    }
  }
  else // sparsely-packed mode
  {
    auto coeff = CoeffDecodingCollapse(A,rotGroup,levelBudget,false);
    auto coeffi = CoeffDecodingCollapse(A,rotGroup,levelBudget,true);

//#pragma omp parallel for
    for (int32_t s = 0; s < levelBudget-flagRem; s++) {
      for (int32_t i=0; i < b; i++) {
#pragma omp parallel for
        for (int32_t j=0; j < g; j++) {
          if (g*i + j != int32_t(numRotations)) {
            uint32_t rot = ReduceRotation(-g*i*(1<<(s*layersCollapse)),m/4);
            // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
            auto clearTemp = coeff[s][g*i+j];
            auto clearTempi = coeffi[s][g*i+j];
            clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
            if ((flagRem == 0) && (s == levelBudget-flagRem-1)) {// do the scaling only at the last set of coefficients
              for (uint32_t k=0; k < clearTemp.size(); k++)
                clearTemp[k] *= scale;
            }
            auto rotateTemp = Rotate(clearTemp,rot);
            Plaintext temp = cc.MakeCKKSPackedPlaintext( Fill(rotateTemp,m/4), 1, level0 + s, paramsVector[s] );
            result[s][g*i+j] = temp;
          }
        }
      }
    }

    if(flagRem){

      int32_t s = levelBudget-flagRem;
      for (int32_t i=0; i < bRem; i++) {
#pragma omp parallel for
        for (int32_t j=0; j < gRem; j++) {
          if (gRem*i + j != int32_t(numRotationsRem)) {
            uint32_t rot = ReduceRotation(-gRem*i*(1<<(s*layersCollapse)),m/4);
            // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
            auto clearTemp = coeff[s][gRem*i+j];
            auto clearTempi = coeffi[s][gRem*i+j];
            clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
            for (uint32_t k=0; k < clearTemp.size(); k++)
              clearTemp[k] *= scale;
            auto rotateTemp = Rotate(clearTemp,rot);
            Plaintext temp = cc.MakeCKKSPackedPlaintext( Fill(rotateTemp,m/4), 1, level0 + s, paramsVector[s] );
            result[s][gRem*i+j] = temp;
          }
        }
      }
    }
  }

  return result;
}

std::vector<std::vector<ConstPlaintext>> FHECKKSRNS::EvalBootstrapPrecomputeEncoding(
  const CryptoContextImpl<DCRTPoly> &cc, const std::vector<std::complex<double>> &A,const std::vector<uint32_t> &rotGroup,
  bool flag_i, double scale, uint32_t L) {

  uint32_t slots = rotGroup.size();
  uint32_t m = cc.GetCyclotomicOrder();

  int32_t levelBudget = precom.m_paramsEnc[FFT_PARAMS::LEVEL_BUDGET];
  int32_t layersCollapse = precom.m_paramsEnc[FFT_PARAMS::LAYERS_COLL];
  int32_t remCollapse = precom.m_paramsEnc[FFT_PARAMS::LAYERS_REM];
  int32_t numRotations = precom.m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS];
  int32_t b = precom.m_paramsEnc[FFT_PARAMS::BABY_STEP];
  int32_t g = precom.m_paramsEnc[FFT_PARAMS::GIANT_STEP];
  int32_t numRotationsRem = precom.m_paramsEnc[FFT_PARAMS::NUM_ROTATIONS_REM];
  int32_t bRem = precom.m_paramsEnc[FFT_PARAMS::BABY_STEP_REM];
  int32_t gRem = precom.m_paramsEnc[FFT_PARAMS::GIANT_STEP_REM];

  int32_t stop = -1;
  int32_t flagRem = 0;

  if(remCollapse!=0){
    stop = 0;
    flagRem = 1;
  }

  // result is the rotated plaintext version of the coefficients
  std::vector<std::vector<ConstPlaintext>> result(levelBudget);
  for(uint32_t i = 0; i < uint32_t(levelBudget); i++){
    if (flagRem == 1 && i == 0) // remainder corresponds to index 0 in encoding and to last index in decoding
      result[i] = std::vector<ConstPlaintext>(numRotationsRem);
    else
      result[i] = std::vector<ConstPlaintext>(numRotations);
  }

  // make sure the plaintext is created only with the necessary amount of moduli

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          cc.GetCryptoParameters());

  ILDCRTParams<DCRTPoly::Integer> elementParams = *(cryptoParams->GetElementParams());

  uint32_t towersToDrop = 0;

  if (L != 0)
  {
    towersToDrop = elementParams.GetParams().size() - L - levelBudget;
    for (uint32_t i = 0; i < towersToDrop; i++)
      elementParams.PopLastParam();
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
  std::vector<std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>>> paramsVector(levelBudget - stop);
  for (int32_t s = levelBudget - 1; s >= stop; s--) {
      paramsVector[s - stop] = std::make_shared<typename DCRTPoly::Params>(m, moduli, roots);
      moduli.erase(moduli.begin() + sizeQ - 1);
      roots.erase(roots.begin() + sizeQ - 1);
      sizeQ--;
  }

  if (slots == m/4) // fully-packed mode
  {

    auto coeff = CoeffEncodingCollapse(A,rotGroup,levelBudget,flag_i);

    for (int32_t s = levelBudget - 1; s > stop; s--) {
      for (int32_t i=0; i < b; i++) {
#pragma omp parallel for
        for (int32_t j=0; j < g; j++) {
          if (g*i + j != int32_t(numRotations)) {
            uint32_t rot = ReduceRotation(-g*i*(1<<((s-flagRem)*layersCollapse+remCollapse)),slots);
              if ((flagRem == 0) && (s == stop + 1)) {// do the scaling only at the last set of coefficients
              for (uint32_t k=0; k < slots; k++)
                coeff[s][g*i+j][k] *= scale;
              }
            auto rotateTemp = Rotate(coeff[s][g*i+j],rot);
            Plaintext temp = cc.MakeCKKSPackedPlaintext(Fill(rotateTemp,slots),1,level0 - s,paramsVector[s - stop]);
            result[s][g*i+j] = temp;
            }
          }
      }
    }

    if(flagRem){

      for (int32_t i=0; i < bRem; i++) {
#pragma omp parallel for
        for (int32_t j=0; j < gRem; j++) {
          if (gRem*i + j != int32_t(numRotationsRem)) {
            uint32_t rot = ReduceRotation(-gRem*i,slots);
            for (uint32_t k=0; k < slots; k++)
              coeff[stop][gRem*i+j][k] *= scale;

            auto rotateTemp = Rotate(coeff[stop][gRem*i+j],rot);
            Plaintext temp = cc.MakeCKKSPackedPlaintext(Fill(rotateTemp,slots),1,level0,paramsVector[0]);
            result[stop][gRem*i+j] = temp;
          }
        }
      }
    }
  }
  else
  { //sparsely-packed mode

    auto coeff = CoeffEncodingCollapse(A,rotGroup,levelBudget,false);
    auto coeffi = CoeffEncodingCollapse(A,rotGroup,levelBudget,true);

    for (int32_t s = levelBudget - 1; s > stop; s--) {
      for (int32_t i=0; i < b; i++) {
#pragma omp parallel for
        for (int32_t j=0; j < g; j++) {
          if (g*i + j != int32_t(numRotations)) {
            uint32_t rot = ReduceRotation(-g*i*(1<<((s-flagRem)*layersCollapse+remCollapse)),m/4);
            // concatenate the coefficients horizontally on their third dimension, which corresponds to the # of slots
            auto clearTemp = coeff[s][g*i+j];
            auto clearTempi = coeffi[s][g*i+j];
            clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
            if ((flagRem == 0) && (s == stop+1)) {// do the scaling only at the last set of coefficients
              for (uint32_t k=0; k < clearTemp.size(); k++)
                clearTemp[k] *= scale;
            }

            auto rotateTemp = Rotate(clearTemp,rot);
            Plaintext temp = cc.MakeCKKSPackedPlaintext(Fill(rotateTemp,m/4), 1, level0 - s, paramsVector[s - stop]);
            result[s][g*i+j] = temp;
          }
        }
      }
    }

    if(flagRem){

      for (int32_t i=0; i < bRem; i++) {
#pragma omp parallel for
        for (int32_t j=0; j < gRem; j++) {
          if (gRem*i + j != int32_t(numRotationsRem)) {
            uint32_t rot = ReduceRotation(-gRem*i,m/4);
            // concatenate the coefficients on their third dimension, which corresponds to the # of slots
            auto clearTemp = coeff[stop][gRem*i+j];
            auto clearTempi = coeffi[stop][gRem*i+j];
            clearTemp.insert(clearTemp.end(), clearTempi.begin(), clearTempi.end());
            for (uint32_t k=0; k < clearTemp.size(); k++)
              clearTemp[k] *= scale;

            auto rotateTemp = Rotate(clearTemp,rot);
            Plaintext temp = cc.MakeCKKSPackedPlaintext(Fill(rotateTemp,m/4), 1, level0, paramsVector[0]);
            result[stop][gRem*i+j] = temp;
          }
        }
      }
    }

  }

  return result;

}

uint32_t FHECKKSRNS::GetBootstrapDepth(
    const CryptoContextImpl<DCRTPoly> &cc,
    const std::vector<uint32_t> &levelBudget) {

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          cc.GetCryptoParameters());

  uint32_t approxModDepth = 8;

  if (cryptoParams->GetMode() == OPTIMIZED) {
      if (cryptoParams->GetRescalingTechnique() == FIXEDMANUAL)
        approxModDepth += R - 1;
      else
        approxModDepth += R;
  }

  return approxModDepth + levelBudget[0] + levelBudget[1] + 1;
}

EvalKey<DCRTPoly> FHECKKSRNS::ConjugateKeyGen(
    const PrivateKey<DCRTPoly> privateKey) const {
  const DCRTPoly &s = privateKey->GetPrivateElement();

  usint n = s.GetRingDimension();

  PrivateKey<DCRTPoly> privateKeyPermuted(
      std::make_shared<PrivateKeyImpl<DCRTPoly>>(
          privateKey->GetCryptoContext()));

  usint index =  2 * n - 1;
  std::vector<usint> map(n);
  PrecomputeAutoMap(n, index, &map);

  DCRTPoly sPermuted = s.AutomorphismTransform(index);

  privateKeyPermuted->SetPrivateElement(sPermuted);
  privateKeyPermuted->SetKeyTag(privateKey->GetKeyTag());

  auto cc = privateKey->GetCryptoContext();
  auto algo = cc->GetScheme();
  return algo->KeySwitchGen(privateKey, privateKeyPermuted);
}

Ciphertext<DCRTPoly> FHECKKSRNS::Conjugate(
    ConstCiphertext<DCRTPoly> ciphertext,
    const std::map<usint, EvalKey<DCRTPoly>> &evalKeys) const {
  if (nullptr == ciphertext) {
    std::string errorMsg(std::string("Input ciphertext is nullptr") +
                         CALLER_INFO);
    OPENFHE_THROW(type_error, errorMsg);
  }
  usint n = ciphertext->GetElements()[0].GetRingDimension();
  if (evalKeys.empty()) {
    std::string errorMsg(std::string("Empty input key map") + CALLER_INFO);
    OPENFHE_THROW(type_error, errorMsg);
  }
  auto key = evalKeys.find(2 * n - 1);
  if (key == evalKeys.end()) {
    std::string errorMsg(std::string("Could not find an EvalKey for index ") +
                         std::to_string(2 * n - 1) + CALLER_INFO);
    OPENFHE_THROW(type_error, errorMsg);
  }
  auto fk = key->second;
  if (nullptr == fk) {
    std::string errorMsg(std::string("Invalid evalKey") + CALLER_INFO);
    OPENFHE_THROW(type_error, errorMsg);
  }
  if (ciphertext->GetCryptoContext() != fk->GetCryptoContext()) {
    std::string errorMsg(
        std::string("Items were not created in the same CryptoContextImpl") +
        CALLER_INFO);
    OPENFHE_THROW(type_error, errorMsg);
  }
  if (ciphertext->GetKeyTag() != fk->GetKeyTag()) {
    std::string errorMsg(
        std::string("Items were not encrypted with same keys") + CALLER_INFO);
    OPENFHE_THROW(type_error, errorMsg);
  }

  const std::vector<DCRTPoly> &c = ciphertext->GetElements();
  if (c.size() < 2) {
    std::string errorMsg(
        std::string("Insufficient number of elements in ciphertext: ") +
        std::to_string(c.size()) + CALLER_INFO);
    OPENFHE_THROW(config_error, errorMsg);
  }

  auto cc = ciphertext->GetCryptoContext();
  auto algo = cc->GetScheme();
  Ciphertext<DCRTPoly> permutedCiphertext = algo->KeySwitch(ciphertext, fk);

  std::vector<usint> map(n);
  PrecomputeAutoMap(n, 2 * n - 1, &map);

  permutedCiphertext->SetElements(
      {std::move(
           permutedCiphertext->GetElements()[0].AutomorphismTransform(2 * n - 1, map)),
       std::move(permutedCiphertext->GetElements()[1].AutomorphismTransform(
           2 * n - 1, map))});

  permutedCiphertext->SetDepth(ciphertext->GetDepth());
  permutedCiphertext->SetLevel(ciphertext->GetLevel());
  permutedCiphertext->SetScalingFactor(ciphertext->GetScalingFactor());

  return permutedCiphertext;

}

}
