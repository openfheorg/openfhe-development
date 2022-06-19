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
#include "scheme/ckksrns/ckksrns-advancedshe.h"
#include "utils/polynomials.h"

namespace lbcrypto {

//------------------------------------------------------------------------------
// LINEAR WEIGHTED SUM
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalLinearWSum(
    std::vector<ConstCiphertext<DCRTPoly>>& ciphertexts, const std::vector<double> &constants) const {
  std::vector<Ciphertext<DCRTPoly>> cts(ciphertexts.size());

  for (uint32_t i = 0; i < ciphertexts.size(); i++) {
    cts[i] = ciphertexts[i]->Clone();
  }

  return EvalLinearWSumMutable(cts, constants);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalLinearWSumMutable(
    std::vector<Ciphertext<DCRTPoly>>& ciphertexts, const std::vector<double> &constants) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(ciphertexts[0]->GetCryptoParameters());

  auto cc = ciphertexts[0]->GetCryptoContext();
  auto algo = cc->GetScheme();

  if (cryptoParams->GetRescalingTechnique() != FIXEDMANUAL) {

    // Check to see if input ciphertexts are of same level
    // and adjust if needed to the max level among them
    uint32_t maxLevel = ciphertexts[0]->GetLevel();
    uint32_t maxIdx = 0;
    for (uint32_t i = 1; i < ciphertexts.size(); i++) {
      if ((ciphertexts[i]->GetLevel() > maxLevel) ||
          ((ciphertexts[i]->GetLevel() == maxLevel) && (ciphertexts[i]->GetDepth() == 2))) {
        maxLevel = ciphertexts[i]->GetLevel();
        maxIdx = i;
      }
    }

    for (uint32_t i = 0; i < maxIdx; i++) {
      algo->AdjustLevelsAndDepthInPlace(ciphertexts[i], ciphertexts[maxIdx]);
    }

    for (uint32_t i = maxIdx + 1; i < ciphertexts.size(); i++) {
      algo->AdjustLevelsAndDepthInPlace(ciphertexts[i], ciphertexts[maxIdx]);
    }

    if (ciphertexts[maxIdx]->GetDepth() == 2) {
      for (uint32_t i = 0; i < ciphertexts.size(); i++) {
        algo->ModReduceInternalInPlace(ciphertexts[i], BASE_NUM_LEVELS_TO_DROP);
      }
    }
  }

  Ciphertext<DCRTPoly> weightedSum = cc->EvalMult(ciphertexts[0], constants[0]);

  Ciphertext<DCRTPoly> tmp;
  for (uint32_t i = 1; i < ciphertexts.size(); i++) {
    tmp = cc->EvalMult(ciphertexts[i], constants[i]);
    cc->EvalAddInPlace(weightedSum, tmp);
  }

  cc->ModReduceInPlace(weightedSum);

  return weightedSum;
}

//------------------------------------------------------------------------------
// EVAL POLYNOMIAL
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPoly(
    ConstCiphertext<DCRTPoly> x,
    const std::vector<double> &coefficients) const {
  uint32_t n = Degree(coefficients);

  if (n < 5) {
    return EvalPolyLinear(x, coefficients);
  }

  return EvalPolyPS(x, coefficients);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPolyLinear(
    ConstCiphertext<DCRTPoly> x,
    const std::vector<double> &coefficients) const {
  if (coefficients[coefficients.size() - 1] == 0)
    OPENFHE_THROW(
        math_error,
        "EvalPolyLinear: The highest-order coefficient cannot be set to 0.");

  std::vector<Ciphertext<DCRTPoly>> powers(coefficients.size() - 1);
  std::vector<int32_t> indices(coefficients.size() - 1, 0);

  // set the indices for the powers of x that need to be computed to 1
  for (size_t i = coefficients.size() - 1; i > 0; i--) {
    // if i is a power of 2
    if (!(i & (i-1))) {
      indices[i - 1] = 1;
    } else {  // non-power of 2
      if (coefficients[i] != 0) {
        indices[i - 1] = 1;
        int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
        int64_t rem = i % powerOf2;
        if (indices[rem - 1] == 0) indices[rem - 1] = 1;
        // while rem is not a power of 2, set indices required to compute rem to
        // 1
        while ((rem & (rem-1))) {
          powerOf2 = 1 << (int64_t)std::floor(std::log2(rem));
          rem = rem % powerOf2;
          if (indices[rem - 1] == 0) indices[rem - 1] = 1;
        }
      }
    }
  }

  powers[0] = Ciphertext<DCRTPoly>(new CiphertextImpl<DCRTPoly>(*x));

  auto cc = x->GetCryptoContext();

  // computes all powers for x
  for (size_t i = 2; i < coefficients.size(); i++) {
    if (!(i & (i-1))) {
      powers[i - 1] = cc->EvalMult(powers[i / 2 - 1], powers[i / 2 - 1]);
      cc->ModReduceInPlace(powers[i - 1]);
    } else {  // non-power of 2
      if (indices[i - 1] == 1) {
        int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
        int64_t rem = i % powerOf2;
        cc->LevelReduceInPlace(powers[rem - 1], nullptr, powers[powerOf2 - 1]->GetLevel() - powers[rem - 1]->GetLevel());

        powers[i - 1] = cc->EvalMult(powers[powerOf2 - 1], powers[rem - 1]);
        cc->ModReduceInPlace(powers[i - 1]);
      }
    }
  }

  // brings all powers of x to the same level
  for (size_t i = 1; i < coefficients.size() - 1; i++) {
    if (indices[i - 1] == 1) {
      cc->LevelReduceInPlace(powers[i - 1], nullptr, powers[coefficients.size() - 2]->GetLevel() - powers[i - 1]->GetLevel());
    }
  }

  // perform scalar multiplication for the highest-order term
  auto result = cc->EvalMult(powers[coefficients.size() - 2],
                             coefficients[coefficients.size() - 1]);

  // perform scalar multiplication for all other terms and sum them up
  for (size_t i = 0; i < coefficients.size() - 2; i++) {
    if (coefficients[i + 1] != 0) {
      cc->EvalMultInPlace(powers[i], coefficients[i + 1]);
      cc->EvalAddInPlace(result, powers[i]);
    }
  }

  // Do rescaling after scalar multiplication
  cc->ModReduceInPlace(result);

  // adds the free term (at x^0)
  cc->EvalAddInPlace(result, coefficients[0]);

  return result;
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::InnerEvalPolyPS(
    ConstCiphertext<DCRTPoly> x,
    const std::vector<double> &coefficients,
    uint32_t k, uint32_t m,
    std::vector<Ciphertext<DCRTPoly>> &powers,
    std::vector<Ciphertext<DCRTPoly>> &powers2) const {

  auto cc = x->GetCryptoContext();

  // Compute k*2^m because we use it often
  uint32_t k2m2k = k*(1<<(m-1)) - k;

  // Divide coefficients by x^{k*2^{m-1}}
  std::vector<double> xkm(int32_t(k2m2k+k)+1, 0.0);
  xkm.back() = 1;

  longDiv *divqr = LongDivisionPoly(coefficients, xkm);

  // Subtract x^{k(2^{m-1} - 1)} from r
  std::vector<double> r2 = divqr->r;
  if (int32_t(k2m2k-Degree(divqr->r)) <= 0) {
    r2[int32_t(k2m2k)] -= 1;
    r2.resize(Degree(r2) + 1);
  } else {
    r2.resize(int32_t(k2m2k+1), 0.0);
    r2.back() = -1;
  }

  // Divide r2 by q
  longDiv *divcs = LongDivisionPoly(r2, divqr->q);

  // Add x^{k(2^{m-1} - 1)} to s
  std::vector<double> s2 = divcs->r;
  s2.resize(int32_t(k2m2k+1), 0.0);
  s2.back() = 1;

  Ciphertext<DCRTPoly> cu;
  uint32_t dc = Degree(divcs->q);
  bool flag_c = false;

  if (dc >= 1) {
    if (dc == 1) {
      if (divcs->q[1] != 1) {
        cu = cc->EvalMult(powers.front(), divcs->q[1]);
        // Do rescaling after scalar multiplication
        cc->ModReduceInPlace(cu);
      }
      else
        cu = powers.front();
    } else {
      std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
      std::vector<double> weights(dc);

      for (uint32_t i = 0; i < dc; i++) {
        ctxs[i] = powers[i];
        weights[i] = divcs->q[i+1];
      }

      cu = cc->EvalLinearWSumMutable(ctxs, weights);
      // Do rescaling after scalar multiplication
      cc->ModReduceInPlace(cu);
    }

    // adds the free term (at x^0)
    cc->EvalAddInPlace(cu,divcs->q.front());
    flag_c = true;
  }

  // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
  Ciphertext<DCRTPoly> qu;

  if(Degree(divqr->q) > k) {
    qu = InnerEvalPolyPS(x, divqr->q, k, m-1, powers, powers2);
  } else {
    // dq = k from construction
    // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
    auto qcopy = divqr->q;
    qcopy.resize(k);
    if (Degree(qcopy) > 0){

      std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
      std::vector<double> weights(Degree(qcopy));

      for (uint32_t i = 0; i < Degree(qcopy); i++) {
        ctxs[i] = powers[i];
        weights[i] = divqr->q[i+1];
      }

      qu = cc->EvalLinearWSumMutable(ctxs, weights);

      cc->ModReduceInPlace(qu);
      // the highest order term will always be 1 because q is monic
      cc->EvalAddMutableInPlace(qu, powers[k-1]);
    } else {
      qu = powers[k-1];
    }
    // adds the free term (at x^0)
    cc->EvalAddInPlace(qu, divqr->q.front());
  }

  uint32_t ds = Degree(s2);
  Ciphertext<DCRTPoly> su;

  if(std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
    su = qu;
  } else {
    if (ds > k) {
      su = InnerEvalPolyPS(x, s2, k, m-1, powers, powers2);
    } else {
      // ds = k from construction
      // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
      auto scopy = s2;
      scopy.resize(k);
      if (Degree(scopy) > 0) {

        std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
        std::vector<double> weights(Degree(scopy));

        for (uint32_t i = 0; i < Degree(scopy); i++) {
          ctxs[i] = powers[i];
          weights[i] = s2[i+1];
        }

        su = cc->EvalLinearWSumMutable(ctxs, weights);

        cc->ModReduceInPlace(su);
        // the highest order term will always be 1 because q is monic
        cc->EvalAddMutableInPlace(su,powers[k-1]);
      } else {
        su = powers[k-1];
      }
      // adds the free term (at x^0)
      cc->EvalAddInPlace(su,s2.front());
    }
  }


  Ciphertext<DCRTPoly> result;

  if(flag_c)
    result = cc->EvalAddMutable(powers2[m-1],cu);
  else
    result = cc->EvalAdd(powers2[m-1], divcs->q.front());

  cc->EvalMultMutableInPlace(result, qu);
  cc->ModReduceInPlace(result);
  cc->EvalAddMutableInPlace(result, su);

  return result;

}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPolyPS(
    ConstCiphertext<DCRTPoly> x,
    const std::vector<double> &coefficients) const {
  uint32_t n = Degree(coefficients);

  std::vector<double> f2 = coefficients;

  // Make sure the coefficients do not have the dominant terms zero
  if (coefficients[coefficients.size()-1] == 0)
    f2.resize(n+1);

  std::vector<uint32_t> degs = ComputeDegreesPS(n);
  uint32_t k = degs[0]; uint32_t m = degs[1];

//  std::cerr << "\n Degree: n = " << n << ", k = " << k << ", m = " << m << endl;

  std::vector<Ciphertext<DCRTPoly>> powers(k);
  std::vector<Ciphertext<DCRTPoly>> powers2(m);

  powers.front() = Ciphertext<DCRTPoly>(new CiphertextImpl<DCRTPoly>(*x));

  auto cc = x->GetCryptoContext();

  // set the indices for the powers of x that need to be computed to 1
  std::vector<int32_t> indices(n,0);

  for (size_t i = k; i > 0; i--)
  {
    // if i is a power of 2
    if (!(i & (i-1)))
      indices[i - 1] = 1;
    // non-power of 2
    else
    {
      indices[i-1] = 1;
      int64_t powerOf2 = 1<<(int64_t)std::floor(std::log2(i));
      int64_t rem = i % powerOf2;
      if (indices[rem-1] == 0)
        indices[rem-1] = 1;
      while ((rem & (rem-1))){ // while rem is not a power of 2, set indices required to compute rem to 1
        powerOf2 = 1<<(int64_t)std::floor(std::log2(rem));
        rem = rem % powerOf2;
        if (indices[rem-1] == 0)
          indices[rem-1] = 1;
      }
    }
  }

  // computes all powers up to k for x
  for (size_t i = 2; i <= k; i++) {
    // if i is a power of two
    if (!(i & (i-1)))
    {
      powers[i-1] = cc->EvalMultMutable(powers[i/2-1], powers[i/2-1]);
      cc->ModReduceInPlace(powers[i-1]);
    }
    // non-power of 2
    else
    {
      if (indices[i-1] == 1)
      {
        int64_t powerOf2 = 1<<(int64_t)std::floor(std::log2(i));
        int64_t rem = i % powerOf2;
        int levelDiff = powers[powerOf2-1]->GetElements()[0].GetNumOfElements() -
            powers[rem-1]->GetElements()[0].GetNumOfElements();
        cc->LevelReduceInPlace(powers[rem-1],nullptr, levelDiff);

        powers[i-1] = cc->EvalMultMutable(powers[powerOf2-1],powers[rem-1]);
        cc->ModReduceInPlace(powers[i-1]);
      }
    }
  }

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(powers[k-1]->GetCryptoParameters());

  auto algo = cc->GetScheme();

  // brings all powers to the same level of powers[k-1] (in FLEXIBLEAUTO).
  if (cryptoParams->GetRescalingTechnique() != FIXEDMANUAL) {
    for (uint32_t i = 1; i <= k; i++) {
      if (powers[i-1]->GetDepth() == 2)
        algo->ModReduceInternalInPlace(powers[i-1], BASE_NUM_LEVELS_TO_DROP);
      if (powers[i-1]->GetLevel() < powers[k-1]->GetLevel()) {
        algo->AdjustLevelsAndDepthToOneInPlace(powers[i-1], powers[k-1]);
      }
    }
  }

  // computes powers of form k*2^i for x
  powers2.front() = powers.back();
  for (uint32_t i = 1; i < m; i++) {
    powers2[i] = cc->EvalMultMutable(powers2[i-1],powers2[i-1]);
    cc->ModReduceInPlace(powers2[i]);
  }

  // computes the product of the powers in power2, that yield x^{k(2*m - 1)}
  auto power2km1 = powers2.front();
  for (uint32_t i = 1; i < m; i++) {
    power2km1 = cc->EvalMultMutable(power2km1, powers2[i]);
    cc->ModReduceInPlace(power2km1);
  }

  // Compute k*2^{m-1}-k because we use it a lot
  uint32_t k2m2k = k*(1<<(m-1)) - k;

  //Add x^{k(2^m - 1)} to the polynomial that has to be evaluated
  // std::vector<double> f2 = coefficients;
  f2.resize(2*k2m2k+k+1, 0.0);
  f2.back() = 1;

  // Divide f2 by x^{k*2^{m-1}}
  std::vector<double> xkm(int32_t(k2m2k+k)+1, 0.0);
  xkm.back() = 1;
  longDiv *divqr = LongDivisionPoly(f2, xkm);

  // Subtract x^{k(2^{m-1} - 1)} from r
  std::vector<double> r2 = divqr->r;
  if (int32_t(k2m2k-Degree(divqr->r)) <= 0) {
    r2[int32_t(k2m2k)] -= 1;
    r2.resize(Degree(r2) + 1);
  } else {
    r2.resize(int32_t(k2m2k+1), 0.0);
    r2.back() = -1;
  }

  // Divide r2 by q
  longDiv *divcs = LongDivisionPoly(r2, divqr->q);

  // Add x^{k(2^{m-1} - 1)} to s
  std::vector<double> s2 = divcs->r;
  s2.resize(int32_t(k2m2k+1), 0.0);
  s2.back() = 1;

  // Evaluate c at u
  Ciphertext<DCRTPoly> cu;
  uint32_t dc = Degree(divcs->q);
  bool flag_c = false;

  if (dc >= 1) {
    if (dc == 1) {
      if (divcs->q[1] != 1) {
        cu = cc->EvalMult(powers.front(), divcs->q[1]);
        // Do rescaling after scalar multiplication
        cc->ModReduceInPlace(cu);
      } else {
        cu = powers.front();
      }
    } else {
      std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
      std::vector<double> weights(dc);

      for (uint32_t i = 0; i < dc; i++) {
        ctxs[i] = powers[i];
        weights[i] = divcs->q[i+1];
      }

      cu = cc->EvalLinearWSumMutable(ctxs, weights);
      // Do rescaling after scalar multiplication
      cc->ModReduceInPlace(cu);
    }

    // adds the free term (at x^0)
    cc->EvalAddInPlace(cu, divcs->q.front());
    flag_c = true;
  }


  // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
  Ciphertext<DCRTPoly> qu;

  if(Degree(divqr->q) > k) {
    qu = InnerEvalPolyPS(x, divqr->q, k, m-1, powers, powers2);
  } else {
    // dq = k from construction
    // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
    auto qcopy = divqr->q;
    qcopy.resize(k);
    if (Degree(qcopy) > 0) {

      std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
      std::vector<double> weights(Degree(qcopy));

      for (uint32_t i = 0; i < Degree(qcopy); i++) {
        ctxs[i] = powers[i];
        weights[i] = divqr->q[i+1];
      }

      qu = cc->EvalLinearWSumMutable(ctxs, weights);

      cc->ModReduceInPlace(qu);
      // the highest order term will always be 1 because q is monic
      cc->EvalAddMutableInPlace(qu,powers[k-1]);
    } else {
      qu = powers[k-1];
    }
    // adds the free term (at x^0)
    cc->EvalAddInPlace(qu, divqr->q.front());
  }

  uint32_t ds = Degree(s2);
  Ciphertext<DCRTPoly> su;

  if (std::equal(s2.begin(), s2.end(), divqr->q.begin())) {
    su = qu;
  } else {
    if(ds > k) {
      su = InnerEvalPolyPS(x, s2, k, m-1, powers, powers2);
    } else {
      // ds = k from construction
      // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
      auto scopy = s2;
      scopy.resize(k);
      if (Degree(scopy) > 0) {

        std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
        std::vector<double> weights(Degree(scopy));

        for (uint32_t i = 0; i < Degree(scopy); i++) {
          ctxs[i] = powers[i];
          weights[i] = s2[i+1];
        }

        su = cc->EvalLinearWSumMutable(ctxs, weights);

        cc->ModReduceInPlace(su);
        // the highest order term will always be 1 because q is monic
        cc->EvalAddMutableInPlace(su,powers[k-1]);
      } else {
        su = powers[k-1];
      }
      // adds the free term (at x^0)
      cc->EvalAddInPlace(su, s2.front());
    }
  }


  Ciphertext<DCRTPoly> result;

  if(flag_c) {
    result = cc->EvalAddMutable(powers2[m-1], cu);
  } else {
    result = cc->EvalAdd(powers2[m-1], divcs->q.front());
  }

  cc->EvalMultMutableInPlace(result, qu);
  cc->ModReduceInPlace(result);
  cc->EvalAddMutableInPlace(result, su);
  cc->EvalSubMutableInPlace(result, power2km1);

  return result;

}

//------------------------------------------------------------------------------
// EVAL CHEBYSHEV SERIES
//------------------------------------------------------------------------------

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeries(
    ConstCiphertext<DCRTPoly> x,
    const std::vector<double> &coefficients,
    double a, double b) const {
  uint32_t n = Degree(coefficients);

  if (n < 5) {
    return EvalChebyshevSeriesLinear(x, coefficients, a, b);
  }

  return EvalChebyshevSeriesPS(x, coefficients, a, b);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeriesLinear(
    ConstCiphertext<DCRTPoly> x,
    const std::vector<double> &coefficients,
    double a, double b) const {

  std::vector<Ciphertext<DCRTPoly>> T(coefficients.size()-1);

  // computes linear transformation y = -1 + 2 (x-a)/(b-a)
  // consumes one level when a <> -1 && b <> 1

  auto cc = x->GetCryptoContext();

  if ( (a - std::round(a) < 1e-10)
      && (b - std::round(b) < 1e-10)
      && (std::round(a) == -1) && (std::round(b) == 1) ) {
    // no linear transformation is needed if a = -1, b = 1
    T[0] = Ciphertext<DCRTPoly>(new CiphertextImpl<DCRTPoly>(*x)); //T_1(y) = y
  } else {
    // linear transformation is needed

    double alpha = 2/(b-a);
    double beta = 2*a/(b-a);

    Ciphertext<DCRTPoly> tmp1 = x->Clone();
    auto y = cc->EvalMult(tmp1, alpha);
    cc->ModReduceInPlace(y);
    cc->EvalSubInPlace(y, 1.0+beta);

    T[0] = Ciphertext<DCRTPoly>(new CiphertextImpl<DCRTPoly>(*y)); //T_1(y) = y

  }

  Ciphertext<DCRTPoly> yReduced(new CiphertextImpl<DCRTPoly>(*T[0]));

  // computes all Chebyshev functions for y
  // uses binary tree multiplication
  for (size_t i = 2; i < coefficients.size(); i++) {
    // if i is a power of two
    if (!(i & (i-1))) {

      // compute T_2i(y) = 2*T_i(y)^2 - 1
      auto square = cc->EvalMultMutable(T[i/2-1],T[i/2-1]);
      if (i==2) {
        cc->LevelReduceInPlace(T[i/2-1],nullptr);
        cc->LevelReduceInPlace(yReduced,nullptr);
      }
      cc->LevelReduceInPlace(yReduced,nullptr); //depth log_2 i + 1
      auto temp = cc->EvalAddMutable(square,square);
      cc->ModReduceInPlace(temp);
      T[i-1] = cc->EvalSub(temp,1.0);

      // i/2 will now be used only at a lower level
      if (i/2 > 1) {
        cc->LevelReduceInPlace(T[i/2-1],nullptr);
      }
    } else {
      // non-power of 2
      if ( i % 2 == 1) {
        // if i is odd
        // compute T_2i+1(y) = 2*T_i(y)*T_i+1(y) - y
        auto temp = cc->EvalMultMutable(T[i/2-1],T[i/2]);
        cc->EvalAddMutableInPlace(temp,temp);
        cc->ModReduceInPlace(temp);
        T[i-1] = cc->EvalSubMutable(temp,yReduced);
      } else {
        // i is even but not power of 2
        // compute T_2i(y) = 2*T_i(y)^2 - 1
        auto square = cc->EvalMultMutable(T[i/2-1],T[i/2-1]);
        auto temp = cc->EvalAddMutable(square,square);
        cc->ModReduceInPlace(temp);
        T[i-1] = cc->EvalSub(temp,1.0);
      }
    }
  }

  //gets the highest depth (lowest number of CRT limbs)
  int64_t limbs = T[coefficients.size()-2]->GetElements()[0].GetNumOfElements();

  // brings all powers of y to the same level
  for (size_t i = 1; i < coefficients.size()-1; i++) {
    int levelDiff = limbs -
        T[i-1]->GetElements()[0].GetNumOfElements();
    cc->LevelReduceInPlace(T[i-1],nullptr, levelDiff);
  }

  // perform scalar multiplication for the highest-order term
  auto result = cc->EvalMult(T[coefficients.size()-2],coefficients[coefficients.size()-1]);

  // perform scalar multiplication for all other terms and sum them up
  for (size_t i = 0; i < coefficients.size()-2; i++) {
    if (coefficients[i+1] != 0) {
      Ciphertext<DCRTPoly> tmp2 = cc->EvalMult(T[i],coefficients[i+1]);
      cc->EvalAddMutableInPlace(result, tmp2);
    }
  }

  // Do rescaling after scalar multiplication
  cc->ModReduceInPlace(result);

  // adds the free term (at x^0)
  cc->EvalAddInPlace(result,coefficients[0]/2);

  return result;

}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::InnerEvalChebyshevPS(
    ConstCiphertext<DCRTPoly> x,
    const std::vector<double> &coefficients,
    uint32_t k, uint32_t m,
    std::vector<Ciphertext<DCRTPoly>> &T,
    std::vector<Ciphertext<DCRTPoly>> &T2) const {

  auto cc = x->GetCryptoContext();

  // Compute k*2^{m-1}-k because we use it a lot
  uint32_t k2m2k = k*(1<<(m-1)) - k;

  // number of levels of T2[m-1]
  uint32_t Lm = T2[m-1]->GetElements()[0].GetNumOfElements();

  // Divide coefficients by T^{k*2^{m-1}}
  std::vector<double> Tkm(int32_t(k2m2k+k)+1, 0.0);
  Tkm.back() = 1;
  longDiv *divqr = LongDivisionChebyshev(coefficients, Tkm);

  // Subtract x^{k(2^{m-1} - 1)} from r
  std::vector<double> r2 = divqr->r;
  if(int32_t(k2m2k-Degree(divqr->r)) <= 0){
    r2[int32_t(k2m2k)] -= 1;
    r2.resize(Degree(r2) + 1);
  }
  else{
    r2.resize(int32_t(k2m2k+1), 0.0);
    r2.back() = -1;
  }

  // Divide r2 by q
  longDiv *divcs = LongDivisionChebyshev(r2, divqr->q);

  // Add x^{k(2^{m-1} - 1)} to s
  std::vector<double> s2 = divcs->r;
  s2.resize(int32_t(k2m2k+1), 0.0);
  s2.back() = 1;


  // Evaluate c at u
  Ciphertext<DCRTPoly> cu;
  uint32_t dc = Degree(divcs->q);
  bool flag_c = false;
  if (dc >= 1) {
    if (dc == 1) {
      if (divcs->q[1] != 1) {
        cu = cc->EvalMult(T.front(), divcs->q[1]);
        // Do rescaling after scalar multiplication
        cc->ModReduceInPlace(cu);
      } else {
        cu = T.front();
      }
    } else {
      std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
      std::vector<double> weights(dc);

      for (uint32_t i = 0; i < dc; i++) {
        ctxs[i] = T[i];
        weights[i] = divcs->q[i+1];
      }

      cu = cc->EvalLinearWSumMutable(ctxs, weights);

      // Do rescaling after scalar multiplication
      cc->ModReduceInPlace(cu);
    }

    // adds the free term (at x^0)
    cc->EvalAddInPlace(cu,divcs->q.front()/2);

    // Need to reduce levels up to the level of T2[m-1].
    uint32_t limbs = cu->GetElements()[0].GetNumOfElements();
    cc->LevelReduceInPlace(cu, nullptr, limbs - Lm);

    flag_c = true;
  }


  // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
  Ciphertext<DCRTPoly> qu;

  if(Degree(divqr->q) > k){
    qu = InnerEvalChebyshevPS(x, divqr->q, k, m-1, T, T2);
  }
  else{// dq = k from construction
    // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
    auto qcopy = divqr->q;
    qcopy.resize(k);
    if (Degree(qcopy) > 0){

      std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
      std::vector<double> weights(Degree(qcopy));

      for (uint32_t i = 0; i < Degree(qcopy); i++) {
        ctxs[i] = T[i];
        weights[i] = divqr->q[i+1];
      }

      qu = cc->EvalLinearWSumMutable(ctxs, weights);

      cc->ModReduceInPlace(qu);

      // the highest order coefficient will always be a power of two up to 2^{m-1} because q is "monic" but the Chebyshev rule adds a factor of 2
      // we don't need to increase the depth by multiplying the highest order coefficient, but instead checking and summing, since we work with m <= 4.
      Ciphertext<DCRTPoly> sum = T[k-1];
      for (uint32_t i = 0; i < log2(divqr->q.back()); i ++){
        cc->EvalAddMutableInPlace(sum,sum);
      }
      cc->EvalAddMutableInPlace(qu, sum);

    }
    else {
      Ciphertext<DCRTPoly> sum = T[k-1];
      for (uint32_t i = 0; i < log2(divqr->q.back()); i ++){
        cc->EvalAddMutableInPlace(sum,sum);
      }
      qu = sum;
    }

    // adds the free term (at x^0)
    cc->EvalAddInPlace(qu,divqr->q.front()/2);
    // The number of levels of qu is the same as the number of levels of T[k-1] or T[k-1] + 1.
    // No need to reduce it to T2[m-1] because it only reaches here when m = 2.
  }

  Ciphertext<DCRTPoly> su;

  if (Degree(s2) > k) {
    su = InnerEvalChebyshevPS(x, s2, k, m-1, T, T2);
  } else {
    // ds = k from construction
    // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
    auto scopy = s2;
    scopy.resize(k);
    if (Degree(scopy) > 0) {
      std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
      std::vector<double> weights(Degree(scopy));

      for (uint32_t i = 0; i < Degree(scopy); i++) {
        ctxs[i] = T[i];
        weights[i] = s2[i+1];
      }

      su = cc->EvalLinearWSumMutable(ctxs, weights);

      cc->ModReduceInPlace(su);
      // the highest order coefficient will always be 1 because s2 is monic.
      cc->EvalAddMutableInPlace(su,T[k-1]);

    } else {
      su = T[k-1];
    }

    // adds the free term (at x^0)
    cc->EvalAddInPlace(su,s2.front()/2);

    // The number of levels of su is the same as the number of levels of T[k-1] or T[k-1] + 1. Need to reduce it to T2[m-1] + 1.
    // su = cc->LevelReduce(su, nullptr, su->GetElements()[0].GetNumOfElements() - Lm + 1) ;
    cc->LevelReduceInPlace(su, nullptr);
  }

  Ciphertext<DCRTPoly> result;

  if(flag_c)
    result = cc->EvalAddMutable(T2[m-1],cu);
  else
    result = cc->EvalAdd(T2[m-1],divcs->q.front()/2);

  cc->EvalMultMutableInPlace(result,qu);
  cc->ModReduceInPlace(result);
  cc->EvalAddMutableInPlace(result,su);

  return result;

}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalChebyshevSeriesPS(
    ConstCiphertext<DCRTPoly> x,
    const std::vector<double> &coefficients,
    double a, double b) const {
  uint32_t n = Degree(coefficients);

  std::vector<double> f2 = coefficients;

  // Make sure the coefficients do not have the zero dominant terms
  if (coefficients[coefficients.size()-1] == 0)
    f2.resize(n+1);

  std::vector<uint32_t> degs = ComputeDegreesPS(n);
  uint32_t k = degs[0]; uint32_t m = degs[1];

//  std::cerr << "\n Degree: n = " << n << ", k = " << k << ", m = " << m << endl;

  std::vector<Ciphertext<DCRTPoly>> T(k);
  std::vector<Ciphertext<DCRTPoly>> T2(m);

  // computes linear transformation y = -1 + 2 (x-a)/(b-a)
  // consumes one level when a <> -1 && b <> 1

  auto cc = x->GetCryptoContext();

  if ( (a - std::round(a) < 1e-10) && (b - std::round(b) < 1e-10) && (std::round(a) == -1) && (std::round(b) == 1) )
  { // no linear transformation is needed if a = -1, b = 1
    T[0] = Ciphertext<DCRTPoly>(new CiphertextImpl<DCRTPoly>(*x)); //T_1(y) = y
  }
  else
  { // linear transformation is needed

    double alpha = 2/(b-a);
    double beta = 2*a/(b-a);

    Ciphertext<DCRTPoly> xTmp = x->Clone();
    auto y = cc->EvalMult(xTmp,alpha);
    cc->ModReduceInPlace(y);
    cc->EvalSubInPlace(y,1.0+beta);

    T[0] = Ciphertext<DCRTPoly>(new CiphertextImpl<DCRTPoly>(*y)); //T_1(y) = y

  }

  Ciphertext<DCRTPoly> yReduced(new CiphertextImpl<DCRTPoly>(*T[0]));

  uint32_t L = yReduced->GetElements()[0].GetNumOfElements();

  // Computes Chebyshev polynomials up to degree k for y: T_1(y) = y, T_2(y), ... , T_k(y)
  // uses binary tree multiplication
  for (uint32_t i = 2; i <= k; i++) {
    // if i is a power of two
    if (!(i & (i-1))) {
      // compute T_{2i}(y) = 2*T_i(y)^2 - 1
      auto square = cc->EvalMultMutable(T[i/2-1],T[i/2-1]);
      auto temp = cc->EvalAddMutable(square,square);
      cc->ModReduceInPlace(temp);
      T[i-1] = cc->EvalSub(temp,1.0);
    } else {
      // non-power of 2
      if ( i % 2 == 1) {
        // if i is odd
        // compute T_{2i+1}(y) = 2*T_i(y)*T_i+1(y) - y
        auto temp = cc->EvalMultMutable(T[i/2-1],T[i/2]);
        temp = cc->EvalAddMutable(temp,temp);
        cc->ModReduceInPlace(temp);
        T[i-1] = cc->EvalSubMutable(temp,yReduced);
      } else {
        // i is even but not power of 2
        // compute T_{2i}(y) = 2*T_i(y)^2 - 1
        auto square = cc->EvalMultMutable(T[i/2-1],T[i/2-1]);
        auto temp = cc->EvalAddMutable(square,square);
        cc->ModReduceInPlace(temp);
        T[i-1] = cc->EvalSub(temp,1.0);
      }
    }
  }

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          T[k-1]->GetCryptoParameters());

  auto algo = cc->GetScheme();

  // brings all Chebyshev polynomials to the same level of T[k-1].
  for (uint32_t i = 1; i <= k; i++) {
    cc->LevelReduceInPlace(T[i-1],nullptr,ceil(log2(k)) - ceil(log2(i)));

    if (cryptoParams->GetRescalingTechnique() != FIXEDMANUAL) {
      if (T[i-1]->GetDepth() == 2)
        algo->ModReduceInternalInPlace(T[i-1], BASE_NUM_LEVELS_TO_DROP);
      if (T[i-1]->GetLevel() < T[k-1]->GetLevel()) {
        algo->AdjustLevelsAndDepthToOneInPlace(T[i-1], T[k-1]);
      }
    }
  }

  // Compute the Chebyshev polynomials T_{2k}(y), T_{4k}(y), ... , T_{2^{m-1}k}(y)
  T2.front() = T.back();
  for (uint32_t i = 1; i < m; i++) {
    auto square = cc->EvalMultMutable(T2[i-1],T2[i-1]);
    auto temp = cc->EvalAddMutable(square,square);
    cc->ModReduceInPlace(temp);
    T2[i] = cc->EvalSub(temp,1.0);
  }

  // computes T_{k(2*m - 1)}(y)
  auto T2km1 = T2.front();
  for (uint32_t i = 1; i < m; i++) {
    // compute T_{k(2*m - 1)} = 2*T_{k(2^{m-1}-1)}(y)*T_{k*2^{m-1}}(y) - T_k(y)
    auto temp = cc->EvalMultMutable(T2km1,T2[i]);
    cc->EvalAddMutableInPlace(temp,temp);
    cc->ModReduceInPlace(temp);
    T2km1 = cc->EvalSubMutable(temp,T2.front());
  }

  // We also need to reduce the number of levels of T[k-1] and of T2[0] by another level.
  cc->LevelReduceInPlace(T[k-1],nullptr);
  cc->LevelReduceInPlace(T2.front(),nullptr);

  // Compute k*2^{m-1}-k because we use it a lot
  uint32_t k2m2k = k*(1<<(m-1)) - k;

  //Add T^{k(2^m - 1)}(y) to the polynomial that has to be evaluated
  f2.resize(2*k2m2k+k+1, 0.0);
  f2.back() = 1;

  // Divide f2 by T^{k*2^{m-1}}
  std::vector<double> Tkm(int32_t(k2m2k+k)+1, 0.0);
  Tkm.back() = 1;
  longDiv *divqr = LongDivisionChebyshev(f2, Tkm);

  // Subtract x^{k(2^{m-1} - 1)} from r
  std::vector<double> r2 = divqr->r;
  if (int32_t(k2m2k-Degree(divqr->r)) <= 0) {
    r2[int32_t(k2m2k)] -= 1;
    r2.resize(Degree(r2) + 1);
  } else {
    r2.resize(int32_t(k2m2k+1), 0.0);
    r2.back() = -1;
  }

  // Divide r2 by q
  longDiv *divcs = LongDivisionChebyshev(r2, divqr->q);

  // Add x^{k(2^{m-1} - 1)} to s
  std::vector<double> s2 = divcs->r;
  s2.resize(int32_t(k2m2k+1), 0.0);
  s2.back() = 1;

  // Evaluate c at u
  Ciphertext<DCRTPoly> cu;
  uint32_t dc = Degree(divcs->q);
  bool flag_c = false;
  if (dc >= 1) {
    if (dc == 1) {
      if (divcs->q[1] != 1) {
        cu = cc->EvalMult(T.front(), divcs->q[1]);
        // Do rescaling after scalar multiplication
        cc->ModReduceInPlace(cu);
      } else {
        cu = T.front();
      }
    } else {
      std::vector<Ciphertext<DCRTPoly>> ctxs(dc);
      std::vector<double> weights(dc);

      for (uint32_t i = 0; i < dc; i++) {
        ctxs[i] = T[i];
        weights[i] = divcs->q[i+1];
      }

      cu = cc->EvalLinearWSumMutable(ctxs, weights);
      // Do rescaling after scalar multiplication
      cc->ModReduceInPlace(cu);
    }

    // adds the free term (at x^0)
    cc->EvalAddInPlace(cu,divcs->q.front()/2);
    // Need to reduce levels to the level of T2[m-1].
    cc->LevelReduceInPlace(cu, nullptr, cu->GetElements()[0].GetNumOfElements() - (L - ceil(log2(k)) - m) - 1) ;

    flag_c = true;
  }

  // Evaluate q and s2 at u. If their degrees are larger than k, then recursively apply the Paterson-Stockmeyer algorithm.
  Ciphertext<DCRTPoly> qu;

  if(Degree(divqr->q) > k){
    qu = InnerEvalChebyshevPS(x, divqr->q, k, m-1, T, T2);
  }
  else{// dq = k from construction
    // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
    auto qcopy = divqr->q;
    qcopy.resize(k);
    if (Degree(qcopy) > 0){

      std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(qcopy));
      std::vector<double> weights(Degree(qcopy));

      for (uint32_t i = 0; i < Degree(qcopy); i++) {
        ctxs[i] = T[i];
        weights[i] = divqr->q[i+1];
      }

      qu = cc->EvalLinearWSumMutable(ctxs, weights);

      cc->ModReduceInPlace(qu);
      // the highest order coefficient will always be 2 after one division because of the Chebyshev division rule
      Ciphertext<DCRTPoly> sum = cc->EvalAddMutable(T[k-1],T[k-1]);
      cc->EvalAddMutableInPlace(qu,sum);

    } else {
      qu = T[k-1];

      for (uint32_t i = 1; i < divqr->q.back(); i ++) {
        cc->EvalAddMutableInPlace(qu,T[k-1]);
      }
    }

    // adds the free term (at x^0)
    cc->EvalAddInPlace(qu,divqr->q.front()/2);
    // The number of levels of qu is the same as the number of levels of T[k-1] + 1.
    // Will only get here when m = 2, so the number of levels of qu and T2[m-1] will be the same.
  }

  Ciphertext<DCRTPoly> su;

  if(Degree(s2) > k){
    su = InnerEvalChebyshevPS(x, s2, k, m-1, T, T2);
  }
  else{// ds = k from construction
    // perform scalar multiplication for all other terms and sum them up if there are non-zero coefficients
    auto scopy = s2;
    scopy.resize(k);
    if (Degree(scopy) > 0){

      std::vector<Ciphertext<DCRTPoly>> ctxs(Degree(scopy));
      std::vector<double> weights(Degree(scopy));

      for (uint32_t i = 0; i < Degree(scopy); i++) {
        ctxs[i] = T[i];
        weights[i] = s2[i+1];
      }

      su = cc->EvalLinearWSumMutable(ctxs, weights);

      cc->ModReduceInPlace(su);
      // the highest order coefficient will always be 1 because s2 is monic.
      cc->EvalAddMutableInPlace(su,T[k-1]);
    } else {
      su = T[k-1];
    }

    // adds the free term (at x^0)
    cc->EvalAddInPlace(su,s2.front()/2);
    // The number of levels of su is the same as the number of levels of T[k-1] + 1.
    // Will only get here when m = 2, so need to reduce the number of levels by 1.
  }

  //Reduce number of levels of su to number of levels of T2km1.
  cc->LevelReduceInPlace(su, nullptr) ;

  Ciphertext<DCRTPoly> result;
  if(flag_c)
    result = cc->EvalAddMutable(T2[m-1], cu);
  else
    result = cc->EvalAdd(T2[m-1], divcs->q.front()/2);

  cc->EvalMultMutableInPlace(result, qu);
  cc->ModReduceInPlace(result);
  cc->EvalAddMutableInPlace(result, su);
  cc->EvalSubMutable(result, T2km1);

  return result;

}

//------------------------------------------------------------------------------
// EVAL LINEAR TRANSFORMATION
//------------------------------------------------------------------------------

std::shared_ptr<std::map<usint, EvalKey<DCRTPoly>>> AdvancedSHECKKSRNS::EvalLTKeyGen(
    const PrivateKey<DCRTPoly> privateKey, uint32_t dim1,
    int32_t bootstrapFlag, int32_t conjFlag ) {

  auto cc = privateKey->GetCryptoContext();

  uint32_t m = cc->GetCyclotomicOrder();

  // computing all indices for baby-step giant-step procedure
  std::vector<int32_t> indexList = this->FindLTRotationIndices(dim1, bootstrapFlag, m, cc->GetBlockDimension());

  auto algo = cc->GetScheme();
  auto evalKeys = algo->EvalAtIndexKeyGen(nullptr, privateKey, indexListEvalLT);

  // Add conjugation key
  if (bootstrapFlag == 1 || conjFlag == 1){
    auto conjKey = ConjugateKeyGen(privateKey);
    (*evalKeys)[m - 1] = conjKey;
  }

  return evalKeys;
}

std::vector<int32_t> AdvancedSHECKKSRNS::FindLTRotationIndices(
    uint32_t dim1 = 0, int32_t bootstrapFlag = 0,
    uint32_t m = 0, uint32_t blockDimension = 0) {

  // m_slots and m_dim1 are not available when we call solely EvalLT
  uint32_t slots;

  if ((bootstrapFlag == 1) && (blockDimension > 0)) {
      PALISADE_THROW(not_implemented_error, "bootstrapping with linear encoding/decoding "
   " + matrix arithmetic are not currently supported.");
  }

  if (bootstrapFlag == 0) {
    if (blockDimension > 0)
      m_slots = blockDimension;
  }

if ((m_slots == 0) || (m_slots == m/4)) // fully-packed mode
slots = m/4;
else //sparse mode
slots = m_slots;

  // Computing the baby-step g and the giant-step h.
  int g = (dim1 == 0) ? ceil(sqrt(slots)) : dim1;
  int h =  ceil((double)slots/g);

  // computing all indices for baby-step giant-step procedure
  // ATTN: resize() is used as indexListEvalLT may be empty here
  indexListEvalLT.reserve(g + h - 2);
  for(int i = 0; i < g; i++)
      indexListEvalLT.emplace_back(i + 1);
  for(int i = 2; i < h; i++)
      indexListEvalLT.emplace_back(g*i);

  // additional automorphisms are needed for sparse bootstrapping
  if (bootstrapFlag == 1)
  {
      indexListEvalLT.emplace_back(slots);

      for(int j = 0; j < int(std::log2(m/(4*slots))); j++){
          indexListEvalLT.emplace_back((1<<j)*slots);
      }

      // remove any duplicate indices to avoid the generation of extra automorphism keys
      sort(indexListEvalLT.begin(), indexListEvalLT.end() );
      indexListEvalLT.erase( std::unique(indexListEvalLT.begin(), indexListEvalLT.end() ), indexListEvalLT.end() );
  }

  return indexListEvalLT;
}

}

