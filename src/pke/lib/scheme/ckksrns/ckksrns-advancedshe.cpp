// @file pke-rns.cpp - CKKS scheme implementation.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, Duality Technologies Inc.
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

namespace lbcrypto {

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalLinearWSum(
    vector<ConstCiphertext<DCRTPoly>>& ciphertexts, const vector<double> &constants) const {
  vector<Ciphertext<DCRTPoly>> cts(ciphertexts.size());

  for (uint32_t i = 0; i < ciphertexts.size(); i++) {
    cts[i] = ciphertexts[i]->Clone();
  }

  return EvalLinearWSumMutable(cts, constants);
}

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalLinearWSumMutable(
    vector<Ciphertext<DCRTPoly>>& ciphertexts, const vector<double> &constants) const {
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
        algo->ModReduceInternalInPlace(ciphertexts[i]);
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

Ciphertext<DCRTPoly> AdvancedSHECKKSRNS::EvalPoly(
    ConstCiphertext<DCRTPoly> x,
    const std::vector<double> &coefficients) const {
  if (coefficients[coefficients.size() - 1] == 0)
    PALISADE_THROW(
        math_error,
        "EvalPoly: The highest-order coefficient cannot be set to 0.");

  std::vector<Ciphertext<DCRTPoly>> powers(coefficients.size() - 1);
  std::vector<int32_t> indices(coefficients.size() - 1, 0);

  // set the indices for the powers of x that need to be computed to 1
  for (size_t i = coefficients.size() - 1; i > 0; i--) {
    if (IsPowerOfTwo(i)) {
      indices[i - 1] = 1;
    } else {  // non-power of 2
      if (coefficients[i] != 0) {
        indices[i - 1] = 1;
        int64_t powerOf2 = 1 << (int64_t)std::floor(std::log2(i));
        int64_t rem = i % powerOf2;
        if (indices[rem - 1] == 0) indices[rem - 1] = 1;
        // while rem is not a power of 2, set indices required to compute rem to
        // 1
        while (!IsPowerOfTwo(rem)) {
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
    if (IsPowerOfTwo(i)) {
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
  if (coefficients[0] != 0) {
    cc->EvalAddInPlace(result, coefficients[0]);
  }

  return result;
}

}

