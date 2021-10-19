// @file fhew.cpp - FHEW scheme (RingGSW accumulator) implementation
// The scheme is described in https://eprint.iacr.org/2014/816 and in
// Daniele Micciancio and Yuriy Polyakov, "Bootstrapping in FHEW-like
// Cryptosystems", Cryptology ePrint Archive, Report 2020/086,
// https://eprint.iacr.org/2020/086.
//
// Full reference to https://eprint.iacr.org/2014/816:
// @misc{cryptoeprint:2014:816,
//   author = {Leo Ducas and Daniele Micciancio},
//   title = {FHEW: Bootstrapping Homomorphic Encryption in less than a second},
//   howpublished = {Cryptology ePrint Archive, Report 2014/816},
//   year = {2014},
//   note = {\url{https://eprint.iacr.org/2014/816}},
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

#include "fhew.h"

namespace lbcrypto {

// Encryption as described in Section 5 of https://eprint.iacr.org/2014/816
// skNTT corresponds to the secret key z
std::shared_ptr<RingGSWCiphertext> RingGSWAccumulatorScheme::EncryptAP(
    const std::shared_ptr<RingGSWCryptoParams> params, const NativePoly &skNTT,
    const LWEPlaintext &m) const {
  NativeInteger Q = params->GetLWEParams()->GetQ();
  int64_t q = params->GetLWEParams()->Getq().ConvertToInt();
  uint32_t N = params->GetLWEParams()->GetN();
  uint32_t digitsG = params->GetDigitsG();
  uint32_t digitsG2 = params->GetDigitsG2();
  const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

  auto result = std::make_shared<RingGSWCiphertext>(digitsG2, 2);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(Q);

  // Reduce mod q (dealing with negative number as well)
  int64_t mm = (((m % q) + q) % q) * (2 * N / q);
  int64_t sign = 1;
  if (mm >= N) {
    mm -= N;
    sign = -1;
  }

  // tempA is introduced to minimize the number of NTTs
  std::vector<NativePoly> tempA(digitsG2);

  for (uint32_t i = 0; i < digitsG2; ++i) {
    // populate result[i][0] with uniform random a
    (*result)[i][0] = NativePoly(dug, polyParams, Format::COEFFICIENT);
    tempA[i] = (*result)[i][0];
    // populate result[i][1] with error e
    (*result)[i][1] = NativePoly(params->GetLWEParams()->GetDgg(), polyParams,
                                 Format::COEFFICIENT);
  }

  for (uint32_t i = 0; i < digitsG; ++i) {
    if (sign > 0) {
      // Add G Multiple
      (*result)[2 * i][0][mm].ModAddEq(params->GetGPower()[i], Q);
      // [a,as+e] + X^m*G
      (*result)[2 * i + 1][1][mm].ModAddEq(params->GetGPower()[i], Q);
    } else {
      // Subtract G Multiple
      (*result)[2 * i][0][mm].ModSubEq(params->GetGPower()[i], Q);
      // [a,as+e] - X^m*G
      (*result)[2 * i + 1][1][mm].ModSubEq(params->GetGPower()[i], Q);
    }
  }

  // 3*digitsG2 NTTs are called
  result->SetFormat(Format::EVALUATION);
  for (uint32_t i = 0; i < digitsG2; ++i) {
    tempA[i].SetFormat(Format::EVALUATION);
    (*result)[i][1] += tempA[i] * skNTT;
  }

  return result;
}

// Encryption for the GINX variant, as described in "Bootstrapping in FHEW-like
// Cryptosystems"
std::shared_ptr<RingGSWCiphertext> RingGSWAccumulatorScheme::EncryptGINX(
    const std::shared_ptr<RingGSWCryptoParams> params, const NativePoly &skNTT,
    const LWEPlaintext &m) const {
  NativeInteger Q = params->GetLWEParams()->GetQ();
  uint32_t digitsG = params->GetDigitsG();
  uint32_t digitsG2 = params->GetDigitsG2();
  const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

  auto result = std::make_shared<RingGSWCiphertext>(digitsG2, 2);

  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(Q);

  // tempA is introduced to minimize the number of NTTs
  std::vector<NativePoly> tempA(digitsG2);

  for (uint32_t i = 0; i < digitsG2; ++i) {
    (*result)[i][0] = NativePoly(dug, polyParams, Format::COEFFICIENT);
    tempA[i] = (*result)[i][0];
    (*result)[i][1] = NativePoly(params->GetLWEParams()->GetDgg(), polyParams,
                                 Format::COEFFICIENT);
  }

  for (uint32_t i = 0; i < digitsG; ++i) {
    if (m > 0) {
      // Add G Multiple
      (*result)[2 * i][0][0].ModAddEq(params->GetGPower()[i], Q);
      // [a,as+e] + G
      (*result)[2 * i + 1][1][0].ModAddEq(params->GetGPower()[i], Q);
    }
  }

  // 3*digitsG2 NTTs are called
  result->SetFormat(Format::EVALUATION);
  for (uint32_t i = 0; i < digitsG2; ++i) {
    tempA[i].SetFormat(Format::EVALUATION);
    (*result)[i][1] += tempA[i] * skNTT;
  }

  return result;
}

// wrapper for KeyGen methods
RingGSWEvalKey RingGSWAccumulatorScheme::KeyGen(
    const std::shared_ptr<RingGSWCryptoParams> params,
    const std::shared_ptr<LWEEncryptionScheme> lwescheme,
    const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const {
  if (params->GetMethod() == AP)
    return KeyGenAP(params, lwescheme, LWEsk);
  else  // GINX
    return KeyGenGINX(params, lwescheme, LWEsk);
}

// Key generation as described in Section 4 of https://eprint.iacr.org/2014/816
RingGSWEvalKey RingGSWAccumulatorScheme::KeyGenAP(
    const std::shared_ptr<RingGSWCryptoParams> params,
    const std::shared_ptr<LWEEncryptionScheme> lwescheme,
    const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const {
  const auto &LWEParams = params->GetLWEParams();

  const std::shared_ptr<const LWEPrivateKeyImpl> skN =
      lwescheme->KeyGenN(LWEParams);

  RingGSWEvalKey ek;
  ek.KSkey = lwescheme->KeySwitchGen(LWEParams, LWEsk, skN);

  NativePoly skNPoly = NativePoly(params->GetPolyParams());
  skNPoly.SetValues(skN->GetElement(), Format::COEFFICIENT);
  skNPoly.SetFormat(Format::EVALUATION);

  NativeInteger q = LWEParams->Getq();
  NativeInteger qHalf = q >> 1;
  int32_t qInt = q.ConvertToInt();
  uint32_t n = LWEParams->Getn();
  uint32_t baseR = params->GetBaseR();
  std::vector<NativeInteger> digitsR = params->GetDigitsR();

  ek.BSkey = std::make_shared<RingGSWBTKey>(n, baseR, digitsR.size());

#pragma omp parallel for
  for (uint32_t i = 0; i < n; ++i)
    for (uint32_t j = 1; j < baseR; ++j)
      for (uint32_t k = 0; k < digitsR.size(); ++k) {
        int32_t signedSK;
        if (LWEsk->GetElement()[i] < qHalf)
          signedSK = LWEsk->GetElement()[i].ConvertToInt();
        else
          signedSK = (int32_t)LWEsk->GetElement()[i].ConvertToInt() - qInt;
        if (LWEsk->GetElement()[i] >= qHalf) signedSK -= qInt;
        (*ek.BSkey)[i][j][k] = *(EncryptAP(
            params, skNPoly,
            signedSK * (int32_t)j * (int32_t)digitsR[k].ConvertToInt()));
      }

  return ek;
}

// Bootstrapping keys generation for the GINX variant, as described in
// "Bootstrapping in FHEW-like Cryptosystems"
RingGSWEvalKey RingGSWAccumulatorScheme::KeyGenGINX(
    const std::shared_ptr<RingGSWCryptoParams> params,
    const std::shared_ptr<LWEEncryptionScheme> lwescheme,
    const std::shared_ptr<const LWEPrivateKeyImpl> LWEsk) const {
  RingGSWEvalKey ek;
  const std::shared_ptr<const LWEPrivateKeyImpl> skN =
      lwescheme->KeyGenN(params->GetLWEParams());

  ek.KSkey = lwescheme->KeySwitchGen(params->GetLWEParams(), LWEsk, skN);

  NativePoly skNPoly = NativePoly(params->GetPolyParams());
  skNPoly.SetValues(skN->GetElement(), Format::COEFFICIENT);
  skNPoly.SetFormat(Format::EVALUATION);

  uint64_t q = params->GetLWEParams()->Getq().ConvertToInt();
  uint32_t n = params->GetLWEParams()->Getn();

  ek.BSkey = std::make_shared<RingGSWBTKey>(1, 2, n);

  int64_t qHalf = (q >> 1);

  // handles ternary secrets using signed mod 3 arithmetic; 0 -> {0,0}, 1 ->
  // {1,0}, -1 -> {0,1}
#pragma omp parallel for
  for (uint32_t i = 0; i < n; ++i) {
    int64_t s = LWEsk->GetElement()[i].ConvertToInt();
    if (s > qHalf) s -= q;
    switch (s) {
      case 0:
        (*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 0));
        (*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 0));
        break;
      case 1:
        (*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 1));
        (*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 0));
        break;
      case -1:
        (*ek.BSkey)[0][0][i] = *(EncryptGINX(params, skNPoly, 0));
        (*ek.BSkey)[0][1][i] = *(EncryptGINX(params, skNPoly, 1));
        break;
      default:
        std::string errMsg =
            "ERROR: only ternary secret key distributions are supported.";
        PALISADE_THROW(not_implemented_error, errMsg);
    }
  }

  return ek;
}

// SignedDigitDecompose is a bottleneck operation
// There are two approaches to do it.
// The current approach appears to give the best performance
// results. The two variants are labeled A and B.
void RingGSWAccumulatorScheme::SignedDigitDecompose(
    const std::shared_ptr<RingGSWCryptoParams> params,
    const std::vector<NativePoly> &input,
    std::vector<NativePoly> *output) const {
  uint32_t N = params->GetLWEParams()->GetN();
  uint32_t digitsG = params->GetDigitsG();
  NativeInteger Q = params->GetLWEParams()->GetQ();
  NativeInteger QHalf = Q >> 1;
  NativeInteger::SignedNativeInt Q_int = Q.ConvertToInt();

  NativeInteger::SignedNativeInt baseG =
      NativeInteger(params->GetBaseG()).ConvertToInt();

  NativeInteger::SignedNativeInt d = 0;

  NativeInteger::SignedNativeInt gBits =
      (NativeInteger::SignedNativeInt)std::log2(baseG);

  // VARIANT A
  NativeInteger::SignedNativeInt gBitsMaxBits =
      NativeInteger::MaxBits() - gBits;

  // VARIANT B
  // NativeInteger::SignedNativeInt gminus1 = (1 << gBits) - 1;
  // NativeInteger::SignedNativeInt baseGdiv2 =
  // (baseG >> 1)-1;

  // Signed digit decomposition
  for (uint32_t j = 0; j < 2; j++) {
    for (uint32_t k = 0; k < N; k++) {
      NativeInteger t = input[j][k];
      if (t < QHalf)
        d += t.ConvertToInt();
      else
        d += (NativeInteger::SignedNativeInt)t.ConvertToInt() - Q_int;

      for (uint32_t l = 0; l < digitsG; l++) {
        // remainder is signed

        // This approach gives a slightly better performance
        // VARIANT A
        NativeInteger::SignedNativeInt r = d << gBitsMaxBits;
        r >>= gBitsMaxBits;

        // VARIANT B
        // NativeInteger::SignedNativeInt r = d & gminus1;
        // if (r > baseGdiv2) r -= baseG;

        d -= r;
        d >>= gBits;

        if (r >= 0)
          (*output)[j + 2 * l][k] += NativeInteger(r);
        else
          (*output)[j + 2 * l][k] += NativeInteger(r + Q_int);
      }
      d = 0;
    }
  }
}

// AP Accumulation as described in "Bootstrapping in FHEW-like Cryptosystems"
void RingGSWAccumulatorScheme::AddToACCAP(
    const std::shared_ptr<RingGSWCryptoParams> params,
    const RingGSWCiphertext &input,
    std::shared_ptr<RingGSWCiphertext> acc) const {
  uint32_t digitsG2 = params->GetDigitsG2();
  const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

  std::vector<NativePoly> ct = acc->GetElements()[0];
  std::vector<NativePoly> dct(digitsG2);

  // initialize dct to zeros
  for (uint32_t i = 0; i < digitsG2; i++)
    dct[i] = NativePoly(polyParams, Format::COEFFICIENT, true);

  // calls 2 NTTs
  for (uint32_t i = 0; i < 2; i++) ct[i].SetFormat(Format::COEFFICIENT);

  SignedDigitDecompose(params, ct, &dct);

  // calls digitsG2 NTTs
  for (uint32_t j = 0; j < digitsG2; j++) dct[j].SetFormat(Format::EVALUATION);

  // acc = dct * input (matrix product);
  // uses in-place * operators for the last call to dct[i] to gain performance
  // improvement
  for (uint32_t j = 0; j < 2; j++) {
    (*acc)[0][j].SetValuesToZero();
    for (uint32_t l = 0; l < digitsG2; l++) {
      if (j == 0)
        (*acc)[0][j] += dct[l] * input[l][j];
      else
        (*acc)[0][j] += (dct[l] *= input[l][j]);
    }
  }
}

// GINX Accumulation as described in "Bootstrapping in FHEW-like Cryptosystems"
void RingGSWAccumulatorScheme::AddToACCGINX(
    const std::shared_ptr<RingGSWCryptoParams> params,
    const RingGSWCiphertext &input, const NativeInteger &a,
    std::shared_ptr<RingGSWCiphertext> acc) const {
  // cycltomic order
  uint32_t m = 2 * params->GetLWEParams()->GetN();
  uint32_t digitsG2 = params->GetDigitsG2();
  int64_t q = params->GetLWEParams()->Getq().ConvertToInt();
  const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();

  std::vector<NativePoly> ct = acc->GetElements()[0];
  std::vector<NativePoly> dct(digitsG2);

  // initialize dct to zeros
  for (uint32_t i = 0; i < digitsG2; i++)
    dct[i] = NativePoly(polyParams, Format::COEFFICIENT, true);

  // calls 2 NTTs
  for (uint32_t i = 0; i < 2; i++) ct[i].SetFormat(Format::COEFFICIENT);

  SignedDigitDecompose(params, ct, &dct);

  for (uint32_t j = 0; j < digitsG2; j++) dct[j].SetFormat(Format::EVALUATION);

  uint64_t index = a.ConvertToInt() * (m / q);
  // index is in range [0,m] - so we need to adjust the edge case when
  // index = m to index = 0
  if (index == m) index = 0;
  const NativePoly &monomial = params->GetMonomial(index);

  // acc = dct * input (matrix product);
  // uses in-place * operators for the last call to dct[i] to gain performance
  // improvement
  for (uint32_t j = 0; j < 2; j++) {
    NativePoly temp1 = (j < 1) ? dct[0] * input[0][j] : (dct[0] *= input[0][j]);
    for (uint32_t l = 1; l < digitsG2; l++) {
      if (j == 0)
        temp1 += dct[l] * input[l][j];
      else
        temp1 += (dct[l] *= input[l][j]);
    }
    (*acc)[0][j] += (temp1 *= monomial);
  }
}

std::shared_ptr<RingGSWCiphertext> RingGSWAccumulatorScheme::BootstrapCore(
    const std::shared_ptr<RingGSWCryptoParams> params, const BINGATE gate,
    const RingGSWEvalKey &EK, const NativeVector &a, const NativeInteger &b,
    const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const {
  if ((EK.BSkey == nullptr) || (EK.KSkey == nullptr)) {
    std::string errMsg =
        "Bootstrapping keys have not been generated. Please call BTKeyGen "
        "before calling bootstrapping.";
    PALISADE_THROW(config_error, errMsg);
  }

  const shared_ptr<ILNativeParams> polyParams = params->GetPolyParams();
  NativeInteger q = params->GetLWEParams()->Getq();
  NativeInteger Q = params->GetLWEParams()->GetQ();
  uint32_t N = params->GetLWEParams()->GetN();
  uint32_t baseR = params->GetBaseR();
  uint32_t n = params->GetLWEParams()->Getn();
  std::vector<NativeInteger> digitsR = params->GetDigitsR();

  // Specifies the range [q1,q2) that will be used for mapping
  uint32_t qHalf = q.ConvertToInt() >> 1;
  NativeInteger q1 = params->GetGateConst()[static_cast<int>(gate)];
  NativeInteger q2 = q1.ModAddFast(NativeInteger(qHalf), q);

  // depending on whether the value is the range, it will be set
  // to either Q/8 or -Q/8 to match binary arithmetic
  NativeInteger Q8 = Q / NativeInteger(8) + 1;
  NativeInteger Q8Neg = Q - Q8;

  NativeVector m(params->GetLWEParams()->GetN(),
                 params->GetLWEParams()->GetQ());
  // Since q | (2*N), we deal with a sparse embedding of Z_Q[x]/(X^{q/2}+1) to
  // Z_Q[x]/(X^N+1)
  uint32_t factor = (2 * N / q.ConvertToInt());

  for (uint32_t j = 0; j < qHalf; j++) {
    NativeInteger temp = b.ModSub(j, q);
    if (q1 < q2)
      m[j * factor] = ((temp >= q1) && (temp < q2)) ? Q8Neg : Q8;
    else
      m[j * factor] = ((temp >= q2) && (temp < q1)) ? Q8 : Q8Neg;
  }
  std::vector<NativePoly> res(2);
  // no need to do NTT as all coefficients of this poly are zero
  res[0] = NativePoly(polyParams, Format::EVALUATION, true);
  res[1] = NativePoly(polyParams, Format::COEFFICIENT, false);
  res[1].SetValues(std::move(m), Format::COEFFICIENT);
  res[1].SetFormat(Format::EVALUATION);

  // main accumulation computation
  // the following loop is the bottleneck of bootstrapping/binary gate
  // evaluation
  auto acc = std::make_shared<RingGSWCiphertext>(1, 2);
  (*acc)[0] = std::move(res);

  if (params->GetMethod() == AP) {
    for (uint32_t i = 0; i < n; i++) {
      NativeInteger aI = q.ModSub(a[i], q);
      for (uint32_t k = 0; k < digitsR.size();
           k++, aI /= NativeInteger(baseR)) {
        uint32_t a0 = (aI.Mod(baseR)).ConvertToInt();
        if (a0) this->AddToACCAP(params, (*EK.BSkey)[i][a0][k], acc);
      }
    }
  } else {  // if GINX
    for (uint32_t i = 0; i < n; i++) {
      // handles -a*E(1)
      this->AddToACCGINX(params, (*EK.BSkey)[0][0][i], q.ModSub(a[i], q), acc);
      // handles -a*E(-1) = a*E(1)
      this->AddToACCGINX(params, (*EK.BSkey)[0][1][i], a[i], acc);
    }
  }

  return acc;
}

// Full evaluation as described in "Bootstrapping in FHEW-like
// Cryptosystems"
std::shared_ptr<LWECiphertextImpl> RingGSWAccumulatorScheme::EvalBinGate(
    const std::shared_ptr<RingGSWCryptoParams> params, const BINGATE gate,
    const RingGSWEvalKey &EK,
    const std::shared_ptr<const LWECiphertextImpl> ct1,
    const std::shared_ptr<const LWECiphertextImpl> ct2,
    const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const {
  NativeInteger q = params->GetLWEParams()->Getq();
  NativeInteger Q = params->GetLWEParams()->GetQ();
  uint32_t n = params->GetLWEParams()->Getn();
  uint32_t N = params->GetLWEParams()->GetN();
  NativeInteger Q8 = Q / NativeInteger(8) + 1;

  if (ct1 == ct2) {
    std::string errMsg =
        "ERROR: Please only use independent ciphertexts as inputs.";
    PALISADE_THROW(config_error, errMsg);
  }

  // By default, we compute XOR/XNOR using a combination of AND, OR, and NOT
  // gates
  if ((gate == XOR) || (gate == XNOR)) {
    auto ct1NOT = EvalNOT(params, ct1);
    auto ct2NOT = EvalNOT(params, ct2);
    auto ctAND1 = EvalBinGate(params, AND, EK, ct1, ct2NOT, LWEscheme);
    auto ctAND2 = EvalBinGate(params, AND, EK, ct1NOT, ct2, LWEscheme);
    auto ctOR = EvalBinGate(params, OR, EK, ctAND1, ctAND2, LWEscheme);
    // NOT is free so there is not cost to do it an extra time for XNOR
    if (gate == XOR)
      return ctOR;
    else  // XNOR
      return EvalNOT(params, ctOR);
  } else {
    NativeVector a(n, q);
    NativeInteger b;

    // the additive homomorphic operation for XOR/NXOR is different from the
    // other gates we compute 2*(ct1 - ct2) mod 4 for XOR, me map 1,2 -> 1 and
    // 3,0 -> 0
    if ((gate == XOR_FAST) || (gate == XNOR_FAST)) {
      a = ct1->GetA() - ct2->GetA();
      a += a;
      b = ct1->GetB().ModSubFast(ct2->GetB(), q);
      b.ModAddFastEq(b, q);
    } else {
      // for all other gates, we simply compute (ct1 + ct2) mod 4
      // for AND: 0,1 -> 0 and 2,3 -> 1
      // for OR: 1,2 -> 1 and 3,0 -> 0
      a = ct1->GetA() + ct2->GetA();
      b = ct1->GetB().ModAddFast(ct2->GetB(), q);
    }

    auto acc = BootstrapCore(params, gate, EK, a, b, LWEscheme);

    NativeInteger bNew;
    NativeVector aNew(N, Q);

    // the accumulator result is encrypted w.r.t. the transposed secret key
    // we can transpose "a" to get an encryption under the original secret key
    NativePoly temp = (*acc)[0][0];
    temp = temp.Transpose();
    temp.SetFormat(Format::COEFFICIENT);
    aNew = temp.GetValues();

    temp = (*acc)[0][1];
    temp.SetFormat(Format::COEFFICIENT);
    // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
    bNew = Q8.ModAddFast(temp[0], Q);

    auto eQN =
        std::make_shared<LWECiphertextImpl>(std::move(aNew), std::move(bNew));

    // Key switching
    const std::shared_ptr<const LWECiphertextImpl> eQ =
        LWEscheme->KeySwitch(params->GetLWEParams(), EK.KSkey, eQN);

    // Modulus switching
    return LWEscheme->ModSwitch(params->GetLWEParams(), eQ);
  }
}

// Full evaluation as described in "Bootstrapping in FHEW-like
// Cryptosystems"
std::shared_ptr<LWECiphertextImpl> RingGSWAccumulatorScheme::Bootstrap(
    const std::shared_ptr<RingGSWCryptoParams> params, const RingGSWEvalKey &EK,
    const std::shared_ptr<const LWECiphertextImpl> ct1,
    const std::shared_ptr<LWEEncryptionScheme> LWEscheme) const {
  NativeInteger q = params->GetLWEParams()->Getq();
  NativeInteger Q = params->GetLWEParams()->GetQ();
  uint32_t n = params->GetLWEParams()->Getn();
  uint32_t N = params->GetLWEParams()->GetN();
  NativeInteger Q8 = Q / NativeInteger(8) + 1;

  NativeVector a(n, q);
  NativeInteger b;

  a = ct1->GetA();
  b = ct1->GetB().ModAddFast(q >> 2, q);

  auto acc = BootstrapCore(params, AND, EK, a, b, LWEscheme);

  NativeInteger bNew;
  NativeVector aNew(N, Q);

  // the accumulator result is encrypted w.r.t. the transposed secret key
  // we can transpose "a" to get an encryption under the original secret key
  NativePoly temp = (*acc)[0][0];
  temp = temp.Transpose();
  temp.SetFormat(Format::COEFFICIENT);
  aNew = temp.GetValues();

  temp = (*acc)[0][1];
  temp.SetFormat(Format::COEFFICIENT);
  // we add Q/8 to "b" to to map back to Q/4 (i.e., mod 2) arithmetic.
  bNew = Q8.ModAddFast(temp[0], Q);

  auto eQN =
      std::make_shared<LWECiphertextImpl>(std::move(aNew), std::move(bNew));

  // Key switching
  const std::shared_ptr<const LWECiphertextImpl> eQ =
      LWEscheme->KeySwitch(params->GetLWEParams(), EK.KSkey, eQN);

  // Modulus switching
  return LWEscheme->ModSwitch(params->GetLWEParams(), eQ);
}

// Evaluation of the NOT operation; no key material is needed
std::shared_ptr<LWECiphertextImpl> RingGSWAccumulatorScheme::EvalNOT(
    const std::shared_ptr<RingGSWCryptoParams> params,
    const std::shared_ptr<const LWECiphertextImpl> ct) const {
  NativeInteger q = params->GetLWEParams()->Getq();
  uint32_t n = params->GetLWEParams()->Getn();

  NativeVector a(n, q);

  for (uint32_t i = 0; i < n; i++) a[i] = q - ct->GetA(i);

  NativeInteger b = (q >> 2).ModSubFast(ct->GetB(), q);

  return std::make_shared<LWECiphertextImpl>(std::move(a), b);
}

};  // namespace lbcrypto
