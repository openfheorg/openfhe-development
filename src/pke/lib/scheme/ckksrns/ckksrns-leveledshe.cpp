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

#include "cryptocontext.h"
#include "scheme/ckksrns/ckksrns-cryptoparameters.h"
#include "scheme/ckksrns/ckksrns-leveledshe.h"

namespace lbcrypto {

/////////////////////////////////////////
// SHE ADDITION CONSTANT
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalAdd(ConstCiphertext<DCRTPoly> ciphertext,
                                    double constant) const {
  Ciphertext<DCRTPoly> result = ciphertext->Clone();
  EvalAddInPlace(result, constant);
  return result;
}

void LeveledSHECKKSRNS::EvalAddInPlace(Ciphertext<DCRTPoly> &ciphertext,
                                       double constant) const {
  std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  cv[0] = cv[0] + GetElementForEvalAddOrSub(ciphertext, constant);
}

/////////////////////////////////////////
// SHE SUBTRACTION CONSTANT
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalSub(ConstCiphertext<DCRTPoly> ciphertext,
                                    double constant) const {
  Ciphertext<DCRTPoly> result = ciphertext->Clone();
  EvalSubInPlace(result, constant);
  return result;
}

void LeveledSHECKKSRNS::EvalSubInPlace(Ciphertext<DCRTPoly> &ciphertext,
                                       double constant) const {
  std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  cv[0] = cv[0] - GetElementForEvalAddOrSub(ciphertext, constant);
}

/////////////////////////////////////////
// SHE MULTIPLICATION
/////////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalMult(ConstCiphertext<DCRTPoly> ciphertext,
                                    double constant) const {
  Ciphertext<DCRTPoly> result = ciphertext->Clone();
  EvalMultInPlace(result, constant);
  return result;
}

void LeveledSHECKKSRNS::EvalMultInPlace(Ciphertext<DCRTPoly> &ciphertext,
                            double constant) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  if (cryptoParams->GetRescalingTechnique() != FIXEDMANUAL) {
    if (ciphertext->GetDepth() == 2) {
      ModReduceInternalInPlace(ciphertext);
    }
  }

  EvalMultCoreInPlace(ciphertext, constant);
}

/////////////////////////////////////////
// SHE MULTIPLICATION PLAINTEXT
/////////////////////////////////////////

#if 0
Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalMultFixed(
    ConstCiphertext<DCRTPoly> ciphertext, ConstPlaintext plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  DCRTPoly pt = plaintext->GetElement<DCRTPoly>();

  usint sizeQlc = cv[0].GetParams()->GetParams().size();
  usint sizeQlp = pt.GetParams()->GetParams().size();
  if (sizeQlp >= sizeQlc) {
    pt.DropLastElements(sizeQlp - sizeQlc);
  } else {
    PALISADE_THROW(not_available_error,
                   "In FIXEDMANUAL EvalMult, ciphertext "
                   "cannot have more towers than the plaintext");
  }

  pt.SetFormat(Format::EVALUATION);

  std::vector<DCRTPoly> cvMult;

  for (size_t i = 0; i < cv.size(); i++) {
    cvMult.push_back((cv[i] * pt));
  }

  result->SetElements(std::move(cvMult));

  result->SetDepth(ciphertext->GetDepth() + plaintext->GetDepth());
  result->SetScalingFactor(ciphertext->GetScalingFactor() *
                           plaintext->GetScalingFactor());
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

#endif

#if 0
Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalMultMutable(
    Ciphertext<DCRTPoly> &ciphertext, Plaintext plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  // In the case of EXACT RNS rescaling, we automatically rescale ciphertexts
  // that are not at the same level
  if (cryptoParams->GetRescalingTechnique() == FIXEDMANUAL) {
    return EvalMultApprox(ciphertext, plaintext);
  }

  CryptoContext<DCRTPoly> cc = ciphertext->GetCryptoContext();
  auto algo = cc->GetScheme();

  // First bring input to depth 1 (by rescaling)
  if (ciphertext->GetDepth() > 1) algo->ModReduceInternalInPlace(ciphertext);

  DCRTPoly pt;
  double ptxSF = 1.0;
  uint32_t ptxDepth = 1;
  std::vector<DCRTPoly> cvMult;

  if (plaintext->GetDepth() != ciphertext->GetDepth() ||
      plaintext->GetLevel() != ciphertext->GetLevel()) {
    // TODO - it's not efficient to re-make the plaintexts
    // Allow for rescaling of plaintexts, and the ability to
    // increase the towers of a plaintext to get better performance.

    vector<std::complex<double>> values = plaintext->GetCKKSPackedValue();

    Plaintext ptxt = cc->MakeCKKSPackedPlaintext(values, ciphertext->GetDepth(),
                                                 ciphertext->GetLevel());

    pt = ptxt->GetElement<DCRTPoly>();
    ptxSF = ptxt->GetScalingFactor();
    ptxDepth = ptxt->GetDepth();

  } else {
    pt = plaintext->GetElement<DCRTPoly>();
    ptxSF = plaintext->GetScalingFactor();
    ptxDepth = plaintext->GetDepth();
  }

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  pt.SetFormat(Format::EVALUATION);

  for (size_t i = 0; i < cv.size(); i++) {
    cvMult.push_back((cv[i] * pt));
  }

  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  result->SetElements(std::move(cvMult));
  result->SetDepth(ciphertext->GetDepth() + ptxDepth);
  result->SetScalingFactor(ciphertext->GetScalingFactor() * ptxSF);
  result->SetLevel(ciphertext->GetLevel());

  return result;
}

#endif

/////////////////////////////////////
// Automorphisms
/////////////////////////////////////

/////////////////////////////////////
// Mod Reduce
/////////////////////////////////////

void LeveledSHECKKSRNS::ModReduceInternalInPlace(
    Ciphertext<DCRTPoly> &ciphertext, size_t levels) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  size_t sizeQ = cryptoParams->GetElementParams()->GetParams().size();
  size_t sizeQl = cv[0].GetNumOfElements();
  size_t diffQl = sizeQ - sizeQl;

  for (size_t l = 0; l < levels; ++l) {
    for (size_t i = 0; i < cv.size(); ++i) {
      cv[i].DropLastElementAndScale(
          cryptoParams->GetQlQlInvModqlDivqlModq(diffQl + l),
          cryptoParams->GetQlQlInvModqlDivqlModqPrecon(diffQl + l),
          cryptoParams->GetqlInvModq(diffQl + l),
          cryptoParams->GetqlInvModqPrecon(diffQl + l));
    }
  }

  ciphertext->SetDepth(ciphertext->GetDepth() - levels);
  ciphertext->SetLevel(ciphertext->GetLevel() + levels);

  for (usint i = 0; i < levels; ++i) {
    double modReduceFactor = cryptoParams->GetModReduceFactor(sizeQl - 1 + i);
    ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() /
                                 modReduceFactor);
  }
}

/////////////////////////////////////
// Level Reduce
/////////////////////////////////////

void LeveledSHECKKSRNS::LevelReduceInternalInPlace(
    Ciphertext<DCRTPoly> &ciphertext, const EvalKey<DCRTPoly> evalKey,
    size_t levels) const {
  std::vector<DCRTPoly> &elements = ciphertext->GetElements();
  for (auto &element : elements) {
    element.DropLastElements(levels);
  }
  ciphertext->SetLevel(ciphertext->GetLevel() + levels);
}

/////////////////////////////////////
// Compress
/////////////////////////////////////

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::Compress(
    ConstCiphertext<DCRTPoly> ciphertext, size_t towersLeft) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  Ciphertext<DCRTPoly> result =
      std::make_shared<CiphertextImpl<DCRTPoly>>(*ciphertext);

  while (result->GetDepth() > 1) {
    ModReduceInternalInPlace(result);
  }
  const std::vector<DCRTPoly> &cv = result->GetElements();
  usint sizeQl = cv[0].GetNumOfElements();

  if (towersLeft >= sizeQl) {
    return result;
  }

#if 0
  if (cryptoParams->GetRescalingTechnique() == FLEXIBLEAUTO) {
    const shared_ptr<ParmType> paramsQ = cryptoParams->GetElementParams();
    usint sizeQ = paramsQ->GetParams().size();
    AdjustLevelWithRescaleInPlace(result, sizeQ - towersLeft);
    return result;
  }
#endif

  LevelReduceInternalInPlace(result, nullptr, sizeQl - towersLeft);
  return result;
}

/////////////////////////////////////
// CKKS Core
/////////////////////////////////////

#if NATIVEINT == 128
vector<DCRTPoly::Integer> LeveledSHECKKSRNS::GetElementForEvalAddOrSub(
    ConstCiphertext<DCRTPoly> ciphertext, double constant) const {
  const auto cryptoParams =
      std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  uint32_t precision = 52;
  double powP = std::pow(2, precision);

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  usint numTowers = cv[0].GetNumOfElements();
  vector<DCRTPoly::Integer> moduli(numTowers);

  for (usint i = 0; i < numTowers; i++) {
    moduli[i] = cv[0].GetElementAtIndex(i).GetModulus();
  }

  // the idea is to break down real numbers
  // expressed as input_mantissa * 2^input_exponent
  // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
  // to preserve 52-bit precision of doubles
  // when converting to 128-bit numbers
  int32_t n1 = 0;
  int64_t scaled64 =
      std::llround(static_cast<double>(std::frexp(constant, &n1)) * powP);

  int32_t pCurrent = cryptoParams->GetPlaintextModulus() - precision;
  int32_t pRemaining = pCurrent + n1;

  DCRTPoly::Integer scaledConstant;
  if (pRemaining < 0) {
    scaledConstant =
        NativeInteger(((unsigned __int128)scaled64) >> (-pRemaining));
  } else {
    __int128 ppRemaining = ((__int128)1) << pRemaining;
    scaledConstant = NativeInteger((unsigned __int128)scaled64 * ppRemaining);
  }

  DCRTPoly::Integer intPowP;
  int64_t powp64 = ((int64_t)1) << precision;
  if (pCurrent < 0) {
    intPowP = NativeInteger((unsigned __int128)powp64 >> (-pCurrent));
  } else {
    intPowP = NativeInteger((unsigned __int128)powp64 << pCurrent);
  }

  vector<DCRTPoly::Integer> crtPowP(numTowers, intPowP);
  vector<DCRTPoly::Integer> currPowP(numTowers, scaledConstant);

  // multiply c*powP with powP a total of (depth-1) times to get c*powP^d
  for (size_t i = 0; i < ciphertext->GetDepth() - 1; i++) {
    currPowP = CKKSPackedEncoding::CRTMult(currPowP, crtPowP, moduli);
  }

  return currPowP;
}
#else  // NATIVEINT == 64
vector<DCRTPoly::Integer> LeveledSHECKKSRNS::GetElementForEvalAddOrSub(
    ConstCiphertext<DCRTPoly> ciphertext, double constant) const {
  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  usint sizeQl = cv[0].GetNumOfElements();
  vector<DCRTPoly::Integer> moduli(sizeQl);
  for (usint i = 0; i < sizeQl; i++) {
    moduli[i] = cv[0].GetElementAtIndex(i).GetModulus();
  }

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());
  double scFactor =
      cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());

  DCRTPoly::Integer intScFactor = static_cast<uint64_t>(scFactor + 0.5);
  DCRTPoly::Integer scConstant =
      static_cast<uint64_t>(constant * scFactor + 0.5);

  vector<DCRTPoly::Integer> crtScFactor(sizeQl, intScFactor);
  vector<DCRTPoly::Integer> crtConstant(sizeQl, scConstant);

  for (usint i = 0; i < ciphertext->GetDepth() - 1; i++) {
    crtConstant = CKKSPackedEncoding::CRTMult(crtConstant, crtScFactor, moduli);
  }

  return crtConstant;
}
#endif

#if NATIVEINT == 128
vector<DCRTPoly::Integer> LeveledSHECKKSRNS::GetElementForEvalMult(
    ConstCiphertext<DCRTPoly> ciphertext, double constant) const {
  const auto cryptoParams =
      std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  uint32_t precision = 52;
  double powP = std::pow(2, precision);

  // the idea is to break down real numbers
  // expressed as input_mantissa * 2^input_exponent
  // into (input_mantissa * 2^52) * 2^(p - 52 + input_exponent)
  // to preserve 52-bit precision of doubles
  // when converting to 128-bit numbers
  int32_t n1 = 0;
  int64_t scaled64 =
      std::llround(static_cast<double>(std::frexp(constant, &n1)) * powP);
  int32_t pCurrent = cryptoParams->GetPlaintextModulus() - precision;
  int32_t pRemaining = pCurrent + n1;
  __int128 scaled128 = 0;

  if (pRemaining < 0) {
    scaled128 = scaled64 >> (-pRemaining);
  } else {
    __int128 ppRemaining = ((__int128)1) << pRemaining;
    scaled128 = ppRemaining * scaled64;
  }

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  uint32_t numTowers = cv[0].GetNumOfElements();
  vector<DCRTPoly::Integer> factors(numTowers);

  for (usint i = 0; i < numTowers; i++) {
    DCRTPoly::Integer modulus = cv[0].GetElementAtIndex(i).GetModulus();
    __int128 reduced = scaled128 % modulus.ConvertToInt();

    factors[i] = (reduced < 0) ?
      static_cast<BasicInteger>(reduced + modulus.ConvertToInt()) :
      static_cast<BasicInteger>(reduced);
  }
  return factors;
}
#else  // NATIVEINT == 64
vector<DCRTPoly::Integer> LeveledSHECKKSRNS::GetElementForEvalMult(
    ConstCiphertext<DCRTPoly> ciphertext, double constant) const {
  const auto cryptoParams =
      std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  double scFactor = cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());

#if defined(HAVE_INT128)
  typedef int128_t DoubleInteger;
#else
  typedef int64_t DoubleInteger;
#endif

  DoubleInteger large = static_cast<DoubleInteger>(constant * scFactor + 0.5);
  DoubleInteger large_abs = (large < 0 ? -large : large);
  DoubleInteger bound = (uint64_t)1 << 63;

  uint32_t numTowers = cv[0].GetNumOfElements();
  vector<DCRTPoly::Integer> factors(numTowers);

  if (large_abs > bound) {
    for (usint i = 0; i < numTowers; i++) {
      DCRTPoly::Integer modulus = cv[0].GetElementAtIndex(i).GetModulus();
      DoubleInteger reduced = large % modulus.ConvertToInt();

      factors[i] = (reduced < 0) ?
        static_cast<uint64_t>(reduced + modulus.ConvertToInt()) :
        static_cast<uint64_t>(reduced);
    }
  } else {
    int64_t scConstant = static_cast<int64_t>(large);
    for (usint i = 0; i < numTowers; i++) {
      DCRTPoly::Integer modulus = cv[0].GetElementAtIndex(i).GetModulus();
      int64_t reduced = scConstant % static_cast<int64_t>(modulus.ConvertToInt());

      factors[i] = (reduced < 0) ?
          reduced + modulus.ConvertToInt() :
          reduced;
    }
  }
  return factors;
}

#endif




#if 0
Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalAddCore(
    ConstCiphertext<DCRTPoly> ciphertext, DCRTPoly ptxt) const {
  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  // Bring to same depth if not already same
  if (ptxtDepth < ciphertext->GetDepth()) {
    // Find out how many levels to scale plaintext up.
    size_t diffDepth = ciphertext->GetDepth() - ptxtDepth;

    DCRTPoly ptxtClone = ptxt.Clone();

    // Get moduli chain to create CRT representation of powP
    usint sizeQl = cv[0].GetNumOfElements();
    vector<DCRTPoly::Integer> moduli(sizeQl);

    for (usint i = 0; i < sizeQl; i++) {
      moduli[i] = cv[0].GetElementAtIndex(i).GetModulus();
    }

    double scFactor = cryptoParams->GetScalingFactorReal();

    DCRTPoly::Integer intSF =
        static_cast<bigintnat::NativeInteger::Integer>(scFactor + 0.5);
    std::vector<DCRTPoly::Integer> crtSF(sizeQl, intSF);
    auto crtPowSF = crtSF;
    for (usint j = 0; j < diffDepth - 1; j++) {
      crtPowSF = CKKSPackedEncoding::CRTMult(crtPowSF, crtSF, moduli);
    }

    // Update ptElem with scaled up element
    ptxt = ptxtClone.Times(crtPowSF);
  } else if (ptxtDepth > ciphertext->GetDepth()) {
    PALISADE_THROW(not_available_error,
                   "AlgorithmSHECKKS<DCRTPoly>::EvalAdd "
                   "- plaintext cannot be encoded at a larger depth than that "
                   "of the ciphertext.");
  }

  ptxt.SetFormat(Format::EVALUATION);

  std::vector<DCRTPoly> cvAdd(cv);
  cvAdd[0] = cvAdd[0] + ptxt;

  result->SetElements(std::move(cvAdd));

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}

Ciphertext<DCRTPoly> LeveledSHECKKSRNS::EvalSubCore(
    ConstCiphertext<DCRTPoly> ciphertext, DCRTPoly ptxt,
    usint ptxtDepth) const {
  Ciphertext<DCRTPoly> result = ciphertext->CloneEmpty();

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  // Bring to same depth if not already same
  if (ptxtDepth < ciphertext->GetDepth()) {
    // Find out how many levels to scale plaintext up.
    size_t diffDepth = ciphertext->GetDepth() - ptxtDepth;

    DCRTPoly ptxtClone = ptxt.Clone();

    // Get moduli chain to create CRT representation of powP
    usint sizeQl = cv[0].GetNumOfElements();
    vector<DCRTPoly::Integer> moduli(sizeQl);
    for (usint i = 0; i < sizeQl; i++) {
      moduli[i] = cv[0].GetElementAtIndex(i).GetModulus();
    }

    double scFactor = cryptoParams->GetScalingFactorReal();

    DCRTPoly::Integer intSF =
        static_cast<bigintnat::NativeInteger::Integer>(scFactor + 0.5);
    std::vector<DCRTPoly::Integer> crtSF(sizeQl, intSF);
    // Compute powP^depthDiff in CRT
    auto crtPowSF = crtSF;
    for (usint j = 1; j < diffDepth; j++) {
      crtPowSF = CKKSPackedEncoding::CRTMult(crtPowSF, crtSF, moduli);
    }

    // Update ptElem with scaled up element
    ptxt = ptxtClone.Times(crtPowSF);
  } else if (ptxtDepth > ciphertext->GetDepth()) {
    PALISADE_THROW(not_available_error,
                   "AlgorithmSHECKKS<DCRTPoly>::EvalSub "
                   "- plaintext cannot be encoded at a larger depth than that "
                   "of the ciphertext.");
  }

  ptxt.SetFormat(Format::EVALUATION);

  std::vector<DCRTPoly> cvSub(cv);
  cvSub[0] = cvSub[0] - ptxt;

  result->SetElements(std::move(cvSub));

  result->SetDepth(ciphertext->GetDepth());
  result->SetLevel(ciphertext->GetLevel());
  result->SetScalingFactor(ciphertext->GetScalingFactor());

  return result;
}
#endif

void LeveledSHECKKSRNS::AdjustLevelsAndDepthInPlace(
    Ciphertext<DCRTPoly> &ciphertext1, Ciphertext<DCRTPoly> &ciphertext2) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext1->GetCryptoParameters());
  usint c1lvl = ciphertext1->GetLevel();
  usint c2lvl = ciphertext2->GetLevel();
  usint c1depth = ciphertext1->GetDepth();
  usint c2depth = ciphertext2->GetDepth();
  auto sizeQl1 = ciphertext1->GetElements()[0].GetNumOfElements();
  auto sizeQl2 = ciphertext2->GetElements()[0].GetNumOfElements();

  if (c1lvl < c2lvl) {
    if (c1depth == 2) {
      if (c2depth == 2) {
        double scf1 = ciphertext1->GetScalingFactor();
        double scf2 = ciphertext2->GetScalingFactor();
        double scf = cryptoParams->GetScalingFactorReal(c1lvl);
        double q1 = cryptoParams->GetModReduceFactor(sizeQl1 - 1);
        EvalMultCoreInPlace(ciphertext1, scf2 / scf1 * q1 / scf);
        ModReduceInternalInPlace(ciphertext1);
        if (c1lvl + 1 < c2lvl) {
          LevelReduceInternalInPlace(ciphertext1, nullptr, c2lvl - c1lvl - 1);
        }
        ciphertext1->SetScalingFactor(ciphertext2->GetScalingFactor());
      } else {
        if (c1lvl + 1 == c2lvl) {
          ModReduceInternalInPlace(ciphertext1);
        } else {
          double scf1 = ciphertext1->GetScalingFactor();
          double scf2 = cryptoParams->GetScalingFactorRealBig(c2lvl - 1);
          double scf = cryptoParams->GetScalingFactorReal(c1lvl);
          double q1 = cryptoParams->GetModReduceFactor(sizeQl1 - 1);
          EvalMultCoreInPlace(ciphertext1, scf2 / scf1 * q1 / scf);
          ModReduceInternalInPlace(ciphertext1);
          if (c1lvl + 2 < c2lvl) {
            LevelReduceInternalInPlace(ciphertext1, nullptr, c2lvl - c1lvl - 2);
          }
          ModReduceInternalInPlace(ciphertext1);
          ciphertext1->SetScalingFactor(ciphertext2->GetScalingFactor());
        }
      }
    } else {
      if (c2depth == 2) {
        double scf1 = ciphertext1->GetScalingFactor();
        double scf2 = ciphertext2->GetScalingFactor();
        double scf = cryptoParams->GetScalingFactorReal(c1lvl);
        EvalMultCoreInPlace(ciphertext1, scf2 / scf1 / scf);
        LevelReduceInternalInPlace(ciphertext1, nullptr, c2lvl - c1lvl);
        ciphertext1->SetScalingFactor(scf2);
      } else {
        double scf1 = ciphertext1->GetScalingFactor();
        double scf2 = cryptoParams->GetScalingFactorRealBig(c2lvl - 1);
        double scf = cryptoParams->GetScalingFactorReal(c1lvl);
        EvalMultCoreInPlace(ciphertext1, scf2 / scf1 / scf);
        if (c1lvl + 1 < c2lvl) {
          LevelReduceInternalInPlace(ciphertext1, nullptr, c2lvl - c1lvl - 1);
        }
        ModReduceInternalInPlace(ciphertext1);
        ciphertext1->SetScalingFactor(ciphertext2->GetScalingFactor());
      }
    }
  } else if (c1lvl > c2lvl) {
    if (c2depth == 2) {
      if (c1depth == 2) {
        double scf2 = ciphertext2->GetScalingFactor();
        double scf1 = ciphertext1->GetScalingFactor();
        double scf = cryptoParams->GetScalingFactorReal(c2lvl);
        double q2 = cryptoParams->GetModReduceFactor(sizeQl2 - 1);
        EvalMultCoreInPlace(ciphertext2, scf1 / scf2 * q2 / scf);
        ModReduceInternalInPlace(ciphertext2);
        if (c2lvl + 1 < c1lvl) {
          LevelReduceInternalInPlace(ciphertext2, nullptr, c1lvl - c2lvl - 1);
        }
        ciphertext2->SetScalingFactor(ciphertext1->GetScalingFactor());
      } else {
        if (c2lvl + 1 == c1lvl) {
          ModReduceInternalInPlace(ciphertext2);
        } else {
          double scf2 = ciphertext2->GetScalingFactor();
          double scf1 = cryptoParams->GetScalingFactorRealBig(c1lvl - 1);
          double scf = cryptoParams->GetScalingFactorReal(c2lvl);
          double q2 = cryptoParams->GetModReduceFactor(sizeQl2 - 1);
          EvalMultCoreInPlace(ciphertext2, scf1 / scf2 * q2 / scf);
          ModReduceInternalInPlace(ciphertext2);
          if (c2lvl + 2 < c1lvl) {
            LevelReduceInternalInPlace(ciphertext2, nullptr, c1lvl - c2lvl - 2);
          }
          ModReduceInternalInPlace(ciphertext2);
          ciphertext2->SetScalingFactor(ciphertext1->GetScalingFactor());
        }
      }
    } else {
      if (c1depth == 2) {
        double scf2 = ciphertext2->GetScalingFactor();
        double scf1 = ciphertext1->GetScalingFactor();
        double scf = cryptoParams->GetScalingFactorReal(c2lvl);
        EvalMultCoreInPlace(ciphertext2, scf1 / scf2 / scf);
        LevelReduceInternalInPlace(ciphertext2, nullptr, c1lvl - c2lvl);
        ciphertext2->SetScalingFactor(scf1);
      } else {
        double scf2 = ciphertext2->GetScalingFactor();
        double scf1 = cryptoParams->GetScalingFactorRealBig(c1lvl - 1);
        double scf = cryptoParams->GetScalingFactorReal(c2lvl);
        EvalMultCoreInPlace(ciphertext2, scf1 / scf2 / scf);
        if (c2lvl + 1 < c1lvl) {
          LevelReduceInternalInPlace(ciphertext2, nullptr, c1lvl - c2lvl - 1);
        }
        ModReduceInternalInPlace(ciphertext2);
        ciphertext2->SetScalingFactor(ciphertext1->GetScalingFactor());
      }
    }
  } else {
    if (c1depth < c2depth) {
      EvalMultCoreInPlace(ciphertext1, 1.0);
    } else if (c2depth < c1depth) {
      EvalMultCoreInPlace(ciphertext2, 1.0);
    }
  }
}

void LeveledSHECKKSRNS::AdjustLevelsAndDepthToOneInPlace(
    Ciphertext<DCRTPoly> &ciphertext1, Ciphertext<DCRTPoly> &ciphertext2) const {
  AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);

  if(ciphertext1->GetDepth() == 2) {
    ModReduceInternalInPlace(ciphertext1);
    ModReduceInternalInPlace(ciphertext2);
  }
}

void LeveledSHECKKSRNS::AdjustLevelsAndDepthInPlace(
    Ciphertext<DCRTPoly> &ciphertext, DCRTPoly &pt, usint ptDepth) const {
  //TODO implement
}


void LeveledSHECKKSRNS::AdjustLevelsAndDepthToOneInPlace(
    Ciphertext<DCRTPoly> &ciphertext, DCRTPoly &pt, usint ptDepth) const {
  //TODO implement
}

void LeveledSHECKKSRNS::EvalMultCoreInPlace(Ciphertext<DCRTPoly> &ciphertext, double constant) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersCKKSRNS>(
          ciphertext->GetCryptoParameters());

  vector<DCRTPoly::Integer> factors = GetElementForEvalMult(ciphertext, constant);
  std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  for (usint i = 0; i < cv.size(); ++i) {
    cv[i] = cv[i] * factors;
  }
  ciphertext->SetDepth(ciphertext->GetDepth() + 1);

  double scFactor =
      cryptoParams->GetScalingFactorReal(ciphertext->GetLevel());
  ciphertext->SetScalingFactor(ciphertext->GetScalingFactor() * scFactor);

}

}  // namespace lbcrypto
