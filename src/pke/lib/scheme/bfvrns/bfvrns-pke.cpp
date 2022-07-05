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
#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "scheme/bfvrns/bfvrns-pke.h"

namespace lbcrypto {

KeyPair<DCRTPoly> PKEBFVRNS::KeyGen(CryptoContext<DCRTPoly> cc,
                                    bool makeSparse) {
  KeyPair<DCRTPoly> keyPair(std::make_shared<PublicKeyImpl<DCRTPoly>>(cc),
                           std::make_shared<PrivateKeyImpl<DCRTPoly>>(cc));

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          cc->GetCryptoParameters());

  std::shared_ptr<ParmType> elementParams = cryptoParams->GetElementParams();
  if (cryptoParams->GetEncryptionTechnique() == POVERQ) {
    elementParams = cryptoParams->GetParamsQr();
  }
  const std::shared_ptr<ParmType> paramsPK = cryptoParams->GetParamsPK();

  const auto ns = cryptoParams->GetNoiseScale();
  const DggType &dgg = cryptoParams->GetDiscreteGaussianGenerator();
  DugType dug;
  TugType tug;

  // Private Key Generation

  DCRTPoly s;
  switch (cryptoParams->GetSecretKeyDist()) {
    case GAUSSIAN:
      s = DCRTPoly(dgg, paramsPK, Format::EVALUATION);
      break;
    case UNIFORM_TERNARY:
      s = DCRTPoly(tug, paramsPK, Format::EVALUATION);
      break;
    case SPARSE_TERNARY:
      s = DCRTPoly(tug, paramsPK, Format::EVALUATION, 64);
      break;
    default:
      break;
  }

  // Public Key Generation

  DCRTPoly a(dug, paramsPK, Format::EVALUATION);
  DCRTPoly e(dgg, paramsPK, Format::EVALUATION);

  DCRTPoly b = ns * e - a * s;

  usint sizeQ = elementParams->GetParams().size();
  usint sizePK = paramsPK->GetParams().size();
  if (sizePK > sizeQ) {
    s.DropLastElements(sizePK - sizeQ);
  }

  keyPair.secretKey->SetPrivateElement(std::move(s));
  keyPair.publicKey->SetPublicElementAtIndex(0, std::move(b));
  keyPair.publicKey->SetPublicElementAtIndex(1, std::move(a));

  return keyPair;
}

Ciphertext<DCRTPoly> PKEBFVRNS::Encrypt(DCRTPoly ptxt,
    const PrivateKey<DCRTPoly> privateKey) const {
  Ciphertext<DCRTPoly> ciphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(privateKey));

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          privateKey->GetCryptoParameters());

  const auto elementParams = cryptoParams->GetElementParams();
  auto encParams = elementParams;
<<<<<<< HEAD

  std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();
  if (cryptoParams->GetEncryptionTechnique() == POVERQ) {
    encParams = cryptoParams->GetParamsQr();
    ptxt.SetFormat(Format::COEFFICIENT);
    Poly bigPtxt = ptxt.CRTInterpolate();
    DCRTPoly plain(bigPtxt, encParams);
    ptxt = plain;
    tInvModq = cryptoParams->GettInvModqr();
  }
  ptxt.SetFormat(Format::COEFFICIENT);

  std::shared_ptr<std::vector<DCRTPoly>> ba =
      EncryptZeroCore(privateKey, encParams);

  NativeInteger NegQModt = cryptoParams->GetNegQModt();
  NativeInteger NegQModtPrecon = cryptoParams->GetNegQModtPrecon();

  if (cryptoParams->GetEncryptionTechnique() == POVERQ) {
    NegQModt = cryptoParams->GetNegQrModt();
    NegQModtPrecon = cryptoParams->GetNegQrModtPrecon();
  }

  const NativeInteger t = cryptoParams->GetPlaintextModulus();

  ptxt.TimesQovert(encParams, tInvModq, t, NegQModt, NegQModtPrecon);
  ptxt.SetFormat(Format::EVALUATION);
  (*ba)[0] += ptxt;

  (*ba)[0].SetFormat(Format::COEFFICIENT);
  (*ba)[1].SetFormat(Format::COEFFICIENT);

  if (cryptoParams->GetEncryptionTechnique() == POVERQ) {
    (*ba)[0].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
    (*ba)[1].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq());
  }

  (*ba)[0].SetFormat(Format::EVALUATION);
  (*ba)[1].SetFormat(Format::EVALUATION);
=======

  if (cryptoParams->GetEncryptionTechnique() == POVERQ) {
    encParams = cryptoParams->GetParamsQr();
    ptxt.SetFormat(Format::COEFFICIENT);
    Poly bigPtxt = ptxt.CRTInterpolate();
    DCRTPoly plain(bigPtxt, encParams);
    ptxt = plain;
  }

  std::shared_ptr<std::vector<DCRTPoly>> ba =
      EncryptZeroCore(privateKey, encParams);

  const std::vector<NativeInteger> &QDivtModq = cryptoParams->GetQDivtModq();
  DCRTPoly prod = ptxt.Times(QDivtModq);
  prod.SetFormat(Format::EVALUATION);
  (*ba)[0] += prod;

  (*ba)[0].SetFormat(Format::COEFFICIENT);
  (*ba)[1].SetFormat(Format::COEFFICIENT);

  if (cryptoParams->GetEncryptionTechnique() == POVERQ) {
    (*ba)[0].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq(), cryptoParams->GetrInvModqPrecon());
    (*ba)[1].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq(), cryptoParams->GetrInvModqPrecon());
  }
>>>>>>> Initial POVERQ changes.

  ciphertext->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});
  ciphertext->SetDepth(1);

  return ciphertext;
}

Ciphertext<DCRTPoly> PKEBFVRNS::Encrypt(DCRTPoly ptxt,
    const PublicKey<DCRTPoly> publicKey) const {
  Ciphertext<DCRTPoly> ciphertext(
      std::make_shared<CiphertextImpl<DCRTPoly>>(publicKey));

  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          publicKey->GetCryptoParameters());

  const auto elementParams = cryptoParams->GetElementParams();
  auto encParams = elementParams;

  if (cryptoParams->GetEncryptionTechnique() == POVERQ) {
    std::cout << "plaintext: " << ptxt << std::endl;
    encParams = cryptoParams->GetParamsQr();
    ptxt.SetFormat(Format::COEFFICIENT);
    Poly bigPtxt = ptxt.CRTInterpolate();
    std::cout << "bigPtxt: " << bigPtxt << std::endl;
    DCRTPoly plain(bigPtxt, encParams);
    ptxt = plain;
    std::cout << "plain: " << ptxt << std::endl;
    ptxt.SetFormat(Format::COEFFICIENT);
  }

  std::shared_ptr<std::vector<DCRTPoly>> ba =
      EncryptZeroCore(publicKey, encParams);

  if (0) {
    const NativeInteger &MinusQpModt = cryptoParams->GetNegQrModt();
    const NativeInteger &MinusQpModtPrecon = cryptoParams->GetNegQrModtPrecon();
    const std::vector<NativeInteger> &tInvModq = cryptoParams->GettInvModq();
    const std::vector<NativeInteger> &tInvModqPrecon = cryptoParams->GettInvModqPrecon();
    const NativeInteger t = cryptoParams->GetPlaintextModulus();

    DCRTPoly prod = ptxt;
    prod.TimesQovert(encParams, tInvModq, tInvModqPrecon, t, MinusQpModt, MinusQpModtPrecon);
    std::cout << "prod: " << prod << std::endl;
    prod.SetFormat(Format::EVALUATION);
    (*ba)[0] += prod;
    
  } else {
    const std::vector<NativeInteger> &QDivtModq = cryptoParams->GetQDivtModq();
    DCRTPoly prod = ptxt.Times(QDivtModq);
    std::cout << "prod: " << prod << std::endl;
    prod.SetFormat(Format::EVALUATION);
    (*ba)[0] += prod;
  }

  (*ba)[0].SetFormat(Format::COEFFICIENT);
  (*ba)[1].SetFormat(Format::COEFFICIENT);

  if (cryptoParams->GetEncryptionTechnique() == POVERQ) {
    (*ba)[0].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq(), cryptoParams->GetrInvModqPrecon());
    (*ba)[1].ScaleAndRoundPOverQ(elementParams, cryptoParams->GetrInvModq(), cryptoParams->GetrInvModqPrecon());
  }
  std::cout << "ba[0]: " << (*ba)[0] << std::endl;

  (*ba)[0].SetFormat(Format::EVALUATION);
  (*ba)[1].SetFormat(Format::EVALUATION);

  ciphertext->SetElements({std::move((*ba)[0]), std::move((*ba)[1])});
  ciphertext->SetDepth(1);

  return ciphertext;
}

DecryptResult PKEBFVRNS::Decrypt(ConstCiphertext<DCRTPoly> ciphertext,
    const PrivateKey<DCRTPoly> privateKey, NativePoly *plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          privateKey->GetCryptoParameters());

  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  DCRTPoly b = DecryptCore(cv, privateKey);
  b.SetFormat(Format::COEFFICIENT);

  if (cryptoParams->GetMultiplicationTechnique() == HPS
   || cryptoParams->GetMultiplicationTechnique() == HPSPOVERQ
   || cryptoParams->GetMultiplicationTechnique() == HPSPOVERQLEVELED) {
    *plaintext = b.ScaleAndRound(cryptoParams->GetPlaintextModulus(),
                                 cryptoParams->GettQHatInvModqDivqModt(),
                                 cryptoParams->GettQHatInvModqDivqModtPrecon(),
                                 cryptoParams->GettQHatInvModqBDivqModt(),
                                 cryptoParams->GettQHatInvModqBDivqModtPrecon(),
                                 cryptoParams->GettQHatInvModqDivqFrac(),
                                 cryptoParams->GettQHatInvModqBDivqFrac());
  } else {
    *plaintext = b.ScaleAndRound(
        cryptoParams->GetModuliQ(), cryptoParams->GetPlaintextModulus(),
        cryptoParams->Gettgamma(), cryptoParams->GettgammaQHatInvModq(),
        cryptoParams->GettgammaQHatInvModqPrecon(),
        cryptoParams->GetNegInvqModtgamma(),
        cryptoParams->GetNegInvqModtgammaPrecon());
  }

  return DecryptResult(plaintext->GetLength());
}

}  // namespace lbcrypto
