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
#include "scheme/bgvrns/bgvrns-pke.h"

namespace lbcrypto {

DecryptResult PKEBGVRNS::Decrypt(ConstCiphertext<DCRTPoly> ciphertext,
    const PrivateKey<DCRTPoly> privateKey, NativePoly *plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBGVRNS>(
          ciphertext->GetCryptoParameters());
  const std::vector<DCRTPoly> &cv = ciphertext->GetElements();
  size_t sizeQl = cv[0].GetParams()->GetParams().size();

  DCRTPoly b;
  NativeInteger scalingFactorInt = ciphertext->GetScalingFactorInt();
  if (cv[0].GetFormat() == Format::EVALUATION) {
    b = PKERNS::DecryptCore(cv, privateKey);
    b.SetFormat(Format::COEFFICIENT);
    for (int l = ((int)sizeQl) - 1; l > 0; l--) {
      b.ModReduce(
          cryptoParams->GetPlaintextModulus(),
          cryptoParams->GettModqPrecon(),
          cryptoParams->GetNegtInvModq(l),
          cryptoParams->GetNegtInvModqPrecon(l),
          cryptoParams->GetqlInvModq(l),
          cryptoParams->GetqlInvModqPrecon(l));
    }
    // TODO: Use pre-computed scaling factor at level L.
    if (cryptoParams->GetRescalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetRescalingTechnique() == FLEXIBLEAUTOEXT) {
      for (int i = 0; i < ((int)sizeQl) - 1; i++) {
        NativeInteger modReduceFactor = cryptoParams->GetModReduceFactorInt(sizeQl - 1 - i);
        NativeInteger modReduceFactorInv = modReduceFactor.ModInverse(cryptoParams->GetPlaintextModulus());
        scalingFactorInt = scalingFactorInt.ModMul(modReduceFactorInv, cryptoParams->GetPlaintextModulus());
      }
    }
  } else {
    std::vector<DCRTPoly> ct(cv);
    for (int l = ((int)sizeQl) - 1; l > 0; l--) {
      for (usint i = 0; i < ct.size(); i++) {
        ct[i].ModReduce(
            cryptoParams->GetPlaintextModulus(),
            cryptoParams->GettModqPrecon(),
            cryptoParams->GetNegtInvModq(l),
            cryptoParams->GetNegtInvModqPrecon(l),
            cryptoParams->GetqlInvModq(l),
            cryptoParams->GetqlInvModqPrecon(l));
      }
    }
    if (cryptoParams->GetRescalingTechnique() == FLEXIBLEAUTO || cryptoParams->GetRescalingTechnique() == FLEXIBLEAUTOEXT) {
      for (int i = 0; i < ((int)sizeQl) - 1; i++) {
        NativeInteger modReduceFactor = cryptoParams->GetModReduceFactorInt(sizeQl - 1 - i);
        NativeInteger modReduceFactorInv = modReduceFactor.ModInverse(cryptoParams->GetPlaintextModulus());
        scalingFactorInt = scalingFactorInt.ModMul(modReduceFactorInv, cryptoParams->GetPlaintextModulus());
      }
    }

    b = PKERNS::DecryptCore(ct, privateKey);
    b.SetFormat(Format::COEFFICIENT);
  }

  *plaintext = b.GetElementAtIndex(0).DecryptionCRTInterpolate(cryptoParams->GetPlaintextModulus());

  return DecryptResult(plaintext->GetLength(), scalingFactorInt);
}

}  // namespace lbcrypto
