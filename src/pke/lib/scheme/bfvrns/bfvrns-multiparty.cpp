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
#include "scheme/bfvrns/bfvrns-pke.h"
#include "scheme/bfvrns/bfvrns-multiparty.h"

namespace lbcrypto {

DecryptResult MultipartyBFVRNS::MultipartyDecryptFusion(
    const std::vector<Ciphertext<DCRTPoly>> &ciphertextVec,
    NativePoly *plaintext) const {
  const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersBFVRNS>(
          ciphertextVec[0]->GetCryptoParameters());

  const std::vector<DCRTPoly> &cv0 = ciphertextVec[0]->GetElements();

  DCRTPoly b = cv0[0];
  for (size_t i = 1; i < ciphertextVec.size(); i++) {
    const std::vector<DCRTPoly> &cvi = ciphertextVec[i]->GetElements();
    b += cvi[0];
  }

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

}
