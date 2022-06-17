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

#include "cryptocontext.h"
#include "schemebase/base-pke.h"
#include "schemebase/base-pre.h"

namespace lbcrypto {

template <class Element>
EvalKey<Element> PREBase<Element>::ReKeyGen(
        const PrivateKey<Element> oldPrivateKey,
        const PublicKey<Element> newPublicKey) const {
  auto algo = oldPrivateKey->GetCryptoContext()->GetScheme();
  return algo->KeySwitchGen(oldPrivateKey, newPublicKey);
}

template <class Element>
Ciphertext<Element> PREBase<Element>::ReEncrypt(
  ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey,
  const PublicKey<Element> publicKey) const {
  auto algo = ciphertext->GetCryptoContext()->GetScheme();

  Ciphertext<Element> result = ciphertext->Clone();
  if (publicKey != nullptr) {
    const auto cryptoParams =
      std::static_pointer_cast<CryptoParametersRNS>(
         publicKey->GetCryptoParameters());

    const DggType &floodingdist = cryptoParams->GetFloodingDiscreteGaussianGenerator();
    
    std::vector<Element> &cv = result->GetElements();

    std::shared_ptr<std::vector<Element>> ba =
        algo->EncryptZeroCore(publicKey, nullptr, floodingdist);

    cv[0] += (*ba)[0];
    cv[1] += (*ba)[1];
  }

  algo->KeySwitchInPlace(result, evalKey);

  return result;
}

}

// the code below is from base-pre-impl.cpp
namespace lbcrypto {

    //template class PREBase<Poly>;
    //template class PREBase<NativePoly>;
    template class PREBase<DCRTPoly>;

}  // namespace lbcrypto

