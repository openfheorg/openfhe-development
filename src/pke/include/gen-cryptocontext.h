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
  Constructs CryptoContext based on the provided set of parameters
 */

/*
* HOW TO GENERATE CRYPTOCONTEXT BY CALLING GenCryptoContext()
*
* 1. Pick the scheme you want to use. I choose CKKS for our tutorial example.
* 2. Your code must include this header file and the header with the scheme-specific
*    context generator (scheme/<scheme>/cryptocontext-<scheme>.h):
*       #include "scheme/ckks/cryptocontext-ckks.h"
*       #include "gen-cryptocontext.h"
* 3. Create a parameter object to be passed as a parameter in to GenCryptoContext(). Its generic
*    form would look like this: CCParams<GeneratorName<Element>> parameters
*    where
*    - GeneratorName is the name of the class defined in cryptocontext-<scheme>.h. In our case
*      it is CryptoContextCKKS.
*    - Element is a template parameter representing integer lattice. So, it can stay Element or
*      be replaced with Poly, NativePoly or DCRTPoly. I leave "Element".
*      As the result we can add this line:
*       CCParams<CryptoContextCKKS<Element>> parameters;
* 4. Adjust the parameters' values with set functions for CCParams<CryptoContextCKKS<Element>> as
*    the object is created using default values from scheme/cryptocontextparams-defaults.h.
* 5. Call GenCryptoContext() to generate cryptocontext.
*
* Now your code should look like this:
*       #include "scheme/ckks/cryptocontext-ckks.h"
*       #include "gen-cryptocontext.h"
*       ...........................................
*       CCParams<CryptoContextCKKS<Element>> parameters;
*       parameters.SetMultiplicativeDepth(1);
*       parameters.SetScalingModSize(50);
*       parameters.SetBatchSize(8);
*       parameters.SetSecurityLevel(HEStd_NotSet);
*       parameters.SetRingDim(16);
*
*       auto cryptoContext = GenCryptoContext(parameters);
*
*       cryptoContext->Enable(ENCRYPTION);
*       cryptoContext->Enable(KEYSWITCH);
*       cryptoContext->Enable(LEVELEDSHE);
*       ...........................................
*
* More examples can be found in src/pke/unittest/UnitTestAutomorphism.cpp or in
* src/pke/unittest/UnitTestEvalMult.cpp.
*/

#ifndef _GEN_CRYPTOCONTEXT_H_
#define _GEN_CRYPTOCONTEXT_H_

namespace lbcrypto {

// forward declarations (don't include headers as compilation fails when you do)
template <typename T>
class CCParams;

template <typename T>
typename T::ContextType GenCryptoContext(const CCParams<T>& params) {
    return T::genCryptoContext(params);
}

}  // namespace lbcrypto

#endif  // _GEN_CRYPTOCONTEXT_H_
