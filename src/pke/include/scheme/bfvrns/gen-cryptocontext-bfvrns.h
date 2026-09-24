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
 * API to generate BFVRNS crypto context
 */

#ifndef SRC_PKE_INCLUDE_SCHEME_BFVRNS_GEN_CRYPTOCONTEXT_BFVRNS_H_
#define SRC_PKE_INCLUDE_SCHEME_BFVRNS_GEN_CRYPTOCONTEXT_BFVRNS_H_

#include "cryptocontext-fwd.h"
#include "lattice/lat-hal.h"
#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "scheme/bfvrns/bfvrns-scheme.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns-internal.h"
#include "scheme/bfvrns/gen-cryptocontext-bfvrns-params.h"
#include "scheme/gen-cryptocontext-params-validation.h"

namespace lbcrypto {

template <typename Element>
class CryptoContextFactory;

/**
 * @brief Context generator for the BFV scheme: binds the BFV scheme, crypto parameters and factory types
 * used by GenCryptoContext() and builds a CryptoContext from CCParams<CryptoContextBFVRNS>.
 */
class CryptoContextBFVRNS {
    using Element = DCRTPoly;

  public:
    /**
   * The crypto context type produced by this generator (required by GenCryptoContext()).
   */
    using ContextType = CryptoContext<Element>;  // required by GenCryptoContext() in gen-cryptocontext.h
    /**
   * The factory that registers and returns the generated contexts.
   */
    using Factory = CryptoContextFactory<Element>;
    /**
   * The scheme implementation class instantiated for the context.
   */
    using PublicKeyEncryptionScheme = SchemeBFVRNS;
    /**
   * The crypto parameters class instantiated for the context.
   */
    using CryptoParams = CryptoParametersBFVRNS;

    /**
   * Validates the parameters and generates a BFV crypto context from them.
   *
   * @param parameters the BFV parameters.
   * @return the generated crypto context.
   */
    static CryptoContext<Element> genCryptoContext(const CCParams<CryptoContextBFVRNS>& parameters) {
        validateParametersForCryptocontext(parameters);
        return genCryptoContextBFVRNSInternal<CryptoContextBFVRNS, Element>(parameters);
    }
};

}  // namespace lbcrypto

#endif  // SRC_PKE_INCLUDE_SCHEME_BFVRNS_GEN_CRYPTOCONTEXT_BFVRNS_H_
