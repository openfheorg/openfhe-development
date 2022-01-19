// @file gen-cryptocontext.h -- Constructs CryptoContext based on the provided
// set of parameters
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT))
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
 * HOW TO GENERATE CRYPTOCONTEXT BY CALLING GenCryptoContext()
 *
 * 1. Pick the scheme you want to use. I choose CKKS for our tutorial example.
 * 2. Your code must include this header file and the header with the
 * scheme-specific context generator (scheme/<scheme>/cryptocontext-<scheme>.h):
 *       #include "scheme/ckks/cryptocontext-ckks.h"
 *       #include "gen-cryptocontext.h"
 * 3. Create a parameter object to be passed as a parameter in to
 * GenCryptoContext(). Its generic form would look like this:
 * CCParams<GeneratorName<Element>> parameters where
 *    - GeneratorName is the name of the class defined in
 * cryptocontext-<scheme>.h. In our case it is CryptoContextCKKS.
 *    - Element is a template parameter representing integer lattice. So, it can
 * stay Element or be replaced with Poly, NativePoly or DCRTPoly. I leave
 * "Element". As the result we can add this line:
 *       CCParams<CryptoContextCKKS<Element>> parameters;
 * 4. Adjust the parameters' values with set functions for
 * CCParams<CryptoContextCKKS<Element>> as the object is created using default
 * values from scheme/cryptocontextparams-defaults.h.
 * 5. Call GenCryptoContext() to generate cryptocontext.
 *
 * Now your code should look like this:
 *       #include "scheme/ckks/cryptocontext-ckks.h"
 *       #include "gen-cryptocontext.h"
 *       ...........................................
 *       CCParams<CryptoContextCKKS<Element>> parameters;
 *       parameters.SetMultiplicativeDepth(1);
 *       parameters.SetScalingFactorBits(50);
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

#ifndef LBCRYPTO_CRYPTO_CRYPTOOBJECT_H
#define LBCRYPTO_CRYPTO_CRYPTOOBJECT_H

#include <algorithm>
#include <memory>
#include <string>
#include <utility>

#include "encoding/encodingparams.h"
#include "schemebase/base-cryptoparameters.h"

namespace lbcrypto {

template <typename Element>
class CryptoContextImpl;

template <typename Element>
using CryptoContext = std::shared_ptr<CryptoContextImpl<Element>>;

template <typename Element>
class CryptoContextFactory;

/**
 * @brief CryptoObject
 *
 * A class to aid in referring to the crypto context that an object belongs to
 */
template <typename Element>
class CryptoObject {
 protected:
  CryptoContext<Element> context;  // crypto context this object belongs to
                                   // tag used to find the evaluation key needed
                                   // for SHE/FHE operations
  std::string keyTag;

 public:
  explicit CryptoObject(CryptoContext<Element> cc = nullptr,
                        const std::string& tag = "")
      : context(cc), keyTag(tag) {}

  CryptoObject(const CryptoObject& rhs) {
    context = rhs.context;
    keyTag = rhs.keyTag;
  }

  CryptoObject(const CryptoObject&& rhs) {
    context = std::move(rhs.context);
    keyTag = std::move(rhs.keyTag);
  }

  virtual ~CryptoObject() {}

  const CryptoObject& operator=(const CryptoObject& rhs) {
    this->context = rhs.context;
    this->keyTag = rhs.keyTag;
    return *this;
  }

  const CryptoObject& operator=(const CryptoObject&& rhs) {
    this->context = std::move(rhs.context);
    this->keyTag = std::move(rhs.keyTag);
    return *this;
  }

  bool operator==(const CryptoObject& rhs) const {
    return context.get() == rhs.context.get() && keyTag == rhs.keyTag;
  }

  CryptoContext<Element> GetCryptoContext() const { return context; }

  const std::shared_ptr<CryptoParametersBase<Element>> GetCryptoParameters() const {
    return context->GetCryptoParameters();
  }

  const EncodingParams GetEncodingParameters() const {
    return context->GetCryptoParameters()->GetEncodingParams();
  }

  const std::string GetKeyTag() const { return keyTag; }

  void SetKeyTag(const std::string& tag) { keyTag = tag; }

  template <class Archive>
  void save(Archive& ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("cc", context));
    ar(::cereal::make_nvp("kt", keyTag));
  }

  template <class Archive>
  void load(Archive& ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      PALISADE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }
    ar(::cereal::make_nvp("cc", context));
    ar(::cereal::make_nvp("kt", keyTag));

    context = CryptoContextFactory<Element>::GetContext(
        context->GetCryptoParameters(), context->GetScheme());
  }

  std::string SerializedObjectName() const { return "CryptoObject"; }
  static uint32_t SerializedVersion() { return 1; }
};

}

#endif
