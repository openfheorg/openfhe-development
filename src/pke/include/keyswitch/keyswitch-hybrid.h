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

#ifndef LBCRYPTO_CRYPTO_KEYSWITCH_HYBRID_H
#define LBCRYPTO_CRYPTO_KEYSWITCH_HYBRID_H

#include "keyswitch/keyswitch-rns.h"
#include "schemebase/rlwe-cryptoparameters.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

/**
 * @brief Abstract interface class for LBC SHE algorithms
 * @tparam Element a ring element.
 */
class KeySwitchHYBRID : public KeySwitchRNS {
  using ParmType = typename DCRTPoly::Params;
  using DugType = typename DCRTPoly::DugType;
  using DggType = typename DCRTPoly::DggType;
  using TugType = typename DCRTPoly::TugType;

 public:
  KeySwitchHYBRID() {};

  virtual ~KeySwitchHYBRID() {};

  using KeySwitchRNS::KeySwitchGen;

  virtual EvalKey<DCRTPoly> KeySwitchGen(
      const PrivateKey<DCRTPoly> oldPrivateKey,
      const PrivateKey<DCRTPoly> newPrivateKey) const override;

  virtual EvalKey<DCRTPoly> KeySwitchGen(
      const PrivateKey<DCRTPoly> oldPrivateKey,
      const PrivateKey<DCRTPoly> newPrivateKey,
      const EvalKey<DCRTPoly> evalKey) const override;

  virtual void KeySwitchInPlace(Ciphertext<DCRTPoly> &ciphertext,
                                const EvalKey<DCRTPoly> evalKey) const override;

  /////////////////////////////////////////
  // CORE OPERATIONS
  /////////////////////////////////////////

  virtual std::shared_ptr<std::vector<DCRTPoly>> KeySwitchCore(
      DCRTPoly a, const EvalKey<DCRTPoly> evalKey) const override;

  virtual std::shared_ptr<std::vector<DCRTPoly>> EvalKeySwitchPrecomputeCore(
      DCRTPoly c, std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParamsBase) const override;

  virtual std::shared_ptr<std::vector<DCRTPoly>> EvalFastKeySwitchCore(
      const std::shared_ptr<std::vector<DCRTPoly>> digits,
      const EvalKey<DCRTPoly> evalKey,
      const std::shared_ptr<ParmType> paramsQl) const override;

  /////////////////////////////////////////
  // SERIALIZATION
  /////////////////////////////////////////

  template <class Archive>
  void save(Archive &ar) const {
    ar(cereal::base_class<KeySwitchRNS>(this));
  }

  template <class Archive>
  void load(Archive &ar) {
    ar(cereal::base_class<KeySwitchRNS>(this));
  }

  virtual std::string SerializedObjectName() const override { return "KeySwitchHYBRID"; }
};

}  // namespace lbcrypto

#endif
