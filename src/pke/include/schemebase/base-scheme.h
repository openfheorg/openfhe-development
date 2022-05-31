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

#ifndef LBCRYPTO_CRYPTO_BASE_SCHEME_H
#define LBCRYPTO_CRYPTO_BASE_SCHEME_H

#include "utils/caller_info.h"

#include "key/allkey.h"

#include "keyswitch/keyswitch-base.h"

#include "schemebase/rlwe-cryptoparameters.h"
#include "schemebase/base-parametergeneration.h"
#include "schemebase/base-pke.h"
#include "schemebase/base-pre.h"
#include "schemebase/base-leveledshe.h"
#include "schemebase/base-advancedshe.h"
#include "schemebase/base-multiparty.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

//template <typename Element>
//class KeyPair;

/**
 * @brief Abstract interface for public key encryption schemes
 * @tparam Element a ring element.
 */
template <typename Element>
class SchemeBase {
  using ParmType = typename Element::Params;
  using IntType = typename Element::Integer;
  using DugType = typename Element::DugType;
  using DggType = typename Element::DggType;
  using TugType = typename Element::TugType;

 protected:
  inline void CheckMultipartyDecryptCompatibility(
      ConstCiphertext<Element> &ciphertext, CALLER_INFO_ARGS_HDR) const {
    if (ciphertext->GetElements().size() > 2) {
      std::string errorMsg(std::string("ciphertext's number of elements is [") +
                           std::to_string(ciphertext->GetElements().size()) +
                           "]. Must be 2 or less for Multiparty Decryption." +
                           CALLER_INFO);
      OPENFHE_THROW(openfhe_error, errorMsg);
    }
  }

 public:
  SchemeBase() {}

  virtual ~SchemeBase() {}

  virtual bool operator==(const SchemeBase &sch) const {
    OPENFHE_THROW(config_error, "operator== is not supported");
  }

  virtual bool operator!=(const SchemeBase &sch) const {
    return !(*this == sch);
  }

  /**
   * Enable features with a bit mast of PKESchemeFeature codes
   * @param mask
   */
  virtual void Enable(usint mask) {
    if (mask & PKE) Enable(PKE);
    if (mask & KEYSWITCH) Enable(KEYSWITCH);
    if (mask & LEVELEDSHE) Enable(LEVELEDSHE);
    if (mask & ADVANCEDSHE) Enable(ADVANCEDSHE);
    if (mask & PRE) Enable(PRE);
    if (mask & MULTIPARTY) Enable(MULTIPARTY);
  }

  virtual usint GetEnabled() const {
    usint flag = 0;

    if (m_PKE != nullptr) flag |= PKE;
    if (m_KeySwitch != nullptr) flag |= KEYSWITCH;
    if (m_LeveledSHE != nullptr) flag |= LEVELEDSHE;
    if (m_AdvancedSHE != nullptr) flag |= ADVANCEDSHE;
    if (m_PRE != nullptr) flag |= PRE;
    if (m_Multiparty != nullptr) flag |= MULTIPARTY;

    return flag;
  }

  // instantiated in the scheme implementation class
  virtual void Enable(PKESchemeFeature feature) {
    OPENFHE_THROW(config_error,
                         "Enable is not implemented");
  }

  /////////////////////////////////////////
  // PARAMETER GENERATION WRAPPER
  /////////////////////////////////////////

  virtual bool ParamsGenBFVRNS(std::shared_ptr<CryptoParametersBase<Element>> cryptoParams,
                         int32_t evalAddCount,
                         int32_t evalMultCount,
                         int32_t keySwitchCount,
                         size_t dcrtBits,
                         uint32_t n,
                         enum KeySwitchTechnique ksTech,
                         enum RescalingTechnique rsTech,
                         enum EncryptionTechnique encTech,
                         enum MultiplicationTechnique multTech) const {
    if (m_ParamsGen) {
      return m_ParamsGen->ParamsGenBFVRNS(cryptoParams, evalAddCount, evalMultCount,
                                    keySwitchCount, dcrtBits, n,
                                    ksTech, rsTech, encTech, multTech);
    }
    OPENFHE_THROW(not_implemented_error,
                   "Parameter generation operation has not been implemented");
  }

  virtual bool ParamsGenCKKSRNS(std::shared_ptr<CryptoParametersBase<Element>> cryptoParams,
                         usint cyclOrder,
                         usint numPrimes,
                         usint scaleExp,
                         usint relinWindow,
                         MODE mode,
                         usint firstModSize,
                         uint32_t numPartQ,
                         enum KeySwitchTechnique ksTech,
                         enum RescalingTechnique rsTech,
                         enum EncryptionTechnique encTech,
                         enum MultiplicationTechnique multTech) const {
    if (m_ParamsGen) {
      return m_ParamsGen->ParamsGenCKKSRNS(cryptoParams, cyclOrder, numPrimes,
                                    scaleExp, relinWindow, mode, firstModSize, numPartQ,
                                    ksTech, rsTech, encTech, multTech);
    }
    OPENFHE_THROW(not_implemented_error,
                   "Parameter generation operation has not been implemented "
                   "for this scheme.");
  }

  virtual bool ParamsGenBGVRNS(std::shared_ptr<CryptoParametersBase<Element>> cryptoParams,
                         usint cyclOrder,
                         usint ptm,
                         usint numPrimes,
                         usint relinWindow,
                         MODE mode,
                         usint firstModSize,
                         usint dcrtBits,
                         uint32_t numPartQ,
                         usint multihopQBound,
                         enum KeySwitchTechnique ksTech,
                         enum RescalingTechnique rsTech,
                         enum EncryptionTechnique encTech,
                         enum MultiplicationTechnique multTech) const {
    if (m_ParamsGen) {
      return m_ParamsGen->ParamsGenBGVRNS(cryptoParams, cyclOrder, ptm, numPrimes,
                                    relinWindow, mode, firstModSize,
                                    dcrtBits, numPartQ, multihopQBound,
                                    ksTech, rsTech, encTech, multTech);
    }
    OPENFHE_THROW(
        not_implemented_error,
        "Parameter generation operation has not been implemented for this "
        "scheme.");
  }

  /////////////////////////////////////////
  // PKE WRAPPER
  /////////////////////////////////////////

  virtual KeyPair<Element> KeyGen(CryptoContext<Element> cc, bool makeSparse) {
    if (m_PKE) {
      auto kp = m_PKE->KeyGen(cc, makeSparse);
      kp.publicKey->SetKeyTag(kp.secretKey->GetKeyTag());
      return kp;
    }
    OPENFHE_THROW(config_error, "KeyGen operation has not been enabled");
  }

  virtual Ciphertext<Element> Encrypt(const Element &plaintext, const PrivateKey<Element> privateKey) const {
    if (m_PKE) {
//      if (!plaintext)
//        OPENFHE_THROW(config_error, "Input plaintext is nullptr");
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      return m_PKE->Encrypt(plaintext, privateKey);
    }
    OPENFHE_THROW(config_error, "Encrypt operation has not been enabled");
  }

  virtual Ciphertext<Element> Encrypt(const Element &plaintext, const PublicKey<Element> publicKey) const {
    if (m_PKE) {
//      if (!plaintext)
//        OPENFHE_THROW(config_error, "Input plaintext is nullptr");
      if (!publicKey)
        OPENFHE_THROW(config_error, "Input public key is nullptr");

      return m_PKE->Encrypt(plaintext, publicKey);
    }
    OPENFHE_THROW(config_error, "Encrypt operation has not been enabled");
  }

  virtual DecryptResult Decrypt(ConstCiphertext<Element> ciphertext,
                                const PrivateKey<Element> privateKey,
                                NativePoly *plaintext) const {
    if (m_PKE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      return m_PKE->Decrypt(ciphertext, privateKey, plaintext);
    }
    OPENFHE_THROW(config_error, "Decrypt operation has not been enabled");
  }

  virtual DecryptResult Decrypt(ConstCiphertext<Element> ciphertext,
                                const PrivateKey<Element> privateKey,
                                Poly *plaintext) const {
    if (m_PKE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      return m_PKE->Decrypt(ciphertext, privateKey, plaintext);
    }
    OPENFHE_THROW(config_error, "Decrypt operation has not been enabled");
  }

  std::shared_ptr< std::vector<Element> > EncryptZeroCore(const PrivateKey<Element> privateKey) const {
    if (m_PKE) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      return m_PKE->EncryptZeroCore(privateKey, nullptr);
    }
    OPENFHE_THROW(config_error,
                   "EncryptZeroCore operation has not been enabled");
  }

  std::shared_ptr< std::vector<Element> > EncryptZeroCore(const PublicKey<Element> publicKey) const {
    if (m_PKE) {
      if (!publicKey)
        OPENFHE_THROW(config_error, "Input public key is nullptr");

      return m_PKE->EncryptZeroCore(publicKey, nullptr);
    }
    OPENFHE_THROW(config_error,
                   "EncryptZeroCore operation has not been enabled");
  }

  Element DecryptCore(ConstCiphertext<Element> ciphertext, const PrivateKey<Element> privateKey) const {
    if (m_PKE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      return m_PKE->DecryptCore(ciphertext->GetElements(), privateKey);
    }
    OPENFHE_THROW(config_error, "DecryptCore operation has not been enabled");
  }

  /////////////////////////////////////////
  // KEY SWITCH WRAPPER
  /////////////////////////////////////////

  virtual EvalKey<Element> KeySwitchGen(
      const PrivateKey<Element> oldPrivateKey,
      const PrivateKey<Element> newPrivateKey) const {
    if (m_KeySwitch) {
      if (!oldPrivateKey)
        OPENFHE_THROW(config_error, "Input first private key is nullptr");
      if (!newPrivateKey)
        OPENFHE_THROW(config_error, "Input second private key is nullptr");

      auto result = m_KeySwitch->KeySwitchGen(oldPrivateKey, newPrivateKey);
      result->SetKeyTag(newPrivateKey->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error, "KeySwitchGen operation has not been enabled");
  }

  virtual EvalKey<Element> KeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                        const PrivateKey<Element> newPrivateKey,
                                        const EvalKey<Element> evalKey) const {
    if (m_KeySwitch) {
      if (!oldPrivateKey)
        OPENFHE_THROW(config_error, "Input first private key is nullptr");
      if (!newPrivateKey)
        OPENFHE_THROW(config_error, "Input second private key is nullptr");
      if (!evalKey) OPENFHE_THROW(config_error, "Input eval key is nullptr");

      auto result = m_KeySwitch->KeySwitchGen(oldPrivateKey, newPrivateKey, evalKey);
      result->SetKeyTag(newPrivateKey->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error, "KeySwitchGen operation has not been enabled");
  }

  virtual EvalKey<Element> KeySwitchGen(
      const PrivateKey<Element> oldPrivateKey,
      const PublicKey<Element> newPublicKey) const {
    if (m_KeySwitch) {
      if (!oldPrivateKey)
        OPENFHE_THROW(config_error, "Input first private key is nullptr");
      if (!newPublicKey)
        OPENFHE_THROW(config_error, "Input second public key is nullptr");

      auto result = m_KeySwitch->KeySwitchGen(oldPrivateKey, newPublicKey);
      result->SetKeyTag(newPublicKey->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error, "KeySwitchGen operation has not been enabled");
  }

  virtual Ciphertext<Element> KeySwitch(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey) const {
    if (m_KeySwitch) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKey)
        OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

      return m_KeySwitch->KeySwitch(ciphertext, evalKey);
    }
    OPENFHE_THROW(config_error, "KeySwitch operation has not been enabled");
  }

  virtual void KeySwitchInPlace(Ciphertext<Element> &ciphertext,
                                const EvalKey<Element> evalKey) const {
    if (m_KeySwitch) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKey)
        OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

      m_KeySwitch->KeySwitchInPlace(ciphertext, evalKey);
      return;
    }
    OPENFHE_THROW(config_error,
                   "KeySwitchInPlace operation has not been enabled");
  }

  virtual std::shared_ptr<std::vector<Element>> EvalKeySwitchPrecomputeCore(
      Element c, std::shared_ptr<CryptoParametersBase<Element>> cryptoParamsBase) const {
    if (m_KeySwitch) {
      return m_KeySwitch->EvalKeySwitchPrecomputeCore(c, cryptoParamsBase);
    }
    OPENFHE_THROW(
        config_error,
        "EvalKeySwitchPrecomputeCore operation has not been enabled");
  }

  virtual std::shared_ptr<std::vector<Element>> EvalFastKeySwitchCore(
      const std::shared_ptr<std::vector<Element>> digits,
      const EvalKey<Element> evalKey,
      const std::shared_ptr<ParmType> params) const {
    if (m_KeySwitch) {
      if (nullptr == digits)
        OPENFHE_THROW(config_error, "Input digits is nullptr");
      if (digits->size() == 0)
        OPENFHE_THROW(config_error, "Input digits size is 0");
      if (!evalKey)
        OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
      if (!params)
        OPENFHE_THROW(config_error, "Input params is nullptr");

      return m_KeySwitch->EvalFastKeySwitchCore(digits, evalKey, params);
    }
    OPENFHE_THROW(config_error,
                   "EvalFastKeySwitchCore operation has not been enabled");
  }

  virtual std::shared_ptr<std::vector<Element>> KeySwitchCore(Element a, const EvalKey<Element> evalKey) const {
    if (m_KeySwitch) {
      if (!evalKey)
        OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

      return m_KeySwitch->KeySwitchCore(a, evalKey);
    }
    OPENFHE_THROW(config_error,
                   "KeySwitchCore operation has not been enabled");
  }

  /////////////////////////////////////////
  // PRE WRAPPER
  /////////////////////////////////////////

  virtual EvalKey<Element> ReKeyGen(
      const PrivateKey<Element> oldPrivateKey,
      const PublicKey<Element> newPublicKey) const {
    if (m_PRE) {
      if (!oldPrivateKey)
        OPENFHE_THROW(config_error, "Input first private key is nullptr");
      if (!newPublicKey)
        OPENFHE_THROW(config_error, "Input second public key is nullptr");

      auto result = m_PRE->ReKeyGen(oldPrivateKey, newPublicKey);
      result->SetKeyTag(newPublicKey->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error, "ReKeyGen operation has not been enabled");
  }

  virtual Ciphertext<Element> ReEncrypt(ConstCiphertext<Element> ciphertext,
                                        const EvalKey<Element> evalKey,
                                        const PublicKey<Element> publicKey,
                                        usint noiseflooding) const {
    if (m_PRE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKey)
        OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

      auto result =
          m_PRE->ReEncrypt(ciphertext, evalKey, publicKey, noiseflooding);
      result->SetKeyTag(evalKey->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error, "ReEncrypt operation has not been enabled");
  }

  /////////////////////////////////////////
  // SHE NEGATION WRAPPER
  /////////////////////////////////////////

  virtual Ciphertext<Element> EvalNegate(ConstCiphertext<Element> ciphertext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_LeveledSHE->EvalNegate(ciphertext);
    }
    OPENFHE_THROW(config_error, "EvalNegate operation has not been enabled");
  }

  virtual void EvalNegateInPlace(Ciphertext<Element> &ciphertext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      m_LeveledSHE->EvalNegateInPlace(ciphertext);
      return;
    }
    OPENFHE_THROW(config_error, "EvalNegate operation has not been enabled");
  }

  /////////////////////////////////////////
  // SHE ADDITION Wrapper
  /////////////////////////////////////////

  virtual Ciphertext<Element> EvalAdd(
      ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");

      return m_LeveledSHE->EvalAdd(ciphertext1, ciphertext2);
    }
    OPENFHE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  virtual void EvalAddInPlace(Ciphertext<Element> &ciphertext1, ConstCiphertext<Element> ciphertext2) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");

      m_LeveledSHE->EvalAddInPlace(ciphertext1, ciphertext2);
      return;
    }
    OPENFHE_THROW(config_error,
                   "EvalAddInPlace operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAddMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");

      return m_LeveledSHE->EvalAddMutable(ciphertext1, ciphertext2);
    }
    OPENFHE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        OPENFHE_THROW(config_error, "Input plaintext is nullptr");

      return m_LeveledSHE->EvalAdd(ciphertext, plaintext);
    }
    OPENFHE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  virtual void EvalAddInPlace(Ciphertext<Element> &ciphertext, ConstPlaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        OPENFHE_THROW(config_error, "Input plaintext is nullptr");

      m_LeveledSHE->EvalAddInPlace(ciphertext, plaintext);
      return;
    }
    OPENFHE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element> &ciphertext, Plaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        OPENFHE_THROW(config_error, "Input plaintext is nullptr");

      return m_LeveledSHE->EvalAddMutable(ciphertext, plaintext);
    }
    OPENFHE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  // TODO (dsuponit): commented the code below to avoid compiler errors
  //virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, const NativeInteger &constant) const {
  //  if (m_LeveledSHE) {
  //    if (!ciphertext)
  //      OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

  //    return m_LeveledSHE->EvalAdd(ciphertext, constant);
  //  }
  //  OPENFHE_THROW(config_error, "EvalAdd operation has not been enabled");
  //}

  virtual void EvalAddInPlace(Ciphertext<Element> &ciphertext, const NativeInteger &constant) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      m_LeveledSHE->EvalAddInPlace(ciphertext, constant);
      return;
    }
    OPENFHE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, double constant) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_LeveledSHE->EvalAdd(ciphertext, constant);
    }
    OPENFHE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  virtual void EvalAddInPlace(Ciphertext<Element> &ciphertext, double constant) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      m_LeveledSHE->EvalAddInPlace(ciphertext, constant);
      return;
    }
    OPENFHE_THROW(config_error, "EvalAdd operation has not been enabled");
  }

  /////////////////////////////////////////
  // SHE SUBTRACTION Wrapper
  /////////////////////////////////////////

  virtual Ciphertext<Element> EvalSub(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");

      return m_LeveledSHE->EvalSub(ciphertext1, ciphertext2);
    }
    OPENFHE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual void EvalSubInPlace(Ciphertext<Element> &ciphertext1, ConstCiphertext<Element> ciphertext2) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");

      m_LeveledSHE->EvalSubInPlace(ciphertext1, ciphertext2);
      return;
    }
    OPENFHE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSubMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");

      return m_LeveledSHE->EvalSubMutable(ciphertext1, ciphertext2);
    }
    OPENFHE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        OPENFHE_THROW(config_error, "Input plaintext is nullptr");

      return m_LeveledSHE->EvalSub(ciphertext, plaintext);
    }
    OPENFHE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual void EvalSubInPlace(Ciphertext<Element> ciphertext, ConstPlaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        OPENFHE_THROW(config_error, "Input plaintext is nullptr");

      m_LeveledSHE->EvalSubInPlace(ciphertext, plaintext);
      return;
    }
    OPENFHE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element> &ciphertext, Plaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        OPENFHE_THROW(config_error, "Input plaintext is nullptr");

      return m_LeveledSHE->EvalSubMutable(ciphertext, plaintext);
    }
    OPENFHE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, const NativeInteger &constant) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_LeveledSHE->EvalSub(ciphertext, constant);
    }
    OPENFHE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual void EvalSubInPlace(Ciphertext<Element> &ciphertext, const NativeInteger &constant) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      m_LeveledSHE->EvalSubInPlace(ciphertext, constant);
      return;
    }
    OPENFHE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, double constant) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_LeveledSHE->EvalSub(ciphertext, constant);
    }
    OPENFHE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  virtual void EvalSubInPlace(Ciphertext<Element> &ciphertext, double constant) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      m_LeveledSHE->EvalSubInPlace(ciphertext, constant);
      return;
    }
    OPENFHE_THROW(config_error, "EvalSub operation has not been enabled");
  }

  /////////////////////////////////////////
  // SHE MULTIPLICATION Wrapper
  /////////////////////////////////////////

  virtual EvalKey<Element> EvalMultKeyGen(const PrivateKey<Element> privateKey) const {
    if (m_LeveledSHE) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      auto evalKey = m_LeveledSHE->EvalMultKeyGen(privateKey);
      evalKey->SetKeyTag(privateKey->GetKeyTag());
      return evalKey;
    }
    OPENFHE_THROW(config_error,
                   "EvalMultKeyGen operation has not been enabled");
  }

  virtual std::vector<EvalKey<Element>> EvalMultKeysGen(const PrivateKey<Element> privateKey) const {
    if (m_LeveledSHE) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      auto evalKeyVec = m_LeveledSHE->EvalMultKeysGen(privateKey);
      for (auto &evalKey : evalKeyVec)
        evalKey->SetKeyTag(privateKey->GetKeyTag());
      return evalKeyVec;
    }
    OPENFHE_THROW(config_error,
                   "EvalMultKeysGen operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMult(
      ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");

      return m_LeveledSHE->EvalMult(ciphertext1, ciphertext2);
    }
    OPENFHE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMultMutable(
      Ciphertext<Element> &ciphertext1,
      Ciphertext<Element> &ciphertext2) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");

      return m_LeveledSHE->EvalMultMutable(ciphertext1, ciphertext2);
    }
    OPENFHE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
                                       ConstCiphertext<Element> ciphertext2,
                                       const EvalKey<Element> evalKey) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
      if (!evalKey)
        OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

      return m_LeveledSHE->EvalMult(ciphertext1, ciphertext2, evalKey);
    }
    OPENFHE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMultMutable(
      Ciphertext<Element> &ciphertext1, Ciphertext<Element> &ciphertext2,
      const EvalKey<Element> evalKey) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
      if (!evalKey)
        OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

      return m_LeveledSHE->EvalMultMutable(ciphertext1, ciphertext2, evalKey);
    }
    OPENFHE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMultAndRelinearize(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2,
      const std::vector<EvalKey<Element>> &evalKeyVec) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
      if (!evalKeyVec.size())
        OPENFHE_THROW(config_error, "Input evaluation key vector is empty");

      return m_LeveledSHE->EvalMultAndRelinearize(ciphertext1, ciphertext2,
                                                  evalKeyVec);
    }
    OPENFHE_THROW(config_error,
                   "EvalMultAndRelinearize operation has not been enabled");
  }

  virtual Ciphertext<Element> Relinearize(
      ConstCiphertext<Element> ciphertext,
      const std::vector<EvalKey<Element>> &evalKeyVec) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKeyVec.size())
        OPENFHE_THROW(config_error, "Input evaluation key vector is empty");

      return m_LeveledSHE->Relinearize(ciphertext, evalKeyVec);
    }
    OPENFHE_THROW(config_error, "Relinearize operation has not been enabled");
  }

  virtual void RelinearizeInPlace(
      Ciphertext<Element> &ciphertext,
      const std::vector<EvalKey<Element>> &evalKeyVec) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKeyVec.size())
        OPENFHE_THROW(config_error, "Input evaluation key vector is empty");

      m_LeveledSHE->RelinearizeInPlace(ciphertext, evalKeyVec);
      return;
    }
    OPENFHE_THROW(config_error,
                   "RelinearizeInPlace operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        OPENFHE_THROW(config_error, "Input plaintext is nullptr");

      return m_LeveledSHE->EvalMult(ciphertext, plaintext);
    }
    OPENFHE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual void EvalMultInPlace(Ciphertext<Element> &ciphertext, ConstPlaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        OPENFHE_THROW(config_error, "Input plaintext is nullptr");
      m_LeveledSHE->EvalMultInPlace(ciphertext, plaintext);
      return;
    }
    OPENFHE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element> &ciphertext, Plaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!plaintext)
        OPENFHE_THROW(config_error, "Input plaintext is nullptr");

      return m_LeveledSHE->EvalMultMutable(ciphertext, plaintext);
    }
    OPENFHE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  // TODO (dsuponit): commented the code below to avoid compiler errors
  //virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext,
  //                                     const NativeInteger &constant) const {
  //  if (m_LeveledSHE) {
  //    if (!ciphertext)
  //      OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

  //    return m_LeveledSHE->EvalMult(ciphertext, constant);
  //  }
  //  OPENFHE_THROW(config_error, "EvalMult operation has not been enabled");
  //}

  // TODO (dsuponit): commented the code below to avoid compiler errors
  //virtual void EvalMultInPlace(Ciphertext<Element> &ciphertext, const NativeInteger &constant) const {
  //  if (m_LeveledSHE) {
  //    if (!ciphertext)
  //      OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

  //    m_LeveledSHE->EvalMultInPlace(ciphertext, constant);
  //    return;
  //  }
  //  OPENFHE_THROW(config_error, "EvalMult operation has not been enabled");
  //}

  virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, double constant) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_LeveledSHE->EvalMult(ciphertext, constant);
    }
    OPENFHE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  virtual void EvalMultInPlace(Ciphertext<Element> &ciphertext, double constant) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      m_LeveledSHE->EvalMultInPlace(ciphertext, constant);
      return;
    }
    OPENFHE_THROW(config_error, "EvalMult operation has not been enabled");
  }

  /////////////////////////////////////////
  // SHE AUTOMORPHISM Wrapper
  /////////////////////////////////////////

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAutomorphismKeyGen(
      const PrivateKey<Element> privateKey,
      const std::vector<usint> &indexList) const {
    if (m_LeveledSHE) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      auto evalKeyMap =
          m_LeveledSHE->EvalAutomorphismKeyGen(privateKey, indexList);
      for (auto &key : *evalKeyMap)
        key.second->SetKeyTag(privateKey->GetKeyTag());
      return evalKeyMap;
    }
    OPENFHE_THROW(config_error,
                   "EvalAutomorphismKeyGen operation has not been enabled");
  }

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAutomorphismKeyGen(
      const PublicKey<Element> publicKey,
      const PrivateKey<Element> privateKey,
      const std::vector<usint> &indexList) const {
    if (m_LeveledSHE) {
      if (!publicKey)
        OPENFHE_THROW(config_error, "Input public key is nullptr");
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      auto evalKeyMap = m_LeveledSHE->EvalAutomorphismKeyGen(
          publicKey, privateKey, indexList);
      for (auto &key : *evalKeyMap)
        key.second->SetKeyTag(privateKey->GetKeyTag());
      return evalKeyMap;
    }
    OPENFHE_THROW(config_error,
                   "EvalAutomorphismKeyGen operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAutomorphism(
      ConstCiphertext<Element> ciphertext, usint i,
      const std::map<usint, EvalKey<Element>> &evalKeyMap,
      CALLER_INFO_ARGS_HDR) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKeyMap.size())
        OPENFHE_THROW(config_error, "Input evaluation key map is empty");

      return m_LeveledSHE->EvalAutomorphism(ciphertext, i, evalKeyMap);
    }
    std::string errorMsg(
        std::string("EvalAutomorphism operation has not been enabled") +
        CALLER_INFO);
    OPENFHE_THROW(config_error, errorMsg);
  }

  virtual std::shared_ptr<std::vector<Element>> EvalFastRotationPrecompute(ConstCiphertext<Element> ciphertext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_LeveledSHE->EvalFastRotationPrecompute(ciphertext);
    }
    OPENFHE_THROW(config_error,
                   "EvalFastRotationPrecompute operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalFastRotation(
      ConstCiphertext<Element> ciphertext, const usint index, const usint m,
      const std::shared_ptr<std::vector<Element>> digits) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_LeveledSHE->EvalFastRotation(ciphertext, index, m, digits);
    }
    OPENFHE_THROW(config_error,
                   "EvalFastRotation operation has not been enabled");
  }

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAtIndexKeyGen(
      const PublicKey<Element> publicKey,
      const PrivateKey<Element> privateKey,
      const std::vector<int32_t> &indexList) const {
    if (m_LeveledSHE) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      auto evalKeyMap = m_LeveledSHE->EvalAtIndexKeyGen(publicKey, privateKey, indexList);
      for (auto &key : *evalKeyMap)
        key.second->SetKeyTag(privateKey->GetKeyTag());
      return evalKeyMap;
    }
    OPENFHE_THROW(config_error,
                   "EvalAtIndexKeyGen operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAtIndex(
      ConstCiphertext<Element> ciphertext, usint i,
      const std::map<usint, EvalKey<Element>> &evalKeyMap) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKeyMap.size())
        OPENFHE_THROW(config_error, "Input evaluation key map is empty");

      return m_LeveledSHE->EvalAtIndex(ciphertext, i, evalKeyMap);
    }
    OPENFHE_THROW(config_error, "EvalAtIndex operation has not been enabled");
  }

  /////////////////////////////////////////
  // SHE Leveled Methods Wrapper
  /////////////////////////////////////////

  virtual Ciphertext<Element> ComposedEvalMult(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2,
      const EvalKey<Element> evalKey) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
      if (!evalKey)
        OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

      auto result =
          m_LeveledSHE->ComposedEvalMult(ciphertext1, ciphertext2, evalKey);
      result->SetKeyTag(evalKey->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error,
                   "ComposedEvalMult operation has not been enabled");
  }

  virtual Ciphertext<Element> ModReduce(ConstCiphertext<Element> ciphertext, size_t levels) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      auto result = m_LeveledSHE->ModReduce(ciphertext, levels);
      result->SetKeyTag(ciphertext->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error, "ModReduce operation has not been enabled");
  }

  virtual void ModReduceInPlace(Ciphertext<Element> &ciphertext, size_t levels) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      m_LeveledSHE->ModReduceInPlace(ciphertext, levels);
      return;
    }
    OPENFHE_THROW(config_error, "ModReduce operation has not been enabled");
  }

  virtual Ciphertext<Element> ModReduceInternal(ConstCiphertext<Element> ciphertext, size_t levels) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_LeveledSHE->ModReduceInternal(ciphertext, levels);
    }
    OPENFHE_THROW(config_error,
                   "ModReduceInternal has not been enabled for this scheme.");
  }

  virtual void ModReduceInternalInPlace(Ciphertext<Element> &ciphertext, size_t levels) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      m_LeveledSHE->ModReduceInternalInPlace(ciphertext, levels);
      return;
    }
    OPENFHE_THROW(
        config_error,
        "ModReduceInternalInPlace has not been enabled for this scheme.");
  }

  virtual Ciphertext<Element> LevelReduce(ConstCiphertext<Element> ciphertext,
                                          const EvalKey<Element> evalKey,
                                          size_t levels = 1) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      auto result = m_LeveledSHE->LevelReduce(ciphertext, evalKey, levels);
      result->SetKeyTag(ciphertext->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error, "LevelReduce operation has not been enabled");
  }

  virtual void LevelReduceInPlace(Ciphertext<Element> &ciphertext,
                                          const EvalKey<Element> evalKey,
                                          size_t levels = 1) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      m_LeveledSHE->LevelReduceInPlace(ciphertext, evalKey, levels);
      return;
    }
    OPENFHE_THROW(config_error, "LevelReduce operation has not been enabled");
  }

  virtual Ciphertext<Element> LevelReduceInternal(ConstCiphertext<Element> ciphertext, size_t levels) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_LeveledSHE->LevelReduceInternal(ciphertext, levels);
    }
    OPENFHE_THROW(not_implemented_error, "LevelReduceInternal has not been enabled for this scheme.");
  }

  virtual void LevelReduceInternalInPlace(Ciphertext<Element> &ciphertext, size_t levels) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      m_LeveledSHE->LevelReduceInternalInPlace(ciphertext, levels);
      return;
    }
    OPENFHE_THROW(not_implemented_error, "LevelReduceInternalInPlace has not been enabled for this scheme.");
  }

  virtual Ciphertext<Element> Compress(ConstCiphertext<Element> ciphertext, size_t towersLeft) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_LeveledSHE->Compress(ciphertext, towersLeft);
    }
    OPENFHE_THROW(config_error,
                   "Compress has not been enabled for this scheme.");
  }

  virtual void AdjustLevelsInPlace(Ciphertext<DCRTPoly> &ciphertext1, Ciphertext<DCRTPoly> &ciphertext2) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input ciphertext1 is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input ciphertext2 is nullptr");

      return m_LeveledSHE->AdjustLevelsInPlace(ciphertext1, ciphertext2);
    }
    OPENFHE_THROW(config_error,
                   "Compress has not been enabled for this scheme.");

  }

  virtual void AdjustLevelsAndDepthInPlace(Ciphertext<DCRTPoly> &ciphertext1,
                                   Ciphertext<DCRTPoly> &ciphertext2) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input ciphertext1 is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input ciphertext2 is nullptr");

      return m_LeveledSHE->AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);
    }
  }

  virtual void AdjustLevelsAndDepthToOneInPlace(Ciphertext<DCRTPoly> &ciphertext1,
                                   Ciphertext<DCRTPoly> &ciphertext2) const {
    if (m_LeveledSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input ciphertext1 is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input ciphertext2 is nullptr");

      return m_LeveledSHE->AdjustLevelsAndDepthToOneInPlace(ciphertext1, ciphertext2);
    }
  }

  virtual DCRTPoly AdjustLevelsInPlace(Ciphertext<DCRTPoly> &ciphertext, ConstPlaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext1 is nullptr");

      return m_LeveledSHE->AdjustLevelsInPlace(ciphertext, plaintext);
    }
    OPENFHE_THROW(config_error,
                       "AdjustLevelsInPlace has not been enabled for this scheme.");
  }

  virtual DCRTPoly AdjustLevelsAndDepthInPlace(Ciphertext<DCRTPoly> &ciphertext,
      ConstPlaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext1 is nullptr");

      return m_LeveledSHE->AdjustLevelsAndDepthInPlace(ciphertext, plaintext);
    }
    OPENFHE_THROW(config_error,
                       "AdjustLevelsAndDepthInPlace has not been enabled for this scheme.");
  }

  virtual DCRTPoly AdjustLevelsAndDepthToOneInPlace(Ciphertext<DCRTPoly> &ciphertext,
      ConstPlaintext plaintext) const {
    if (m_LeveledSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext1 is nullptr");

      return m_LeveledSHE->AdjustLevelsAndDepthToOneInPlace(ciphertext, plaintext);
    }
    OPENFHE_THROW(config_error,
                           "AdjustLevelsAndDepthToOneInPlace has not been enabled for this scheme.");
  }

  /////////////////////////////////////////
  // Advanced SHE Wrapper
  /////////////////////////////////////////

  virtual Ciphertext<Element> EvalAddMany(const std::vector<Ciphertext<Element>> &ciphertextVec) const {
    if (m_AdvancedSHE) {
      if (!ciphertextVec.size())
        OPENFHE_THROW(config_error, "Input ciphertext vector is empty");

      return m_AdvancedSHE->EvalAddMany(ciphertextVec);
    }
    OPENFHE_THROW(config_error, "EvalAddMany operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalAddManyInPlace(std::vector<Ciphertext<Element>> &ciphertextVec) const {
    if (m_AdvancedSHE) {
      if (!ciphertextVec.size())
        OPENFHE_THROW(config_error, "Input ciphertext vector is empty");

      return m_AdvancedSHE->EvalAddManyInPlace(ciphertextVec);
    }
    OPENFHE_THROW(config_error,
                   "EvalAddManyInPlace operation has not been enabled");
  }

  virtual Ciphertext<Element> AddRandomNoise(ConstCiphertext<Element> ciphertext) const {
    if (m_AdvancedSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_AdvancedSHE->AddRandomNoise(ciphertext);
    }
    OPENFHE_THROW(config_error,
                   "AddRandomNoise operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalLinearWSum(
      std::vector<ConstCiphertext<Element>>& ciphertextVec,
      const std::vector<double> &constantVec) const {
    if (m_AdvancedSHE) {
      if (!ciphertextVec.size())
        OPENFHE_THROW(config_error, "Input ciphertext vector is empty");

      return m_AdvancedSHE->EvalLinearWSum(ciphertextVec, constantVec);
    }
    OPENFHE_THROW(config_error,
                   "EvalLinearWSum operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalLinearWSumMutable(
      std::vector<Ciphertext<Element>> ciphertextVec,
      const std::vector<double> &constantVec) const {
    if (m_AdvancedSHE) {
      if (!ciphertextVec.size())
        OPENFHE_THROW(config_error, "Input ciphertext vector is empty");

      return m_AdvancedSHE->EvalLinearWSumMutable(ciphertextVec, constantVec);
    }
    OPENFHE_THROW(config_error,
                   "EvalLinearWSumMutable operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMultMany(
      const std::vector<Ciphertext<Element>> &ciphertextVec,
      const std::vector<EvalKey<Element>> &evalKeyVec) const {
    if (m_AdvancedSHE) {
      if (!ciphertextVec.size())
        OPENFHE_THROW(config_error, "Input ciphertext vector is empty");
      if (!evalKeyVec.size())
        OPENFHE_THROW(config_error, "Input evaluation key vector is empty");

      return m_AdvancedSHE->EvalMultMany(ciphertextVec, evalKeyVec);
    }
    OPENFHE_THROW(config_error, "EvalMultMany operation has not been enabled");
  }

  Ciphertext<Element> EvalPoly(ConstCiphertext<Element> ciphertext, const std::vector<double> &coefficients) const {
    if (m_AdvancedSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

      return m_AdvancedSHE->EvalPoly(ciphertext, coefficients);
    } else {
      OPENFHE_THROW(config_error, "EvalPoly operation has not been enabled");
    }
  }

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumKeyGen(
      const PrivateKey<Element> privateKey,
      const PublicKey<Element> publicKey) const {
    if (m_AdvancedSHE) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      auto evalKeyMap = m_AdvancedSHE->EvalSumKeyGen(privateKey, publicKey);
      for (auto &key : *evalKeyMap) {
        key.second->SetKeyTag(privateKey->GetKeyTag());
      }
      return evalKeyMap;
    }
    OPENFHE_THROW(config_error,
                   "EvalSumKeyGen operation has not been enabled");
  }

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumRowsKeyGen(
      const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey,
      usint rowSize, usint subringDim = 0) const {
    if (m_AdvancedSHE) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      auto evalKeyMap = m_AdvancedSHE->EvalSumRowsKeyGen(privateKey, publicKey,
                                                         rowSize, subringDim);
      for (auto &key : *evalKeyMap) {
        key.second->SetKeyTag(privateKey->GetKeyTag());
      }
      return evalKeyMap;
    }
    OPENFHE_THROW(config_error,
                   "EvalSumRowsKeyGen operation has not been enabled");
  }

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumColsKeyGen(
      const PrivateKey<Element> privateKey,
      const PublicKey<Element> publicKey) const {
    if (m_AdvancedSHE) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");

      auto evalKeyMap = m_AdvancedSHE->EvalSumColsKeyGen(privateKey, publicKey);
      for (auto &key : *evalKeyMap) {
        key.second->SetKeyTag(privateKey->GetKeyTag());
      }
      return evalKeyMap;
    }
    OPENFHE_THROW(config_error,
                   "EvalSumColsKeyGen operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSum(
      ConstCiphertext<Element> ciphertext, usint batchSize,
      const std::map<usint, EvalKey<Element>> &evalKeyMap) const {
    if (m_AdvancedSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKeyMap.size())
        OPENFHE_THROW(config_error, "Input evaluation key map is empty");

      return m_AdvancedSHE->EvalSum(ciphertext, batchSize, evalKeyMap);
    }
    OPENFHE_THROW(config_error, "EvalSum operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSumRows(
      ConstCiphertext<Element> ciphertext, usint rowSize,
      const std::map<usint, EvalKey<Element>> &evalKeyMap,
      usint subringDim = 0) const {
    if (m_AdvancedSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
      if (!evalKeyMap.size())
        OPENFHE_THROW(config_error, "Input evaluation key map is empty");

      return m_AdvancedSHE->EvalSumRows(ciphertext, rowSize, evalKeyMap,
                                        subringDim);
    }
    OPENFHE_THROW(config_error, "EvalSumRow operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalSumCols(
      ConstCiphertext<Element> ciphertext, usint batchSize,
      const std::map<usint, EvalKey<Element>> &evalKeyMap,
      const std::map<usint, EvalKey<Element>> &rightEvalKeyMap) const {
    if (m_AdvancedSHE) {
      if (!evalKeyMap.size())
        OPENFHE_THROW(config_error, "Input first evaluation key map is empty");
      if (!rightEvalKeyMap.size())
        OPENFHE_THROW(config_error,
                       "Input second evaluation key map is empty");

      return m_AdvancedSHE->EvalSumCols(ciphertext, batchSize, evalKeyMap,
                                        rightEvalKeyMap);
    }
    OPENFHE_THROW(config_error, "EvalSumCols operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalInnerProduct(
      ConstCiphertext<Element> ciphertext1,
      ConstCiphertext<Element> ciphertext2, usint batchSize,
      const std::map<usint, EvalKey<Element>> &evalSumKeyMap,
      const EvalKey<Element> evalMultKey) const {
    if (m_AdvancedSHE) {
      if (!ciphertext1)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!ciphertext2)
        OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
      if (!evalSumKeyMap.size())
        OPENFHE_THROW(config_error, "Input evaluation key map is empty");
      if (!evalMultKey)
        OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

      auto result = m_AdvancedSHE->EvalInnerProduct(
          ciphertext1, ciphertext2, batchSize, evalSumKeyMap, evalMultKey);
      result->SetKeyTag(evalSumKeyMap.begin()->second->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error,
                   "EvalInnerProduct operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalInnerProduct(
      ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext,
      usint batchSize,
      const std::map<usint, EvalKey<Element>> &evalSumKeyMap) const {
    if (m_AdvancedSHE) {
      if (!ciphertext)
        OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
      if (!plaintext)
        OPENFHE_THROW(config_error, "Input plaintext is nullptr");
      if (!evalSumKeyMap.size())
        OPENFHE_THROW(config_error, "Input evaluation key map is empty");

      return m_AdvancedSHE->EvalInnerProduct(ciphertext, plaintext, batchSize,
                                             evalSumKeyMap);
    }
    OPENFHE_THROW(config_error,
                   "EvalInnerProduct operation has not been enabled");
  }

  virtual Ciphertext<Element> EvalMerge(
      const std::vector<Ciphertext<Element>> &ciphertextVec,
      const std::map<usint, EvalKey<Element>> &evalKeyMap) const {
    if (m_AdvancedSHE) {
      if (!ciphertextVec.size())
        OPENFHE_THROW(config_error, "Input ciphertext vector is empty");
      if (!evalKeyMap.size())
        OPENFHE_THROW(config_error, "Input evaluation key map is empty");

      return m_AdvancedSHE->EvalMerge(ciphertextVec, evalKeyMap);
    }
    OPENFHE_THROW(config_error, "EvalMerge operation has not been enabled");
  }

  /////////////////////////////////////////
  // MULTIPARTY WRAPPER
  /////////////////////////////////////////

  virtual KeyPair<Element> MultipartyKeyGen(
      CryptoContext<Element> cc,
      const std::vector<PrivateKey<Element>> &privateKeyVec, bool makeSparse) {
    if (m_Multiparty) {
      if (!cc) OPENFHE_THROW(config_error, "Input crypto context is nullptr");
      if (!privateKeyVec.size())
        OPENFHE_THROW(config_error, "Input private key vector is empty");

      auto keyPair =
          m_Multiparty->MultipartyKeyGen(cc, privateKeyVec, makeSparse);
      keyPair.publicKey->SetKeyTag(keyPair.secretKey->GetKeyTag());
      return keyPair;
    }
    OPENFHE_THROW(config_error,
                   "MultipartyKeyGen operation has not been enabled");
  }

  virtual KeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
                                            const PublicKey<Element> publicKey,
                                            bool makeSparse, bool PRE) {
    if (m_Multiparty) {
      if (!cc) OPENFHE_THROW(config_error, "Input crypto context is nullptr");
      if (!publicKey) OPENFHE_THROW(config_error, "Input public key is empty");

      auto keyPair =
          m_Multiparty->MultipartyKeyGen(cc, publicKey, makeSparse, PRE);
      keyPair.publicKey->SetKeyTag(keyPair.secretKey->GetKeyTag());
      return keyPair;
    }
    OPENFHE_THROW(config_error,
                   "MultipartyKeyGen operation has not been enabled");
  }

  virtual Ciphertext<Element> MultipartyDecryptMain(
      ConstCiphertext<Element> ciphertext,
      const PrivateKey<Element> privateKey) const {
    if (m_Multiparty) {
      CheckMultipartyDecryptCompatibility(ciphertext);

      auto result = m_Multiparty->MultipartyDecryptMain(ciphertext, privateKey);
      result->SetKeyTag(privateKey->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error,
                   "MultipartyDecryptMain operation has not been enabled");
  }

  virtual Ciphertext<Element> MultipartyDecryptLead(
      ConstCiphertext<Element> ciphertext,
      const PrivateKey<Element> privateKey) const {
    if (m_Multiparty) {
      CheckMultipartyDecryptCompatibility(ciphertext);

      auto result = m_Multiparty->MultipartyDecryptLead(ciphertext, privateKey);
      result->SetKeyTag(privateKey->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error,
                   "MultipartyDecryptLead operation has not been enabled");
  }

  virtual DecryptResult MultipartyDecryptFusion(
      const std::vector<Ciphertext<Element>> &ciphertextVec,
      NativePoly *plaintext) const {
    if (m_Multiparty) {
      if (!ciphertextVec.size())
        OPENFHE_THROW(config_error, "Input ciphertext vector is empty");

      return m_Multiparty->MultipartyDecryptFusion(ciphertextVec, plaintext);
    }
    OPENFHE_THROW(config_error,
                   "MultipartyDecrypt operation has not been enabled");
  }

  virtual DecryptResult MultipartyDecryptFusion(
      const std::vector<Ciphertext<Element>> &ciphertextVec, Poly *plaintext) const {
    if (m_Multiparty) {
      if (!ciphertextVec.size())
        OPENFHE_THROW(config_error, "Input ciphertext vector is empty");

      return m_Multiparty->MultipartyDecryptFusion(ciphertextVec, plaintext);
    }
    OPENFHE_THROW(config_error,
                   "MultipartyDecrypt operation has not been enabled");
  }

  virtual EvalKey<Element> MultiKeySwitchGen(
      const PrivateKey<Element> oldPrivateKey,
      const PrivateKey<Element> newPrivateKey,
      const EvalKey<Element> evalKey) const {
    if (m_Multiparty) {
      if (!oldPrivateKey)
        OPENFHE_THROW(config_error, "Input first private key is nullptr");
      if (!newPrivateKey)
        OPENFHE_THROW(config_error, "Input second private key is nullptr");
      if (!evalKey)
        OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

      auto result = m_Multiparty->MultiKeySwitchGen(oldPrivateKey,
                                                    newPrivateKey, evalKey);
      result->SetKeyTag(newPrivateKey->GetKeyTag());
      return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>>
  MultiEvalAutomorphismKeyGen(
      const PrivateKey<Element> privateKey,
      const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalAutoKeyMap,
      const std::vector<usint> &indexList, const std::string &keyId = "") {
    if (m_Multiparty) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");
      if (!evalAutoKeyMap)
        OPENFHE_THROW(config_error, "Input evaluation key map is nullptr");
      if (!indexList.size())
        OPENFHE_THROW(config_error, "Input index vector is empty");

      auto result = m_Multiparty->MultiEvalAutomorphismKeyGen(
          privateKey, evalAutoKeyMap, indexList);
      for (auto &key : *result) {
        if (key.second) {
          key.second->SetKeyTag(keyId);
        }
      }
      return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalAtIndexKeyGen(
      const PrivateKey<Element> privateKey,
      const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalAutoKeyMap,
      const std::vector<int32_t> &indexList, const std::string &keyId = "") {
    if (m_Multiparty) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");
      if (!evalAutoKeyMap)
        OPENFHE_THROW(config_error, "Input evaluation key map is nullptr");
      if (!indexList.size())
        OPENFHE_THROW(config_error, "Input index vector is empty");

      auto result = m_Multiparty->MultiEvalAtIndexKeyGen(
          privateKey, evalAutoKeyMap, indexList);
      for (auto &key : *result) {
        if (key.second) {
          key.second->SetKeyTag(keyId);
        }
      }
      return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalSumKeyGen(
      const PrivateKey<Element> privateKey,
      const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap,
      const std::string &keyId = "") {
    if (m_Multiparty) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");
      if (!evalSumKeyMap)
        OPENFHE_THROW(config_error, "Input evaluation key map is nullptr");

      auto result = m_Multiparty->MultiEvalSumKeyGen(privateKey, evalSumKeyMap);
      for (auto &key : *result) {
        if (key.second) {
          key.second->SetKeyTag(keyId);
        }
      }
      return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual EvalKey<Element> MultiAddEvalKeys(EvalKey<Element> evalKey1,
                                            EvalKey<Element> evalKey2,
                                            const std::string &keyId = "") {
    if (m_Multiparty) {
      if (!evalKey1)
        OPENFHE_THROW(config_error, "Input first evaluation key is nullptr");
      if (!evalKey2)
        OPENFHE_THROW(config_error, "Input second evaluation key is nullptr");

      auto evalKeySum = m_Multiparty->MultiAddEvalKeys(evalKey1, evalKey2);
      evalKeySum->SetKeyTag(keyId);
      return evalKeySum;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual EvalKey<Element> MultiMultEvalKey(PrivateKey<Element> privateKey,
                                            EvalKey<Element> evalKey,
                                            const std::string &keyId = "") {
    if (m_Multiparty) {
      if (!privateKey)
        OPENFHE_THROW(config_error, "Input private key is nullptr");
      if (!evalKey)
        OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

      auto result = m_Multiparty->MultiMultEvalKey(privateKey, evalKey);
      result->SetKeyTag(keyId);
      return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiAddEvalSumKeys(
      const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap1,
      const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap2,
      const std::string &keyId = "") {
    if (m_Multiparty) {
      if (!evalSumKeyMap1)
        OPENFHE_THROW(config_error,
                       "Input first evaluation key map is nullptr");
      if (!evalSumKeyMap2)
        OPENFHE_THROW(config_error,
                       "Input second evaluation key map is nullptr");

      auto result =
          m_Multiparty->MultiAddEvalSumKeys(evalSumKeyMap1, evalSumKeyMap2);
      for (auto &key : *result) {
        if (key.second) {
          key.second->SetKeyTag(keyId);
        }
      }
      return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual std::shared_ptr<std::map<usint, EvalKey<Element>>>
  MultiAddEvalAutomorphismKeys(
      const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap1,
      const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap2,
      const std::string &keyId = "") {
    if (m_Multiparty) {
      if (!evalSumKeyMap1)
        OPENFHE_THROW(config_error,
                       "Input first evaluation key map is nullptr");
      if (!evalSumKeyMap2)
        OPENFHE_THROW(config_error,
                       "Input second evaluation key map is nullptr");

      auto result = m_Multiparty->MultiAddEvalAutomorphismKeys(evalSumKeyMap1,
                                                               evalSumKeyMap2);
      for (auto &key : *result) {
        if (key.second) {
          key.second->SetKeyTag(keyId);
        }
      }
      return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual PublicKey<Element> MultiAddPubKeys(PublicKey<Element> publicKey1,
                                             PublicKey<Element> publicKey2,
                                             const std::string &keyId = "") {
    if (m_Multiparty) {
      if (!publicKey1)
        OPENFHE_THROW(config_error, "Input first public key is nullptr");
      if (!publicKey2)
        OPENFHE_THROW(config_error, "Input second public key is nullptr");

      auto publicKeySum = m_Multiparty->MultiAddPubKeys(publicKey1, publicKey2);
      publicKeySum->SetKeyTag(keyId);
      return publicKeySum;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  virtual EvalKey<Element> MultiAddEvalMultKeys(EvalKey<Element> evalKey1,
                                                EvalKey<Element> evalKey2,
                                                const std::string &keyId = "") {
    if (m_Multiparty) {
      if (!evalKey1)
        OPENFHE_THROW(config_error, "Input first evaluation key is nullptr");
      if (!evalKey2)
        OPENFHE_THROW(config_error, "Input second evaluation key is nullptr");

      auto evalKeySum = m_Multiparty->MultiAddEvalMultKeys(evalKey1, evalKey2);
      evalKeySum->SetKeyTag(keyId);
      return evalKeySum;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
  }

  const std::shared_ptr<PKEBase<Element>> getAlgorithm() const { return m_PKE; }

  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {
    ar(::cereal::make_nvp("enabled", GetEnabled()));
  }

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {
    if (version > SerializedVersion()) {
      OPENFHE_THROW(deserialize_error,
                     "serialized object version " + std::to_string(version) +
                         " is from a later version of the library");
    }

    usint enabled;
    ar(::cereal::make_nvp("enabled", enabled));
    this->Enable(enabled);
  }

  virtual std::string SerializedObjectName() const { return "SchemeBase"; }

  static uint32_t SerializedVersion() { return 1; }

  friend std::ostream &operator<<(std::ostream &out,
                                  const SchemeBase<Element> &s) {
    out << typeid(s).name() << ":";
    out << " ParamsGen "
        << (s.m_ParamsGen == 0 ? "none" : typeid(*s.m_ParamsGen).name());
    out << ", PKE " << (s.m_PKE == 0 ? "none" : typeid(*s.m_PKE).name());
    out << ", KeySwitch "
        << (s.m_KeySwitch == 0 ? "none" : typeid(*s.m_KeySwitch).name());
    out << ", PRE " << (s.m_PRE == 0 ? "none" : typeid(*s.m_PRE).name());
    out << ", LeveledSHE "
        << (s.m_LeveledSHE == 0 ? "none" : typeid(*s.m_LeveledSHE).name());
    out << ", AdvancedSHE "
        << (s.m_AdvancedSHE == 0 ? "none" : typeid(*s.m_AdvancedSHE).name());
    out << ", Multiparty "
        << (s.m_Multiparty == 0 ? "none" : typeid(*s.m_Multiparty).name());
    return out;
  }

 protected:
  std::shared_ptr<ParameterGenerationBase<Element>> m_ParamsGen;
  std::shared_ptr<PKEBase<Element>> m_PKE;
  std::shared_ptr<KeySwitchBase<Element>> m_KeySwitch;
  std::shared_ptr<PREBase<Element>> m_PRE;
  std::shared_ptr<LeveledSHEBase<Element>> m_LeveledSHE;
  std::shared_ptr<AdvancedSHEBase<Element>> m_AdvancedSHE;
  std::shared_ptr<MultipartyBase<Element>> m_Multiparty;
};

}  // namespace lbcrypto

#endif
