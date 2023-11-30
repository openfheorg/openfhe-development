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

#include "key/evalkey-fwd.h"
#include "schemebase/base-parametergeneration.h"
#include "keyswitch/keyswitch-base.h"
#include "schemebase/base-advancedshe.h"
#include "schemebase/base-leveledshe.h"
#include "schemebase/base-multiparty.h"
#include "schemebase/base-fhe.h"
#include "schemebase/base-pke.h"
#include "schemebase/base-pre.h"
#include "ciphertext.h"

#include "key/keypair.h"

#include "utils/exception.h"
#include "utils/caller_info.h"

#include <vector>
#include <map>
#include <string>
#include <memory>
#include <utility>

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

template <typename Element>
class KeyPair;

// TODO: fix DCRTPoly passed by value

/**
 * @brief Abstract interface for public key encryption schemes
 * @tparam Element a ring element.
 */
template <typename Element>
class SchemeBase {
    using ParmType = typename Element::Params;
    using IntType  = typename Element::Integer;
    using DugType  = typename Element::DugType;
    using DggType  = typename Element::DggType;
    using TugType  = typename Element::TugType;

protected:
    inline void CheckMultipartyDecryptCompatibility(ConstCiphertext<Element>& ciphertext, CALLER_INFO_ARGS_HDR) const {
        if (ciphertext->GetElements().size() > 2) {
            std::string errorMsg(std::string("ciphertext's number of elements is [") +
                                 std::to_string(ciphertext->GetElements().size()) +
                                 "]. Must be 2 or less for Multiparty Decryption." + CALLER_INFO);
            OPENFHE_THROW(openfhe_error, errorMsg);
        }
    }

public:
    SchemeBase() {}

    virtual ~SchemeBase() {}

    virtual bool operator==(const SchemeBase& sch) const {
        OPENFHE_THROW(config_error, "operator== is not supported");
    }

    virtual bool operator!=(const SchemeBase& sch) const {
        return !(*this == sch);
    }

    /**
   * Enable features with a bit mast of PKESchemeFeature codes
   * @param mask
   */
    void Enable(uint32_t mask) {
        if (mask & PKE)
            Enable(PKE);
        if (mask & KEYSWITCH)
            Enable(KEYSWITCH);
        if (mask & LEVELEDSHE)
            Enable(LEVELEDSHE);
        if (mask & ADVANCEDSHE)
            Enable(ADVANCEDSHE);
        if (mask & PRE)
            Enable(PRE);
        if (mask & MULTIPARTY)
            Enable(MULTIPARTY);
        if (mask & FHE)
            Enable(FHE);
        if (mask & SCHEMESWITCH)
            Enable(SCHEMESWITCH);
    }

    uint32_t GetEnabled() const {
        uint32_t flag = 0;
        if (m_PKE != nullptr)
            flag |= PKE;
        if (m_KeySwitch != nullptr)
            flag |= KEYSWITCH;
        if (m_LeveledSHE != nullptr)
            flag |= LEVELEDSHE;
        if (m_AdvancedSHE != nullptr)
            flag |= ADVANCEDSHE;
        if (m_PRE != nullptr)
            flag |= PRE;
        if (m_Multiparty != nullptr)
            flag |= MULTIPARTY;
        if (m_FHE != nullptr)
            flag |= FHE;
        if (m_SchemeSwitch != nullptr)
            flag |= SCHEMESWITCH;
        return flag;
    }

    bool IsFeatureEnabled(PKESchemeFeature feature) {
        switch (feature) {
            case PKE:
                if (m_PKE != nullptr)
                    return true;
                break;
            case KEYSWITCH:
                if (m_KeySwitch != nullptr)
                    return true;
                break;
            case LEVELEDSHE:
                if (m_LeveledSHE != nullptr)
                    return true;
                break;
            case ADVANCEDSHE:
                if (m_AdvancedSHE != nullptr)
                    return true;
                break;
            case PRE:
                if (m_PRE != nullptr)
                    return true;
                break;
            case MULTIPARTY:
                if (m_Multiparty != nullptr)
                    return true;
                break;
            case FHE:
                if (m_FHE != nullptr)
                    return true;
                break;
            case SCHEMESWITCH:
                if (m_SchemeSwitch != nullptr)
                    return true;
                break;
            default:
                OPENFHE_THROW(config_error, "Unknown PKESchemeFeature " + std::to_string(feature));
                break;
        }
        return false;
    }
    // instantiated in the scheme implementation class
    virtual void Enable(PKESchemeFeature feature) {
        OPENFHE_THROW(config_error, "Enable is not implemented");
    }

    //------------------------------------------------------------------------------
    // PARAMETER GENERATION WRAPPER
    //------------------------------------------------------------------------------

    virtual bool ParamsGenBFVRNS(std::shared_ptr<CryptoParametersBase<Element>> cryptoParams, uint32_t evalAddCount,
                                 uint32_t multiplicativeDepth, uint32_t keySwitchCount, size_t dcrtBits, uint32_t n,
                                 uint32_t numPartQ) const {
        if (!m_ParamsGen)
            OPENFHE_THROW(config_error, "m_ParamsGen is nullptr");
        return m_ParamsGen->ParamsGenBFVRNS(cryptoParams, evalAddCount, multiplicativeDepth, keySwitchCount, dcrtBits,
                                            n, numPartQ);
    }

    virtual bool ParamsGenCKKSRNS(std::shared_ptr<CryptoParametersBase<Element>> cryptoParams, usint cyclOrder,
                                  usint numPrimes, usint scalingModSize, usint firstModSize, uint32_t numPartQ,
                                  COMPRESSION_LEVEL mPIntBootCiphertextCompressionLevel) const {
        if (!m_ParamsGen)
            OPENFHE_THROW(config_error, "m_ParamsGen is nullptr");
        return m_ParamsGen->ParamsGenCKKSRNS(cryptoParams, cyclOrder, numPrimes, scalingModSize, firstModSize, numPartQ,
                                             mPIntBootCiphertextCompressionLevel);
    }

    virtual bool ParamsGenBGVRNS(std::shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams, uint32_t evalAddCount,
                                 uint32_t keySwitchCount, usint cyclOrder, usint numPrimes, usint firstModSize,
                                 usint dcrtBits, uint32_t numPartQ, usint multihopQBound) const {
        if (!m_ParamsGen)
            OPENFHE_THROW(config_error, "m_ParamsGen is nullptr");
        return m_ParamsGen->ParamsGenBGVRNS(cryptoParams, evalAddCount, keySwitchCount, cyclOrder, numPrimes,
                                            firstModSize, dcrtBits, numPartQ, multihopQBound);
    }

    /////////////////////////////////////////
    // PKE WRAPPER
    /////////////////////////////////////////

    virtual KeyPair<Element> KeyGen(CryptoContext<Element> cc, bool makeSparse) {
        VerifyPKEEnabled(__func__);
        return m_PKE->KeyGenInternal(cc, makeSparse);
    }

    virtual Ciphertext<Element> Encrypt(const Element& plaintext, const PrivateKey<Element> privateKey) const {
        VerifyPKEEnabled(__func__);
        //      if (!plaintext)
        //        OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");

        return m_PKE->Encrypt(plaintext, privateKey);
    }

    virtual Ciphertext<Element> Encrypt(const Element& plaintext, const PublicKey<Element> publicKey) const {
        VerifyPKEEnabled(__func__);
        //      if (!plaintext)
        //        OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        if (!publicKey)
            OPENFHE_THROW(config_error, "Input public key is nullptr");

        return m_PKE->Encrypt(plaintext, publicKey);
    }

    virtual DecryptResult Decrypt(ConstCiphertext<Element> ciphertext, const PrivateKey<Element> privateKey,
                                  NativePoly* plaintext) const {
        VerifyPKEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");
        return m_PKE->Decrypt(ciphertext, privateKey, plaintext);
    }

    virtual DecryptResult Decrypt(ConstCiphertext<Element> ciphertext, const PrivateKey<Element> privateKey,
                                  Poly* plaintext) const {
        VerifyPKEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");
        return m_PKE->Decrypt(ciphertext, privateKey, plaintext);
    }

    std::shared_ptr<std::vector<Element>> EncryptZeroCore(const PrivateKey<Element> privateKey) const {
        VerifyPKEEnabled(__func__);
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");
        return m_PKE->EncryptZeroCore(privateKey, nullptr);
    }

    std::shared_ptr<std::vector<Element>> EncryptZeroCore(const PublicKey<Element> publicKey) const {
        VerifyPKEEnabled(__func__);
        if (!publicKey)
            OPENFHE_THROW(config_error, "Input public key is nullptr");
        return m_PKE->EncryptZeroCore(publicKey, nullptr);
    }

    Element DecryptCore(ConstCiphertext<Element> ciphertext, const PrivateKey<Element> privateKey) const {
        VerifyPKEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");
        return m_PKE->DecryptCore(ciphertext->GetElements(), privateKey);
    }

    /////////////////////////////////////////
    // KEY SWITCH WRAPPER
    /////////////////////////////////////////

    virtual EvalKey<Element> KeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                          const PrivateKey<Element> newPrivateKey) const {
        VerifyKeySwitchEnabled(__func__);
        if (!oldPrivateKey)
            OPENFHE_THROW(config_error, "Input first private key is nullptr");
        if (!newPrivateKey)
            OPENFHE_THROW(config_error, "Input second private key is nullptr");
        return m_KeySwitch->KeySwitchGenInternal(oldPrivateKey, newPrivateKey);
    }

    virtual EvalKey<Element> KeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                          const PrivateKey<Element> newPrivateKey,
                                          const EvalKey<Element> evalKey) const {
        VerifyKeySwitchEnabled(__func__);
        if (!oldPrivateKey)
            OPENFHE_THROW(config_error, "Input first private key is nullptr");
        if (!newPrivateKey)
            OPENFHE_THROW(config_error, "Input second private key is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input eval key is nullptr");
        return m_KeySwitch->KeySwitchGenInternal(oldPrivateKey, newPrivateKey, evalKey);
    }

    virtual EvalKey<Element> KeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                          const PublicKey<Element> newPublicKey) const {
        VerifyKeySwitchEnabled(__func__);
        if (!oldPrivateKey)
            OPENFHE_THROW(config_error, "Input first private key is nullptr");
        if (!newPublicKey)
            OPENFHE_THROW(config_error, "Input second public key is nullptr");
        return m_KeySwitch->KeySwitchGenInternal(oldPrivateKey, newPublicKey);
    }

    virtual Ciphertext<Element> KeySwitch(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey) const {
        VerifyKeySwitchEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
        return m_KeySwitch->KeySwitch(ciphertext, evalKey);
    }

    virtual void KeySwitchInPlace(Ciphertext<Element>& ciphertext, const EvalKey<Element> evalKey) const {
        VerifyKeySwitchEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
        m_KeySwitch->KeySwitchInPlace(ciphertext, evalKey);
        return;
    }

    virtual Ciphertext<Element> KeySwitchDown(ConstCiphertext<Element> ciphertext) const {
        VerifyKeySwitchEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_KeySwitch->KeySwitchDown(ciphertext);
    }

    virtual std::shared_ptr<std::vector<Element>> EvalKeySwitchPrecomputeCore(
        const Element& c, std::shared_ptr<CryptoParametersBase<Element>> cryptoParamsBase) const {
        VerifyKeySwitchEnabled(__func__);
        return m_KeySwitch->EvalKeySwitchPrecomputeCore(c, cryptoParamsBase);
    }

    virtual std::shared_ptr<std::vector<Element>> EvalFastKeySwitchCoreExt(
        const std::shared_ptr<std::vector<Element>> digits, const EvalKey<Element> evalKey,
        const std::shared_ptr<ParmType> params) const {
        VerifyKeySwitchEnabled(__func__);
        if (nullptr == digits)
            OPENFHE_THROW(config_error, "Input digits is nullptr");
        if (digits->size() == 0)
            OPENFHE_THROW(config_error, "Input digits size is 0");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
        if (!params)
            OPENFHE_THROW(config_error, "Input params is nullptr");
        return m_KeySwitch->EvalFastKeySwitchCoreExt(digits, evalKey, params);
    }

    virtual std::shared_ptr<std::vector<Element>> EvalFastKeySwitchCore(
        const std::shared_ptr<std::vector<Element>> digits, const EvalKey<Element> evalKey,
        const std::shared_ptr<ParmType> params) const {
        VerifyKeySwitchEnabled(__func__);
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

    virtual std::shared_ptr<std::vector<Element>> KeySwitchCore(const Element& a,
                                                                const EvalKey<Element> evalKey) const {
        VerifyKeySwitchEnabled(__func__);
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
        return m_KeySwitch->KeySwitchCore(a, evalKey);
    }

    /////////////////////////////////////////
    // PRE WRAPPER
    /////////////////////////////////////////

    virtual EvalKey<Element> ReKeyGen(const PrivateKey<Element> oldPrivateKey,
                                      const PublicKey<Element> newPublicKey) const;

    virtual Ciphertext<Element> ReEncrypt(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey,
                                          const PublicKey<Element> publicKey) const;

    /////////////////////////////////////////
    // SHE NEGATION WRAPPER
    /////////////////////////////////////////

    virtual Ciphertext<Element> EvalNegate(ConstCiphertext<Element> ciphertext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->EvalNegate(ciphertext);
    }

    virtual void EvalNegateInPlace(Ciphertext<Element>& ciphertext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        m_LeveledSHE->EvalNegateInPlace(ciphertext);
        return;
    }

    /////////////////////////////////////////
    // SHE ADDITION Wrapper
    /////////////////////////////////////////

    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext1,
                                        ConstCiphertext<Element> ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        return m_LeveledSHE->EvalAdd(ciphertext1, ciphertext2);
    }

    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        m_LeveledSHE->EvalAddInPlace(ciphertext1, ciphertext2);
        return;
    }

    virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext1,
                                               Ciphertext<Element>& ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        return m_LeveledSHE->EvalAddMutable(ciphertext1, ciphertext2);
    }

    virtual void EvalAddMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        m_LeveledSHE->EvalAddMutableInPlace(ciphertext1, ciphertext2);
        return;
    }

    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!plaintext)
            OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        return m_LeveledSHE->EvalAdd(ciphertext, plaintext);
    }

    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!plaintext)
            OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        m_LeveledSHE->EvalAddInPlace(ciphertext, plaintext);
        return;
    }

    virtual Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!plaintext)
            OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        return m_LeveledSHE->EvalAddMutable(ciphertext, plaintext);
    }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, const NativeInteger &constant) const {
    //  VerifyLeveledSHEEnabled(__func__);
    //  if (!ciphertext)
    //      OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

    //  return m_LeveledSHE->EvalAdd(ciphertext, constant);
    //}

    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext, const NativeInteger& constant) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        m_LeveledSHE->EvalAddInPlace(ciphertext, constant);
        return;
    }

    virtual Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, double constant) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->EvalAdd(ciphertext, constant);
    }

    virtual void EvalAddInPlace(Ciphertext<Element>& ciphertext, double constant) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        m_LeveledSHE->EvalAddInPlace(ciphertext, constant);
        return;
    }

    /////////////////////////////////////////
    // SHE SUBTRACTION Wrapper
    /////////////////////////////////////////

    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1,
                                        ConstCiphertext<Element> ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        return m_LeveledSHE->EvalSub(ciphertext1, ciphertext2);
    }

    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        m_LeveledSHE->EvalSubInPlace(ciphertext1, ciphertext2);
        return;
    }

    virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext1,
                                               Ciphertext<Element>& ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        return m_LeveledSHE->EvalSubMutable(ciphertext1, ciphertext2);
    }

    virtual void EvalSubMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        m_LeveledSHE->EvalSubMutableInPlace(ciphertext1, ciphertext2);
        return;
    }

    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!plaintext)
            OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        return m_LeveledSHE->EvalSub(ciphertext, plaintext);
    }

    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!plaintext)
            OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        m_LeveledSHE->EvalSubInPlace(ciphertext, plaintext);
        return;
    }

    virtual Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!plaintext)
            OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        return m_LeveledSHE->EvalSubMutable(ciphertext, plaintext);
    }

    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, const NativeInteger& constant) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->EvalSub(ciphertext, constant);
    }

    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext, const NativeInteger& constant) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        m_LeveledSHE->EvalSubInPlace(ciphertext, constant);
        return;
    }

    virtual Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, double constant) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->EvalSub(ciphertext, constant);
    }

    virtual void EvalSubInPlace(Ciphertext<Element>& ciphertext, double constant) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        m_LeveledSHE->EvalSubInPlace(ciphertext, constant);
        return;
    }

    /////////////////////////////////////////
    // SHE MULTIPLICATION Wrapper
    /////////////////////////////////////////

    virtual EvalKey<Element> EvalMultKeyGen(const PrivateKey<Element> privateKey) const;

    virtual std::vector<EvalKey<Element>> EvalMultKeysGen(const PrivateKey<Element> privateKey) const;

    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1,
                                         ConstCiphertext<Element> ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        return m_LeveledSHE->EvalMult(ciphertext1, ciphertext2);
    }

    virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext1,
                                                Ciphertext<Element>& ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        return m_LeveledSHE->EvalMultMutable(ciphertext1, ciphertext2);
    }

    virtual Ciphertext<Element> EvalSquare(ConstCiphertext<Element> ciphertext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->EvalSquare(ciphertext);
    }

    virtual Ciphertext<Element> EvalSquareMutable(Ciphertext<Element>& ciphertext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->EvalSquareMutable(ciphertext);
    }

    /////////////////////////////////////////
    // MULTIPLICATION With Eval Key
    /////////////////////////////////////////

    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2,
                                         const EvalKey<Element> evalKey) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
        return m_LeveledSHE->EvalMult(ciphertext1, ciphertext2, evalKey);
    }

    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2,
                                 const EvalKey<Element> evalKey) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
        m_LeveledSHE->EvalMultInPlace(ciphertext1, ciphertext2, evalKey);
        return;
    }

    virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2,
                                                const EvalKey<Element> evalKey) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
        return m_LeveledSHE->EvalMultMutable(ciphertext1, ciphertext2, evalKey);
    }

    virtual void EvalMultMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2,
                                        const EvalKey<Element> evalKey) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
        m_LeveledSHE->EvalMultMutableInPlace(ciphertext1, ciphertext2, evalKey);
        return;
    }

    virtual Ciphertext<Element> EvalSquare(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
        return m_LeveledSHE->EvalSquare(ciphertext, evalKey);
    }

    virtual void EvalSquareInPlace(Ciphertext<Element>& ciphertext, const EvalKey<Element> evalKey) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
        m_LeveledSHE->EvalSquareInPlace(ciphertext, evalKey);
        return;
    }

    virtual Ciphertext<Element> EvalSquareMutable(Ciphertext<Element>& ciphertext,
                                                  const EvalKey<Element> evalKey) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");
        return m_LeveledSHE->EvalSquareMutable(ciphertext, evalKey);
    }

    virtual Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element> ciphertext1,
                                                       ConstCiphertext<Element> ciphertext2,
                                                       const std::vector<EvalKey<Element>>& evalKeyVec) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        if (!evalKeyVec.size())
            OPENFHE_THROW(config_error, "Input evaluation key vector is empty");
        return m_LeveledSHE->EvalMultAndRelinearize(ciphertext1, ciphertext2, evalKeyVec);
    }

    virtual Ciphertext<Element> Relinearize(ConstCiphertext<Element> ciphertext,
                                            const std::vector<EvalKey<Element>>& evalKeyVec) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!evalKeyVec.size())
            OPENFHE_THROW(config_error, "Input evaluation key vector is empty");
        return m_LeveledSHE->Relinearize(ciphertext, evalKeyVec);
    }

    virtual void RelinearizeInPlace(Ciphertext<Element>& ciphertext,
                                    const std::vector<EvalKey<Element>>& evalKeyVec) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!evalKeyVec.size())
            OPENFHE_THROW(config_error, "Input evaluation key vector is empty");
        m_LeveledSHE->RelinearizeInPlace(ciphertext, evalKeyVec);
        return;
    }

    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!plaintext)
            OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        return m_LeveledSHE->EvalMult(ciphertext, plaintext);
    }

    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!plaintext)
            OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        m_LeveledSHE->EvalMultInPlace(ciphertext, plaintext);
        return;
    }

    virtual Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!plaintext)
            OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        return m_LeveledSHE->EvalMultMutable(ciphertext, plaintext);
    }

    virtual Ciphertext<Element> MultByMonomial(ConstCiphertext<Element> ciphertext, usint power) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->MultByMonomial(ciphertext, power);
    }

    virtual void MultByMonomialInPlace(Ciphertext<Element>& ciphertext, usint power) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        m_LeveledSHE->MultByMonomialInPlace(ciphertext, power);
        return;
    }

    virtual Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, double constant) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->EvalMult(ciphertext, constant);
    }

    virtual void EvalMultInPlace(Ciphertext<Element>& ciphertext, double constant) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        m_LeveledSHE->EvalMultInPlace(ciphertext, constant);
        return;
    }

    virtual Ciphertext<DCRTPoly> MultByInteger(ConstCiphertext<DCRTPoly> ciphertext, uint64_t integer) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->MultByInteger(ciphertext, integer);
    }

    virtual void MultByIntegerInPlace(Ciphertext<DCRTPoly>& ciphertext, uint64_t integer) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        m_LeveledSHE->MultByIntegerInPlace(ciphertext, integer);
        return;
    }

    /////////////////////////////////////////
    // SHE AUTOMORPHISM Wrapper
    /////////////////////////////////////////

    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAutomorphismKeyGen(
        const PrivateKey<Element> privateKey, const std::vector<usint>& indexList) const;

    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAutomorphismKeyGen(
        const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
        const std::vector<usint>& indexList) const;

    virtual Ciphertext<Element> EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
                                                 const std::map<usint, EvalKey<Element>>& evalKeyMap,
                                                 CALLER_INFO_ARGS_HDR) const {
        if (m_LeveledSHE) {
            if (!ciphertext)
                OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
            if (!evalKeyMap.size())
                OPENFHE_THROW(config_error, "Input evaluation key map is empty");

            return m_LeveledSHE->EvalAutomorphism(ciphertext, i, evalKeyMap);
        }
        std::string errorMsg(std::string("EvalAutomorphism operation has not been enabled") + CALLER_INFO);
        OPENFHE_THROW(config_error, errorMsg);
    }

    virtual Ciphertext<Element> EvalFastRotation(ConstCiphertext<Element> ciphertext, const usint index, const usint m,
                                                 const std::shared_ptr<std::vector<Element>> digits) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->EvalFastRotation(ciphertext, index, m, digits);
    }

    virtual std::shared_ptr<std::vector<Element>> EvalFastRotationPrecompute(
        ConstCiphertext<Element> ciphertext) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->EvalFastRotationPrecompute(ciphertext);
    }

    /**
   * Only supported for hybrid key switching.
   * Performs fast (hoisted) rotation and returns the results
   * in the extended CRT basis P*Q
   *
   * @param ciphertext input ciphertext
   * @param index the rotation index.
   * @param precomp the precomputed digits for the ciphertext
   * @param addFirst if true, the the first element c0 is also computed (otherwise ignored)
   * @return resulting ciphertext
   */
    virtual Ciphertext<Element> EvalFastRotationExt(ConstCiphertext<Element> ciphertext, usint index,
                                                    const std::shared_ptr<std::vector<Element>> digits, bool addFirst,
                                                    const std::map<usint, EvalKey<Element>>& evalKeys) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->EvalFastRotationExt(ciphertext, index, digits, addFirst, evalKeys);
    }

    /**
   * Only supported for hybrid key switching.
   * Scales down the polynomial c0 from extended basis P*Q to Q.
   *
   * @param ciphertext input ciphertext in the extended basis
   * @return resulting polynomial
   */
    Element KeySwitchDownFirstElement(ConstCiphertext<Element> ciphertext) const {
        VerifyKeySwitchEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_KeySwitch->KeySwitchDownFirstElement(ciphertext);
    }

    virtual Ciphertext<Element> KeySwitchExt(ConstCiphertext<Element> ciphertext, bool addFirst) const {
        VerifyKeySwitchEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_KeySwitch->KeySwitchExt(ciphertext, addFirst);
    }

    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAtIndexKeyGen(
        const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
        const std::vector<int32_t>& indexList) const;

    virtual Ciphertext<Element> EvalAtIndex(ConstCiphertext<Element> ciphertext, usint i,
                                            const std::map<usint, EvalKey<Element>>& evalKeyMap) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!evalKeyMap.size())
            OPENFHE_THROW(config_error, "Input evaluation key map is empty");
        return m_LeveledSHE->EvalAtIndex(ciphertext, i, evalKeyMap);
    }

    virtual usint FindAutomorphismIndex(usint index, usint m) {
        VerifyLeveledSHEEnabled(__func__);
        return m_LeveledSHE->FindAutomorphismIndex(index, m);
    }

    /////////////////////////////////////////
    // SHE Leveled Methods Wrapper
    /////////////////////////////////////////

    virtual Ciphertext<Element> ComposedEvalMult(ConstCiphertext<Element> ciphertext1,
                                                 ConstCiphertext<Element> ciphertext2,
                                                 const EvalKey<Element> evalKey) const;

    virtual Ciphertext<Element> ModReduce(ConstCiphertext<Element> ciphertext, size_t levels) const;

    virtual void ModReduceInPlace(Ciphertext<Element>& ciphertext, size_t levels) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        m_LeveledSHE->ModReduceInPlace(ciphertext, levels);
        return;
    }

    virtual Ciphertext<Element> ModReduceInternal(ConstCiphertext<Element> ciphertext, size_t levels) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->ModReduceInternal(ciphertext, levels);
    }

    virtual void ModReduceInternalInPlace(Ciphertext<Element>& ciphertext, size_t levels) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (levels == 0)
            return;
        m_LeveledSHE->ModReduceInternalInPlace(ciphertext, levels);
        return;
    }

    virtual Ciphertext<Element> LevelReduce(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey,
                                            size_t levels) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        auto result = m_LeveledSHE->LevelReduce(ciphertext, evalKey, levels);
        result->SetKeyTag(ciphertext->GetKeyTag());
        return result;
    }

    virtual void LevelReduceInPlace(Ciphertext<Element>& ciphertext, const EvalKey<Element> evalKey,
                                    size_t levels) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        m_LeveledSHE->LevelReduceInPlace(ciphertext, evalKey, levels);
        return;
    }

    virtual Ciphertext<Element> LevelReduceInternal(ConstCiphertext<Element> ciphertext, size_t levels) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->LevelReduceInternal(ciphertext, levels);
    }

    virtual void LevelReduceInternalInPlace(Ciphertext<Element>& ciphertext, size_t levels) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        m_LeveledSHE->LevelReduceInternalInPlace(ciphertext, levels);
        return;
    }

    virtual Ciphertext<Element> Compress(ConstCiphertext<Element> ciphertext, size_t towersLeft) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_LeveledSHE->Compress(ciphertext, towersLeft);
    }

    virtual void AdjustLevelsInPlace(Ciphertext<DCRTPoly>& ciphertext1, Ciphertext<DCRTPoly>& ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input ciphertext1 is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input ciphertext2 is nullptr");
        m_LeveledSHE->AdjustLevelsInPlace(ciphertext1, ciphertext2);
        return;
    }

    virtual void AdjustLevelsAndDepthInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                             Ciphertext<DCRTPoly>& ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input ciphertext1 is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input ciphertext2 is nullptr");
        m_LeveledSHE->AdjustLevelsAndDepthInPlace(ciphertext1, ciphertext2);
        return;
    }

    virtual void AdjustLevelsAndDepthToOneInPlace(Ciphertext<DCRTPoly>& ciphertext1,
                                                  Ciphertext<DCRTPoly>& ciphertext2) const {
        VerifyLeveledSHEEnabled(__func__);
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input ciphertext1 is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input ciphertext2 is nullptr");
        m_LeveledSHE->AdjustLevelsAndDepthToOneInPlace(ciphertext1, ciphertext2);
        return;
    }

    /////////////////////////////////////////
    // Advanced SHE Wrapper
    /////////////////////////////////////////

    virtual Ciphertext<Element> EvalAddMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertextVec.size())
            OPENFHE_THROW(config_error, "Input ciphertext vector is empty");
        return m_AdvancedSHE->EvalAddMany(ciphertextVec);
    }

    virtual Ciphertext<Element> EvalAddManyInPlace(std::vector<Ciphertext<Element>>& ciphertextVec) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertextVec.size())
            OPENFHE_THROW(config_error, "Input ciphertext vector is empty");

        return m_AdvancedSHE->EvalAddManyInPlace(ciphertextVec);
    }

    virtual Ciphertext<Element> EvalMultMany(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                             const std::vector<EvalKey<Element>>& evalKeyVec) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertextVec.size())
            OPENFHE_THROW(config_error, "Input ciphertext vector is empty");
        if (!evalKeyVec.size())
            OPENFHE_THROW(config_error, "Input evaluation key vector is empty");
        return m_AdvancedSHE->EvalMultMany(ciphertextVec, evalKeyVec);
    }

    /////////////////////////////////////
    // Advanced SHE LINEAR WEIGHTED SUM
    /////////////////////////////////////

    virtual Ciphertext<Element> EvalLinearWSum(std::vector<ConstCiphertext<Element>>& ciphertextVec,
                                               const std::vector<double>& constantVec) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertextVec.size())
            OPENFHE_THROW(config_error, "Input ciphertext vector is empty");
        return m_AdvancedSHE->EvalLinearWSum(ciphertextVec, constantVec);
    }

    virtual Ciphertext<Element> EvalLinearWSumMutable(std::vector<Ciphertext<Element>>& ciphertextVec,
                                                      const std::vector<double>& constantVec) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertextVec.size())
            OPENFHE_THROW(config_error, "Input ciphertext vector is empty");
        return m_AdvancedSHE->EvalLinearWSumMutable(ciphertextVec, constantVec);
    }

    /////////////////////////////////////
    // Advanced SHE EVAL POLYNOMIAL
    /////////////////////////////////////

    Ciphertext<Element> EvalPoly(ConstCiphertext<Element> ciphertext, const std::vector<double>& coefficients) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_AdvancedSHE->EvalPoly(ciphertext, coefficients);
    }

    Ciphertext<Element> EvalPolyLinear(ConstCiphertext<Element> ciphertext,
                                       const std::vector<double>& coefficients) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_AdvancedSHE->EvalPolyLinear(ciphertext, coefficients);
    }

    Ciphertext<Element> EvalPolyPS(ConstCiphertext<Element> ciphertext, const std::vector<double>& coefficients) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_AdvancedSHE->EvalPolyPS(ciphertext, coefficients);
    }

    /////////////////////////////////////
    // Advanced SHE EVAL CHEBYSHEV SERIES
    /////////////////////////////////////

    Ciphertext<Element> EvalChebyshevSeries(ConstCiphertext<Element> ciphertext,
                                            const std::vector<double>& coefficients, double a, double b) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_AdvancedSHE->EvalChebyshevSeries(ciphertext, coefficients, a, b);
    }

    Ciphertext<Element> EvalChebyshevSeriesLinear(ConstCiphertext<Element> ciphertext,
                                                  const std::vector<double>& coefficients, double a, double b) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_AdvancedSHE->EvalChebyshevSeriesLinear(ciphertext, coefficients, a, b);
    }

    Ciphertext<Element> EvalChebyshevSeriesPS(ConstCiphertext<Element> ciphertext,
                                              const std::vector<double>& coefficients, double a, double b) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_AdvancedSHE->EvalChebyshevSeriesPS(ciphertext, coefficients, a, b);
    }

    /////////////////////////////////////
    // Advanced SHE EVAL SUM
    /////////////////////////////////////

    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumKeyGen(const PrivateKey<Element> privateKey,
                                                                             const PublicKey<Element> publicKey) const;

    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumRowsKeyGen(const PrivateKey<Element> privateKey,
                                                                                 const PublicKey<Element> publicKey,
                                                                                 usint rowSize, usint subringDim) const;

    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumColsKeyGen(
        const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) const;

    virtual Ciphertext<Element> EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize,
                                        const std::map<usint, EvalKey<Element>>& evalKeyMap) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!evalKeyMap.size())
            OPENFHE_THROW(config_error, "Input evaluation key map is empty");
        return m_AdvancedSHE->EvalSum(ciphertext, batchSize, evalKeyMap);
    }

    virtual Ciphertext<Element> EvalSumRows(ConstCiphertext<Element> ciphertext, usint rowSize,
                                            const std::map<usint, EvalKey<Element>>& evalKeyMap,
                                            usint subringDim) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!evalKeyMap.size())
            OPENFHE_THROW(config_error, "Input evaluation key map is empty");
        return m_AdvancedSHE->EvalSumRows(ciphertext, rowSize, evalKeyMap, subringDim);
    }

    virtual Ciphertext<Element> EvalSumCols(ConstCiphertext<Element> ciphertext, usint batchSize,
                                            const std::map<usint, EvalKey<Element>>& evalKeyMap,
                                            const std::map<usint, EvalKey<Element>>& rightEvalKeyMap) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!evalKeyMap.size())
            OPENFHE_THROW(config_error, "Input first evaluation key map is empty");
        if (!rightEvalKeyMap.size())
            OPENFHE_THROW(config_error, "Input second evaluation key map is empty");
        return m_AdvancedSHE->EvalSumCols(ciphertext, batchSize, evalKeyMap, rightEvalKeyMap);
    }

    /////////////////////////////////////
    // Advanced SHE EVAL INNER PRODUCT
    /////////////////////////////////////

    virtual Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
                                                 ConstCiphertext<Element> ciphertext2, usint batchSize,
                                                 const std::map<usint, EvalKey<Element>>& evalSumKeyMap,
                                                 const EvalKey<Element> evalMultKey) const;

    virtual Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext,
                                                 usint batchSize,
                                                 const std::map<usint, EvalKey<Element>>& evalSumKeyMap) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!plaintext)
            OPENFHE_THROW(config_error, "Input plaintext is nullptr");
        if (!evalSumKeyMap.size())
            OPENFHE_THROW(config_error, "Input evaluation key map is empty");
        return m_AdvancedSHE->EvalInnerProduct(ciphertext, plaintext, batchSize, evalSumKeyMap);
    }

    virtual Ciphertext<Element> AddRandomNoise(ConstCiphertext<Element> ciphertext) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        return m_AdvancedSHE->AddRandomNoise(ciphertext);
    }

    virtual Ciphertext<Element> EvalMerge(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                          const std::map<usint, EvalKey<Element>>& evalKeyMap) const {
        VerifyAdvancedSHEEnabled(__func__);
        if (!ciphertextVec.size())
            OPENFHE_THROW(config_error, "Input ciphertext vector is empty");
        if (!evalKeyMap.size())
            OPENFHE_THROW(config_error, "Input evaluation key map is empty");
        return m_AdvancedSHE->EvalMerge(ciphertextVec, evalKeyMap);
    }

    /////////////////////////////////////////
    // MULTIPARTY WRAPPER
    /////////////////////////////////////////

    virtual KeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc,
                                              const std::vector<PrivateKey<Element>>& privateKeyVec, bool makeSparse);

    virtual KeyPair<Element> MultipartyKeyGen(CryptoContext<Element> cc, const PublicKey<Element> publicKey,
                                              bool makeSparse, bool PRE);

    virtual Ciphertext<Element> MultipartyDecryptMain(ConstCiphertext<Element> ciphertext,
                                                      const PrivateKey<Element> privateKey) const;

    virtual Ciphertext<Element> MultipartyDecryptLead(ConstCiphertext<Element> ciphertext,
                                                      const PrivateKey<Element> privateKey) const;

    virtual DecryptResult MultipartyDecryptFusion(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                  NativePoly* plaintext) const {
        VerifyMultipartyEnabled(__func__);
        if (!ciphertextVec.size())
            OPENFHE_THROW(config_error, "Input ciphertext vector is empty");

        return m_Multiparty->MultipartyDecryptFusion(ciphertextVec, plaintext);
    }

    virtual DecryptResult MultipartyDecryptFusion(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                  Poly* plaintext) const {
        VerifyMultipartyEnabled(__func__);
        if (!ciphertextVec.size())
            OPENFHE_THROW(config_error, "Input ciphertext vector is empty");
        return m_Multiparty->MultipartyDecryptFusion(ciphertextVec, plaintext);
    }

    virtual EvalKey<Element> MultiKeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                               const PrivateKey<Element> newPrivateKey,
                                               const EvalKey<Element> evalKey) const;

    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalAutomorphismKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalAutoKeyMap,
        const std::vector<usint>& indexList, const std::string& keyId);

    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalAtIndexKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalAutoKeyMap,
        const std::vector<int32_t>& indexList, const std::string& keyId);

    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalSumKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap,
        const std::string& keyId = "");

    virtual EvalKey<Element> MultiAddEvalKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2,
                                              const std::string& keyId);

    virtual EvalKey<Element> MultiMultEvalKey(PrivateKey<Element> privateKey, EvalKey<Element> evalKey,
                                              const std::string& keyId);

    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiAddEvalSumKeys(
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap1,
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap2, const std::string& keyId);

    virtual std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiAddEvalAutomorphismKeys(
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap1,
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap2, const std::string& keyId);

    virtual PublicKey<Element> MultiAddPubKeys(PublicKey<Element> publicKey1, PublicKey<Element> publicKey2,
                                               const std::string& keyId);

    virtual EvalKey<Element> MultiAddEvalMultKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2,
                                                  const std::string& keyId);

    virtual Ciphertext<Element> IntMPBootAdjustScale(ConstCiphertext<Element> ciphertext) const {
        if (m_Multiparty) {
            return m_Multiparty->IntMPBootAdjustScale(ciphertext);
        }
        OPENFHE_THROW(config_error, "IntMPBootAdjustScale operation has not been enabled");
    }

    virtual Ciphertext<Element> IntMPBootRandomElementGen(std::shared_ptr<CryptoParametersCKKSRNS> cryptoParameters,
                                                          const PublicKey<Element> publicKey) const {
        if (m_Multiparty) {
            return m_Multiparty->IntMPBootRandomElementGen(cryptoParameters, publicKey);
        }
        OPENFHE_THROW(config_error, "IntMPBootRandomElementGen operation has not been enabled");
    }

    virtual std::vector<Ciphertext<Element>> IntMPBootDecrypt(const PrivateKey<Element> privateKey,
                                                              ConstCiphertext<Element> ciphertext,
                                                              ConstCiphertext<Element> a) const {
        if (m_Multiparty) {
            return m_Multiparty->IntMPBootDecrypt(privateKey, ciphertext, a);
        }
        OPENFHE_THROW(config_error, "IntMPBootDecrypt operation has not been enabled");
    }

    std::vector<Ciphertext<Element>> IntMPBootAdd(std::vector<std::vector<Ciphertext<Element>>>& sharesPairVec) const {
        if (m_Multiparty) {
            return m_Multiparty->IntMPBootAdd(sharesPairVec);
        }
        OPENFHE_THROW(config_error, "IntMPBootAdd operation has not been enabled");
    }

    Ciphertext<Element> IntMPBootEncrypt(const PublicKey<Element> publicKey,
                                         const std::vector<Ciphertext<Element>>& sharesPair, ConstCiphertext<Element> a,
                                         ConstCiphertext<Element> ciphertext) const {
        if (m_Multiparty) {
            return m_Multiparty->IntMPBootEncrypt(publicKey, sharesPair, a, ciphertext);
        }
        OPENFHE_THROW(config_error, "IntMPBootEncrypt operation has not been enabled");
    }

    // FHE METHODS

    // TODO Andrey: do we need this method?
    //  const std::shared_ptr<PKEBase<Element>> getAlgorithm() const { return m_PKE; }

    void EvalBootstrapSetup(const CryptoContextImpl<Element>& cc, const std::vector<uint32_t>& levelBudget = {5, 4},
                            const std::vector<uint32_t>& dim1 = {0, 0}, uint32_t slots = 0,
                            uint32_t correctionFactor = 0, bool precompute = true) {
        VerifyFHEEnabled(__func__);
        m_FHE->EvalBootstrapSetup(cc, levelBudget, dim1, slots, correctionFactor, precompute);
        return;
    }

    std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalBootstrapKeyGen(const PrivateKey<Element> privateKey,
                                                                           uint32_t slots) {
        VerifyFHEEnabled(__func__);
        return m_FHE->EvalBootstrapKeyGen(privateKey, slots);
    }

    void EvalBootstrapPrecompute(const CryptoContextImpl<Element>& cc, uint32_t slots = 0) {
        VerifyFHEEnabled(__func__);
        m_FHE->EvalBootstrapPrecompute(cc, slots);
        return;
    }

    Ciphertext<Element> EvalBootstrap(ConstCiphertext<Element> ciphertext, uint32_t numIterations = 1,
                                      uint32_t precision = 0) const {
        VerifyFHEEnabled(__func__);
        return m_FHE->EvalBootstrap(ciphertext, numIterations, precision);
    }

    // SCHEMESWITCHING methods

    std::pair<BinFHEContext, LWEPrivateKey> EvalCKKStoFHEWSetup(const CryptoContextImpl<Element>& cc,
                                                                SecurityLevel sl      = HEStd_128_classic,
                                                                BINFHE_PARAMSET slBin = STD128, bool arbFunc = false,
                                                                uint32_t logQ = 29, bool dynamic = false,
                                                                uint32_t numSlotsCKKS = 0, uint32_t logQswitch = 27) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalCKKStoFHEWSetup(cc, sl, slBin, arbFunc, logQ, dynamic, numSlotsCKKS, logQswitch);
    }

    std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalCKKStoFHEWKeyGen(const KeyPair<Element>& keyPair,
                                                                            ConstLWEPrivateKey& lwesk,
                                                                            uint32_t dim1 = 0, uint32_t L = 1) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalCKKStoFHEWKeyGen(keyPair, lwesk, dim1, L);
    }

    void EvalCKKStoFHEWPrecompute(const CryptoContextImpl<Element>& cc, double scale = 1.0) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalCKKStoFHEWPrecompute(cc, scale);
    }

    std::vector<std::shared_ptr<LWECiphertextImpl>> EvalCKKStoFHEW(ConstCiphertext<Element> ciphertext,
                                                                   uint32_t numCtxts = 0) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalCKKStoFHEW(ciphertext, numCtxts);
    }

    void EvalFHEWtoCKKSSetup(const CryptoContextImpl<DCRTPoly>& ccCKKS, const BinFHEContext& ccLWE,
                             uint32_t numSlotsCKKS = 0, uint32_t logQ = 25) {
        VerifySchemeSwitchEnabled(__func__);
        m_SchemeSwitch->EvalFHEWtoCKKSSetup(ccCKKS, ccLWE, numSlotsCKKS, logQ);
        return;
    }

    std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalFHEWtoCKKSKeyGen(const KeyPair<Element>& keyPair,
                                                                            ConstLWEPrivateKey& lwesk,
                                                                            uint32_t numSlots = 0, uint32_t dim1 = 0,
                                                                            uint32_t L = 0) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalFHEWtoCKKSKeyGen(keyPair, lwesk, numSlots, dim1, L);
    }

    void EvalCompareSwitchPrecompute(const CryptoContextImpl<Element>& ccCKKS, uint32_t pLWE = 0,
                                     uint32_t initLevel = 0, double scaleSign = 1.0, bool unit = false) {
        VerifySchemeSwitchEnabled(__func__);
        m_SchemeSwitch->EvalCompareSwitchPrecompute(ccCKKS, pLWE, initLevel, scaleSign, unit);
        return;
    }

    Ciphertext<Element> EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                       uint32_t numCtxts = 0, uint32_t numSlots = 0, uint32_t p = 4, double pmin = 0.0,
                                       double pmax = 2.0) const {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalFHEWtoCKKS(LWECiphertexts, numCtxts, numSlots, p, pmin, pmax);
    }

    std::pair<BinFHEContext, LWEPrivateKey> EvalSchemeSwitchingSetup(const CryptoContextImpl<DCRTPoly>& cc,
                                                                     SecurityLevel sl      = HEStd_128_classic,
                                                                     BINFHE_PARAMSET slBin = STD128,
                                                                     bool arbFunc = false, uint32_t logQ = 29,
                                                                     bool dynamic = false, uint32_t numSlotsCKKS = 0,
                                                                     uint32_t logQswitch = 27) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalSchemeSwitchingSetup(cc, sl, slBin, arbFunc, logQ, dynamic, numSlotsCKKS,
                                                        logQswitch);
    }

    std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSchemeSwitchingKeyGen(
        const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t numValues = 0, bool oneHot = true,
        bool alt = false, uint32_t dim1CF = 0, uint32_t dim1FC = 0, uint32_t LCF = 1, uint32_t LFC = 0) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalSchemeSwitchingKeyGen(keyPair, lwesk, numValues, oneHot, alt, dim1CF, dim1FC, LCF,
                                                         LFC);
    }

    Ciphertext<Element> EvalCompareSchemeSwitching(ConstCiphertext<Element> ciphertext1,
                                                   ConstCiphertext<Element> ciphertext2, uint32_t numCtxts = 0,
                                                   uint32_t numSlots = 0, uint32_t pLWE = 0, double scaleSign = 1.0,
                                                   bool unit = false) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalCompareSchemeSwitching(ciphertext1, ciphertext2, numCtxts, numSlots, pLWE, scaleSign,
                                                          unit);
    }

    std::vector<Ciphertext<Element>> EvalMinSchemeSwitching(ConstCiphertext<Element> ciphertext,
                                                            PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                            uint32_t numSlots = 0, bool oneHot = true,
                                                            uint32_t pLWE = 0, double scaleSign = 1.0) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalMinSchemeSwitching(ciphertext, publicKey, numValues, numSlots, oneHot, pLWE,
                                                      scaleSign);
    }

    std::vector<Ciphertext<Element>> EvalMinSchemeSwitchingAlt(ConstCiphertext<Element> ciphertext,
                                                               PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                               uint32_t numSlots = 0, bool oneHot = true,
                                                               uint32_t pLWE = 0, double scaleSign = 1.0) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalMinSchemeSwitchingAlt(ciphertext, publicKey, numValues, numSlots, oneHot, pLWE,
                                                         scaleSign);
    }

    std::vector<Ciphertext<Element>> EvalMaxSchemeSwitching(ConstCiphertext<Element> ciphertext,
                                                            PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                            uint32_t numSlots = 0, bool oneHot = true,
                                                            uint32_t pLWE = 0, double scaleSign = 1.0) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalMaxSchemeSwitching(ciphertext, publicKey, numValues, numSlots, oneHot, pLWE,
                                                      scaleSign);
    }

    std::vector<Ciphertext<Element>> EvalMaxSchemeSwitchingAlt(ConstCiphertext<Element> ciphertext,
                                                               PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                               uint32_t numSlots = 0, bool oneHot = true,
                                                               uint32_t pLWE = 0, double scaleSign = 1.0) {
        VerifySchemeSwitchEnabled(__func__);
        return m_SchemeSwitch->EvalMaxSchemeSwitchingAlt(ciphertext, publicKey, numValues, numSlots, oneHot, pLWE,
                                                         scaleSign);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        // TODO (dsuponit): should we serialize all feature pointers???
        // if (IsFeatureEnabled()) {
        // }
        // ar(::cereal::make_nvp("params", m_ParamsGen));
        // ar(::cereal::make_nvp("pke", m_PKE));
        // ar(::cereal::make_nvp("keyswitch", m_KeySwitch));
        // ar(::cereal::make_nvp("pre", m_PRE));
        // ar(::cereal::make_nvp("lvldshe", m_LeveledSHE));
        // ar(::cereal::make_nvp("advshe", m_AdvancedSHE));
        ar(::cereal::make_nvp("fhe", m_FHE));
        // ar(::cereal::make_nvp("schswitch", m_SchemeSwitch));
        ar(::cereal::make_nvp("enabled", GetEnabled()));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }

        // ar(::cereal::make_nvp("params", m_ParamsGen));
        // ar(::cereal::make_nvp("pke", m_PKE));
        // ar(::cereal::make_nvp("keyswitch", m_KeySwitch));
        // ar(::cereal::make_nvp("pre", m_PRE));
        // ar(::cereal::make_nvp("lvldshe", m_LeveledSHE));
        // ar(::cereal::make_nvp("advshe", m_AdvancedSHE));
        ar(::cereal::make_nvp("fhe", m_FHE));
        // ar(::cereal::make_nvp("schswitch", m_SchemeSwitch));
        uint32_t enabled = 0;
        ar(::cereal::make_nvp("enabled", enabled));
        Enable(enabled);
    }

    virtual std::string SerializedObjectName() const {
        return "SchemeBase";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

    //=================================================================================================================
    // Functions to check enabled features in the cryptocontext
    //=================================================================================================================
    /**
    * @brief VerifyAdvancedSHEEnabled is to check if Enable(ADVANCEDSHE) has been called and if it has not
    *        it will thow an exception
    * @param functionName is the calling function name. __func__ can be used instead
    */
    inline void VerifyAdvancedSHEEnabled(const std::string& functionName) const {
        if (m_AdvancedSHE == nullptr) {
            std::string errMsg = std::string(functionName) +
                                 " operation has not been enabled. Enable(ADVANCEDSHE) must be called to enable it.";
            OPENFHE_THROW(config_error, errMsg);
        }
    }
    /**
    * @brief VerifyMultipartyEnabled is to check if Enable(MULTIPARTY) has been called and if it has not
    *        it will thow an exception
    * @param functionName is the calling function name. __func__ can be used instead
    */
    inline void VerifyMultipartyEnabled(const std::string& functionName) const {
        if (m_Multiparty == nullptr) {
            std::string errMsg = std::string(functionName) +
                                 " operation has not been enabled. Enable(MULTIPARTY) must be called to enable it.";
            OPENFHE_THROW(config_error, errMsg);
        }
    }
    /**
    * @brief VerifyLeveledSHEEnabled is to check if Enable(LEVELEDSHE) has been called and if it has not
    *        it will thow an exception
    * @param functionName is the calling function name. __func__ can be used instead
    */
    inline void VerifyLeveledSHEEnabled(const std::string& functionName) const {
        if (m_LeveledSHE == nullptr) {
            std::string errMsg = std::string(functionName) +
                                 " operation has not been enabled. Enable(LEVELEDSHE) must be called to enable it.";
            OPENFHE_THROW(config_error, errMsg);
        }
    }
    /**
    * @brief VerifyPKEEnabled is to check if Enable(PKE) has been called and if it has not
    *        it will thow an exception
    * @param functionName is the calling function name. __func__ can be used instead
    */
    inline void VerifyPKEEnabled(const std::string& functionName) const {
        if (m_PKE == nullptr) {
            std::string errMsg =
                std::string(functionName) + " operation has not been enabled. Enable(PKE) must be called to enable it.";
            OPENFHE_THROW(config_error, errMsg);
        }
    }
    /**
    * @brief VerifyPREEnabled is to check if Enable(PRE) has been called and if it has not
    *        it will thow an exception
    * @param functionName is the calling function name. __func__ can be used instead
    */
    inline void VerifyPREEnabled(const std::string& functionName) const {
        if (m_PRE == nullptr) {
            std::string errMsg =
                std::string(functionName) + " operation has not been enabled. Enable(PRE) must be called to enable it.";
            OPENFHE_THROW(config_error, errMsg);
        }
    }
    /**
    * @brief VerifyKeySwitchEnabled is to check if Enable(KEYSWITCH) has been called and if it has not
    *        it will thow an exception
    * @param functionName is the calling function name. __func__ can be used instead
    */
    inline void VerifyKeySwitchEnabled(const std::string& functionName) const {
        if (m_KeySwitch == nullptr) {
            std::string errMsg = std::string(functionName) +
                                 " operation has not been enabled. Enable(KEYSWITCH) must be called to enable it.";
            OPENFHE_THROW(config_error, errMsg);
        }
    }
    /**
    * @brief VerifyFHEEnabled is to check if Enable(FHE) has been called and if it has not
    *        it will thow an exception
    * @param functionName is the calling function name. __func__ can be used instead
    */
    inline void VerifyFHEEnabled(const std::string& functionName) const {
        if (m_FHE == nullptr) {
            std::string errMsg =
                std::string(functionName) + " operation has not been enabled. Enable(FHE) must be called to enable it.";
            OPENFHE_THROW(config_error, errMsg);
        }
    }

    /**
    * @brief VerifySchemeSwitchEnabled is to check if Enable(SCHEMESWITCH) has been called and if it has not
    *        it will thow an exception
    * @param functionName is the calling function name. __func__ can be used instead
    */
    inline void VerifySchemeSwitchEnabled(const std::string& functionName) const {
        if (m_SchemeSwitch == nullptr) {
            std::string errMsg = std::string(functionName) +
                                 " operation has not been enabled. Enable(SCHEMESWITCH) must be called to enable it.";
            OPENFHE_THROW(config_error, errMsg);
        }
    }

    friend std::ostream& operator<<(std::ostream& out, const SchemeBase<Element>& s) {
        out << typeid(s).name() << ":";
        out << " ParamsGen " << (s.m_ParamsGen == 0 ? "none" : typeid(*s.m_ParamsGen).name());
        out << ", PKE " << (s.m_PKE == 0 ? "none" : typeid(*s.m_PKE).name());
        out << ", KeySwitch " << (s.m_KeySwitch == 0 ? "none" : typeid(*s.m_KeySwitch).name());
        out << ", PRE " << (s.m_PRE == 0 ? "none" : typeid(*s.m_PRE).name());
        out << ", LeveledSHE " << (s.m_LeveledSHE == 0 ? "none" : typeid(*s.m_LeveledSHE).name());
        out << ", AdvancedSHE " << (s.m_AdvancedSHE == 0 ? "none" : typeid(*s.m_AdvancedSHE).name());
        out << ", Multiparty " << (s.m_Multiparty == 0 ? "none" : typeid(*s.m_Multiparty).name());
        out << ", FHE " << (s.m_FHE == 0 ? "none" : typeid(*s.m_FHE).name());
        out << ", SchemeSwitch " << (s.m_SchemeSwitch == 0 ? "none" : typeid(*s.m_SchemeSwitch).name());

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
    std::shared_ptr<FHEBase<Element>> m_FHE;
    std::shared_ptr<FHEBase<Element>> m_SchemeSwitch;
};

}  // namespace lbcrypto

#endif
