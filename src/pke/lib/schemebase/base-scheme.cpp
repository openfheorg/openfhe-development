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

#include "schemebase/base-scheme.h"

#include "key/keypair.h"
#include "key/evalkey.h"

// the code below is from base-scheme-impl.cpp
namespace lbcrypto {

template <typename Element>
EvalKey<Element> SchemeBase<Element>::ReKeyGen(const PrivateKey<Element> oldPrivateKey,
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

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::ReEncrypt(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey,
                                                   const PublicKey<Element> publicKey) const {
    if (m_PRE) {
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

        auto result = m_PRE->ReEncrypt(ciphertext, evalKey, publicKey);
        result->SetKeyTag(evalKey->GetKeyTag());
        return result;
    }
    OPENFHE_THROW(config_error, "ReEncrypt operation has not been enabled");
}

template <typename Element>
EvalKey<Element> SchemeBase<Element>::EvalMultKeyGen(const PrivateKey<Element> privateKey) const {
    if (m_LeveledSHE) {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");

        auto evalKey = m_LeveledSHE->EvalMultKeyGen(privateKey);
        evalKey->SetKeyTag(privateKey->GetKeyTag());
        return evalKey;
    }
    OPENFHE_THROW(config_error, "EvalMultKeyGen operation has not been enabled");
}

template <typename Element>
std::vector<EvalKey<Element>> SchemeBase<Element>::EvalMultKeysGen(const PrivateKey<Element> privateKey) const {
    if (m_LeveledSHE) {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");

        auto evalKeyVec = m_LeveledSHE->EvalMultKeysGen(privateKey);
        for (auto& evalKey : evalKeyVec)
            evalKey->SetKeyTag(privateKey->GetKeyTag());
        return evalKeyVec;
    }
    OPENFHE_THROW(config_error, "EvalMultKeysGen operation has not been enabled");
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> SchemeBase<Element>::EvalAtIndexKeyGen(
    const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
    const std::vector<int32_t>& indexList) const {
    if (m_LeveledSHE) {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");

        auto evalKeyMap = m_LeveledSHE->EvalAtIndexKeyGen(publicKey, privateKey, indexList);
        for (auto& key : *evalKeyMap)
            key.second->SetKeyTag(privateKey->GetKeyTag());
        return evalKeyMap;
    }
    OPENFHE_THROW(config_error, "EvalAtIndexKeyGen operation has not been enabled");
}

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::ComposedEvalMult(ConstCiphertext<Element> ciphertext1,
                                                          ConstCiphertext<Element> ciphertext2,
                                                          const EvalKey<Element> evalKey) const {
    if (m_LeveledSHE) {
        if (!ciphertext1)
            OPENFHE_THROW(config_error, "Input first ciphertext is nullptr");
        if (!ciphertext2)
            OPENFHE_THROW(config_error, "Input second ciphertext is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

        auto result = m_LeveledSHE->ComposedEvalMult(ciphertext1, ciphertext2, evalKey);
        result->SetKeyTag(evalKey->GetKeyTag());
        return result;
    }
    OPENFHE_THROW(config_error, "ComposedEvalMult operation has not been enabled");
}

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::ModReduce(ConstCiphertext<Element> ciphertext, size_t levels) const {
    if (m_LeveledSHE) {
        if (!ciphertext)
            OPENFHE_THROW(config_error, "Input ciphertext is nullptr");

        auto result = m_LeveledSHE->ModReduce(ciphertext, levels);
        result->SetKeyTag(ciphertext->GetKeyTag());
        return result;
    }
    OPENFHE_THROW(config_error, "ModReduce operation has not been enabled");
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> SchemeBase<Element>::EvalSumKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) const {
    if (m_AdvancedSHE) {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");

        auto evalKeyMap = m_AdvancedSHE->EvalSumKeyGen(privateKey, publicKey);
        for (auto& key : *evalKeyMap) {
            key.second->SetKeyTag(privateKey->GetKeyTag());
        }
        return evalKeyMap;
    }
    OPENFHE_THROW(config_error, "EvalSumKeyGen operation has not been enabled");
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> SchemeBase<Element>::EvalSumRowsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey, usint rowSize, usint subringDim) const {
    if (m_AdvancedSHE) {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");

        auto evalKeyMap = m_AdvancedSHE->EvalSumRowsKeyGen(privateKey, publicKey, rowSize, subringDim);
        for (auto& key : *evalKeyMap) {
            key.second->SetKeyTag(privateKey->GetKeyTag());
        }
        return evalKeyMap;
    }
    OPENFHE_THROW(config_error, "EvalSumRowsKeyGen operation has not been enabled");
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> SchemeBase<Element>::EvalSumColsKeyGen(
    const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) const {
    if (m_AdvancedSHE) {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");

        auto evalKeyMap = m_AdvancedSHE->EvalSumColsKeyGen(privateKey, publicKey);
        for (auto& key : *evalKeyMap) {
            key.second->SetKeyTag(privateKey->GetKeyTag());
        }
        return evalKeyMap;
    }
    OPENFHE_THROW(config_error, "EvalSumColsKeyGen operation has not been enabled");
}

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::EvalInnerProduct(ConstCiphertext<Element> ciphertext1,
                                                          ConstCiphertext<Element> ciphertext2, usint batchSize,
                                                          const std::map<usint, EvalKey<Element>>& evalSumKeyMap,
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

        auto result = m_AdvancedSHE->EvalInnerProduct(ciphertext1, ciphertext2, batchSize, evalSumKeyMap, evalMultKey);
        result->SetKeyTag(evalSumKeyMap.begin()->second->GetKeyTag());
        return result;
    }
    OPENFHE_THROW(config_error, "EvalInnerProduct operation has not been enabled");
}

template <typename Element>
KeyPair<Element> SchemeBase<Element>::MultipartyKeyGen(CryptoContext<Element> cc,
                                                       const std::vector<PrivateKey<Element>>& privateKeyVec,
                                                       bool makeSparse) {
    if (m_Multiparty) {
        if (!cc)
            OPENFHE_THROW(config_error, "Input crypto context is nullptr");
        if (!privateKeyVec.size())
            OPENFHE_THROW(config_error, "Input private key vector is empty");

        auto keyPair = m_Multiparty->MultipartyKeyGen(cc, privateKeyVec, makeSparse);
        keyPair.publicKey->SetKeyTag(keyPair.secretKey->GetKeyTag());
        return keyPair;
    }
    OPENFHE_THROW(config_error, "MultipartyKeyGen operation has not been enabled");
}

template <typename Element>
KeyPair<Element> SchemeBase<Element>::MultipartyKeyGen(CryptoContext<Element> cc, const PublicKey<Element> publicKey,
                                                       bool makeSparse, bool PRE) {
    if (m_Multiparty) {
        if (!cc)
            OPENFHE_THROW(config_error, "Input crypto context is nullptr");
        if (!publicKey)
            OPENFHE_THROW(config_error, "Input public key is empty");

        auto keyPair = m_Multiparty->MultipartyKeyGen(cc, publicKey, makeSparse, PRE);
        keyPair.publicKey->SetKeyTag(keyPair.secretKey->GetKeyTag());
        return keyPair;
    }
    OPENFHE_THROW(config_error, "MultipartyKeyGen operation has not been enabled");
}

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::MultipartyDecryptMain(ConstCiphertext<Element> ciphertext,
                                                               const PrivateKey<Element> privateKey) const {
    if (m_Multiparty) {
        CheckMultipartyDecryptCompatibility(ciphertext);

        auto result = m_Multiparty->MultipartyDecryptMain(ciphertext, privateKey);
        result->SetKeyTag(privateKey->GetKeyTag());
        return result;
    }
    OPENFHE_THROW(config_error, "MultipartyDecryptMain operation has not been enabled");
}

template <typename Element>
Ciphertext<Element> SchemeBase<Element>::MultipartyDecryptLead(ConstCiphertext<Element> ciphertext,
                                                               const PrivateKey<Element> privateKey) const {
    if (m_Multiparty) {
        CheckMultipartyDecryptCompatibility(ciphertext);

        auto result = m_Multiparty->MultipartyDecryptLead(ciphertext, privateKey);
        result->SetKeyTag(privateKey->GetKeyTag());
        return result;
    }
    OPENFHE_THROW(config_error, "MultipartyDecryptLead operation has not been enabled");
}

template <typename Element>
EvalKey<Element> SchemeBase<Element>::MultiKeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                                        const PrivateKey<Element> newPrivateKey,
                                                        const EvalKey<Element> evalKey) const {
    if (m_Multiparty) {
        if (!oldPrivateKey)
            OPENFHE_THROW(config_error, "Input first private key is nullptr");
        if (!newPrivateKey)
            OPENFHE_THROW(config_error, "Input second private key is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

        auto result = m_Multiparty->MultiKeySwitchGen(oldPrivateKey, newPrivateKey, evalKey);
        result->SetKeyTag(newPrivateKey->GetKeyTag());
        return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> SchemeBase<Element>::MultiEvalAutomorphismKeyGen(
    const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalAutoKeyMap,
    const std::vector<usint>& indexList, const std::string& keyId) {
    if (m_Multiparty) {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");
        if (!evalAutoKeyMap)
            OPENFHE_THROW(config_error, "Input evaluation key map is nullptr");
        if (!indexList.size())
            OPENFHE_THROW(config_error, "Input index vector is empty");

        auto result = m_Multiparty->MultiEvalAutomorphismKeyGen(privateKey, evalAutoKeyMap, indexList);
        for (auto& key : *result) {
            if (key.second) {
                key.second->SetKeyTag(keyId);
            }
        }
        return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> SchemeBase<Element>::MultiEvalAtIndexKeyGen(
    const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalAutoKeyMap,
    const std::vector<int32_t>& indexList, const std::string& keyId) {
    if (m_Multiparty) {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");
        if (!evalAutoKeyMap)
            OPENFHE_THROW(config_error, "Input evaluation key map is nullptr");
        if (!indexList.size())
            OPENFHE_THROW(config_error, "Input index vector is empty");

        auto result = m_Multiparty->MultiEvalAtIndexKeyGen(privateKey, evalAutoKeyMap, indexList);
        for (auto& key : *result) {
            if (key.second) {
                key.second->SetKeyTag(keyId);
            }
        }
        return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> SchemeBase<Element>::MultiEvalSumKeyGen(
    const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap,
    const std::string& keyId) {
    if (m_Multiparty) {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");
        if (!evalSumKeyMap)
            OPENFHE_THROW(config_error, "Input evaluation key map is nullptr");

        auto result = m_Multiparty->MultiEvalSumKeyGen(privateKey, evalSumKeyMap);
        for (auto& key : *result) {
            if (key.second) {
                key.second->SetKeyTag(keyId);
            }
        }
        return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
}

template <typename Element>
EvalKey<Element> SchemeBase<Element>::MultiAddEvalKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2,
                                                       const std::string& keyId) {
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

template <typename Element>
EvalKey<Element> SchemeBase<Element>::MultiMultEvalKey(PrivateKey<Element> privateKey, EvalKey<Element> evalKey,
                                                       const std::string& keyId) {
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

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> SchemeBase<Element>::MultiAddEvalSumKeys(
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap1,
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap2, const std::string& keyId) {
    if (m_Multiparty) {
        if (!evalSumKeyMap1)
            OPENFHE_THROW(config_error, "Input first evaluation key map is nullptr");
        if (!evalSumKeyMap2)
            OPENFHE_THROW(config_error, "Input second evaluation key map is nullptr");

        auto result = m_Multiparty->MultiAddEvalSumKeys(evalSumKeyMap1, evalSumKeyMap2);
        for (auto& key : *result) {
            if (key.second) {
                key.second->SetKeyTag(keyId);
            }
        }
        return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> SchemeBase<Element>::MultiAddEvalAutomorphismKeys(
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap1,
    const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalSumKeyMap2, const std::string& keyId) {
    if (m_Multiparty) {
        if (!evalSumKeyMap1)
            OPENFHE_THROW(config_error, "Input first evaluation key map is nullptr");
        if (!evalSumKeyMap2)
            OPENFHE_THROW(config_error, "Input second evaluation key map is nullptr");

        auto result = m_Multiparty->MultiAddEvalAutomorphismKeys(evalSumKeyMap1, evalSumKeyMap2);
        for (auto& key : *result) {
            if (key.second) {
                key.second->SetKeyTag(keyId);
            }
        }
        return result;
    }
    OPENFHE_THROW(config_error, "Multiparty capability has not been enabled");
}

template <typename Element>
PublicKey<Element> SchemeBase<Element>::MultiAddPubKeys(PublicKey<Element> publicKey1, PublicKey<Element> publicKey2,
                                                        const std::string& keyId) {
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

template <typename Element>
EvalKey<Element> SchemeBase<Element>::MultiAddEvalMultKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2,
                                                           const std::string& keyId) {
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

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> SchemeBase<Element>::EvalAutomorphismKeyGen(
    const PrivateKey<Element> privateKey, const std::vector<usint>& indexList) const {
    if (m_LeveledSHE) {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");

        auto evalKeyMap = m_LeveledSHE->EvalAutomorphismKeyGen(privateKey, indexList);
        for (auto& key : *evalKeyMap)
            key.second->SetKeyTag(privateKey->GetKeyTag());
        return evalKeyMap;
    }
    OPENFHE_THROW(config_error, "EvalAutomorphismKeyGen operation has not been enabled");
}

template <typename Element>
std::shared_ptr<std::map<usint, EvalKey<Element>>> SchemeBase<Element>::EvalAutomorphismKeyGen(
    const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
    const std::vector<usint>& indexList) const {
    if (m_LeveledSHE) {
        if (!publicKey)
            OPENFHE_THROW(config_error, "Input public key is nullptr");
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");

        auto evalKeyMap = m_LeveledSHE->EvalAutomorphismKeyGen(publicKey, privateKey, indexList);
        for (auto& key : *evalKeyMap)
            key.second->SetKeyTag(privateKey->GetKeyTag());
        return evalKeyMap;
    }
    OPENFHE_THROW(config_error, "EvalAutomorphismKeyGen operation has not been enabled");
}

template class SchemeBase<DCRTPoly>;

}  // namespace lbcrypto
