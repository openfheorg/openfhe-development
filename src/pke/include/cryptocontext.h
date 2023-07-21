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
  Control for encryption operations
 */

#ifndef SRC_PKE_CRYPTOCONTEXT_H_
#define SRC_PKE_CRYPTOCONTEXT_H_

#include "cryptocontextfactory.h"
#include "cryptocontext-fwd.h"
#include "ciphertext.h"

#include "encoding/plaintextfactory.h"

#include "key/evalkey.h"
#include "key/keypair.h"

#include "schemebase/base-pke.h"
#include "schemebase/base-scheme.h"
#include "schemerns/rns-cryptoparameters.h"

#include "utils/caller_info.h"
#include "utils/serial.h"
#include "utils/type_name.h"

#include "binfhecontext.h"

#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <algorithm>
#include <unordered_map>

namespace lbcrypto {

/**
 * @brief CryptoContextImpl
 *
 * A CryptoContextImpl is the object used to access the OpenFHE library
 *
 * All OpenFHE functionality is accessed by way of an instance of a
 * CryptoContextImpl; we say that various objects are "created in" a context,
 * and can only be used in the context in which they were created
 *
 * All OpenFHE methods are accessed through CryptoContextImpl methods. Guards
 * are implemented to make certain that only valid objects that have been
 * created in the context are used
 *
 * Contexts are created using GenCryptoContext(), and can be serialized
 * and recovered from a serialization
 */
template <typename Element>
class CryptoContextImpl : public Serializable {
    using IntType  = typename Element::Integer;
    using ParmType = typename Element::Params;

    void SetKSTechniqueInScheme();

    const CryptoContext<Element> GetContextForPointer(const CryptoContextImpl<Element>* cc) const {
        const auto& contexts = CryptoContextFactory<Element>::GetAllContexts();
        for (const auto& ctx : contexts) {
            if (cc == ctx.get())
                return ctx;
        }
        OPENFHE_THROW(type_error, "Cannot find context for the given pointer to CryptoContextImpl");
    }

    virtual Plaintext MakeCKKSPackedPlaintextInternal(const std::vector<std::complex<double>>& value,
                                                      size_t noiseScaleDeg, uint32_t level,
                                                      const std::shared_ptr<ParmType> params, usint slots) const {
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(GetCryptoParameters());
        if (level > 0) {
            // validation of level: We need to compare it to multiplicativeDepth, but multiplicativeDepth is not
            // readily available. so, what we get is numModuli and use it for calculations
            size_t numModuli = cryptoParams->GetElementParams()->GetParams().size();
            uint32_t multiplicativeDepth =
                (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) ? (numModuli - 2) : (numModuli - 1);
            // we throw an exception if level >= numModuli. however, we use multiplicativeDepth in the error message,
            // so the user can understand the error more easily.
            if (level >= numModuli) {
                std::string errorMsg;
                if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
                    errorMsg = "The level value should be less than or equal to (multiplicativeDepth + 1).";
                else
                    errorMsg = "The level value should be less than or equal to multiplicativeDepth.";

                errorMsg += " Currently: level is [" + std::to_string(level) + "] and multiplicativeDepth is [" +
                            std::to_string(multiplicativeDepth) + "]";
                OPENFHE_THROW(config_error, errorMsg);
            }
        }

        double scFact = 0;
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT && level == 0) {
            scFact = cryptoParams->GetScalingFactorRealBig(level);
            // In FLEXIBLEAUTOEXT mode at level 0, we don't use the noiseScaleDeg
            // in our encoding function, so we set it to 1 to make sure it
            // has no effect on the encoding.
            noiseScaleDeg = 1;
        }
        else {
            scFact = cryptoParams->GetScalingFactorReal(level);
        }

        Plaintext p;
        if (params == nullptr) {
            std::shared_ptr<ILDCRTParams<DCRTPoly::Integer>> elemParamsPtr;
            if (level != 0) {
                ILDCRTParams<DCRTPoly::Integer> elemParams = *(cryptoParams->GetElementParams());
                for (uint32_t i = 0; i < level; i++) {
                    elemParams.PopLastParam();
                }
                elemParamsPtr = std::make_shared<ILDCRTParams<DCRTPoly::Integer>>(elemParams);
            }
            else {
                elemParamsPtr = cryptoParams->GetElementParams();
            }
            // Check if plaintext has got enough slots for data (value)
            usint ringDim    = elemParamsPtr->GetRingDimension();
            size_t valueSize = value.size();
            if (valueSize > ringDim / 2) {
                OPENFHE_THROW(config_error, "The size [" + std::to_string(valueSize) +
                                                "] of the vector with values should not be greater than ringDim/2 [" +
                                                std::to_string(ringDim / 2) + "] if the scheme is CKKS");
            }
            // TODO (dsuponit): we should call a version of MakePlaintext instead of calling Plaintext() directly here
            p = Plaintext(std::make_shared<CKKSPackedEncoding>(elemParamsPtr, this->GetEncodingParams(), value,
                                                               noiseScaleDeg, level, scFact, slots));
        }
        else {
            // Check if plaintext has got enough slots for data (value)
            usint ringDim    = params->GetRingDimension();
            size_t valueSize = value.size();
            if (valueSize > ringDim / 2) {
                OPENFHE_THROW(config_error, "The size [" + std::to_string(valueSize) +
                                                "] of the vector with values should not be greater than ringDim/2 [" +
                                                std::to_string(ringDim / 2) + "] if the scheme is CKKS");
            }
            // TODO (dsuponit): we should call a version of MakePlaintext instead of calling Plaintext() directly here
            p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, this->GetEncodingParams(), value, noiseScaleDeg,
                                                               level, scFact, slots));
        }
        p->Encode();

        // In FLEXIBLEAUTOEXT mode, a fresh plaintext at level 0 always has noiseScaleDeg 2.
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT && level == 0) {
            p->SetNoiseScaleDeg(2);
        }
        return p;
    }

    /**
    * MakePlaintext constructs a CoefPackedEncoding or PackedEncoding in this context
    * @param encoding is PACKED_ENCODING or COEF_PACKED_ENCODING
    * @param value is the value to encode
    * @param depth is the multiplicative depth to encode the plaintext at
    * @param level is the level to encode the plaintext at
    * @return plaintext
    */
    Plaintext MakePlaintext(const PlaintextEncodings encoding, const std::vector<int64_t>& value, size_t depth,
                            uint32_t level) const {
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(GetCryptoParameters());
        if (level > 0) {
            if (getSchemeId() == SCHEME::BFVRNS_SCHEME) {
                std::string errorMsg("The level value should be zero for BFVRNS_SCHEME. Currently: level is [" +
                                     std::to_string(level) + "]");
                OPENFHE_THROW(config_error, errorMsg);
            }
            // validation of level: We need to compare it to multiplicativeDepth, but multiplicativeDepth is not
            // readily available. so, what we get is numModuli and use it for calculations
            size_t numModuli = cryptoParams->GetElementParams()->GetParams().size();
            uint32_t multiplicativeDepth =
                (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) ? (numModuli - 2) : (numModuli - 1);
            // we throw an exception if level >= numModuli. however, we use multiplicativeDepth in the error message,
            // so the user can understand the error more easily.
            if (level >= numModuli) {
                std::string errorMsg;
                if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
                    errorMsg = "The level value should be less than or equal to (multiplicativeDepth + 1).";
                else
                    errorMsg = "The level value should be less than or equal to multiplicativeDepth.";

                errorMsg += " Currently: level is [" + std::to_string(level) + "] and multiplicativeDepth is [" +
                            std::to_string(multiplicativeDepth) + "]";
                OPENFHE_THROW(config_error, errorMsg);
            }
        }

        Plaintext p;
        if (getSchemeId() == SCHEME::BGVRNS_SCHEME && (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO ||
                                                       cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)) {
            NativeInteger scf;
            if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT && level == 0) {
                scf = cryptoParams->GetScalingFactorIntBig(level);
                p   = PlaintextFactory::MakePlaintext(value, encoding, this->GetElementParams(),
                                                      this->GetEncodingParams(), getSchemeId(), 1, level, scf);
                p->SetNoiseScaleDeg(2);
            }
            else {
                scf = cryptoParams->GetScalingFactorInt(level);
                p   = PlaintextFactory::MakePlaintext(value, encoding, this->GetElementParams(),
                                                      this->GetEncodingParams(), getSchemeId(), depth, level, scf);
            }
        }
        else {
            auto elementParams = this->GetElementParams();
            p = PlaintextFactory::MakePlaintext(value, encoding, elementParams, this->GetEncodingParams(),
                                                getSchemeId());
        }

        return p;
    }

    /**
    * MakePlaintext static that takes a cc and calls the Plaintext Factory
    * @param encoding
    * @param cc
    * @param value
    * @return
    */
    template <typename Value1>
    static Plaintext MakePlaintext(PlaintextEncodings encoding, CryptoContext<Element> cc, const Value1& value) {
        return PlaintextFactory::MakePlaintext(value, encoding, cc->GetElementParams(), cc->GetEncodingParams());
    }

    template <typename Value1, typename Value2>
    static Plaintext MakePlaintext(PlaintextEncodings encoding, CryptoContext<Element> cc, const Value1& value,
                                   const Value2& value2) {
        return PlaintextFactory::MakePlaintext(encoding, cc->GetElementParams(), cc->GetEncodingParams(), value,
                                               value2);
    }

protected:
    // crypto parameters used for this context
    std::shared_ptr<CryptoParametersBase<Element>> params;
    // algorithm used; accesses all crypto methods
    std::shared_ptr<SchemeBase<Element>> scheme;

    static std::map<std::string, std::vector<EvalKey<Element>>>& evalMultKeyMap() {
        // cached evalmult keys, by secret key UID
        static std::map<std::string, std::vector<EvalKey<Element>>> s_evalMultKeyMap;
        return s_evalMultKeyMap;
    }

    static std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>& evalSumKeyMap() {
        // cached evalsum keys, by secret key UID
        static std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> s_evalSumKeyMap;
        return s_evalSumKeyMap;
    }

    static std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>& evalAutomorphismKeyMap() {
        // cached evalautomorphism keys, by secret key UID
        static std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> s_evalAutomorphismKeyMap;
        return s_evalAutomorphismKeyMap;
    }

    SCHEME m_schemeId = SCHEME::INVALID_SCHEME;

    uint32_t m_keyGenLevel;

    /**
   * TypeCheck makes sure that an operation between two ciphertexts is permitted
   * @param a
   * @param b
   */
    void TypeCheck(const ConstCiphertext<Element> a, const ConstCiphertext<Element> b, CALLER_INFO_ARGS_HDR) const {
        if (a == nullptr || b == nullptr) {
            std::string errorMsg(std::string("Null Ciphertext") + CALLER_INFO);
            OPENFHE_THROW(type_error, errorMsg);
        }
        if (a->GetCryptoContext().get() != this) {
            std::string errorMsg(std::string("Ciphertext was not created in this CryptoContext") + CALLER_INFO);
            OPENFHE_THROW(type_error, errorMsg);
        }
        if (a->GetCryptoContext() != b->GetCryptoContext()) {
            std::string errorMsg(std::string("Ciphertexts were not created in the same CryptoContext") + CALLER_INFO);
            OPENFHE_THROW(type_error, errorMsg);
        }
        if (a->GetKeyTag() != b->GetKeyTag()) {
            std::string errorMsg(std::string("Ciphertexts were not encrypted with same keys") + CALLER_INFO);
            OPENFHE_THROW(type_error, errorMsg);
        }
        if (a->GetEncodingType() != b->GetEncodingType()) {
            std::stringstream ss;
            ss << "Ciphertext encoding types " << a->GetEncodingType();
            ss << " and " << b->GetEncodingType();
            ss << " do not match";
            ss << CALLER_INFO;
            OPENFHE_THROW(type_error, ss.str());
        }
    }

    /**
   * TypeCheck makes sure that an operation between a ciphertext and a plaintext
   * is permitted
   * @param a
   * @param b
   */
    void TypeCheck(const ConstCiphertext<Element> a, const ConstPlaintext b, CALLER_INFO_ARGS_HDR) const {
        if (a == nullptr) {
            std::string errorMsg(std::string("Null Ciphertext") + CALLER_INFO);
            OPENFHE_THROW(type_error, errorMsg);
        }
        if (b == nullptr) {
            std::string errorMsg(std::string("Null Plaintext") + CALLER_INFO);
            OPENFHE_THROW(type_error, errorMsg);
        }
        if (a->GetCryptoContext().get() != this) {
            std::string errorMsg(std::string("Ciphertext was not created in this CryptoContext") + CALLER_INFO);
            OPENFHE_THROW(type_error, errorMsg);
        }
        if (a->GetEncodingType() != b->GetEncodingType()) {
            std::stringstream ss;
            ss << "Ciphertext encoding type " << a->GetEncodingType();
            ss << " and Plaintext encoding type " << b->GetEncodingType();
            ss << " do not match";
            ss << CALLER_INFO;
            OPENFHE_THROW(type_error, ss.str());
        }
    }

    bool Mismatched(const CryptoContext<Element> a) const {
        if (a.get() != this) {
            return true;
        }
        return false;
    }

    template <typename T>
    void CheckKey(const T& key, CALLER_INFO_ARGS_HDR) const {
        if (key == nullptr) {
            std::string errorMsg(std::string("Key is nullptr") + CALLER_INFO);
            OPENFHE_THROW(config_error, errorMsg);
        }
        if (Mismatched(key->GetCryptoContext())) {
            std::string errorMsg(std::string("Key was not generated with the same crypto context") + CALLER_INFO);
            OPENFHE_THROW(config_error, errorMsg);
        }
    }

    void CheckCiphertext(const ConstCiphertext<Element>& ciphertext, CALLER_INFO_ARGS_HDR) const {
        if (ciphertext == nullptr) {
            std::string errorMsg(std::string("Ciphertext is nullptr") + CALLER_INFO);
            OPENFHE_THROW(config_error, errorMsg);
        }
        if (Mismatched(ciphertext->GetCryptoContext())) {
            std::string errorMsg(std::string("Ciphertext was not generated with the same crypto context") +
                                 CALLER_INFO);
            OPENFHE_THROW(config_error, errorMsg);
        }
    }

    PrivateKey<Element> privateKey;

public:
    /**
   * This stores the private key in the crypto context.
   * This is only intended for debugging and should not be
   * used in production systems. Please define DEBUG_KEY in
   * openfhe.h to enable this.
   *
   * If used, one can create a key pair and store the secret
   * key in th crypto context like this:
   *
   * auto keys = cc->KeyGen();
   * cc->SetPrivateKey(keys.secretKey);
   *
   * After that, anyone in the code, one can access the
   * secret key by getting the crypto context and doing the
   * following:
   *
   * auto sk = cc->GetPrivateKey();
   *
   * This key can be used for decrypting any intermediate
   * ciphertexts for debugging purposes.
   *
   * @param sk the secret key
   *
   */
    void SetPrivateKey(const PrivateKey<Element> privateKey) {
#ifdef DEBUG_KEY
        std::cerr << "Warning - SetPrivateKey is only intended to be used for debugging "
                     "purposes - not for production systems."
                  << std::endl;
        this->privateKey = privateKey;
#else
        OPENFHE_THROW(not_available_error, "SetPrivateKey is only allowed if DEBUG_KEY is set in openfhe.h");
#endif
    }

    /**
   * This gets the private key from the crypto context.
   * This is only intended for debugging and should not be
   * used in production systems. Please define DEBUG_KEY in
   * openfhe.h to enable this.
   *
   * If used, one can create a key pair and store the secret
   * key in th crypto context like this:
   *
   * auto keys = cc->KeyGen();
   * cc->SetPrivateKey(keys.secretKey);
   *
   * After that, anyone in the code, one can access the
   * secret key by getting the crypto context and doing the
   * following:
   *
   * auto sk = cc->GetPrivateKey();
   *
   * This key can be used for decrypting any intermediate
   * ciphertexts for debugging purposes.
   *
   * @return the secret key
   *
   */
    const PrivateKey<Element> GetPrivateKey() {
#ifdef DEBUG_KEY
        return this->privateKey;
#else
        OPENFHE_THROW(not_available_error, "GetPrivateKey is only allowed if DEBUG_KEY is set in openfhe.h");
#endif
    }

    void setSchemeId(SCHEME schemeTag) {
        this->m_schemeId = schemeTag;
    }

    SCHEME getSchemeId() const {
        return this->m_schemeId;
    }

    /**
   * CryptoContextImpl constructor from pointers to parameters and scheme
   * @param params - pointer to CryptoParameters
   * @param scheme - pointer to Crypto Scheme
   */
    // TODO (dsuponit): investigate if we really need 2 constructors for CryptoContextImpl as one of them take regular pointer
    // and the other one takes shared_ptr
    CryptoContextImpl(CryptoParametersBase<Element>* params = nullptr, SchemeBase<Element>* scheme = nullptr,
                      SCHEME schemeId = SCHEME::INVALID_SCHEME) {
        this->params.reset(params);
        this->scheme.reset(scheme);
        this->m_keyGenLevel = 0;
        this->m_schemeId    = schemeId;
    }

    /**
   * CryptoContextImpl constructor from shared pointers to parameters and scheme
   * @param params - shared pointer to CryptoParameters
   * @param scheme - sharedpointer to Crypto Scheme
   */
    CryptoContextImpl(std::shared_ptr<CryptoParametersBase<Element>> params,
                      std::shared_ptr<SchemeBase<Element>> scheme, SCHEME schemeId = SCHEME::INVALID_SCHEME) {
        this->params        = params;
        this->scheme        = scheme;
        this->m_keyGenLevel = 0;
        this->m_schemeId    = schemeId;
    }

    /**
   * Copy constructor
   * @param c - source
   */
    CryptoContextImpl(const CryptoContextImpl<Element>& c) {
        params              = c.params;
        scheme              = c.scheme;
        this->m_keyGenLevel = 0;
        this->m_schemeId    = c.m_schemeId;
    }

    /**
   * Assignment
   * @param rhs - assigning from
   * @return this
   */
    CryptoContextImpl<Element>& operator=(const CryptoContextImpl<Element>& rhs) {
        params        = rhs.params;
        scheme        = rhs.scheme;
        m_keyGenLevel = rhs.m_keyGenLevel;
        m_schemeId    = rhs.m_schemeId;
        return *this;
    }

    /**
   * A CryptoContextImpl is only valid if the shared pointers are both valid
   */
    operator bool() const {
        return params && scheme;
    }

    /**
   * Private methods to compare two contexts; this is only used internally and
   * is not generally available
   * @param a - operand 1
   * @param b - operand 2
   * @return true if the implementations have identical parms and scheme
   */
    friend bool operator==(const CryptoContextImpl<Element>& a, const CryptoContextImpl<Element>& b) {
        // Identical if the parameters and the schemes are identical... the exact
        // same object, OR the same type and the same values
        if (a.params.get() == b.params.get()) {
            return true;
        }
        else {
            if (typeid(*a.params.get()) != typeid(*b.params.get())) {
                return false;
            }
            if (*a.params.get() != *b.params.get())
                return false;
        }

        if (a.scheme.get() == b.scheme.get()) {
            return true;
        }
        else {
            if (typeid(*a.scheme.get()) != typeid(*b.scheme.get())) {
                return false;
            }
            if (*a.scheme.get() != *b.scheme.get())
                return false;
        }

        return true;
    }

    friend bool operator!=(const CryptoContextImpl<Element>& a, const CryptoContextImpl<Element>& b) {
        return !(a == b);
    }

    /**
   * SerializeEvalMultKey for a single EvalMult key or all EvalMult keys
   *
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @param id for key to serialize - if empty std::string, serialize them all
   * @return true on success
   */
    template <typename ST>
    static bool SerializeEvalMultKey(std::ostream& ser, const ST& sertype, std::string id = "") {
        std::map<std::string, std::vector<EvalKey<Element>>>* smap;
        std::map<std::string, std::vector<EvalKey<Element>>> omap;

        if (id.length() == 0) {
            smap = &GetAllEvalMultKeys();
        }
        else {
            const auto k = GetAllEvalMultKeys().find(id);

            if (k == GetAllEvalMultKeys().end())
                return false;  // no such id

            smap           = &omap;
            omap[k->first] = k->second;
        }

        Serial::Serialize(*smap, ser, sertype);
        return true;
    }

    /**
   * SerializeEvalMultKey for all EvalMultKeys made in a given context
   *
   * @param cc whose keys should be serialized
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @return true on success (false on failure or no keys found)
   */
    template <typename ST>
    static bool SerializeEvalMultKey(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {
        std::map<std::string, std::vector<EvalKey<Element>>> omap;
        for (const auto& k : GetAllEvalMultKeys()) {
            if (k.second[0]->GetCryptoContext() == cc) {
                omap[k.first] = k.second;
            }
        }

        if (omap.size() == 0)
            return false;

        Serial::Serialize(omap, ser, sertype);
        return true;
    }

    /**
   * DeserializeEvalMultKey deserialize all keys in the serialization
   * deserialized keys silently replace any existing matching keys
   * deserialization will create CryptoContextImpl if necessary
   *
   * @param serObj - stream with a serialization
   * @return true on success
   */
    template <typename ST>
    static bool DeserializeEvalMultKey(std::istream& ser, const ST& sertype) {
        std::map<std::string, std::vector<EvalKey<Element>>> evalMultKeyMap;

        Serial::Deserialize(GetAllEvalMultKeys(), ser, sertype);

        // The deserialize call created any contexts that needed to be created....
        // so all we need to do is put the keys into the maps for their context

        for (auto k : GetAllEvalMultKeys()) {
            GetAllEvalMultKeys()[k.first] = k.second;
        }

        return true;
    }

    /**
   * ClearEvalMultKeys - flush EvalMultKey cache
   */
    static void ClearEvalMultKeys() {
        GetAllEvalMultKeys().clear();
    }

    /**
   * ClearEvalMultKeys - flush EvalMultKey cache for a given id
   * @param id
   */
    static void ClearEvalMultKeys(const std::string& id) {
        auto kd = GetAllEvalMultKeys().find(id);
        if (kd != GetAllEvalMultKeys().end())
            GetAllEvalMultKeys().erase(kd);
    }

    /**
   * ClearEvalMultKeys - flush EvalMultKey cache for a given context
   * @param cc
   */
    static void ClearEvalMultKeys(const CryptoContext<Element> cc) {
        for (auto it = GetAllEvalMultKeys().begin(); it != GetAllEvalMultKeys().end();) {
            if (it->second[0]->GetCryptoContext() == cc) {
                it = GetAllEvalMultKeys().erase(it);
            }
            else {
                ++it;
            }
        }
    }

    /**
   * InsertEvalMultKey - add the given vector of keys to the map, replacing the
   * existing vector if there
   * @param vectorToInsert
   */
    static void InsertEvalMultKey(const std::vector<EvalKey<Element>>& evalKeyVec);

    /**
   * SerializeEvalSumKey for a single EvalSum key or all of the EvalSum keys
   *
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @param id - key to serialize; empty std::string means all keys
   * @return true on success
   */
    template <typename ST>
    static bool SerializeEvalSumKey(std::ostream& ser, const ST& sertype, std::string id = "") {
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>* smap;
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> omap;

        if (id.length() == 0) {
            smap = &GetAllEvalSumKeys();
        }
        else {
            auto k = GetAllEvalSumKeys().find(id);

            if (k == GetAllEvalSumKeys().end())
                return false;  // no such id

            smap           = &omap;
            omap[k->first] = k->second;
        }
        Serial::Serialize(*smap, ser, sertype);
        return true;
    }

    /**
   * SerializeEvalSumKey for all of the EvalSum keys for a context
   *
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @param cc - context
   * @return true on success
   */
    template <typename ST>
    static bool SerializeEvalSumKey(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> omap;
        for (const auto& k : GetAllEvalSumKeys()) {
            if (k.second->begin()->second->GetCryptoContext() == cc) {
                omap[k.first] = k.second;
            }
        }

        if (omap.size() == 0)
            return false;

        Serial::Serialize(omap, ser, sertype);

        return true;
    }

    /**
   * DeserializeEvalSumKey deserialize all keys in the serialization
   * deserialized keys silently replace any existing matching keys
   * deserialization will create CryptoContextImpl if necessary
   *
   * @param ser - stream to serialize from
   * @param sertype - type of serialization
   * @return true on success
   */
    template <typename ST>
    static bool DeserializeEvalSumKey(std::istream& ser, const ST& sertype) {
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> evalSumKeyMap;

        Serial::Deserialize(evalSumKeyMap, ser, sertype);

        // The deserialize call created any contexts that needed to be created....
        // so all we need to do is put the keys into the maps for their context

        for (auto k : evalSumKeyMap) {
            GetAllEvalSumKeys()[k.first] = k.second;
        }

        return true;
    }

    /**
   * ClearEvalSumKeys - flush EvalSumKey cache
   */
    static void ClearEvalSumKeys();

    /**
   * ClearEvalSumKeys - flush EvalSumKey cache for a given id
   * @param id
   */
    static void ClearEvalSumKeys(const std::string& id);

    /**
   * ClearEvalSumKeys - flush EvalSumKey cache for a given context
   * @param cc
   */
    static void ClearEvalSumKeys(const CryptoContext<Element> cc);

    /**
   * InsertEvalSumKey - add the given map of keys to the map, replacing the
   * existing map if there
   * @param mapToInsert
   */
    static void InsertEvalSumKey(const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap);

    /**
   * SerializeEvalAutomorphismKey for a single EvalAuto key or all of the
   * EvalAuto keys
   *
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @param id - key to serialize; empty std::string means all keys
   * @return true on success
   */
    template <typename ST>
    static bool SerializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype, std::string id = "") {
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>* smap;
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> omap;
        if (id.length() == 0) {
            smap = &GetAllEvalAutomorphismKeys();
        }
        else {
            auto k = GetAllEvalAutomorphismKeys().find(id);

            if (k == GetAllEvalAutomorphismKeys().end())
                return false;  // no such id

            smap           = &omap;
            omap[k->first] = k->second;
        }
        Serial::Serialize(*smap, ser, sertype);
        return true;
    }

    /**
   * SerializeEvalAutomorphismKey for all of the EvalAuto keys for a context
   *
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @param cc - context
   * @return true on success
   */
    template <typename ST>
    static bool SerializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> omap;
        for (const auto& k : GetAllEvalAutomorphismKeys()) {
            if (k.second->begin()->second->GetCryptoContext() == cc) {
                omap[k.first] = k.second;
            }
        }

        if (omap.size() == 0)
            return false;

        Serial::Serialize(omap, ser, sertype);
        return true;
    }

    /**
   * DeserializeEvalAutomorphismKey deserialize all keys in the serialization
   * deserialized keys silently replace any existing matching keys
   * deserialization will create CryptoContextImpl if necessary
   *
   * @param ser - stream to serialize from
   * @param sertype - type of serialization
   * @return true on success
   */
    template <typename ST>
    static bool DeserializeEvalAutomorphismKey(std::istream& ser, const ST& sertype) {
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> evalSumKeyMap;

        Serial::Deserialize(evalSumKeyMap, ser, sertype);

        // The deserialize call created any contexts that needed to be created....
        // so all we need to do is put the keys into the maps for their context

        for (auto k : evalSumKeyMap) {
            GetAllEvalAutomorphismKeys()[k.first] = k.second;
        }

        return true;
    }

    /**
   * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache
   */
    static void ClearEvalAutomorphismKeys();

    /**
   * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given id
   * @param id
   */
    static void ClearEvalAutomorphismKeys(const std::string& id);

    /**
   * ClearEvalAutomorphismKeys - flush EvalAutomorphismKey cache for a given
   * context
   * @param cc
   */
    static void ClearEvalAutomorphismKeys(const CryptoContext<Element> cc);

    /**
   * InsertEvalAutomorphismKey - add the given map of keys to the map, replacing
   * the existing map if there
   * @param mapToInsert
   */
    static void InsertEvalAutomorphismKey(const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap);

    //------------------------------------------------------------------------------
    // TURN FEATURES ON
    //------------------------------------------------------------------------------

    /**
   * Enable a particular feature for use with this CryptoContextImpl
   * @param feature - the feature that should be enabled
   */
    void Enable(PKESchemeFeature feature) {
        scheme->Enable(feature);
    }

    /**
   * Enable several features at once
   * @param featureMask - bitwise or of several PKESchemeFeatures
   */
    void Enable(usint featureMask) {
        scheme->Enable(featureMask);
    }

    // GETTERS
    /**
   * Getter for Scheme
   * @return scheme
   */
    const std::shared_ptr<SchemeBase<Element>> GetScheme() const {
        return scheme;
    }

    /**
   * Getter for CryptoParams
   * @return params
   */
    const std::shared_ptr<CryptoParametersBase<Element>> GetCryptoParameters() const {
        return params;
    }

    size_t GetKeyGenLevel() const {
        return m_keyGenLevel;
    }

    void SetKeyGenLevel(size_t level) {
        m_keyGenLevel = level;
    }

    /**
   * Getter for element params
   * @return
   */
    const std::shared_ptr<ParmType> GetElementParams() const {
        return params->GetElementParams();
    }

    /**
   * Getter for encoding params
   * @return
   */
    const EncodingParams GetEncodingParams() const {
        return params->GetEncodingParams();
    }

    /**
   * Get the cyclotomic order used for this context
   *
   * @return
   */
    usint GetCyclotomicOrder() const {
        return params->GetElementParams()->GetCyclotomicOrder();
    }

    /**
   * Get the ring dimension used for this context
   *
   * @return
   */
    usint GetRingDimension() const {
        return params->GetElementParams()->GetRingDimension();
    }

    /**
   * Get the ciphertext modulus used for this context
   *
   * @return
   */
    const IntType& GetModulus() const {
        return params->GetElementParams()->GetModulus();
    }

    /**
   * Get the ciphertext modulus used for this context
   *
   * @return
   */
    const IntType& GetRootOfUnity() const {
        return params->GetElementParams()->GetRootOfUnity();
    }

    //------------------------------------------------------------------------------
    // KEYS GETTERS
    //------------------------------------------------------------------------------

    static std::map<std::string, std::vector<EvalKey<Element>>>& GetAllEvalMultKeys() {
        return evalMultKeyMap();
    }

    static const std::vector<EvalKey<Element>>& GetEvalMultKeyVector(const std::string& keyID) {
        auto ekv = GetAllEvalMultKeys().find(keyID);
        if (ekv == GetAllEvalMultKeys().end()) {
            OPENFHE_THROW(not_available_error,
                          "You need to use EvalMultKeyGen so that you have an "
                          "EvalMultKey available for this ID");
        }
        return ekv->second;
    }

    static std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>& GetAllEvalAutomorphismKeys() {
        return evalAutomorphismKeyMap();
    }

    static std::map<usint, EvalKey<Element>>& GetEvalAutomorphismKeyMap(const std::string& id);

    static std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>& GetAllEvalSumKeys();

    /**
   * GetEvalSumKey  returns the map
   *
   * @return the EvalSum key map
   */
    static const std::map<usint, EvalKey<Element>>& GetEvalSumKeyMap(const std::string& id);

    //------------------------------------------------------------------------------
    // PLAINTEXT FACTORY METHODS
    //------------------------------------------------------------------------------

    // TODO to be deprecated in 2.0
    /**
   * MakeStringPlaintext constructs a StringEncoding in this context
   * @param str
   * @return plaintext
   */
    Plaintext MakeStringPlaintext(const std::string& str) const {
        return PlaintextFactory::MakePlaintext(str, STRING_ENCODING, this->GetElementParams(),
                                               this->GetEncodingParams());
    }

    /**
   * MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context
   * @param value
   * @param depth is the multiplicative depth to encode the plaintext at
   * @param level is the level to encode the plaintext at
   * @return plaintext
   */
    Plaintext MakeCoefPackedPlaintext(const std::vector<int64_t>& value, size_t depth = 1, uint32_t level = 0) const {
        if (!value.size())
            OPENFHE_THROW(config_error, "Cannot encode an empty value vector");

        return MakePlaintext(COEF_PACKED_ENCODING, value, depth, level);
    }

    /**
   * MakePackedPlaintext constructs a PackedEncoding in this context
   * @param value
   * @param depth is the multiplicative depth to encode the plaintext at
   * @param level is the level to encode the plaintext at
   * @return plaintext
   */
    Plaintext MakePackedPlaintext(const std::vector<int64_t>& value, size_t depth = 1, uint32_t level = 0) const {
        if (!value.size())
            OPENFHE_THROW(config_error, "Cannot encode an empty value vector");

        return MakePlaintext(PACKED_ENCODING, value, depth, level);
    }

    /**
   * COMPLEX ARITHMETIC IS NOT AVAILABLE STARTING WITH 1.10.6,
   * AND THIS METHOD BE DEPRECATED. USE THE REAL-NUMBER METHOD INSTEAD.
   * MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context
   * from a vector of complex numbers
   * @param value - input vector
   * @paran depth - depth used to encode the vector
   * @param level - level at each the vector will get encrypted
   * @param params - parameters to be usef for the ciphertext
   * @return plaintext
   */
    Plaintext MakeCKKSPackedPlaintext(const std::vector<std::complex<double>>& value, size_t depth = 1,
                                      uint32_t level = 0, const std::shared_ptr<ParmType> params = nullptr,
                                      usint slots = 0) const {
        if (!value.size())
            OPENFHE_THROW(config_error, "Cannot encode an empty value vector");

        return MakeCKKSPackedPlaintextInternal(value, depth, level, params, slots);
    }

    /**
   * MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context
   * from a vector of real numbers
   * @param value - input vector
   * @paran depth - depth used to encode the vector
   * @param level - level at each the vector will get encrypted
   * @param params - parameters to be usef for the ciphertext
   * @return plaintext
   */
    Plaintext MakeCKKSPackedPlaintext(const std::vector<double>& value, size_t depth = 1, uint32_t level = 0,
                                      const std::shared_ptr<ParmType> params = nullptr, usint slots = 0) const {
        if (!value.size())
            OPENFHE_THROW(config_error, "Cannot encode an empty value vector");

        std::vector<std::complex<double>> complexValue(value.size());
        std::transform(value.begin(), value.end(), complexValue.begin(),
                       [](double da) { return std::complex<double>(da); });

        return MakeCKKSPackedPlaintextInternal(complexValue, depth, level, params, slots);
    }

    /**
   * GetPlaintextForDecrypt returns a new Plaintext to be used in decryption.
   *
   * @param pte Type of plaintext we want to return
   * @param evp Element parameters
   * @param ep Encoding parameters
   * @return plaintext
   */
    static Plaintext GetPlaintextForDecrypt(PlaintextEncodings pte, std::shared_ptr<ParmType> evp, EncodingParams ep);

    //------------------------------------------------------------------------------
    // PKE Wrapper
    //------------------------------------------------------------------------------

    /**
   * KeyGen generates a key pair using this algorithm's KeyGen method
   * @return a public/secret key pair
   */
    KeyPair<Element> KeyGen() {
        return GetScheme()->KeyGen(GetContextForPointer(this), false);
    }

    /**
   * SparseKeyGen generates a key pair with special structure, and without full
   * entropy, for use in special cases like Ring Reduction
   * @return a public/secret key pair
   */
    KeyPair<Element> SparseKeyGen() {
        return GetScheme()->KeyGen(GetContextForPointer(this), true);
    }

    /**
   * Encrypt a plaintext using a given public key
   * @param publicKey
   * @param plaintext
   * @return ciphertext (or null on failure)
   */
    Ciphertext<Element> Encrypt(Plaintext plaintext, const PublicKey<Element> publicKey) const {
        if (plaintext == nullptr)
            OPENFHE_THROW(type_error, "Input plaintext is nullptr");
        CheckKey(publicKey);

        Ciphertext<Element> ciphertext = GetScheme()->Encrypt(plaintext->GetElement<Element>(), publicKey);

        if (ciphertext) {
            ciphertext->SetEncodingType(plaintext->GetEncodingType());
            ciphertext->SetScalingFactor(plaintext->GetScalingFactor());
            ciphertext->SetScalingFactorInt(plaintext->GetScalingFactorInt());
            ciphertext->SetNoiseScaleDeg(plaintext->GetNoiseScaleDeg());
            ciphertext->SetLevel(plaintext->GetLevel());
            ciphertext->SetSlots(plaintext->GetSlots());
        }

        return ciphertext;
    }

    Ciphertext<Element> Encrypt(const PublicKey<Element> publicKey, Plaintext plaintext) const {
        return Encrypt(plaintext, publicKey);
    }

    /**
   * Encrypt a plaintext using a given private key
   * @param privateKey
   * @param plaintext
   * @return ciphertext (or null on failure)
   */
    Ciphertext<Element> Encrypt(Plaintext plaintext, const PrivateKey<Element> privateKey) const {
        //    if (plaintext == nullptr)
        //      OPENFHE_THROW(type_error, "Input plaintext is nullptr");
        CheckKey(privateKey);

        Ciphertext<Element> ciphertext = GetScheme()->Encrypt(plaintext->GetElement<Element>(), privateKey);

        if (ciphertext) {
            ciphertext->SetEncodingType(plaintext->GetEncodingType());
            ciphertext->SetScalingFactor(plaintext->GetScalingFactor());
            ciphertext->SetScalingFactorInt(plaintext->GetScalingFactorInt());
            ciphertext->SetNoiseScaleDeg(plaintext->GetNoiseScaleDeg());
            ciphertext->SetLevel(plaintext->GetLevel());
            ciphertext->SetSlots(plaintext->GetSlots());
        }

        return ciphertext;
    }

    Ciphertext<Element> Encrypt(const PrivateKey<Element> privateKey, Plaintext plaintext) const {
        return Encrypt(plaintext, privateKey);
    }

    /**
   * Decrypt a single ciphertext into the appropriate plaintext
   *
   * @param privateKey - decryption key
   * @param ciphertext - ciphertext to decrypt
   * @param plaintext - resulting plaintext object pointer is here
   * @return
   */
    DecryptResult Decrypt(ConstCiphertext<Element> ciphertext, const PrivateKey<Element> privateKey,
                          Plaintext* plaintext);

    inline DecryptResult Decrypt(const PrivateKey<Element> privateKey, ConstCiphertext<Element> ciphertext,
                                 Plaintext* plaintext) {
        return Decrypt(ciphertext, privateKey, plaintext);
    }

    //------------------------------------------------------------------------------
    // KeySwitch Wrapper
    //------------------------------------------------------------------------------

    /**
   * KeySwitchGen creates a key that can be used with the OpenFHE KeySwitch
   * operation
   * @param key1
   * @param key2
   * @return new evaluation key
   */
    EvalKey<Element> KeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                  const PrivateKey<Element> newPrivateKey) const {
        CheckKey(oldPrivateKey);
        CheckKey(newPrivateKey);

        return GetScheme()->KeySwitchGen(oldPrivateKey, newPrivateKey);
    }

    /**
   * KeySwitch - OpenFHE KeySwitch method
   * @param keySwitchHint - reference to KeySwitchHint
   * @param ciphertext - ciphertext
   * @return new CiphertextImpl after applying key switch
   */
    Ciphertext<Element> KeySwitch(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey) const {
        CheckCiphertext(ciphertext);
        CheckKey(evalKey);

        return GetScheme()->KeySwitch(ciphertext, evalKey);
    }

    /**
   * KeySwitch - OpenFHE KeySwitchInPlace method
   * @param keySwitchHint - reference to KeySwitchHint
   * @param ciphertext - ciphertext on which to perform in-place key switching
   */
    void KeySwitchInPlace(Ciphertext<Element>& ciphertext, const EvalKey<Element> evalKey) const {
        CheckCiphertext(ciphertext);
        CheckKey(evalKey);

        GetScheme()->KeySwitchInPlace(ciphertext, evalKey);
    }

    //------------------------------------------------------------------------------
    // SHE NEGATION Wrapper
    //------------------------------------------------------------------------------

    /**
   * EvalSub - OpenFHE Negate method for a ciphertext
   * @param ct
   * @return new ciphertext -ct
   */
    Ciphertext<Element> EvalNegate(ConstCiphertext<Element> ciphertext) const {
        CheckCiphertext(ciphertext);

        return GetScheme()->EvalNegate(ciphertext);
    }

    void EvalNegateInPlace(Ciphertext<Element>& ciphertext) const {
        CheckCiphertext(ciphertext);

        GetScheme()->EvalNegateInPlace(ciphertext);
    }

    //------------------------------------------------------------------------------
    // SHE ADDITION Wrapper
    //------------------------------------------------------------------------------

    Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalAdd(ciphertext1, ciphertext2);
    }

    /**
   * EvalAdd - OpenFHE EvalAddInPlace method for a pair of ciphertexts
   * @param ct1 Input/output ciphertext
   * @param ct2 Input cipherext
   * @return \p ct1 contains \p ct1 + \p ct2
   */
    void EvalAddInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalAddInPlace(ciphertext1, ciphertext2);
    }

    /**
   * EvalAdd - OpenFHE EvalAddMutable method for a pair of ciphertexts.
   * This is a mutable version - input ciphertexts may get automatically
   * rescaled, or level-reduced.
   *
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 + ct2
   */
    Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalAddMutable(ciphertext1, ciphertext2);
    }

    void EvalAddMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalAddMutableInPlace(ciphertext1, ciphertext2);
    }

    /**
   * EvalAdd - OpenFHE EvalAdd method for a ciphertext and plaintext
   * @param ciphertext
   * @param plaintext
   * @return new ciphertext for ciphertext + plaintext
   */
    Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        plaintext->SetFormat(EVALUATION);
        return GetScheme()->EvalAdd(ciphertext, plaintext);
    }

    Ciphertext<Element> EvalAdd(ConstPlaintext plaintext, ConstCiphertext<Element> ciphertext) const {
        return EvalAdd(ciphertext, plaintext);
    }

    void EvalAddInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        plaintext->SetFormat(EVALUATION);
        GetScheme()->EvalAddInPlace(ciphertext, plaintext);
    }

    void EvalAddInPlace(ConstPlaintext plaintext, Ciphertext<Element>& ciphertext) const {
        EvalAddInPlace(ciphertext, plaintext);
    }
    /**
   * EvalAdd - OpenFHE EvalAddMutable method for a ciphertext and plaintext
   * This is a mutable version - input ciphertexts may get automatically
   * rescaled, or level-reduced.
   *
   * @param ciphertext
   * @param plaintext
   * @return new ciphertext for ciphertext + plaintext
   */
    Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        TypeCheck((ConstCiphertext<Element>)ciphertext, (ConstPlaintext)plaintext);
        plaintext->SetFormat(EVALUATION);
        return GetScheme()->EvalAddMutable(ciphertext, plaintext);
    }

    Ciphertext<Element> EvalAddMutable(Plaintext plaintext, Ciphertext<Element>& ciphertext) const {
        return EvalAddMutable(ciphertext, plaintext);
    }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, const NativeInteger& constant) const {
    //  return GetScheme()->EvalAdd(ciphertext, constant);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalAdd(const NativeInteger& constant, ConstCiphertext<Element> ciphertext) const {
    //  return EvalAdd(ciphertext, constant);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // void EvalAddInPlace(Ciphertext<Element>& ciphertext, const NativeInteger& constant) const {
    //  GetScheme()->EvalAddInPlace(ciphertext, constant);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // void EvalAddInPlace(const NativeInteger& constant, Ciphertext<Element>& ciphertext) const {
    //  EvalAddInPlace(ciphertext, constant);
    // }

    /**
   * EvalAdd - OpenFHE EvalAdd method for a ciphertext and constant
   * @param ciphertext
   * @param constant
   * @return new ciphertext for ciphertext + constant
   */
    Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, double constant) const {
        Ciphertext<Element> result =
            constant >= 0 ? GetScheme()->EvalAdd(ciphertext, constant) : GetScheme()->EvalSub(ciphertext, -constant);
        return result;
    }

    Ciphertext<Element> EvalAdd(double constant, ConstCiphertext<Element> ciphertext) const {
        return EvalAdd(ciphertext, constant);
    }

    void EvalAddInPlace(Ciphertext<Element>& ciphertext, double constant) const {
        if (constant == 0)
            return;
        if (constant > 0) {
            GetScheme()->EvalAddInPlace(ciphertext, constant);
        }
        else {
            GetScheme()->EvalSubInPlace(ciphertext, std::fabs(constant));
        }
    }

    void EvalAddInPlace(double constant, Ciphertext<Element>& ciphertext) const {
        EvalAddInPlace(ciphertext, constant);
    }

    //------------------------------------------------------------------------------
    // SHE SUBTRACTION Wrapper
    //------------------------------------------------------------------------------

    /**
   * EvalSub - OpenFHE EvalSub method for a pair of ciphertexts
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 - ct2
   */
    Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalSub(ciphertext1, ciphertext2);
    }

    void EvalSubInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalSubInPlace(ciphertext1, ciphertext2);
    }

    /**
   * EvalSub - OpenFHE EvalSubMutable method for a pair of ciphertexts
   * This is a mutable version - input ciphertexts may get automatically
   * rescaled, or level-reduced.
   *
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 - ct2
   */
    Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalSubMutable(ciphertext1, ciphertext2);
    }

    void EvalSubMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalSubMutableInPlace(ciphertext1, ciphertext2);
    }

    /**
   * EvalSubPlain - OpenFHE EvalSub method for a ciphertext and plaintext
   * @param ciphertext
   * @param plaintext
   * @return new ciphertext for ciphertext - plaintext
   */
    Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        return GetScheme()->EvalSub(ciphertext, plaintext);
    }

    Ciphertext<Element> EvalSub(ConstPlaintext plaintext, ConstCiphertext<Element> ciphertext) const {
        return EvalAdd(EvalNegate(ciphertext), plaintext);
    }

    /**
   * EvalSubPlain - OpenFHE EvalSubMutable method for a ciphertext and
   * plaintext This is a mutable version - input ciphertexts may get
   * automatically rescaled, or level-reduced.
   *
   * @param ciphertext
   * @param plaintext
   * @return new ciphertext for ciphertext - plaintext
   */
    Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        TypeCheck((ConstCiphertext<Element>)ciphertext, (ConstPlaintext)plaintext);
        return GetScheme()->EvalSubMutable(ciphertext, plaintext);
    }

    Ciphertext<Element> EvalSubMutable(Plaintext plaintext, Ciphertext<Element>& ciphertext) const {
        Ciphertext<Element> negated = EvalNegate(ciphertext);
        Ciphertext<Element> result  = EvalAddMutable(negated, plaintext);
        ciphertext                  = EvalNegate(negated);
        return result;
    }

    Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, double constant) const {
        Ciphertext<Element> result =
            constant >= 0 ? GetScheme()->EvalSub(ciphertext, constant) : GetScheme()->EvalAdd(ciphertext, -constant);
        return result;
    }

    Ciphertext<Element> EvalSub(double constant, ConstCiphertext<Element> ciphertext) const {
        return EvalAdd(EvalNegate(ciphertext), constant);
    }

    void EvalSubInPlace(Ciphertext<Element>& ciphertext, double constant) const {
        if (constant >= 0) {
            GetScheme()->EvalSubInPlace(ciphertext, constant);
        }
        else {
            GetScheme()->EvalAddInPlace(ciphertext, -constant);
        }
    }

    void EvalSubInPlace(double constant, Ciphertext<Element>& ciphertext) const {
        EvalNegateInPlace(ciphertext);
        EvalAddInPlace(ciphertext, constant);
    }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, const NativeInteger& constant) const {
    //  return GetScheme()->EvalSub(ciphertext, constant);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalSub(const NativeInteger& constant, ConstCiphertext<Element> ciphertext) const {
    //  return EvalAdd(EvalNegate(ciphertext), constant);
    // }

    //  void EvalSubInPlace(Ciphertext<Element>& ciphertext, const NativeInteger& constant) const {
    //    GetScheme()->EvalSubInPlace(ciphertext, constant);
    //  }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // void EvalSubInPlace(const NativeInteger& constant, Ciphertext<Element>& ciphertext) const {
    //  EvalNegateInPlace(ciphertext);
    //  EvalAddInPlace(ciphertext, constant);
    // }

    //------------------------------------------------------------------------------
    // SHE MULTIPLICATION Wrapper
    //------------------------------------------------------------------------------

    /**
   * EvalMultKeyGen creates a key that can be used with the OpenFHE EvalMult
   * operator
   * the new evaluation key is stored in cryptocontext
   * @param key
   */
    void EvalMultKeyGen(const PrivateKey<Element> key) {
        if (key == nullptr || Mismatched(key->GetCryptoContext()))
            OPENFHE_THROW(config_error, "Key passed to EvalMultKeyGen were not generated with this crypto context");

        EvalKey<Element> k = GetScheme()->EvalMultKeyGen(key);

        GetAllEvalMultKeys()[k->GetKeyTag()] = {k};
    }

    /**
   * EvalMultsKeyGen creates a vector evalmult keys that can be used with the
   * OpenFHE EvalMult operator 1st key (for s^2) is used for multiplication of
   * ciphertexts of depth 1 2nd key (for s^3) is used for multiplication of
   * ciphertexts of depth 2, etc.
   * a vector of new evaluation keys is stored in crytpocontext
   *
   * @param key
   */
    void EvalMultKeysGen(const PrivateKey<Element> key) {
        if (key == nullptr || Mismatched(key->GetCryptoContext()))
            OPENFHE_THROW(config_error, "Key passed to EvalMultsKeyGen were not generated with this crypto context");

        const std::vector<EvalKey<Element>>& evalKeys = GetScheme()->EvalMultKeysGen(key);

        GetAllEvalMultKeys()[evalKeys[0]->GetKeyTag()] = evalKeys;
    }

    /**
   * EvalMult - OpenFHE EvalMult method for a pair of ciphertexts - with key
   * switching
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 * ct2
   */
    Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);

        const auto evalKeyVec = GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW(type_error, "Evaluation key has not been generated for EvalMult");
        }

        return GetScheme()->EvalMult(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    /**
   * EvalMult - OpenFHE EvalMult method for a pair of ciphertexts - with key
   * switching This is a mutable version - input ciphertexts may get
   * automatically rescaled, or level-reduced.
   *
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 * ct2
   */
    Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);

        const auto evalKeyVec = GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW(type_error, "Evaluation key has not been generated for EvalMultMutable");
        }

        return GetScheme()->EvalMultMutable(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    /**
   * EvalMult - OpenFHE EvalMult method for a pair of ciphertexts - with key
   * switching This is a mutable version - input ciphertexts may get
   * automatically rescaled, or level-reduced.
   *
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 * ct2
   */
    void EvalMultMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);

        const auto evalKeyVec = GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW(type_error, "Evaluation key has not been generated for EvalMultMutable");
        }

        GetScheme()->EvalMultMutableInPlace(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    Ciphertext<Element> EvalSquare(ConstCiphertext<Element> ciphertext) const {
        CheckCiphertext(ciphertext);

        const auto evalKeyVec = GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW(type_error, "Evaluation key has not been generated for EvalMult");
        }

        return GetScheme()->EvalSquare(ciphertext, evalKeyVec[0]);
    }

    Ciphertext<Element> EvalSquareMutable(Ciphertext<Element>& ciphertext) const {
        CheckCiphertext(ciphertext);

        const auto evalKeyVec = GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW(type_error, "Evaluation key has not been generated for EvalMultMutable");
        }

        return GetScheme()->EvalSquareMutable(ciphertext, evalKeyVec[0]);
    }

    void EvalSquareInPlace(Ciphertext<Element>& ciphertext) const {
        CheckCiphertext(ciphertext);

        const auto evalKeyVec = GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW(type_error, "Evaluation key has not been generated for EvalMultMutable");
        }

        GetScheme()->EvalSquareInPlace(ciphertext, evalKeyVec[0]);
    }

    /**
   * EvalMult - OpenFHE EvalMult method for a pair of ciphertexts - no key
   * switching (relinearization)
   * @param ct1
   * @param ct2
   * @return new ciphertext for ct1 * ct2
   */
    Ciphertext<Element> EvalMultNoRelin(ConstCiphertext<Element> ciphertext1,
                                        ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalMult(ciphertext1, ciphertext2);
    }

    /**
   * Function for relinearization of a ciphertext.
   *
   * @param ct input ciphertext.
   *
   * @return relinearized ciphertext
   */
    Ciphertext<Element> Relinearize(ConstCiphertext<Element> ciphertext) const {
        // input parameter check
        if (!ciphertext)
            OPENFHE_THROW(type_error, "Input ciphertext is nullptr");

        const auto evalKeyVec = GetEvalMultKeyVector(ciphertext->GetKeyTag());

        if (evalKeyVec.size() < (ciphertext->GetElements().size() - 2)) {
            OPENFHE_THROW(type_error,
                          "Insufficient value was used for maxRelinSkDeg to generate "
                          "keys for EvalMult");
        }

        return GetScheme()->Relinearize(ciphertext, evalKeyVec);
    }

    /**
   * Function for relinearization of a ciphertext.
   *
   * @param ct input ciphertext.
   *
   * @return relinearized ciphertext
   */
    void RelinearizeInPlace(Ciphertext<Element>& ciphertext) const {
        // input parameter check
        if (!ciphertext)
            OPENFHE_THROW(type_error, "Input ciphertext is nullptr");

        const auto evalKeyVec = GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (evalKeyVec.size() < (ciphertext->GetElements().size() - 2)) {
            OPENFHE_THROW(type_error,
                          "Insufficient value was used for maxRelinSkDeg to generate "
                          "keys for EvalMult");
        }

        GetScheme()->RelinearizeInPlace(ciphertext, evalKeyVec);
    }

    /**
   * Function for evaluating multiplication on ciphertext followed by
   * relinearization operation. Currently it assumes that the input arguments
   * have total depth smaller than the supported depth. Otherwise, it throws an
   * error.
   *
   * @param ct1 first input ciphertext.
   * @param ct2 second input ciphertext.
   *
   * @return new ciphertext
   */
    Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element> ciphertext1,
                                               ConstCiphertext<Element> ciphertext2) const {
        // input parameter check
        if (!ciphertext1 || !ciphertext2)
            OPENFHE_THROW(type_error, "Input ciphertext is nullptr");

        const auto evalKeyVec = GetEvalMultKeyVector(ciphertext1->GetKeyTag());

        if (evalKeyVec.size() < (ciphertext1->GetElements().size() + ciphertext2->GetElements().size() - 3)) {
            OPENFHE_THROW(type_error,
                          "Insufficient value was used for maxRelinSkDeg to generate "
                          "keys for EvalMult");
        }

        return GetScheme()->EvalMultAndRelinearize(ciphertext1, ciphertext2, evalKeyVec);
    }

    Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        return GetScheme()->EvalMult(ciphertext, plaintext);
    }

    Ciphertext<Element> EvalMult(ConstPlaintext plaintext, ConstCiphertext<Element> ciphertext) const {
        return EvalMult(ciphertext, plaintext);
    }

    Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        return GetScheme()->EvalMultMutable(ciphertext, plaintext);
    }

    Ciphertext<Element> EvalMultMutable(Plaintext plaintext, Ciphertext<Element>& ciphertext) const {
        return EvalMultMutable(ciphertext, plaintext);
    }

    // template <typename T = const NativeInteger,
    //    typename std::enable_if <!std::is_same<ConstCiphertext<Element>, T>::value, bool>::type = true>

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, const NativeInteger& constant) const {
    //  if (!ciphertext) {
    //    OPENFHE_THROW(type_error, "Input ciphertext is nullptr");
    //  }
    //  return GetScheme()->EvalMult(ciphertext, constant);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalMult(const NativeInteger& constant, ConstCiphertext<Element> ciphertext) const {
    //  return EvalMult(ciphertext, constant);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // void EvalMultInPlace(Ciphertext<Element>& ciphertext, const NativeInteger& constant) const {
    //  if (!ciphertext) {
    //    OPENFHE_THROW(type_error, "Input ciphertext is nullptr");
    //  }

    //  GetScheme()->EvalMultInPlace(ciphertext, constant);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // void EvalMultInPlace(const NativeInteger& constant, Ciphertext<Element>& ciphertext) const {
    //  EvalMultInPlace(ciphertext, constant);
    // }

    Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, double constant) const {
        if (!ciphertext) {
            OPENFHE_THROW(type_error, "Input ciphertext is nullptr");
        }
        return GetScheme()->EvalMult(ciphertext, constant);
    }

    inline Ciphertext<Element> EvalMult(double constant, ConstCiphertext<Element> ciphertext) const {
        return EvalMult(ciphertext, constant);
    }

    void EvalMultInPlace(Ciphertext<Element>& ciphertext, double constant) const {
        if (!ciphertext) {
            OPENFHE_THROW(type_error, "Input ciphertext is nullptr");
        }

        GetScheme()->EvalMultInPlace(ciphertext, constant);
    }

    inline void EvalMultInPlace(double constant, Ciphertext<Element>& ciphertext) const {
        EvalMultInPlace(ciphertext, constant);
    }

    //------------------------------------------------------------------------------
    // SHE AUTOMORPHISM Wrapper
    //------------------------------------------------------------------------------

    /**
   * Generate automophism keys for a given private key; Uses the private key for
   * encryption
   *
   * @param privateKey private key.
   * @param indexList list of automorphism indices to be computed
   * @return returns the evaluation keys
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAutomorphismKeyGen(
        const PrivateKey<Element> privateKey, const std::vector<usint>& indexList) const {
        CheckKey(privateKey);
        if (!indexList.size())
            OPENFHE_THROW(config_error, "Input index vector is empty");

        return GetScheme()->EvalAutomorphismKeyGen(privateKey, indexList);
    }

    /**
   * Generate automophism keys for a given private key
   *
   * @param publicKey original public key.
   * @param origPrivateKey original private key.
   * @param indexList list of automorphism indices to be computed
   * @return returns the evaluation keys; index 0 of the vector corresponds to
   * plaintext index 2, index 1 to plaintex index 3, etc.
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalAutomorphismKeyGen(
        const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
        const std::vector<usint>& indexList) const {
        CheckKey(publicKey);
        CheckKey(privateKey);
        if (!indexList.size())
            OPENFHE_THROW(config_error, "Input index vector is empty");

        return GetScheme()->EvalAutomorphismKeyGen(publicKey, privateKey, indexList);
    }

    /**
   * Function for evaluating automorphism of ciphertext at index i
   *
   * @param ciphertext the input ciphertext.
   * @param i automorphism index
   * @param &evalKeys - reference to the vector of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
                                         const std::map<usint, EvalKey<Element>>& evalKeyMap,
                                         CALLER_INFO_ARGS_HDR) const {
        CheckCiphertext(ciphertext);

        if (evalKeyMap.empty()) {
            std::string errorMsg(std::string("Empty input key map") + CALLER_INFO);
            OPENFHE_THROW(type_error, errorMsg);
        }

        auto key = evalKeyMap.find(i);

        if (key == evalKeyMap.end()) {
            std::string errorMsg(std::string("Could not find an EvalKey for index ") + std::to_string(i) + CALLER_INFO);
            OPENFHE_THROW(type_error, errorMsg);
        }

        auto evalKey = key->second;

        CheckKey(evalKey);

        return GetScheme()->EvalAutomorphism(ciphertext, i, evalKeyMap);
    }

    usint FindAutomorphismIndex(const usint idx) const {
        const auto cryptoParams  = GetCryptoParameters();
        const auto elementParams = cryptoParams->GetElementParams();
        uint32_t m               = elementParams->GetCyclotomicOrder();
        return GetScheme()->FindAutomorphismIndex(idx, m);
    }

    std::vector<usint> FindAutomorphismIndices(const std::vector<usint> idxList) const {
        std::vector<usint> newIndices;
        newIndices.reserve(idxList.size());
        for (const auto idx : idxList) {
            newIndices.emplace_back(FindAutomorphismIndex(idx));
        }
        return newIndices;
    }

    Ciphertext<Element> EvalRotate(ConstCiphertext<Element> ciphertext, int32_t index) const {
        CheckCiphertext(ciphertext);

        auto evalKeyMap = GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
        return GetScheme()->EvalAtIndex(ciphertext, index, evalKeyMap);
    }

    /**
   * EvalFastRotationPrecompute implements the precomputation step of
   * hoisted automorphisms.
   *
   * Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic
   * linear transformations in HELib." for more details, link:
   * https://eprint.iacr.org/2018/244.
   *
   * Generally, automorphisms are performed with three steps: (1) the
   * automorphism is applied on the ciphertext, (2) the automorphed values are
   * decomposed into digits, and (3) key switching is applied to make it
   * possible to further compute on the ciphertext.
   *
   * Hoisted automorphisms is a technique that performs the digit decomposition
   * for the original ciphertext first, and then performs the automorphism and
   * the key switching on the decomposed digits. The benefit of this is that the
   * digit decomposition is independent of the automorphism rotation index, so
   * it can be reused for multiple different indices. This can greatly improve
   * performance when we have to compute many automorphisms on the same
   * ciphertext. This routinely happens when we do permutations (EvalPermute).
   *
   * EvalFastRotationPrecompute implements the digit decomposition step of
   * hoisted automorphisms.
   *
   * @param ct the input ciphertext on which to do the precomputation (digit
   * decomposition)
   */
    std::shared_ptr<std::vector<Element>> EvalFastRotationPrecompute(ConstCiphertext<Element> ciphertext) const {
        return GetScheme()->EvalFastRotationPrecompute(ciphertext);
    }

    /**
   * EvalFastRotation implements the automorphism and key switching step of
   * hoisted automorphisms.
   *
   * Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic
   * linear transformations in HELib." for more details, link:
   * https://eprint.iacr.org/2018/244.
   *
   * Generally, automorphisms are performed with three steps: (1) the
   * automorphism is applied on the ciphertext, (2) the automorphed values are
   * decomposed into digits, and (3) key switching is applied to make it
   * possible to further compute on the ciphertext.
   *
   * Hoisted automorphisms is a technique that performs the digit decomposition
   * for the original ciphertext first, and then performs the automorphism and
   * the key switching on the decomposed digits. The benefit of this is that the
   * digit decomposition is independent of the automorphism rotation index, so
   * it can be reused for multiple different indices. This can greatly improve
   * performance when we have to compute many automorphisms on the same
   * ciphertext. This routinely happens when we do permutations (EvalPermute).
   *
   * EvalFastRotation implements the automorphism and key swithcing step of
   * hoisted automorphisms.
   *
   * This method assumes that all required rotation keys exist. This may not be
   * true if we are using baby-step/giant-step key switching. Please refer to
   * Section 5.1 of the above reference and EvalPermuteBGStepHoisted to see how
   * to deal with this issue.
   *
   * @param ct the input ciphertext to perform the automorphism on
   * @param index the index of the rotation. Positive indices correspond to left
   * rotations and negative indices correspond to right rotations.
   * @param m is the cyclotomic order
   * @param digits the digit decomposition created by EvalFastRotationPrecompute
   * at the precomputation step.
   */
    Ciphertext<Element> EvalFastRotation(ConstCiphertext<Element> ciphertext, const usint index, const usint m,
                                         const std::shared_ptr<std::vector<Element>> digits) const {
        return GetScheme()->EvalFastRotation(ciphertext, index, m, digits);
    }

    /**
   * Only supported for hybrid key switching.
   * Performs fast (hoisted) rotation and returns the results
   * in the extended CRT basis P*Q
   *
   * @param ciphertext input ciphertext
   * @param index the rotation index.
   * @param digits the precomputed digits for the ciphertext
   * @param addFirst if true, the the first element c0 is also computed (otherwise ignored)
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalFastRotationExt(ConstCiphertext<Element> ciphertext, usint index,
                                            const std::shared_ptr<std::vector<Element>> digits, bool addFirst) const {
        auto evalKeyMap = GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());

        return GetScheme()->EvalFastRotationExt(ciphertext, index, digits, addFirst, evalKeyMap);
    }

    /**
   * Only supported for hybrid key switching.
   * Takes a ciphertext in the extended basis P*Q
   * and scales down to Q.
   *
   * @param ciphertext input ciphertext in the extended basis
   * @return resulting ciphertext
   */
    Ciphertext<Element> KeySwitchDown(ConstCiphertext<Element> ciphertext) const {
        return GetScheme()->KeySwitchDown(ciphertext);
    }

    /**
   * Only supported for hybrid key switching.
   * Scales down the polynomial c0 from extended basis P*Q to Q.
   *
   * @param ciphertext input ciphertext in the extended basis
   * @return resulting polynomial
   */
    Element KeySwitchDownFirstElement(ConstCiphertext<Element> ciphertext) const {
        return GetScheme()->KeySwitchDownFirstElement(ciphertext);
    }

    /**
   * Only supported for hybrid key switching.
   * Takes a ciphertext in the normal basis Q
   * and extends it to extended basis P*Q.
   *
   * @param ciphertext input ciphertext in basis Q
   * @return resulting ciphertext in basis P*Q
   */
    Ciphertext<Element> KeySwitchExt(ConstCiphertext<Element> ciphertext, bool addFirst) const {
        return GetScheme()->KeySwitchExt(ciphertext, addFirst);
    }

    /**
   * EvalAtIndexKeyGen generates evaluation keys for a list of indices
   *
   * @param privateKey private key.
   * @param indexList list of indices.
   * @param publicKey public key (used in NTRU schemes).
   */
    void EvalAtIndexKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList,
                           const PublicKey<Element> publicKey = nullptr);

    /**
   * EvalRotateKeyGen generates evaluation keys for a list of indices
   *
   * @param privateKey private key.
   * @param indexList list of indices.
   * @param publicKey public key (used in NTRU schemes).
   */
    void EvalRotateKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList,
                          const PublicKey<Element> publicKey = nullptr) {
        EvalAtIndexKeyGen(privateKey, indexList, publicKey);
    };

    /**
   * Moves i-th slot to slot 0
   *
   * @param ciphertext.
   * @param i the index.
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalAtIndex(ConstCiphertext<Element> ciphertext, int32_t index) const;

    //------------------------------------------------------------------------------
    // SHE Leveled Methods Wrapper
    //------------------------------------------------------------------------------

    /**
   * ComposedEvalMult - OpenFHE composed evalmult
   * @param ciphertext1 - vector for first cipher text
   * @param ciphertext2 - vector for second cipher text
   * @param quadKeySwitchHint - is the quadratic key switch hint from original
   * private key to the quadratic key return vector of resulting ciphertext
   */
    Ciphertext<Element> ComposedEvalMult(ConstCiphertext<Element> ciphertext1,
                                         ConstCiphertext<Element> ciphertext2) const {
        CheckCiphertext(ciphertext1);
        CheckCiphertext(ciphertext2);

        auto evalKeyVec = GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW(type_error, "Evaluation key has not been generated for EvalMult");
        }

        return GetScheme()->ComposedEvalMult(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    /**
   * Rescale - An alias for OpenFHE ModReduce method.
   * This is because ModReduce is called Rescale in CKKS.
   *
   * @param ciphertext - ciphertext
   * @return mod reduced ciphertext
   */
    Ciphertext<Element> Rescale(ConstCiphertext<Element> ciphertext) const {
        CheckCiphertext(ciphertext);

        return GetScheme()->ModReduce(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    }

    /**
   * Rescale - An alias for OpenFHE ModReduceInPlace method.
   * This is because ModReduceInPlace is called RescaleInPlace in CKKS.
   *
   * @param ciphertext - ciphertext to be mod-reduced in-place
   */
    void RescaleInPlace(Ciphertext<Element>& ciphertext) const {
        CheckCiphertext(ciphertext);

        GetScheme()->ModReduceInPlace(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    }

    /**
   * ModReduce - OpenFHE ModReduce method used only for BGVrns
   * @param ciphertext - ciphertext
   * @return mod reduced ciphertext
   */
    Ciphertext<Element> ModReduce(ConstCiphertext<Element> ciphertext) const {
        CheckCiphertext(ciphertext);

        return GetScheme()->ModReduce(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    }

    /**
   * ModReduce - OpenFHE ModReduceInPlace method used only for BGVrns
   * @param ciphertext - ciphertext to be mod-reduced in-place
   */
    void ModReduceInPlace(Ciphertext<Element>& ciphertext) const {
        CheckCiphertext(ciphertext);

        GetScheme()->ModReduceInPlace(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    }

    /**
   * LevelReduce - OpenFHE LevelReduce method
   * @param cipherText1
   * @param linearKeySwitchHint
   * @return vector of level reduced ciphertext
   */
    Ciphertext<Element> LevelReduce(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey,
                                    size_t levels = 1) const {
        CheckCiphertext(ciphertext);

        return GetScheme()->LevelReduce(ciphertext, evalKey, levels);
    }

    void LevelReduceInPlace(Ciphertext<Element>& ciphertext, const EvalKey<Element> evalKey, size_t levels = 1) const {
        CheckCiphertext(ciphertext);
        if (levels <= 0) {
            return;
        }
        GetScheme()->LevelReduceInPlace(ciphertext, evalKey, levels);
    }
    /**
   * Compress - Reduces the size of ciphertext modulus to minimize the
   * communication cost before sending the encrypted result for decryption
   * @param ciphertext1 - input ciphertext
   * @param numTowers - number of CRT limbs after compressing (default is 1)
   * @return compressed ciphertext
   */
    Ciphertext<Element> Compress(ConstCiphertext<Element> ciphertext, uint32_t towersLeft = 1) const {
        if (ciphertext == nullptr)
            OPENFHE_THROW(config_error, "input ciphertext is invalid (has no data)");

        return GetScheme()->Compress(ciphertext, towersLeft);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE Wrapper
    //------------------------------------------------------------------------------

    /**
   * EvalAddMany - Evaluate addition on a vector of ciphertexts.
   * It computes the addition in a binary tree manner.
   *
   * @param ctList is the list of ciphertexts.
   *
   * @return new ciphertext.
   */
    Ciphertext<Element> EvalAddMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const {
        // input parameter check
        if (!ciphertextVec.size())
            OPENFHE_THROW(type_error, "Empty input ciphertext vector");

        if (ciphertextVec.size() == 1) {
            return ciphertextVec[0];
        }

        return GetScheme()->EvalAddMany(ciphertextVec);
    }

    /**
   * EvalAddManyInPlace - Evaluate addition on a vector of ciphertexts.
   * Addition is computed in a binary tree manner. Difference with EvalAddMany
   * is that EvalAddManyInPlace uses the input ciphertext vector to store
   * intermediate results, to avoid the overhead of using extra tepmorary
   * space.
   *
   * @param ctList is the list of ciphertexts.
   *
   * @return new ciphertext.
   */
    Ciphertext<Element> EvalAddManyInPlace(std::vector<Ciphertext<Element>>& ciphertextVec) const {
        // input parameter check
        if (!ciphertextVec.size())
            OPENFHE_THROW(type_error, "Empty input ciphertext vector");

        return GetScheme()->EvalAddManyInPlace(ciphertextVec);
    }

    /**
   * EvalMultMany - OpenFHE function for evaluating multiplication on
   * ciphertext followed by relinearization operation (at the end). It computes
   * the multiplication in a binary tree manner. Also, it reduces the number of
   * elements in the ciphertext to two after each multiplication.
   * Currently it assumes that the consecutive two input arguments have
   * total depth smaller than the supported depth. Otherwise, it throws an
   * error.
   *
   * @param cipherTextList  is the ciphertext list.
   *
   * @return new ciphertext.
   */
    Ciphertext<Element> EvalMultMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const {
        // input parameter check
        if (!ciphertextVec.size()) {
            OPENFHE_THROW(type_error, "Empty input ciphertext vector");
        }

        if (ciphertextVec.size() == 1) {
            return ciphertextVec[0];
        }

        const auto evalKeyVec = GetEvalMultKeyVector(ciphertextVec[0]->GetKeyTag());
        if (evalKeyVec.size() < (ciphertextVec[0]->GetElements().size() - 2)) {
            OPENFHE_THROW(type_error, "Insufficient value was used for maxRelinSkDeg to generate keys");
        }

        return GetScheme()->EvalMultMany(ciphertextVec, evalKeyVec);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE LINEAR WEIGHTED SUM
    //------------------------------------------------------------------------------

    /**
   * EvalLinearWSum - OpenFHE EvalLinearWSum method to compute a linear
   * weighted sum
   *
   * @param ciphertexts a list of ciphertexts
   * @param constants a list of weights
   * @return new ciphertext containing the weighted sum
   */
    Ciphertext<Element> EvalLinearWSum(std::vector<ConstCiphertext<Element>>& ciphertextVec,
                                       const std::vector<double>& constantVec) const {
        return GetScheme()->EvalLinearWSum(ciphertextVec, constantVec);
    }

    Ciphertext<Element> EvalLinearWSum(const std::vector<double>& constantsVec,
                                       std::vector<ConstCiphertext<Element>>& ciphertextVec) const {
        return EvalLinearWSum(ciphertextVec, constantsVec);
    }

    /**
   * EvalLinearWSum - method to compute a linear weighted sum.
   * This is a mutable version, meaning the level/depth of input
   * ciphertexts may change in the process.
   *
   * @param ciphertexts a list of ciphertexts
   * @param constants a list of weights
   * @return new ciphertext containing the weighted sum
   */
    Ciphertext<Element> EvalLinearWSumMutable(std::vector<Ciphertext<Element>>& ciphertextVec,
                                              const std::vector<double>& constantsVec) const {
        return GetScheme()->EvalLinearWSumMutable(ciphertextVec, constantsVec);
    }

    Ciphertext<Element> EvalLinearWSumMutable(const std::vector<double>& constantsVec,
                                              std::vector<Ciphertext<Element>>& ciphertextVec) const {
        return EvalLinearWSumMutable(ciphertextVec, constantsVec);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL POLYNOMIAL
    //------------------------------------------------------------------------------

    /**
   * Method for polynomial evaluation for polynomials represented as power
   * series.
   *
   * @param &cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial + 1
   * @return the result of polynomial evaluation.
   */
    virtual Ciphertext<Element> EvalPoly(ConstCiphertext<Element> ciphertext,
                                         const std::vector<double>& coefficients) const {
        CheckCiphertext(ciphertext);

        return GetScheme()->EvalPoly(ciphertext, coefficients);
    }

    /**
   * Method for polynomial evaluation for polynomials represented in the power
   * series. This uses EvalPolyLinear, which uses a binary tree computation of
   * the polynomial powers.
   *
   * @param &cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial
   * @return the result of polynomial evaluation.
   */
    Ciphertext<Element> EvalPolyLinear(ConstCiphertext<Element> ciphertext,
                                       const std::vector<double>& coefficients) const {
        CheckCiphertext(ciphertext);

        return GetScheme()->EvalPolyLinear(ciphertext, coefficients);
    }

    Ciphertext<Element> EvalPolyPS(ConstCiphertext<Element> ciphertext, const std::vector<double>& coefficients) const {
        CheckCiphertext(ciphertext);

        return GetScheme()->EvalPolyPS(ciphertext, coefficients);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL CHEBYSHEV SERIES
    //------------------------------------------------------------------------------

    /**
   * Method for evaluating Chebyshev polynomial interpolation;
   * first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2
   * (x-a)/(b-a) If the degree of the polynomial is less than 5, use
   * EvalChebyshevSeriesLinear, otherwise, use EvalChebyshevSeriesPS.
   *
   * @param &cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in Chebyshev expansion
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @return the result of polynomial evaluation.
   */
    Ciphertext<Element> EvalChebyshevSeries(ConstCiphertext<Element> ciphertext,
                                            const std::vector<double>& coefficients, double a, double b) const {
        CheckCiphertext(ciphertext);

        return GetScheme()->EvalChebyshevSeries(ciphertext, coefficients, a, b);
    }

    Ciphertext<Element> EvalChebyshevSeriesLinear(ConstCiphertext<Element> ciphertext,
                                                  const std::vector<double>& coefficients, double a, double b) const {
        CheckCiphertext(ciphertext);

        return GetScheme()->EvalChebyshevSeriesLinear(ciphertext, coefficients, a, b);
    }

    Ciphertext<Element> EvalChebyshevSeriesPS(ConstCiphertext<Element> ciphertext,
                                              const std::vector<double>& coefficients, double a, double b) const {
        CheckCiphertext(ciphertext);

        return GetScheme()->EvalChebyshevSeriesPS(ciphertext, coefficients, a, b);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE CHEBYSHEV SERIES EXAMPLES
    //------------------------------------------------------------------------------

    /**
   * Method for calculating Chebyshev evaluation on a ciphertext for a smooth input
   * function over the range [a,b].
   *
   * @param func is the function to be approximated
   * @param ciphertext input ciphertext
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @param degree Desired degree of approximation
   * @return the coefficients of the Chebyshev approximation.
   */
    Ciphertext<Element> EvalChebyshevFunction(std::function<double(double)> func, ConstCiphertext<Element> ciphertext,
                                              double a, double b, uint32_t degree) const;

    /**
   * Evaluate approximate sine function on a ciphertext using the Chebyshev approximation.
   *
   * @param ciphertext input ciphertext
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @param degree Desired degree of approximation
   * @return the result of polynomial evaluation.
   */
    Ciphertext<Element> EvalSin(ConstCiphertext<Element> ciphertext, double a, double b, uint32_t degree) const;

    /**
   * Evaluate approximate cosine function on a ciphertext using the Chebyshev approximation.
   *
   * @param ciphertext input ciphertext
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @param degree Desired degree of approximation
   * @return the result of polynomial evaluation.
   */
    Ciphertext<Element> EvalCos(ConstCiphertext<Element> ciphertext, double a, double b, uint32_t degree) const;

    /**
   * Evaluate approximate logistic function 1/(1 + exp(-x)) on a ciphertext using the Chebyshev approximation.
   *
   * @param ciphertext input ciphertext
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @param degree Desired degree of approximation
   * @return the result of polynomial evaluation.
   */
    Ciphertext<Element> EvalLogistic(ConstCiphertext<Element> ciphertext, double a, double b, uint32_t degree) const;

    /**
   * Evaluate approximate division function 1/x where x >= 1 on a ciphertext using the Chebyshev approximation.
   *
   * @param ciphertext input ciphertext
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @param degree Desired degree of approximation
   * @return the result of polynomial evaluation.
   */
    Ciphertext<Element> EvalDivide(ConstCiphertext<Element> ciphertext, double a, double b, uint32_t degree) const;

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL SUM
    //------------------------------------------------------------------------------

    /**
   * EvalSumKeyGen Generates the key map to be used by evalsum
   *
   * @param privateKey private key.
   * @param publicKey public key (used in NTRU schemes).
   */
    void EvalSumKeyGen(const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey = nullptr);

    std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumRowsKeyGen(const PrivateKey<Element> privateKey,
                                                                         const PublicKey<Element> publicKey = nullptr,
                                                                         usint rowSize = 0, usint subringDim = 0);

    std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumColsKeyGen(const PrivateKey<Element> privateKey,
                                                                         const PublicKey<Element> publicKey = nullptr);

    /**
   * Function for evaluating a sum of all components
   *
   * @param ciphertext the input ciphertext.
   * @param batchSize size of the batch
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize) const;

    Ciphertext<Element> EvalSumRows(ConstCiphertext<Element> ciphertext, usint rowSize,
                                    const std::map<usint, EvalKey<Element>>& evalSumKeyMap, usint subringDim = 0) const;

    Ciphertext<Element> EvalSumCols(ConstCiphertext<Element> ciphertext, usint rowSize,
                                    const std::map<usint, EvalKey<Element>>& evalSumKeyMap) const;

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL INNER PRODUCT
    //------------------------------------------------------------------------------

    /**
   * Evaluates inner product in batched encoding
   *
   * @param ciphertext1 first vector.
   * @param ciphertext2 second vector.
   * @param batchSize size of the batch to be summed up
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2,
                                         usint batchSize) const;

    /**
   * Evaluates inner product in batched encoding
   *
   * @param ciphertext1 first vector - ciphertext.
   * @param plaintext second vector - plaintext.
   * @param batchSize size of the batch to be summed up
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext,
                                         usint batchSize) const;

    /**
   * Merges multiple ciphertexts with encrypted results in slot 0 into a single
   * ciphertext The slot assignment is done based on the order of ciphertexts in
   * the vector
   *
   * @param ciphertextVector vector of ciphertexts to be merged.
   * @param &evalKeys - reference to the map of evaluation keys generated by
   * EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalMerge(const std::vector<Ciphertext<Element>>& ciphertextVec) const;

    //------------------------------------------------------------------------------
    // PRE Wrapper
    //------------------------------------------------------------------------------

    /**
   * ReKeyGen produces an Eval Key that OpenFHE can use for Proxy Re Encryption
   * @param newKey (public)
   * @param oldKey (private)
   * @return new evaluation key
   */
    EvalKey<Element> ReKeyGen(const PrivateKey<Element> oldPrivateKey, const PublicKey<Element> newPublicKey) const {
        CheckKey(oldPrivateKey);
        CheckKey(newPublicKey);

        return GetScheme()->ReKeyGen(oldPrivateKey, newPublicKey);
    }

    /**
   * ReKeyGen produces an Eval Key that OpenFHE can use for Proxy Re Encryption
   * NOTE this functionality has been completely removed from OpenFHE
   * @param newKey (private)
   * @param oldKey (private)
   * @return new evaluation key
   */
    EvalKey<Element> ReKeyGen(const PrivateKey<Element> originalPrivateKey,
                              const PrivateKey<Element> newPrivateKey) const
        __attribute__((deprecated("functionality removed from OpenFHE")));

    /**
   * ReEncrypt - Proxy Re Encryption mechanism for OpenFHE
   * @param evalKey - evaluation key from the PRE keygen method
   * @param ciphertext - vector of shared pointers to encrypted Ciphertext
   * @param publicKey the public key of the recipient of the re-encrypted
   * ciphertext.
   * @return vector of shared pointers to re-encrypted ciphertexts
   */
    Ciphertext<Element> ReEncrypt(ConstCiphertext<Element> ciphertext, EvalKey<Element> evalKey,
                                  const PublicKey<Element> publicKey = nullptr) const {
        CheckCiphertext(ciphertext);
        CheckKey(evalKey);

        return GetScheme()->ReEncrypt(ciphertext, evalKey, publicKey);
    }

    //------------------------------------------------------------------------------
    // Multiparty Wrapper
    //------------------------------------------------------------------------------

    /**
   * Threshold FHE: Generates a public key from a vector of secret shares.
   * ONLY FOR DEBUGGIN PURPOSES. SHOULD NOT BE USED IN PRODUCTION.
   *
   * @param secretkeys secrete key shares.
   * @return key pair including the private for the current party and joined
   * public key
   */
    KeyPair<Element> MultipartyKeyGen(const std::vector<PrivateKey<Element>>& privateKeyVec) {
        if (!privateKeyVec.size())
            OPENFHE_THROW(config_error, "Input private key vector is empty");
        return GetScheme()->MultipartyKeyGen(GetContextForPointer(this), privateKeyVec, false);
    }

    /**
   * Threshold FHE: Generation of a public key derived
   * from a previous joined public key (for prior secret shares) and the secret
   * key share of the current party.
   *
   * @param pk joined public key from prior parties.
   * @param makeSparse set to true if ring reduce by a factor of 2 is to be
   * used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
   * @param fresh set to true if proxy re-encryption is used in the multi-party
   * protocol or star topology is used
   * @return key pair including the secret share for the current party and
   * joined public key
   */
    KeyPair<Element> MultipartyKeyGen(const PublicKey<Element> publicKey, bool makeSparse = false, bool fresh = false) {
        if (!publicKey)
            OPENFHE_THROW(config_error, "Input public key is empty");
        return GetScheme()->MultipartyKeyGen(GetContextForPointer(this), publicKey, makeSparse, fresh);
    }

    /**
   * Threshold FHE: Method for decryption operation run by the lead decryption
   * client
   *
   * @param privateKey secret key share used for decryption.
   * @param ciphertext ciphertext id decrypted.
   */
    std::vector<Ciphertext<Element>> MultipartyDecryptLead(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                           const PrivateKey<Element> privateKey) const {
        CheckKey(privateKey);

        std::vector<Ciphertext<Element>> newCiphertextVec;

        for (size_t i = 0; i < ciphertextVec.size(); i++) {
            CheckCiphertext(ciphertextVec[i]);
            newCiphertextVec.push_back(GetScheme()->MultipartyDecryptLead(ciphertextVec[i], privateKey));
        }

        return newCiphertextVec;
    }

    /**
   * Threshold FHE: "Partial" decryption computed by all parties except for the
   * lead one
   *
   * @param privateKey secret key share used for decryption.
   * @param ciphertext ciphertext that is being decrypted.
   */
    std::vector<Ciphertext<Element>> MultipartyDecryptMain(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                           const PrivateKey<Element> privateKey) const {
        CheckKey(privateKey);

        std::vector<Ciphertext<Element>> newCiphertextVec;
        for (size_t i = 0; i < ciphertextVec.size(); i++) {
            CheckCiphertext(ciphertextVec[i]);
            newCiphertextVec.push_back(GetScheme()->MultipartyDecryptMain(ciphertextVec[i], privateKey));
        }

        return newCiphertextVec;
    }

    /**
   * Threshold FHE: Method for combining the partially decrypted ciphertexts
   * and getting the final decryption in the clear.
   *
   * @param &partialCiphertextVec vector of "partial" decryptions.
   * @param *plaintext the plaintext output.
   * @return the decoding result.
   */
    void MultipartyDecryptFusion(const PrivateKey<Element> key) {
        if (key == nullptr || Mismatched(key->GetCryptoContext()))
            OPENFHE_THROW(config_error, "Key passed to EvalMultsKeyGen were not generated with this crypto context");

        const std::vector<EvalKey<Element>>& evalKeys = GetScheme()->EvalMultKeysGen(key);

        GetAllEvalMultKeys()[evalKeys[0]->GetKeyTag()] = evalKeys;
    }

    DecryptResult MultipartyDecryptFusion(const std::vector<Ciphertext<Element>>& partialCiphertextVec,
                                          Plaintext* plaintext) const {
        std::string datatype = demangle(typeid(Element).name());
        OPENFHE_THROW(config_error, std::string(__func__) + " is not implemented for " + datatype);
    }

    /**
   * Threshold FHE: Generates a joined evaluation key
   * from the current secret share and a prior joined
   * evaluation key
   *
   * @param originalPrivateKey secret key transformed from.
   * @param newPrivateKey secret key transformed to.
   * @param ek the prior joined evaluation key.
   * @return the new joined evaluation key.
   */
    EvalKey<Element> MultiKeySwitchGen(const PrivateKey<Element> originalPrivateKey,
                                       const PrivateKey<Element> newPrivateKey, const EvalKey<Element> evalKey) const {
        if (!originalPrivateKey)
            OPENFHE_THROW(config_error, "Input first private key is nullptr");
        if (!newPrivateKey)
            OPENFHE_THROW(config_error, "Input second private key is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

        return GetScheme()->MultiKeySwitchGen(originalPrivateKey, newPrivateKey, evalKey);
    }

    /**
   * Threshold FHE: Generates joined automorphism keys
   * from the current secret share and prior joined
   * automorphism keys
   *
   * @param privateKey secret key share.
   * @param eAuto a dictionary with prior joined automorphism keys.
   * @param &indexList a vector of automorphism indices.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return a dictionary with new joined automorphism keys.
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalAutomorphismKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap,
        const std::vector<usint>& indexList, const std::string& keyId = "") {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");
        if (!evalKeyMap)
            OPENFHE_THROW(config_error, "Input evaluation key map is nullptr");
        if (!indexList.size())
            OPENFHE_THROW(config_error, "Input index vector is empty");

        return GetScheme()->MultiEvalAutomorphismKeyGen(privateKey, evalKeyMap, indexList, keyId);
    }

    /**
   * Threshold FHE: Generates joined rotation keys
   * from the current secret share and prior joined
   * rotation keys
   *
   * @param privateKey secret key share.
   * @param eAuto a dictionary with prior joined rotation keys.
   * @param &indexList a vector of rotation indices.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return a dictionary with new joined rotation keys.
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalAtIndexKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap,
        const std::vector<int32_t>& indexList, const std::string& keyId = "") {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");
        if (!evalKeyMap)
            OPENFHE_THROW(config_error, "Input evaluation key map is nullptr");
        if (!indexList.size())
            OPENFHE_THROW(config_error, "Input index vector is empty");

        return GetScheme()->MultiEvalAtIndexKeyGen(privateKey, evalKeyMap, indexList, keyId);
    }

    /**
   * Threshold FHE: Generates joined summation evaluation keys
   * from the current secret share and prior joined
   * summation keys
   *
   * @param privateKey secret key share.
   * @param eSum a dictionary with prior joined summation keys.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return new joined summation keys.
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalSumKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap,
        const std::string& keyId = "") {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");
        if (!evalKeyMap)
            OPENFHE_THROW(config_error, "Input evaluation key map is nullptr");
        return GetScheme()->MultiEvalSumKeyGen(privateKey, evalKeyMap, keyId);
    }

    /**
   * Threshold FHE: Adds two prior evaluation keys
   *
   * @param a first evaluation key.
   * @param b second evaluation key.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return the new joined key.
   */
    EvalKey<Element> MultiAddEvalKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2,
                                      const std::string& keyId = "") {
        if (!evalKey1)
            OPENFHE_THROW(config_error, "Input first evaluation key is nullptr");
        if (!evalKey2)
            OPENFHE_THROW(config_error, "Input second evaluation key is nullptr");

        return GetScheme()->MultiAddEvalKeys(evalKey1, evalKey2, keyId);
    }

    /**
   * Threshold FHE: Generates a partial evaluation key for homomorphic
   * multiplication based on the current secret share and an existing partial
   * evaluation key
   *
   * @param evalKey prior evaluation key.
   * @param sk current secret share.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return the new joined key.
   */
    EvalKey<Element> MultiMultEvalKey(PrivateKey<Element> privateKey, EvalKey<Element> evalKey,
                                      const std::string& keyId = "") {
        if (!privateKey)
            OPENFHE_THROW(config_error, "Input private key is nullptr");
        if (!evalKey)
            OPENFHE_THROW(config_error, "Input evaluation key is nullptr");

        return GetScheme()->MultiMultEvalKey(privateKey, evalKey, keyId);
    }

    /**
   * Threshold FHE: Adds two prior evaluation key sets for summation
   *
   * @param es1 first summation key set.
   * @param es2 second summation key set.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return the new joined key set for summation.
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiAddEvalSumKeys(
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap1,
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap2, const std::string& keyId = "") {
        if (!evalKeyMap1)
            OPENFHE_THROW(config_error, "Input first evaluation key map is nullptr");
        if (!evalKeyMap2)
            OPENFHE_THROW(config_error, "Input second evaluation key map is nullptr");

        return GetScheme()->MultiAddEvalSumKeys(evalKeyMap1, evalKeyMap2, keyId);
    }

    /**
   * Threshold FHE: Adds two prior evaluation key sets for automorphisms
   *
   * @param es1 first automorphism key set.
   * @param es2 second automorphism key set.
   * @param keyId - new key identifier used for the resulting evaluation key.
   * @return the new joined key set for summation.
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiAddEvalAutomorphismKeys(
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap1,
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap2, const std::string& keyId = "") {
        if (!evalKeyMap1)
            OPENFHE_THROW(config_error, "Input first evaluation key map is nullptr");
        if (!evalKeyMap2)
            OPENFHE_THROW(config_error, "Input second evaluation key map is nullptr");

        return GetScheme()->MultiAddEvalAutomorphismKeys(evalKeyMap1, evalKeyMap2, keyId);
    }

    /**
   * Threshold FHE: Adds two  partial public keys
   *
   * @param pubKey1 first public key.
   * @param pubKey2 second public key.
   * @param keyId - new key identifier used for the resulting evaluation key.
   * @return the new joined key.
   */
    PublicKey<Element> MultiAddPubKeys(PublicKey<Element> publicKey1, PublicKey<Element> publicKey2,
                                       const std::string& keyId = "") {
        if (!publicKey1)
            OPENFHE_THROW(config_error, "Input first public key is nullptr");
        if (!publicKey2)
            OPENFHE_THROW(config_error, "Input second public key is nullptr");

        return GetScheme()->MultiAddPubKeys(publicKey1, publicKey2, keyId);
    }

    /**
   * Threshold FHE: Adds two  partial evaluation keys for multiplication
   *
   * @param evalKey1 first evaluation key.
   * @param evalKey2 second evaluation key.
   * @param keyId - new key identifier used for the resulting evaluation key.
   * @return the new joined key.
   */
    EvalKey<Element> MultiAddEvalMultKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2,
                                          const std::string& keyId = "") {
        if (!evalKey1)
            OPENFHE_THROW(config_error, "Input first evaluation key is nullptr");
        if (!evalKey2)
            OPENFHE_THROW(config_error, "Input second evaluation key is nullptr");

        return GetScheme()->MultiAddEvalMultKeys(evalKey1, evalKey2, keyId);
    }

    /**
   * Threshold FHE: Prepare a ciphertext for Multi-Party Interactive Bootstrapping.
   *
	 * @param ciphertext: Input Ciphertext
   * @return: Resulting Ciphertext
   */
    Ciphertext<Element> IntMPBootAdjustScale(ConstCiphertext<Element> ciphertext) const;

    /**
   * Threshold FHE: Generate a common random polynomial for Multi-Party Interactive Bootstrapping
   *
   * @param publicKey: the scheme public key (you can also provide the lead party's public-key)
   * @return: Resulting ring element
   */
  	Ciphertext<Element> IntMPBootRandomElementGen(const PublicKey<Element> publicKey) const;

  	 /**
  	* Threshold FHE: Does masked decryption as part of Multi-Party Interactive Bootstrapping.
  	* Each party calls this function as part of the protocol
  	*
  	* @param privateKey: secret key share for party i
  	* @param ciphertext: input ciphertext
  	* @param a: input common random polynomial
  	* @return: Resulting masked decryption
  	*/
  	std::vector<Ciphertext<Element>> IntMPBootDecrypt(const PrivateKey<Element> privateKey,
  	      ConstCiphertext<Element> ciphertext, ConstCiphertext<Element> a) const;

    /**
     * Threshold FHE: Aggregates a vector of masked decryptions and re-encryotion shares,
     * which is the second step of the interactive multiparty bootstrapping procedure.
     *
     * @param sharesPairVec: vector of pair of ciphertexts, each element of this vector contains
     * (h_0i, h_1i) - the masked-decryption and encryption shares ofparty i
     * @return: aggregated pair of shares ((h_0, h_1)
     */
    std::vector<Ciphertext<Element>> IntMPBootAdd(
          std::vector<std::vector<Ciphertext<Element>>> &sharesPairVec) const;

    /**
     *  Threshold FHE: Does public key encryption of lead party's masked decryption
     * as part of interactive multi-party bootstrapping, which increases
     * the ciphertext modulus and enables future computations.
     * This operation is done by the lead party as the final step
     * of interactive multi-party bootstrapping.
     *
     * @param publicKey: the lead party's public key
     * @param sharesPair: aggregated decryption and re-encryption shares
     * @param a: common random ring element
     * @param ciphertext: input ciphertext
     * @return: Resulting encryption
     */
    Ciphertext<Element> IntMPBootEncrypt(const PublicKey<Element> publicKey, const std::vector<Ciphertext<Element>> &sharesPair,
				 ConstCiphertext<Element> a, ConstCiphertext<Element> ciphertext) const;

    /**
   * Threshold FHE: secret sharing of secret key for Aborts
   *
   * @param sk secret key to be shared.
   * @param N total number of parties.
   * @param threshold - threshold number of parties.
   * @param index - index of the party invoking the function.
   * @param shareType - Type of secret sharing to be used - additive or shamir sharing.
   * @return the secret shares of the secret key sk.
   */
    std::unordered_map<uint32_t, Element> ShareKeys(const PrivateKey<Element>& sk, usint N, usint threshold,
                                                    usint index, const std::string& shareType) const {
        std::string datatype = demangle(typeid(Element).name());
        OPENFHE_THROW(config_error, std::string(__func__) + " is not implemented for " + datatype);
    }

    /**
   * Threshold FHE: Adds two  partial evaluation keys for multiplication
   *
   * @param sk secret recovered from the secret shares.
   * @param sk_shares secret shares.
   * @param N total number of parties.
   * @param threshold - threshold number of parties.
   * @param shareType - Type of secret sharing to be used - additive or shamir sharing
   * @return the recovered key from the secret shares assigned to sk.
   */
    void RecoverSharedKey(PrivateKey<Element>& sk, std::unordered_map<uint32_t, Element>& sk_shares, usint N,
                          usint threshold, const std::string& shareType) const;

    //------------------------------------------------------------------------------
    // FHE Bootstrap Methods
    //------------------------------------------------------------------------------

    /**
   * Bootstrap functionality:
   * There are three methods that have to be called in this specific order:
   * 1. EvalBootstrapSetup: computes and encodes the coefficients for encoding and
   * decoding and stores the necessary parameters
   * 2. EvalBootstrapKeyGen: computes and stores the keys for rotations and conjugation
   * 3. EvalBootstrap: refreshes the given ciphertext
   */

    /**
   * Sets all parameters for the linear method for the FFT-like method
   *
   * @param levelBudget - vector of budgets for the amount of levels in encoding
   * and decoding
   * @param dim1 - vector of inner dimension in the baby-step giant-step routine
   * for encoding and decoding
   * @param slots - number of slots to be bootstrapped
   * @param correctionFactor - value to rescale message by to improve precision. If set to 0, we use the default logic. This value is only used when NATIVE_SIZE=64.
   */
    void EvalBootstrapSetup(std::vector<uint32_t> levelBudget = {5, 4}, std::vector<uint32_t> dim1 = {0, 0},
                            uint32_t slots = 0, uint32_t correctionFactor = 0) {
        GetScheme()->EvalBootstrapSetup(*this, levelBudget, dim1, slots, correctionFactor);
    }
    /**
   * Generates all automorphism keys for EvalBT.
   * EvalBootstrapKeyGen uses the baby-step/giant-step strategy.
   *
   * @param privateKey private key.
   * @param slots number of slots to support permutations on
   */
    void EvalBootstrapKeyGen(const PrivateKey<Element> privateKey, uint32_t slots) {
        if (privateKey == NULL || this->Mismatched(privateKey->GetCryptoContext())) {
            OPENFHE_THROW(config_error, "Private key passed to " + std::string(__func__) +
                                            " was not generated with this cryptocontext");
        }

        auto evalKeys = GetScheme()->EvalBootstrapKeyGen(privateKey, slots);

        auto ekv = GetAllEvalAutomorphismKeys().find(privateKey->GetKeyTag());
        if (ekv == GetAllEvalAutomorphismKeys().end()) {
            GetAllEvalAutomorphismKeys()[privateKey->GetKeyTag()] = evalKeys;
        }
        else {
            auto& currRotMap = GetEvalAutomorphismKeyMap(privateKey->GetKeyTag());
            auto iterRowKeys = evalKeys->begin();
            while (iterRowKeys != evalKeys->end()) {
                auto idx = iterRowKeys->first;
                // Search current rotation key map and add key
                // only if it doesn't exist
                if (currRotMap.find(idx) == currRotMap.end()) {
                    currRotMap.insert(*iterRowKeys);
                }
                iterRowKeys++;
            }
        }
    }
    /**
   * Defines the bootstrapping evaluation of ciphertext using either the
   * FFT-like method or the linear method
   *
   * @param ciphertext the input ciphertext.
   * @param numIterations number of iterations to run iterative bootstrapping (Meta-BTS). Increasing the iterations increases the precision of bootstrapping.
   * @param precision precision of initial bootstrapping algorithm. This value is
   * determined by the user experimentally by first running EvalBootstrap with numIterations = 1 and precision = 0 (unused).
   * @return the refreshed ciphertext.
   */
    Ciphertext<Element> EvalBootstrap(ConstCiphertext<Element> ciphertext, uint32_t numIterations = 1,
                                      uint32_t precision = 0) const {
        return GetScheme()->EvalBootstrap(ciphertext, numIterations, precision);
    }

    //------------------------------------------------------------------------------
    // Scheme switching Methods
    //------------------------------------------------------------------------------

    /**
   * Scheme switching between CKKS and FHEW functionality
   * There are three methods that have to be called in this specific order:
   * 1. EvalCKKStoFHEWSetup: generates a FHEW cryptocontext and returns the key, computes and encodes
   * the coefficients for encoding and decoding and stores the necessary parameters
   * 2. EvalCKKStoFHEWKeyGen: computes and stores the keys for rotations and conjugation
   * 3. EvalCKKStoFHEW: returns the FHEW/CGGI ciphertext
   * 1'. EvalFHEWtoCKKSwitchetup: takes in the CKKS cryptocontext and sets the parameters
   * 2'. EvalFHEWtoCKKSKeyGen: computes and stores the switching key and the keys for rotations and conjugation
   * 3'. EvalFHEWtoCKKS: returns the CKKS ciphertext
   * 1''. EvalSchemeSwitchingSetup: generates a FHEW cryptocontext and returns the key, computes and encodes
   * the coefficients for encoding and decoding and stores the necessary parameters
   * 2''. EvalSchemeSwitchingKeyGen: computes and stores the switching key and the keys for rotations and conjugation
   * 3''. EvalCompareSchemeSwitching/EvalFuncSchemeSwitching: returns the CKKS ciphertext of the function specified
   */

    /**
   * Sets all parameters for switching from CKKS to FHEW
   *
   * @param sl security level for CKKS cryptocontext
   * @param slBin security level for FHEW cryptocontext (only STD128 and TOY are currently supported)
   * @param arbFunc whether the binfhecontext should be created for arbitrary function evaluation or not
   * @param logQ size of ciphertext modulus in FHEW for large-precision evaluation
   * @param dynamic whether to use dynamic mode for FHEW
   * @param numSlotsCKKS number of slots in CKKS encryption
   * @param logQswitch size of ciphertext modulus in intermediate switch for security with the FHEW ring dimension
   * @return the FHEW cryptocontext and its secret key (if a method from extracting the binfhecontext
   * from the secret key is created, then we can only return the secret key)
   * TODO: add an overload for when BinFHEContext is already generated and fed as a parameter
   */
    std::pair<BinFHEContext, LWEPrivateKey> EvalCKKStoFHEWSetup(SecurityLevel sl      = HEStd_128_classic,
                                                                BINFHE_PARAMSET slBin = STD128, bool arbFunc = false,
                                                                uint32_t logQ = 25, bool dynamic = false,
                                                                uint32_t numSlotsCKKS = 0, uint32_t logQswitch = 27);

    /**
   * Generates all keys for scheme switching: the rotation keys for the baby-step/giant-step strategy
   * for the linear transform in the homomorphic decoding, conjugation keys, switching key from CKKS to FHEW
   *
   * @param keypair CKKS key pair
   * @param lwesk FHEW secret key
   * @param dim1 baby-step for the linear transform
   * @param L level on which the hom. decoding matrix should be. We want the hom. decoded ciphertext to be on the last level
   */
    void EvalCKKStoFHEWKeyGen(const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t dim1 = 0,
                              uint32_t L = 1);

    /**
   * Performs precomputations for the homomorphic decoding in CKKS. Given as a separate method than EvalCKKStoFHEWSetup
   * to allow the user to specify a scale that depends on the CKKS and FHEW cryptocontexts
   *
   * @param scale factor with which to scale the matrix in the linear transform
   */
    void EvalCKKStoFHEWPrecompute(double scale = 1.0);

    /**
   * Performs the scheme switching on a CKKS ciphertext
   *
   * @param ciphertext CKKS ciphertext to switch
   * @param numCtxts number of coefficients to extract from the CKKS ciphertext. If it is zero, it defaults to number of slots
   * @return a vector of LWE ciphertexts of length the numCtxts
   */
    std::vector<std::shared_ptr<LWECiphertextImpl>> EvalCKKStoFHEW(ConstCiphertext<Element> ciphertext,
                                                                   uint32_t numCtxts = 0);

    /**
   * Sets all parameters for switching from FHEW to CKKS. The CKKS cryptocontext to switch to is
   * already generated.
   *
   * @param ccLWE the FHEW cryptocontext from which to switch
   * @param numSlotsCKKS number of FHEW ciphertexts that becomes the number of slots in CKKS encryption
   * @param logQ size of ciphertext modulus in FHEW for large-precision evaluation
   */
    void EvalFHEWtoCKKSSetup(const BinFHEContext& ccLWE, uint32_t numSlotsCKKS = 0, uint32_t logQ = 25);

    /**
   * Generates all keys for scheme switching: the rotation keys for the baby-step/giant-step strategy
   * in the linear transform for the partial decryption, the switching key from FHEW to CKKS
   *
   * @param keypair CKKS key pair
   * @param lwesk FHEW secret key
   * @param numSlots number of slots for the CKKS encryption of the FHEW secret key
   * @param dim1 baby-step for the linear transform
   * @param L level on which the hom. decoding matrix should be. We want the hom. decoded ciphertext to be on the last level
   */
    void EvalFHEWtoCKKSKeyGen(const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t numSlots = 0,
                              uint32_t dim1 = 0, uint32_t L = 0);

    /**
   * Performs the scheme switching on a vector of FHEW ciphertexts
   *
   * @param LWECiphertexts FHEW/LWE ciphertexts to switch
   * @param numCtxts number of values to encrypt from the LWE ciphertexts in the new CKKS ciphertext
   * @param numSlots number of slots to use in the encoding in the new CKKS/RLWE ciphertext
   * @param p plaintext modulus to use to decide postscaling, by default p = 4
   * @param pmin, pmax plaintext space of the resulting messages (by default [0,2] assuming
   * the LWE ciphertext had plaintext modulus p = 4 and only bits were encrypted)
   * @return a CKKS ciphertext encrypting in its slots the messages in the LWE ciphertexts
   */
    Ciphertext<Element> EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                       uint32_t numCtxts = 0, uint32_t numSlots = 0, uint32_t p = 4, double pmin = 0.0,
                                       double pmax = 2.0) const;

    /**
   * Sets all parameters for switching from CKKS to FHEW and back
   *
   * @param sl security level for CKKS cryptocontext
   * @param slBin security level for FHEW cryptocontext
   * @param arbFunc whether the binfhecontext should be created for arbitrary function evaluation or not
   * @param logQ size of ciphertext modulus in FHEW for large-precision evaluation
   * @param dynamic whether to use dynamic mode for FHEW
   * @param numSlotsCKKS number of slots in CKKS encryption
   * @param logQswitch size of ciphertext modulus in intermediate switch for security with the FHEW ring dimension
   * @return the FHEW cryptocontext and its secret key (if a method from extracting the binfhecontext
   * from the secret key is created, then we can only return the secret key)
   * TODO: add an overload for when BinFHEContext is already generated and fed as a parameter
   */
    std::pair<BinFHEContext, LWEPrivateKey> EvalSchemeSwitchingSetup(SecurityLevel sl      = HEStd_128_classic,
                                                                     BINFHE_PARAMSET slBin = STD128,
                                                                     bool arbFunc = false, uint32_t logQ = 25,
                                                                     bool dynamic = false, uint32_t numSlotsCKKS = 0,
                                                                     uint32_t logQswitch = 27);

    /**
   * Generates all keys for scheme switching: the rotation keys for the baby-step/giant-step strategy
   * in the linear transform for the homomorphic encoding and partial decryption, the switching key from
   * FHEW to CKKS
   *
   * @param keypair CKKS key pair
   * @param lwesk FHEW secret key
   * @param numValues parameter of argmin computation, set to zero if not needed
   * @param oneHot flag that indicates whether the argmin result should have one hot encoding or not
   * @param alt flag that indicates whether to use the alternative version of argmin which requires fewer automorphism keys
   * @param dim1CF baby-step for the linear transform in CKKS to FHEW
   * @param dim1FC baby-step for the linear transform in FHEW to CKKS
   * @param LCF level on which to do the linear transform in CKKS to FHEW
   * @param LFC level on which to do the linear transform in FHEW to CKKS
   */
    void EvalSchemeSwitchingKeyGen(const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t numValues = 0,
                                   bool oneHot = true, bool alt = false, uint32_t dim1CF = 0, uint32_t dim1FC = 0,
                                   uint32_t LCF = 1, uint32_t LFC = 0);

    /**
   * Performs precomputations for the homomorphic decoding in CKKS. Given as a separate method than EvalSchemeSwitchingSetup
   * to allow the user to specify a scale that depends on the CKKS and FHEW cryptocontexts
   *
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
   * @param initLevel the level of the ciphertext that will be switched
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * @param unit whether the input messages are normalized to the unit circle
   */
    void EvalCompareSwitchPrecompute(uint32_t pLWE = 0, uint32_t initLevel = 0, double scaleSign = 1.0,
                                     bool unit = false);

    /**
   * Performs the scheme switching on the difference of two CKKS ciphertexts to compare, evaluates the sign function
   * over the resulting FHEW ciphertexts, then performs the scheme switching back to a CKKS ciphertext
   *
   * @param ciphertext1, ciphertext2 CKKS ciphertexts of messages that need to be compared
   * @param numCtxts number of coefficients to extract from the CKKS ciphertext
   * @param numSlots number of slots to encode the new CKKS ciphertext with
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * pLWE and scaleSign are given here only if the homomorphic decoding matrix is not scaled with the desired values
   * @param unit whether the input messages are normalized to the unit circle
   * @return a CKKS ciphertext encrypting in its slots the sign of  messages in the LWE ciphertexts
   */
    Ciphertext<Element> EvalCompareSchemeSwitching(ConstCiphertext<Element> ciphertext1,
                                                   ConstCiphertext<Element> ciphertext2, uint32_t numCtxts = 0,
                                                   uint32_t numSlots = 0, uint32_t pLWE = 0, double scaleSign = 1.0,
                                                   bool unit = false);

    /**
   * Computes the minimum and argument of the first numValues packed in a CKKS ciphertext via repeated
   * scheme switchings to FHEW and back.
   *
   * @param ciphertext CKKS ciphertexts of values that need to be compared
   * @param publicKey public key of the CKKS cryptocontext
   * @param numValues number of values to extract from the CKKS ciphertext. We always assume for the moment numValues is a power of two
   * @param numSlots number of slots to encode the new CKKS ciphertext with
   * @param oneHot whether the argmin result is given as a one hot/elementary vector or as the index
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * pLWE and scaleSign are given here only if the homomorphic decoding matrix is not scaled with the desired values
   * @return a vector of two CKKS ciphertexts where the first encrypts the minimum value and the second encrypts the
   * index (in the representation specified by oneHot). The ciphertexts have junk after the first slot in the first ciphertext
   * and after numValues in the second ciphertext if oneHot=true and after the first slot if oneHot=false.
   */
    std::vector<Ciphertext<Element>> EvalMinSchemeSwitching(ConstCiphertext<Element> ciphertext,
                                                            PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                            uint32_t numSlots = 0, bool oneHot = true,
                                                            uint32_t pLWE = 0, double scaleSign = 1.0);

    /**
     * Performs more operations in FHEW than in CKKS. Slightly better precision but slower.
    */
    std::vector<Ciphertext<Element>> EvalMinSchemeSwitchingAlt(ConstCiphertext<Element> ciphertext,
                                                               PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                               uint32_t numSlots = 0, bool oneHot = true,
                                                               uint32_t pLWE = 0, double scaleSign = 1.0);

    /**
   * Computes the maximum and argument of the first numValues packed in a CKKS ciphertext via repeated
   * scheme switchings to FHEW and back.
   *
   * @param ciphertext CKKS ciphertexts of values that need to be compared
   * @param publicKey public key of the CKKS cryptocontext
   * @param numValues number of values to extract from the CKKS ciphertext. We always assume for the moment numValues is a power of two
   * @param numSlots number of slots to encode the new CKKS ciphertext with
   * @param oneHot whether the argmax result is given as a one hot/elementary vector or as the index
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * pLWE and scaleSign are given here only if the homomorphic decoding matrix is not scaled with the desired values
   * @return a vector of two CKKS ciphertexts where the first encrypts the maximum value and the second encrypts the
   * index (in the representation specified by oneHot). The ciphertexts have junk after the first slot in the first ciphertext
   * and after numValues in the second ciphertext if oneHot=true and after the first slot if oneHot=false.
   */
    std::vector<Ciphertext<Element>> EvalMaxSchemeSwitching(ConstCiphertext<Element> ciphertext,
                                                            PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                            uint32_t numSlots = 0, bool oneHot = true,
                                                            uint32_t pLWE = 0, double scaleSign = 1.0);

    /**
     * Performs more operations in FHEW than in CKKS. Slightly better precision but slower.
    */
    std::vector<Ciphertext<Element>> EvalMaxSchemeSwitchingAlt(ConstCiphertext<Element> ciphertext,
                                                               PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                               uint32_t numSlots = 0, bool oneHot = true,
                                                               uint32_t pLWE = 0, double scaleSign = 1.0);

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::make_nvp("cc", params));
        ar(cereal::make_nvp("kt", scheme));
        ar(cereal::make_nvp("si", m_schemeId));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(cereal::make_nvp("cc", params));
        ar(cereal::make_nvp("kt", scheme));
        ar(cereal::make_nvp("si", m_schemeId));
        SetKSTechniqueInScheme();

        // NOTE: a pointer to this object will be wrapped in a shared_ptr, and is a
        // "CryptoContext". OpenFHE relies on the notion that identical
        // CryptoContextImpls are not duplicated in memory Once we deserialize this
        // object, we must check to see if there is a matching object for this
        // object that's already existing in memory if it DOES exist, use it. If it
        // does NOT exist, add this to the cache of all contexts
    }

    std::string SerializedObjectName() const override {
        return "CryptoContext";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }
};

// Member function specializations. Their implementations are in cryptocontext.cpp
template <>
DecryptResult CryptoContextImpl<DCRTPoly>::MultipartyDecryptFusion(
    const std::vector<Ciphertext<DCRTPoly>>& partialCiphertextVec, Plaintext* plaintext) const;
template <>
std::unordered_map<uint32_t, DCRTPoly> CryptoContextImpl<DCRTPoly>::ShareKeys(const PrivateKey<DCRTPoly>& sk, usint N,
                                                                              usint threshold, usint index,
                                                                              const std::string& shareType) const;
}  // namespace lbcrypto

#endif /* SRC_PKE_CRYPTOCONTEXT_H_ */
