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

#include "scheme/scheme-swch-params.h"

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
#include <set>

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

    /**
    * @brief VerifyCKKSScheme is to check if the cryptocontext scheme is CKKS. if it is not
    *        the function will thow an exception
    * @param functionName is the calling function name. __func__ can be used instead
    */
    inline void VerifyCKKSScheme(const std::string& functionName) const {
        if (!isCKKS(m_schemeId)) {
            std::string errMsg = "Function " + std::string(functionName) +
                                 " is available for the CKKS scheme only."
                                 " The current scheme is " +
                                 convertToString(m_schemeId);
            OPENFHE_THROW(errMsg);
        }
    }

    void SetKSTechniqueInScheme();

    const CryptoContext<Element> GetContextForPointer(const CryptoContextImpl<Element>* cc) const {
        const auto& contexts = CryptoContextFactory<Element>::GetAllContexts();
        for (const auto& ctx : contexts) {
            if (cc == ctx.get())
                return ctx;
        }
        OPENFHE_THROW("Cannot find context for the given pointer to CryptoContextImpl");
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
            size_t numModuli = cryptoParams->GetElementParams()->GetParams().size();
            if (!isBFVRNS(m_schemeId)) {
                // we throw an exception if level >= numModuli. However, we use multiplicativeDepth in the error message,
                // so the user can understand the error more easily.
                if (level >= numModuli) {
                    uint32_t multiplicativeDepth =
                        (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) ? (numModuli - 2) : (numModuli - 1);
                    std::string errorMsg;
                    if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)
                        errorMsg = "The level value should be less than or equal to (multiplicativeDepth + 1).";
                    else
                        errorMsg = "The level value should be less than or equal to multiplicativeDepth.";

                    errorMsg += " Currently: level is [" + std::to_string(level) + "] and multiplicativeDepth is [" +
                                std::to_string(multiplicativeDepth) + "]";
                    OPENFHE_THROW(errorMsg);
                }
            }
            else {
                if ((cryptoParams->GetMultiplicationTechnique() == BEHZ) ||
                    (cryptoParams->GetMultiplicationTechnique() == HPS)) {
                    OPENFHE_THROW(
                        "BFV: Encoding at level > 0 is not currently supported for BEHZ or HPS. Use one of the HPSPOVERQ* methods instead.");
                }

                if ((cryptoParams->GetEncryptionTechnique() == EXTENDED)) {
                    OPENFHE_THROW(
                        "BFV: Encoding at level > 0 is not currently supported for the EXTENDED encryption method. Use the STANDARD encryption method instead.");
                }
                if (level >= numModuli) {
                    std::string errorMsg =
                        "The level value should be less the current number of RNS limbs in the cryptocontext.";
                    errorMsg += " Currently: level is [" + std::to_string(level) + "] and number of RNS limbs is [" +
                                std::to_string(numModuli) + "]";
                    OPENFHE_THROW(errorMsg);
                }
            }
        }

        // uses a parameter set with a reduced number of RNS limbs corresponding to the level
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

        Plaintext p;
        if (isBGVRNS(m_schemeId) && (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTO ||
                                     cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT)) {
            NativeInteger scf;
            if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT && level == 0) {
                scf = cryptoParams->GetScalingFactorIntBig(level);
                p   = PlaintextFactory::MakePlaintext(value, encoding, elemParamsPtr, this->GetEncodingParams(),
                                                      getSchemeId(), 1, level, scf);
                p->SetNoiseScaleDeg(2);
            }
            else {
                scf = cryptoParams->GetScalingFactorInt(level);
                p   = PlaintextFactory::MakePlaintext(value, encoding, elemParamsPtr, this->GetEncodingParams(),
                                                      getSchemeId(), depth, level, scf);
            }
        }
        else {
            p = PlaintextFactory::MakePlaintext(value, encoding, elemParamsPtr, this->GetEncodingParams(),
                                                getSchemeId(), depth, level);
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

    /**
   * @brief Get indices that do not have automorphism keys for the given secret key tag in the key map
   * @param keyID - secret key tag
   * @param indexList - array of specific indices to check the key map against
   * @return indices that do not have automorphism keys associated with
   */
    static std::set<uint32_t> GetEvalAutomorphismNoKeyIndices(const std::string& keyID,
                                                              const std::set<uint32_t>& indices) {
        std::set<uint32_t> existingIndices{CryptoContextImpl<Element>::GetExistingEvalAutomorphismKeyIndices(keyID)};
        // if no index found for the given keyID, then the entire set "indices" is returned
        return (existingIndices.empty()) ? indices :
                                           CryptoContextImpl<Element>::GetUniqueValues(existingIndices, indices);
    }
    /**
   * Get automorphism keys for a specific secret key tag
   */
    static std::shared_ptr<std::map<usint, EvalKey<Element>>> GetEvalAutomorphismKeyMapPtr(const std::string& keyID);
    /**
   * @brief Get automorphism keys for a specific secret key tag and an array of specific indices
   * @param keyID - secret key tag
   * @param indexList - array of specific indices to retrieve key for
   * @return shared_ptr to std::map where the map key/data pair is index/automorphism key
   */
    static std::shared_ptr<std::map<usint, EvalKey<Element>>> GetPartialEvalAutomorphismKeyMapPtr(
        const std::string& keyID, const std::vector<uint32_t>& indexList);

    // cached evalmult keys, by secret key UID
    static std::map<std::string, std::vector<EvalKey<Element>>> s_evalMultKeyMap;
    // cached evalautomorphism keys, by secret key UID
    static std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> s_evalAutomorphismKeyMap;

protected:
    // crypto parameters used for this context
    std::shared_ptr<CryptoParametersBase<Element>> params{nullptr};
    // algorithm used; accesses all crypto methods
    std::shared_ptr<SchemeBase<Element>> scheme{nullptr};

    SCHEME m_schemeId{SCHEME::INVALID_SCHEME};

    uint32_t m_keyGenLevel{0};

    /**
   * TypeCheck makes sure that an operation between two ciphertexts is permitted
   * @param a
   * @param b
   */
    void TypeCheck(const ConstCiphertext<Element> a, const ConstCiphertext<Element> b, CALLER_INFO_ARGS_HDR) const {
        if (a == nullptr || b == nullptr) {
            std::string errorMsg(std::string("Null Ciphertext") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
        if (a->GetCryptoContext().get() != this) {
            std::string errorMsg(std::string("Ciphertext was not created in this CryptoContext") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
        if (a->GetCryptoContext() != b->GetCryptoContext()) {
            std::string errorMsg(std::string("Ciphertexts were not created in the same CryptoContext") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
        if (a->GetKeyTag() != b->GetKeyTag()) {
            std::string errorMsg(std::string("Ciphertexts were not encrypted with same keys") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
        if (a->GetEncodingType() != b->GetEncodingType()) {
            std::stringstream ss;
            ss << "Ciphertext encoding types " << a->GetEncodingType();
            ss << " and " << b->GetEncodingType();
            ss << " do not match";
            ss << CALLER_INFO;
            OPENFHE_THROW(ss.str());
        }
    }

    /**
   * TypeCheck makes sure that an operation between a ciphertext and a plaintext
   * is permitted
   * @param a
   * @param b
   */
    void TypeCheck(const ConstCiphertext<Element> a, const ConstPlaintext& b, CALLER_INFO_ARGS_HDR) const {
        if (a == nullptr) {
            std::string errorMsg(std::string("Null Ciphertext") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
        if (b == nullptr) {
            std::string errorMsg(std::string("Null Plaintext") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
        if (a->GetCryptoContext().get() != this) {
            std::string errorMsg(std::string("Ciphertext was not created in this CryptoContext") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
        if (a->GetEncodingType() != b->GetEncodingType()) {
            std::stringstream ss;
            ss << "Ciphertext encoding type " << a->GetEncodingType();
            ss << " and Plaintext encoding type " << b->GetEncodingType();
            ss << " do not match";
            ss << CALLER_INFO;
            OPENFHE_THROW(ss.str());
        }
    }

    bool Mismatched(const CryptoContext<Element> a) const {
        if (a.get() != this) {
            return true;
        }
        return false;
    }

    template <typename T>
    void ValidateKey(const T& key, CALLER_INFO_ARGS_HDR) const {
        if (key == nullptr) {
            std::string errorMsg(std::string("Key is nullptr") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
        if (Mismatched(key->GetCryptoContext())) {
            std::string errorMsg(std::string("Key was not generated with the same crypto context") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
    }

    void ValidateCiphertext(const ConstCiphertext<Element>& ciphertext, CALLER_INFO_ARGS_HDR) const {
        if (ciphertext == nullptr) {
            std::string errorMsg(std::string("Ciphertext is nullptr") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
        if (Mismatched(ciphertext->GetCryptoContext())) {
            std::string errorMsg(std::string("Ciphertext was not generated with the same crypto context") +
                                 CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
    }

    virtual Plaintext MakeCKKSPackedPlaintextInternal(const std::vector<std::complex<double>>& value,
                                                      size_t noiseScaleDeg, uint32_t level,
                                                      const std::shared_ptr<ParmType> params, usint slots) const {
        VerifyCKKSScheme(__func__);
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
                OPENFHE_THROW(errorMsg);
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
                OPENFHE_THROW("The size [" + std::to_string(valueSize) +
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
                OPENFHE_THROW("The size [" + std::to_string(valueSize) +
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
        OPENFHE_THROW("SetPrivateKey is only allowed if DEBUG_KEY is set in openfhe.h");
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
        OPENFHE_THROW("GetPrivateKey is only allowed if DEBUG_KEY is set in openfhe.h");
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
   * @param params pointer to CryptoParameters
   * @param scheme pointer to Crypto Scheme object
   * @param schemeId scheme identifier
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
   * @param params shared pointer to CryptoParameters
   * @param scheme sharedpointer to Crypto Scheme object
   * @param schemeId scheme identifier
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
   * Private method to compare two contexts; this is only used internally and
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

    /**
   * Private method to compare two contexts; this is only used internally and
   * is not generally available
   * */
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
        const auto& evalMultKeys = CryptoContextImpl<Element>::GetAllEvalMultKeys();
        if (id.length() == 0) {
            Serial::Serialize(evalMultKeys, ser, sertype);
        }
        else {
            const auto it = evalMultKeys.find(id);
            if (it == evalMultKeys.end())
                return false;  // no such id

            std::map<std::string, std::vector<EvalKey<Element>>> omap{{it->first, it->second}};

            Serial::Serialize(omap, ser, sertype);
        }

        return true;
    }

    /**
   * SerializeEvalMultKey for all EvalMultKeys made in a given context
   *
   * @param ser stream to serialize to
   * @param sertype type of serialization
   * @param cc whose keys should be serialized
   * @return true on success (false on failure or no keys found)
   */
    template <typename ST>
    static bool SerializeEvalMultKey(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {
        std::map<std::string, std::vector<EvalKey<Element>>> omap;
        for (const auto& [key, vec] : CryptoContextImpl<Element>::GetAllEvalMultKeys()) {
            if (vec[0]->GetCryptoContext() == cc) {
                omap[key] = vec;
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
   * @param sertype type of serialization
   * @return true on success
   */
    template <typename ST>
    static bool DeserializeEvalMultKey(std::istream& ser, const ST& sertype) {
        std::map<std::string, std::vector<EvalKey<Element>>> omap;

        Serial::Deserialize(omap, ser, sertype);

        // The deserialize call creates all contexts that need to be created...
        // so, all we need to do is to insert the keys into the maps for their context(s)
        for (auto& [tag, vec] : omap) {
            CryptoContextImpl<Element>::InsertEvalMultKey(vec, tag);
        }
        return true;
    }

    /**
   * ClearEvalMultKeys - flush EvalMultKey cache
   */
    static void ClearEvalMultKeys();

    /**
   * ClearEvalMultKeys - flush EvalMultKey cache for a given id
   * @param id the correponding key id
   */
    static void ClearEvalMultKeys(const std::string& id);
    /**
   * ClearEvalMultKeys - flush EvalMultKey cache for a given context
   * @param cc crypto context
   */
    static void ClearEvalMultKeys(const CryptoContext<Element> cc);

    /**
   * InsertEvalMultKey - add the given vector of keys to the map, replacing the
   * existing vector if it is there
   * @param evalKeyVec vector of keys
   * @param keyTag key identifier, unique for every cryptocontext
   */
    static void InsertEvalMultKey(const std::vector<EvalKey<Element>>& evalKeyVec,
                                  const std::string& keyTag = std::string());

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
        return CryptoContextImpl<Element>::SerializeEvalAutomorphismKey(ser, sertype, id);
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
        return CryptoContextImpl<Element>::SerializeEvalAutomorphismKey(ser, sertype, cc);
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
        return CryptoContextImpl<Element>::DeserializeEvalAutomorphismKey(ser, sertype);
    }

    /**
   * ClearEvalSumKeys - flush EvalSumKey cache
   */
    static void ClearEvalSumKeys();

    /**
   * ClearEvalSumKeys - flush EvalSumKey cache for a given id
   * @param id key id
   */
    static void ClearEvalSumKeys(const std::string& id);

    /**
   * ClearEvalSumKeys - flush EvalSumKey cache for a given context
   * @param cc crypto context
   */
    static void ClearEvalSumKeys(const CryptoContext<Element> cc);

    /**
   * InsertEvalSumKey - add the given map of keys to the map, replacing the
   * existing map if there
   * @param evalKeyMap key map
   */
    static void InsertEvalSumKey(const std::shared_ptr<std::map<usint, EvalKey<Element>>> mapToInsert,
                                 std::string keyTag = "") {
        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(mapToInsert, keyTag);
    }

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
        // TODO (dsuponit): do we need Serailize/Deserialized to return bool?
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>* smap;
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> omap;
        if (id.length() == 0) {
            smap = &CryptoContextImpl<Element>::GetAllEvalAutomorphismKeys();
        }
        else {
            const auto keys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMapPtr(id);
            omap[id]        = keys;
            smap            = &omap;
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
        for (const auto& k : CryptoContextImpl<Element>::GetAllEvalAutomorphismKeys()) {
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
   * @brief Serialize automorphism keys for an array of specific indices within a specific secret key tag
   * @param ser - stream to serialize to
   * @param sertype - type of serialization
   * @param keyID - secret key tag
   * @param indexList - array of specific indices to serialize key for
   * @return true on success
   */
    template <typename ST>
    static bool SerializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype, const std::string& keyID,
                                             const std::vector<uint32_t>& indexList) {
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> keyMap = {
            {keyID, CryptoContextImpl<Element>::GetPartialEvalAutomorphismKeyMapPtr(keyID, indexList)}};

        Serial::Serialize(keyMap, ser, sertype);
        return true;
    }

    /**
   * @brief Deserialize automorphism keys for an array of specific indices within a specific secret key tag
   * @param ser - stream to serialize from
   * @param sertype - type of serialization
   * @param keyID - secret key tag
   * @param indexList - array of specific indices to serialize key for
   * @return true on success
   */
    template <typename ST>
    static bool DeserializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype, const std::string& keyID,
                                               const std::vector<uint32_t>& indexList) {
        if (!indexList.size())
            OPENFHE_THROW("indexList may not be empty");
        if (keyID.empty())
            OPENFHE_THROW("keyID may not be empty");

        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> allDeserKeys;
        Serial::Deserialize(allDeserKeys, ser, sertype);

        const auto& keyMapIt = allDeserKeys.find(keyID);
        if (keyMapIt == allDeserKeys.end()) {
            OPENFHE_THROW("Deserialized automorphism keys are not generated for ID [" + keyID + "].");
        }

        // create a new map with evalkeys for the specified indices
        std::map<usint, EvalKey<Element>> newMap;
        for (const uint32_t indx : indexList) {
            const auto& key = keyMapIt->find(indx);
            if (key == keyMapIt->end()) {
                OPENFHE_THROW("No automorphism key generated for index [" + std::to_string(indx) + "] within keyID [" +
                              keyID + "].");
            }
            newMap[indx] = key->second;
        }

        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(
            std::make_shared<std::map<uint32_t, EvalKey<Element>>>(newMap), keyID);

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
        std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>> keyMap;

        Serial::Deserialize(keyMap, ser, sertype);

        // The deserialize call created any contexts that needed to be created....
        // so all we need to do is put the keys into the maps for their context
        for (auto& k : keyMap) {
            CryptoContextImpl<Element>::InsertEvalAutomorphismKey(k.second, k.first);
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
    // TODO (dsuponit): move InsertEvalAutomorphismKey() to the private section of the class
    static void InsertEvalAutomorphismKey(const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap,
                                          const std::string& keyTag = "");
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

    /**
   * For future use: getter for the level at which evaluation keys should be generated
   */
    size_t GetKeyGenLevel() const {
        return m_keyGenLevel;
    }

    /**
   * For future use: setter for the level at which evaluation keys should be generated
   */
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

    /**
   * Get a map of relinearization keys for all secret keys
   */
    static std::map<std::string, std::vector<EvalKey<Element>>>& GetAllEvalMultKeys();

    /**
   * Get relinearization keys for a specific secret key tag
   */
    static const std::vector<EvalKey<Element>>& GetEvalMultKeyVector(const std::string& keyID);

    /**
   * Get a map of automorphism keys for all secret keys
   */
    static std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>& GetAllEvalAutomorphismKeys();
    /**
   * Get automorphism keys for a specific secret key tag
   */
    static std::map<usint, EvalKey<Element>>& GetEvalAutomorphismKeyMap(const std::string& keyID) {
        return *(CryptoContextImpl<Element>::GetEvalAutomorphismKeyMapPtr(keyID));
    }
    /**
   * Get a map of summation keys (each is composed of several automorphism keys) for all secret keys
   */
    static std::map<std::string, std::shared_ptr<std::map<usint, EvalKey<Element>>>>& GetAllEvalSumKeys();

    /**
   * Get a map of summation keys (each is composed of several automorphism keys) for a specific secret key tag
   */
    static const std::map<usint, EvalKey<Element>>& GetEvalSumKeyMap(const std::string& id);

    //------------------------------------------------------------------------------
    // PLAINTEXT FACTORY METHODS
    //------------------------------------------------------------------------------

    // TODO to be deprecated in 2.0
    /**
   * MakeStringPlaintext constructs a StringEncoding in this context
   * @param str string to be encoded
   * @return plaintext
   */
    Plaintext MakeStringPlaintext(const std::string& str) const {
        return PlaintextFactory::MakePlaintext(str, STRING_ENCODING, this->GetElementParams(),
                                               this->GetEncodingParams());
    }

    /**
   * MakeCoefPackedPlaintext constructs a CoefPackedEncoding in this context
   * @param value vector of signed integers mod t
   * @param noiseScaleDeg is degree of the scaling factor to encode the plaintext at
   * @param level is the level to encode the plaintext at
   * @return plaintext
   */
    Plaintext MakeCoefPackedPlaintext(const std::vector<int64_t>& value, size_t noiseScaleDeg = 1,
                                      uint32_t level = 0) const {
        if (!value.size())
            OPENFHE_THROW("Cannot encode an empty value vector");

        return MakePlaintext(COEF_PACKED_ENCODING, value, noiseScaleDeg, level);
    }

    /**
   * MakePackedPlaintext constructs a PackedEncoding in this context
   * @param value vector of signed integers mod t
   * @param noiseScaleDeg is degree of the scaling factor to encode the plaintext at
   * @param level is the level to encode the plaintext at
   * @return plaintext
   */
    Plaintext MakePackedPlaintext(const std::vector<int64_t>& value, size_t noiseScaleDeg = 1,
                                  uint32_t level = 0) const {
        if (!value.size())
            OPENFHE_THROW("Cannot encode an empty value vector");

        return MakePlaintext(PACKED_ENCODING, value, noiseScaleDeg, level);
    }

    /**
   * COMPLEX ARITHMETIC IS NOT AVAILABLE,
   * AND THIS METHOD BE DEPRECATED. USE THE REAL-NUMBER METHOD INSTEAD.
   * MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context
   * from a vector of complex numbers
   * @param value - input vector of complex number
   * @param scaleDeg - degree of scaling factor used to encode the vector
   * @param level - level at each the vector will get encrypted
   * @param params - parameters to be usef for the ciphertext
   * @return plaintext
   */
    Plaintext MakeCKKSPackedPlaintext(const std::vector<std::complex<double>>& value, size_t scaleDeg = 1,
                                      uint32_t level = 0, const std::shared_ptr<ParmType> params = nullptr,
                                      usint slots = 0) const {
        VerifyCKKSScheme(__func__);
        if (!value.size())
            OPENFHE_THROW("Cannot encode an empty value vector");

        return MakeCKKSPackedPlaintextInternal(value, scaleDeg, level, params, slots);
    }

    /**
   * MakeCKKSPackedPlaintext constructs a CKKSPackedEncoding in this context
   * from a vector of real numbers
   * @param value - input vector of real numbers
   * @param scaleDeg - degree of scaling factor used to encode the vector
   * @param level - level at each the vector will get encrypted
   * @param params - parameters to be usef for the ciphertext
   * @return plaintext
   */
    Plaintext MakeCKKSPackedPlaintext(const std::vector<double>& value, size_t scaleDeg = 1, uint32_t level = 0,
                                      const std::shared_ptr<ParmType> params = nullptr, usint slots = 0) const {
        VerifyCKKSScheme(__func__);
        if (!value.size())
            OPENFHE_THROW("Cannot encode an empty value vector");

        std::vector<std::complex<double>> complexValue(value.size());
        std::transform(value.begin(), value.end(), complexValue.begin(),
                       [](double da) { return std::complex<double>(da); });

        return MakeCKKSPackedPlaintextInternal(complexValue, scaleDeg, level, params, slots);
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
    KeyPair<Element> KeyGen() const {
        return GetScheme()->KeyGen(GetContextForPointer(this), false);
    }

    /**
   * NOT SUPPORTED BY ANY CRYPTO SCHEME NOW
   * SparseKeyGen generates a key pair with special structure, and without full
   * entropy, for use in special cases like Ring Reduction
   * @return a public/secret key pair
   */
    KeyPair<Element> SparseKeyGen() const {
        return GetScheme()->KeyGen(GetContextForPointer(this), true);
    }

    /**
   * Encrypt a plaintext using a given public key
   * @param plaintext plaintext
   * @param publicKey public key
   * @return ciphertext (or null on failure)
   */
    Ciphertext<Element> Encrypt(const Plaintext& plaintext, const PublicKey<Element> publicKey) const {
        if (plaintext == nullptr)
            OPENFHE_THROW("Input plaintext is nullptr");
        ValidateKey(publicKey);

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

    /**
   * Encrypt a plaintext using a given public key
   * @param publicKey public key
   * @param plaintext plaintext
   * @return ciphertext (or null on failure)
   */
    Ciphertext<Element> Encrypt(const PublicKey<Element> publicKey, Plaintext plaintext) const {
        return Encrypt(plaintext, publicKey);
    }

    /**
   * Encrypt a plaintext using a given private key
   * @param plaintext input plaintext
   * @param privateKey private key
   * @return ciphertext (or null on failure)
   */
    Ciphertext<Element> Encrypt(const Plaintext& plaintext, const PrivateKey<Element> privateKey) const {
        //    if (plaintext == nullptr)
        //      OPENFHE_THROW( "Input plaintext is nullptr");
        ValidateKey(privateKey);

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

    /**
   * Encrypt a plaintext using a given private key
   * @param privateKey private key
   * @param plaintext input plaintext
   * @return ciphertext (or null on failure)
   */
    Ciphertext<Element> Encrypt(const PrivateKey<Element> privateKey, Plaintext plaintext) const {
        return Encrypt(plaintext, privateKey);
    }

    /**
   * Decrypt a single ciphertext into the appropriate plaintext
   *
   * @param ciphertext - ciphertext to decrypt
   * @param privateKey - decryption key
   * @param plaintext - resulting plaintext object pointer is here
   * @return
   */
    DecryptResult Decrypt(ConstCiphertext<Element> ciphertext, const PrivateKey<Element> privateKey,
                          Plaintext* plaintext);

    /**
   * Decrypt a single ciphertext into the appropriate plaintext
   *
   * @param privateKey - decryption key
   * @param ciphertext - ciphertext to decrypt
   * @param plaintext - resulting plaintext object pointer is here
   * @return
   */
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
   * @param oldPrivateKey input secrey key
   * @param newPrivateKey output secret key
   * @return new evaluation key
   */
    EvalKey<Element> KeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                  const PrivateKey<Element> newPrivateKey) const {
        ValidateKey(oldPrivateKey);
        ValidateKey(newPrivateKey);

        return GetScheme()->KeySwitchGen(oldPrivateKey, newPrivateKey);
    }

    /**
   * KeySwitch - OpenFHE KeySwitch method
   * @param ciphertext - ciphertext
   * @param evalKey - evaluation key used for key switching
   * @return new CiphertextImpl after applying key switch
   */
    Ciphertext<Element> KeySwitch(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey) const {
        ValidateCiphertext(ciphertext);
        ValidateKey(evalKey);

        return GetScheme()->KeySwitch(ciphertext, evalKey);
    }

    /**
   * KeySwitchInPlace - OpenFHE KeySwitchInPlace method
   * @param ciphertext - ciphertext
   * @param evalKey - evaluation key used for key switching
   */
    void KeySwitchInPlace(Ciphertext<Element>& ciphertext, const EvalKey<Element> evalKey) const {
        ValidateCiphertext(ciphertext);
        ValidateKey(evalKey);

        GetScheme()->KeySwitchInPlace(ciphertext, evalKey);
    }

    //------------------------------------------------------------------------------
    // SHE NEGATION Wrapper
    //------------------------------------------------------------------------------

    /**
   * Negates a ciphertext
   * @param ciphertext input ciphertext
   * @return new ciphertext -ct
   */
    Ciphertext<Element> EvalNegate(ConstCiphertext<Element> ciphertext) const {
        ValidateCiphertext(ciphertext);

        return GetScheme()->EvalNegate(ciphertext);
    }

    /**
   * In-place negation of a ciphertext
   * @param ciphertext input ciphertext
   */
    void EvalNegateInPlace(Ciphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);

        GetScheme()->EvalNegateInPlace(ciphertext);
    }

    //------------------------------------------------------------------------------
    // SHE ADDITION Wrapper
    //------------------------------------------------------------------------------

    /**
   * Homomorphic addition of two ciphertexts
   * @param ciphertext1 first addend
   * @param ciphertext2 second addend
   * @return the result as a new ciphertext
   */
    Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalAdd(ciphertext1, ciphertext2);
    }

    /**
   * In-place homomorphic addition of two ciphertexts
   * @param ciphertext1 first addend
   * @param ciphertext2 second addend
   * @return \p ciphertext1 contains \p ciphertext1 + \p ciphertext2
   */
    void EvalAddInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalAddInPlace(ciphertext1, ciphertext2);
    }

    /**
   * Homomorphic addition of two mutable ciphertexts (they can be changed during the operation)
   * @param ciphertext1 first addend
   * @param ciphertext2 second addend
   * @return the result as a new ciphertext
   */
    Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalAddMutable(ciphertext1, ciphertext2);
    }

    /**
   * In-place homomorphic addition of two mutable ciphertexts (they can be changed during the operation)
   * @param ciphertext1 first addend
   * @param ciphertext2 second addend
   * @return \p ciphertext1 contains \p ciphertext1 + \p ciphertext2
   */
    void EvalAddMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalAddMutableInPlace(ciphertext1, ciphertext2);
    }

    /**
   * EvalAdd - OpenFHE EvalAdd method for a ciphertext and plaintext
   * @param ciphertext input ciphertext
   * @param plaintext input plaintext
   * @return new ciphertext for ciphertext + plaintext
   */
    Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        plaintext->SetFormat(EVALUATION);
        return GetScheme()->EvalAdd(ciphertext, plaintext);
    }

    /**
   * EvalAdd - OpenFHE EvalAdd method for a ciphertext and plaintext
   * @param plaintext input plaintext
   * @param ciphertext input ciphertext
   * @return new ciphertext for ciphertext + plaintext
   */
    Ciphertext<Element> EvalAdd(ConstPlaintext plaintext, ConstCiphertext<Element> ciphertext) const {
        return EvalAdd(ciphertext, plaintext);
    }

    /**
   * In-place addition for a ciphertext and plaintext
   * @param ciphertext input ciphertext
   * @param plaintext input plaintext
   */
    void EvalAddInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        plaintext->SetFormat(EVALUATION);
        GetScheme()->EvalAddInPlace(ciphertext, plaintext);
    }

    /**
   * In-place addition for a ciphertext and plaintext
   * @param plaintext input plaintext
   * @param ciphertext input ciphertext
   */
    void EvalAddInPlace(ConstPlaintext plaintext, Ciphertext<Element>& ciphertext) const {
        EvalAddInPlace(ciphertext, plaintext);
    }

    /**
   * Homomorphic addition a mutable ciphertext and plaintext
   * @param ciphertext input ciphertext
   * @param plaintext input plaintext
   * @return new ciphertext for ciphertext + plaintext
   */
    Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        TypeCheck((ConstCiphertext<Element>)ciphertext, (ConstPlaintext)plaintext);
        plaintext->SetFormat(EVALUATION);
        return GetScheme()->EvalAddMutable(ciphertext, plaintext);
    }

    /**
   * Homomorphic addition a mutable ciphertext and plaintext
   * @param plaintext input plaintext
   * @param ciphertext input ciphertext
   * @return new ciphertext for ciphertext + plaintext
   */
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
   * EvalAdd - OpenFHE EvalAdd method for a ciphertext and a real number.  Supported only in CKKS.
   * @param ciphertext input ciphertext
   * @param constant a real number
   * @return new ciphertext for ciphertext + constant
   */
    Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, double constant) const {
        Ciphertext<Element> result =
            constant >= 0 ? GetScheme()->EvalAdd(ciphertext, constant) : GetScheme()->EvalSub(ciphertext, -constant);
        return result;
    }

    /**
   * EvalAdd - OpenFHE EvalAdd method for a ciphertext and a real number.  Supported only in CKKS.
   * @param constant a real number
   * @param ciphertext input ciphertext
   * @return new ciphertext for ciphertext + constant
   */
    Ciphertext<Element> EvalAdd(double constant, ConstCiphertext<Element> ciphertext) const {
        return EvalAdd(ciphertext, constant);
    }

    /**
   * In-place addition of a ciphertext and a real number. Supported only in CKKS.
   * @param ciphertext input ciphertext
   * @param constant a real number
   */
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

    /**
   * In-place addition of a ciphertext and a real number.  Supported only in CKKS.
   * @param constant a real number
   * @param ciphertext input ciphertext
   */
    void EvalAddInPlace(double constant, Ciphertext<Element>& ciphertext) const {
        EvalAddInPlace(ciphertext, constant);
    }

    //------------------------------------------------------------------------------
    // SHE SUBTRACTION Wrapper
    //------------------------------------------------------------------------------

    /**
   * Homomorphic subtraction of two ciphertexts
   * @param ciphertext1 minuend
   * @param ciphertext2 subtrahend
   * @return the result as a new ciphertext
   */
    Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalSub(ciphertext1, ciphertext2);
    }

    /**
   * In-place homomorphic subtraction of two ciphertexts
   * @param ciphertext1 minuend
   * @param ciphertext2 subtrahend
   * @return the result as a new ciphertext
   */
    void EvalSubInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalSubInPlace(ciphertext1, ciphertext2);
    }

    /**
   * Homomorphic subtraction of two mutable ciphertexts
   * @param ciphertext1 minuend
   * @param ciphertext2 subtrahend
   * @return the result as a new ciphertext
   */
    Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalSubMutable(ciphertext1, ciphertext2);
    }

    /**
   * In-place homomorphic subtraction of two mutable ciphertexts
   * @param ciphertext1 minuend
   * @param ciphertext2 subtrahend
   * @return the updated minuend
   */
    void EvalSubMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalSubMutableInPlace(ciphertext1, ciphertext2);
    }

    /**
   * Homomorphic subtraction of a ciphertext and plaintext
   * @param ciphertext minuend
   * @param plaintext subtrahend
   * @return new ciphertext for ciphertext - plaintext
   */
    Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        return GetScheme()->EvalSub(ciphertext, plaintext);
    }

    /**
   * Homomorphic subtraction of a ciphertext and plaintext
   * @param plaintext minuend
   * @param ciphertext subtrahend
   * @return new ciphertext for plaintext - ciphertext
   */
    Ciphertext<Element> EvalSub(ConstPlaintext plaintext, ConstCiphertext<Element> ciphertext) const {
        return EvalAdd(EvalNegate(ciphertext), plaintext);
    }

    /**
   * Homomorphic subtraction of mutable ciphertext and plaintext
   * @param ciphertext minuend
   * @param plaintext subtrahend
   * @return new ciphertext for ciphertext - plaintext
   */
    Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        TypeCheck((ConstCiphertext<Element>)ciphertext, (ConstPlaintext)plaintext);
        return GetScheme()->EvalSubMutable(ciphertext, plaintext);
    }

    /**
   * Homomorphic subtraction of mutable ciphertext and plaintext
   * @param plaintext minuend
   * @param ciphertext subtrahend
   * @return new ciphertext for plaintext - ciphertext
   */
    Ciphertext<Element> EvalSubMutable(Plaintext plaintext, Ciphertext<Element>& ciphertext) const {
        Ciphertext<Element> negated = EvalNegate(ciphertext);
        Ciphertext<Element> result  = EvalAddMutable(negated, plaintext);
        ciphertext                  = EvalNegate(negated);
        return result;
    }

    /**
   * Subtraction of a ciphertext and a real number. Supported only in CKKS.
   * @param ciphertext input ciphertext
   * @param constant a real number
   * @return new ciphertext for ciphertext - constant
   */
    Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, double constant) const {
        Ciphertext<Element> result =
            constant >= 0 ? GetScheme()->EvalSub(ciphertext, constant) : GetScheme()->EvalAdd(ciphertext, -constant);
        return result;
    }

    /**
   * Subtraction of a ciphertext and a real number.  Supported only in CKKS.
   * @param constant a real number
   * @param ciphertext input ciphertext
   * @return new ciphertext for constant - ciphertext
   */
    Ciphertext<Element> EvalSub(double constant, ConstCiphertext<Element> ciphertext) const {
        return EvalAdd(EvalNegate(ciphertext), constant);
    }

    /**
   * In-place subtraction of a ciphertext and a real number.  Supported only in CKKS.
   * @param ciphertext input ciphertext
   * @param constant a real number
   */
    void EvalSubInPlace(Ciphertext<Element>& ciphertext, double constant) const {
        if (constant >= 0) {
            GetScheme()->EvalSubInPlace(ciphertext, constant);
        }
        else {
            GetScheme()->EvalAddInPlace(ciphertext, -constant);
        }
    }

    /**
   * In-placve subtraction of ciphertext from a real number.  Supported only in CKKS.
   * @param constant a real number
   * @param ciphertext input ciphertext
   */
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
   * EvalMultKeyGen creates a relinearization key (for s^2) that can be used with the OpenFHE EvalMult
   * operator
   * the new evaluation key is stored in cryptocontext
   * @param key secret key
   */
    void EvalMultKeyGen(const PrivateKey<Element> key);

    /**
   * EvalMultsKeyGen creates a vector evalmult keys that can be used with the
   * OpenFHE EvalMult operator 1st key (for s^2) is used for multiplication of
   * ciphertexts of depth 1 2nd key (for s^3) is used for multiplication of
   * ciphertexts of depth 2, etc.
   * a vector of new evaluation keys is stored in crytpocontext
   *
   * @param key secret key
   */
    void EvalMultKeysGen(const PrivateKey<Element> key);

    /**
   * EvalMult - OpenFHE EvalMult method for a pair of ciphertexts (uses a relinearization key from the crypto context)
   * @param ciphertext1 multiplier
   * @param ciphertext2 multiplicand
   * @return new ciphertext for ciphertext1 * ciphertext2
   */
    Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW("Evaluation key has not been generated for EvalMult");
        }

        return GetScheme()->EvalMult(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    /**
   * EvalMult - OpenFHE EvalMult method for a pair of mutable ciphertexts (uses a relinearization key from the crypto context)
   * @param ciphertext1 multiplier
   * @param ciphertext2 multiplicand
   * @return new ciphertext for ciphertext1 * ciphertext2
   */
    Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW("Evaluation key has not been generated for EvalMultMutable");
        }

        return GetScheme()->EvalMultMutable(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    /**
   * In-place EvalMult method for a pair of mutable ciphertexts (uses a relinearization key from the crypto context)
   * @param ciphertext1 multiplier
   * @param ciphertext2 multiplicand
   */
    void EvalMultMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW("Evaluation key has not been generated for EvalMultMutable");
        }

        GetScheme()->EvalMultMutableInPlace(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    /**
   * Efficient homomorphic squaring of a ciphertext - uses a relinearization key stored in the crypto context
   * @param ciphertext input ciphertext
   * @return squared ciphertext
   */
    Ciphertext<Element> EvalSquare(ConstCiphertext<Element> ciphertext) const {
        ValidateCiphertext(ciphertext);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW("Evaluation key has not been generated for EvalMult");
        }

        return GetScheme()->EvalSquare(ciphertext, evalKeyVec[0]);
    }

    /**
   * Efficient homomorphic squaring of a mutable ciphertext - uses a relinearization key stored in the crypto context
   * @param ciphertext input ciphertext
   * @return squared ciphertext
   */
    Ciphertext<Element> EvalSquareMutable(Ciphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW("Evaluation key has not been generated for EvalMultMutable");
        }

        return GetScheme()->EvalSquareMutable(ciphertext, evalKeyVec[0]);
    }

    /**
   * In-place homomorphic squaring of a mutable ciphertext - uses a relinearization key stored in the crypto context
   * @param ciphertext input ciphertext
   * @return squared ciphertext
   */
    void EvalSquareInPlace(Ciphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW("Evaluation key has not been generated for EvalMultMutable");
        }

        GetScheme()->EvalSquareInPlace(ciphertext, evalKeyVec[0]);
    }

    /**
   * Homomorphic multiplication of two ciphertexts withour relinearization
   * @param ciphertext1 multiplier
   * @param ciphertext2 multiplicand
   * @return new ciphertext for ciphertext1 * ciphertext2
   */
    Ciphertext<Element> EvalMultNoRelin(ConstCiphertext<Element> ciphertext1,
                                        ConstCiphertext<Element> ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalMult(ciphertext1, ciphertext2);
    }

    /**
   * Function for relinearization of a ciphertext to the lowest level (with 2 polynomials per ciphertext).
   * @param ciphertext input ciphertext.
   * @return relinearized ciphertext
   */
    Ciphertext<Element> Relinearize(ConstCiphertext<Element> ciphertext) const {
        // input parameter check
        if (!ciphertext)
            OPENFHE_THROW("Input ciphertext is nullptr");

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext->GetKeyTag());

        if (evalKeyVec.size() < (ciphertext->NumberCiphertextElements() - 2)) {
            OPENFHE_THROW(
                "Insufficient value was used for maxRelinSkDeg to generate "
                "keys for EvalMult");
        }

        return GetScheme()->Relinearize(ciphertext, evalKeyVec);
    }

    /**
   * In-place relinearization of a ciphertext to the lowest level (with 2 polynomials per ciphertext).
   * @param ciphertext input ciphertext.
   */
    void RelinearizeInPlace(Ciphertext<Element>& ciphertext) const {
        // input parameter check
        if (!ciphertext)
            OPENFHE_THROW("Input ciphertext is nullptr");

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (evalKeyVec.size() < (ciphertext->NumberCiphertextElements() - 2)) {
            OPENFHE_THROW(
                "Insufficient value was used for maxRelinSkDeg to generate "
                "keys for EvalMult");
        }

        GetScheme()->RelinearizeInPlace(ciphertext, evalKeyVec);
    }

    /**
   * Homomorphic multiplication of two ciphertexts followed by relinearization to the lowest level
   * @param ciphertext1 first input ciphertext.
   * @param ciphertext2 second input ciphertext.
   * @return new ciphertext
   */
    Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element> ciphertext1,
                                               ConstCiphertext<Element> ciphertext2) const {
        // input parameter check
        if (!ciphertext1 || !ciphertext2)
            OPENFHE_THROW("Input ciphertext is nullptr");

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext1->GetKeyTag());

        if (evalKeyVec.size() <
            (ciphertext1->NumberCiphertextElements() + ciphertext2->NumberCiphertextElements() - 3)) {
            OPENFHE_THROW(
                "Insufficient value was used for maxRelinSkDeg to generate "
                "keys for EvalMult");
        }

        return GetScheme()->EvalMultAndRelinearize(ciphertext1, ciphertext2, evalKeyVec);
    }

    /**
   * Multiplication of a ciphertext by a plaintext
   * @param ciphertext multiplier
   * @param plaintext multiplicand
   * @return the result of multiplication
   */
    Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        return GetScheme()->EvalMult(ciphertext, plaintext);
    }

    /**
   * Multiplication of a plaintext by a ciphertext
   * @param plaintext multiplier
   * @param ciphertext multiplicand
   * @return the result of multiplication
   */
    Ciphertext<Element> EvalMult(ConstPlaintext plaintext, ConstCiphertext<Element> ciphertext) const {
        return EvalMult(ciphertext, plaintext);
    }

    /**
   * Multiplication of mutable ciphertext and plaintext
   * @param ciphertext multiplier
   * @param plaintext multiplicand
   * @return the result of multiplication
   */
    Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        return GetScheme()->EvalMultMutable(ciphertext, plaintext);
    }

    /**
   * Multiplication of mutable plaintext and ciphertext
   * @param plaintext multiplier
   * @param ciphertext multiplicand
   * @return the result of multiplication
   */
    Ciphertext<Element> EvalMultMutable(Plaintext plaintext, Ciphertext<Element>& ciphertext) const {
        return EvalMultMutable(ciphertext, plaintext);
    }

    // template <typename T = const NativeInteger,
    //    typename std::enable_if <!std::is_same<ConstCiphertext<Element>, T>::value, bool>::type = true>

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, const NativeInteger& constant) const {
    //  if (!ciphertext) {
    //    OPENFHE_THROW( "Input ciphertext is nullptr");
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
    //    OPENFHE_THROW( "Input ciphertext is nullptr");
    //  }

    //  GetScheme()->EvalMultInPlace(ciphertext, constant);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // void EvalMultInPlace(const NativeInteger& constant, Ciphertext<Element>& ciphertext) const {
    //  EvalMultInPlace(ciphertext, constant);
    // }

    /**
   * Multiplication of a ciphertext by a real number.  Supported only in CKKS.
   * @param ciphertext multiplier
   * @param constant multiplicand
   * @return the result of multiplication
   */
    Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, double constant) const {
        if (!ciphertext) {
            OPENFHE_THROW("Input ciphertext is nullptr");
        }
        return GetScheme()->EvalMult(ciphertext, constant);
    }

    /**
   * Multiplication of a ciphertext by a real number.  Supported only in CKKS.
   * @param constant multiplier
   * @param ciphertext multiplicand
   * @return the result of multiplication
   */
    inline Ciphertext<Element> EvalMult(double constant, ConstCiphertext<Element> ciphertext) const {
        return EvalMult(ciphertext, constant);
    }

    /**
   * In-place multiplication of a ciphertext by a real number. Supported only in CKKS.
   * @param ciphertext multiplier
   * @param constant multiplicand
   */
    void EvalMultInPlace(Ciphertext<Element>& ciphertext, double constant) const {
        if (!ciphertext) {
            OPENFHE_THROW("Input ciphertext is nullptr");
        }

        GetScheme()->EvalMultInPlace(ciphertext, constant);
    }

    /**
   * In-place multiplication of a ciphertext by a real number. Supported only in CKKS.
   * @param constant multiplier (real number)
   * @param ciphertext multiplicand
   */
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
        ValidateKey(privateKey);
        if (!indexList.size())
            OPENFHE_THROW("Input index vector is empty");

        // Do not generate duplicate keys that have been already generated and added to the static storage (map)
        std::set<uint32_t> allIndices(indexList.begin(), indexList.end());
        std::set<uint32_t> indicesToGenerate{
            CryptoContextImpl<Element>::GetEvalAutomorphismNoKeyIndices(privateKey->GetKeyTag(), allIndices)};

        std::vector<uint32_t> newIndices(indicesToGenerate.begin(), indicesToGenerate.end());
        auto evalKeys = GetScheme()->EvalAutomorphismKeyGen(privateKey, newIndices);
        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, privateKey->GetKeyTag());

        return evalKeys;
    }

    [[deprecated(
        "Use EvalAutomorphismKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList) instead.")]] std::
        shared_ptr<std::map<usint, EvalKey<Element>>>
        EvalAutomorphismKeyGen(const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
                               const std::vector<usint>& indexList) const {
        std::string errMsg(
            "This API is deprecated. use EvalAutomorphismKeyGen(const PrivateKey<Element> privateKey, const std::vector<usint>& indexList)");
        OPENFHE_THROW(errMsg);
    }

    /**
   * Function for evaluating automorphism of ciphertext at index i
   *
   * @param ciphertext the input ciphertext.
   * @param i automorphism index
   * @param &evalKeys - reference to the vector of evaluation keys generated by EvalAutomorphismKeyGen.
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalAutomorphism(ConstCiphertext<Element> ciphertext, usint i,
                                         const std::map<usint, EvalKey<Element>>& evalKeyMap,
                                         CALLER_INFO_ARGS_HDR) const {
        ValidateCiphertext(ciphertext);

        if (evalKeyMap.empty()) {
            std::string errorMsg(std::string("Empty input key map") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }

        auto key = evalKeyMap.find(i);

        if (key == evalKeyMap.end()) {
            std::string errorMsg(std::string("Could not find an EvalKey for index ") + std::to_string(i) + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }

        auto evalKey = key->second;

        ValidateKey(evalKey);

        return GetScheme()->EvalAutomorphism(ciphertext, i, evalKeyMap);
    }

    /**
   * Finds an automorphism index for a given vector index using a scheme-specific algorithm
   * @param idx regular vector index
   * @return the automorphism index
   */
    usint FindAutomorphismIndex(const usint idx) const {
        const auto cryptoParams  = GetCryptoParameters();
        const auto elementParams = cryptoParams->GetElementParams();
        uint32_t m               = elementParams->GetCyclotomicOrder();
        return GetScheme()->FindAutomorphismIndex(idx, m);
    }

    /**
   * Finds automorphism indices for a given list of vector indices using a scheme-specific algorithm
   * @param idxList vector of indices
   * @return a vector of automorphism indices
   */
    std::vector<usint> FindAutomorphismIndices(const std::vector<usint>& idxList) const {
        std::vector<usint> newIndices;
        newIndices.reserve(idxList.size());
        for (const auto idx : idxList) {
            newIndices.emplace_back(FindAutomorphismIndex(idx));
        }
        return newIndices;
    }

    /**
   * Rotates a ciphertext by an index (positive index is a left shift, negative index is a right shift).
   * Uses a rotation key stored in a crypto context.
   * Calls EvalAtIndex under the hood.
   * @param ciphertext input ciphertext
   * @param index rotation index
   * @return a rotated ciphertext
   */
    Ciphertext<Element> EvalRotate(ConstCiphertext<Element> ciphertext, int32_t index) const {
        ValidateCiphertext(ciphertext);

        auto evalKeyMap = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
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
   * @param ciphertext the input ciphertext on which to do the precomputation (digit
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
   * @param ciphertext the input ciphertext to perform the automorphism on
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
        auto evalKeyMap = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());

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
   * EvalAtIndexKeyGen generates evaluation keys for a list of rotation indices
   *
   * @param privateKey private key.
   * @param indexList list of indices.
   * @param publicKey public key (used in NTRU schemes). Not used anymore.
   */
    void EvalAtIndexKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList,
                           const PublicKey<Element> publicKey = nullptr);

    // [[deprecated(
    //     "Use EvalAtIndexKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList) instead.")]] void
    // EvalAtIndexKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList,
    //                   const PublicKey<Element> publicKey) {
    //     std::string errMsg(
    //         "This API is deprecated. use EvalAtIndexKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList)");
    //     OPENFHE_THROW( errMsg);
    // }

    /**
   * EvalRotateKeyGen generates evaluation keys for a list of rotation indices.
   * Calls EvalAtIndexKeyGen under the hood.
   *
   * @param privateKey private key.
   * @param indexList list of indices.
   * @param publicKey public key (used in NTRU schemes).
   */
    void EvalRotateKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList,
                          const PublicKey<Element> publicKey = nullptr) {
        EvalAtIndexKeyGen(privateKey, indexList, publicKey);
    };
    // [[deprecated(
    //     "Use EvalRotateKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList) instead.")]] void
    // EvalRotateKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList,
    //                  const PublicKey<Element> publicKey) {
    //     std::string errMsg(
    //         "This API is deprecated. use EvalRotateKeyGen(const PrivateKey<Element> privateKey, const std::vector<int32_t>& indexList)");
    //     OPENFHE_THROW( errMsg);
    // }
    /**
   * Rotates a ciphertext by an index (positive index is a left shift, negative index is a right shift).
   * Uses a rotation key stored in a crypto context.
   * @param ciphertext input ciphertext
   * @param index rotation index
   * @return a rotated ciphertext
   */
    Ciphertext<Element> EvalAtIndex(ConstCiphertext<Element> ciphertext, int32_t index) const;

    //------------------------------------------------------------------------------
    // SHE Leveled Methods Wrapper
    //------------------------------------------------------------------------------

    /**
   * ComposedEvalMult - calls multiplication, relinearization, and then modulus switching/rescaling.
   * Uses a relinearization key stored in the crypto context.
   * @param ciphertext1 - first ciphertext
   * @param ciphertext2 - second ciphertext
   */
    Ciphertext<Element> ComposedEvalMult(ConstCiphertext<Element> ciphertext1,
                                         ConstCiphertext<Element> ciphertext2) const {
        ValidateCiphertext(ciphertext1);
        ValidateCiphertext(ciphertext2);

        auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size()) {
            OPENFHE_THROW("Evaluation key has not been generated for EvalMult");
        }

        return GetScheme()->ComposedEvalMult(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    /**
   * Rescale - An alias for OpenFHE ModReduce method.
   * This is because ModReduce is called Rescale in CKKS.
   *
   * @param ciphertext - ciphertext
   * @return rescaled ciphertext
   */
    Ciphertext<Element> Rescale(ConstCiphertext<Element> ciphertext) const {
        ValidateCiphertext(ciphertext);

        return GetScheme()->ModReduce(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    }

    /**
   * Rescale - An alias for OpenFHE ModReduceInPlace method.
   * This is because ModReduceInPlace is called RescaleInPlace in CKKS.
   *
   * @param ciphertext - ciphertext to be rescaled in-place
   */
    void RescaleInPlace(Ciphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);

        GetScheme()->ModReduceInPlace(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    }

    /**
   * ModReduce - OpenFHE ModReduce method used only for BGV/CKKS.
   * @param ciphertext - ciphertext
   * @return mod reduced ciphertext
   */
    Ciphertext<Element> ModReduce(ConstCiphertext<Element> ciphertext) const {
        ValidateCiphertext(ciphertext);

        return GetScheme()->ModReduce(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    }

    /**
   * ModReduce - OpenFHE ModReduceInPlace method used only for BGV/CKKS.
   * @param ciphertext - ciphertext to be mod-reduced in-place
   */
    void ModReduceInPlace(Ciphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);

        GetScheme()->ModReduceInPlace(ciphertext, BASE_NUM_LEVELS_TO_DROP);
    }

    /**
   * LevelReduce - drops unnecessary RNS limbs (levels) from the ciphertext and evaluation key
   * @param ciphertext input ciphertext. Supported only in BGV/CKKS.
   * @param evalKey input evaluation key (modified in place)
   * @returns the ciphertext with reduced number opf RNS limbs
   */
    Ciphertext<Element> LevelReduce(ConstCiphertext<Element> ciphertext, const EvalKey<Element> evalKey,
                                    size_t levels = 1) const {
        ValidateCiphertext(ciphertext);

        return GetScheme()->LevelReduce(ciphertext, evalKey, levels);
    }

    /**
   * LevelReduceInPlace - drops unnecessary RNS limbs (levels) from the ciphertext and evaluation key. Supported only in BGV/CKKS.
   * @param ciphertext input ciphertext (modified in place)
   * @param evalKey input evaluation key (modified in place)
   */
    void LevelReduceInPlace(Ciphertext<Element>& ciphertext, const EvalKey<Element> evalKey, size_t levels = 1) const {
        ValidateCiphertext(ciphertext);
        if (levels <= 0) {
            return;
        }
        GetScheme()->LevelReduceInPlace(ciphertext, evalKey, levels);
    }
    /**
   * Compress - Reduces the size of ciphertext modulus to minimize the
   * communication cost before sending the encrypted result for decryption.
   * Similar to ModReduce but for BFV where ModReduce is not exposed directly.
   * @param ciphertext - input ciphertext
   * @param numTowers - number of RNS limbs after compressing (default is 1)
   * @return compressed ciphertext
   */
    Ciphertext<Element> Compress(ConstCiphertext<Element> ciphertext, uint32_t towersLeft = 1) const {
        if (ciphertext == nullptr)
            OPENFHE_THROW("input ciphertext is invalid (has no data)");

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
   * @return new ciphertext.
   */
    Ciphertext<Element> EvalAddMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const {
        // input parameter check
        if (!ciphertextVec.size())
            OPENFHE_THROW("Empty input ciphertext vector");

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
   * @return new ciphertext.
   */
    Ciphertext<Element> EvalAddManyInPlace(std::vector<Ciphertext<Element>>& ciphertextVec) const {
        // input parameter check
        if (!ciphertextVec.size())
            OPENFHE_THROW("Empty input ciphertext vector");

        return GetScheme()->EvalAddManyInPlace(ciphertextVec);
    }

    /**
   * EvalMultMany - OpenFHE function for evaluating multiplication on
   * ciphertext followed by relinearization operation (at the end). It computes
   * the multiplication in a binary tree manner. Also, it reduces the number of
   * elements in the ciphertext to two after each multiplication.
   * Currently it assumes that the consecutive two input arguments have
   * total number of ring elements smaller than the supported one (for the secret key degree used by EvalMultsKeyGen). Otherwise, it throws an
   * error.
   *
   * @param ciphertextVec  is the ciphertext list.
   * @return new ciphertext.
   */
    Ciphertext<Element> EvalMultMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const {
        // input parameter check
        if (!ciphertextVec.size()) {
            OPENFHE_THROW("Empty input ciphertext vector");
        }

        if (ciphertextVec.size() == 1) {
            return ciphertextVec[0];
        }

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertextVec[0]->GetKeyTag());
        if (evalKeyVec.size() < (ciphertextVec[0]->NumberCiphertextElements() - 2)) {
            OPENFHE_THROW("Insufficient value was used for maxRelinSkDeg to generate keys");
        }

        return GetScheme()->EvalMultMany(ciphertextVec, evalKeyVec);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE LINEAR WEIGHTED SUM
    //------------------------------------------------------------------------------

    /**
   * EvalLinearWSum - OpenFHE EvalLinearWSum method to compute a linear
   * weighted sum. Supported only in CKKS.
   *
   * @param ciphertextVec& a list of ciphertexts
   * @param constantVec& a list of weights
   * @return new ciphertext containing the weighted sum
   */
    Ciphertext<Element> EvalLinearWSum(std::vector<ConstCiphertext<Element>>& ciphertextVec,
                                       const std::vector<double>& constantVec) const {
        return GetScheme()->EvalLinearWSum(ciphertextVec, constantVec);
    }

    /**
   * EvalLinearWSum - OpenFHE EvalLinearWSum method to compute a linear
   * weighted sum. Supported only in CKKS.
   *
   * @param constantVec& a list of weights
   * @param ciphertextVec& a list of ciphertexts
   * @return new ciphertext containing the weighted sum
   */
    Ciphertext<Element> EvalLinearWSum(const std::vector<double>& constantsVec,
                                       std::vector<ConstCiphertext<Element>>& ciphertextVec) const {
        return EvalLinearWSum(ciphertextVec, constantsVec);
    }

    /**
   * EvalLinearWSum - OpenFHE EvalLinearWSum method to compute a linear
   * weighted sum (mutable version). Supported only in CKKS.
   *
   * @param ciphertextVec& ciphertexts a list of mutable ciphertexts
   * @param constantVec& constants a list of weights
   * @return new ciphertext containing the weighted sum
   */
    Ciphertext<Element> EvalLinearWSumMutable(std::vector<Ciphertext<Element>>& ciphertextVec,
                                              const std::vector<double>& constantsVec) const {
        return GetScheme()->EvalLinearWSumMutable(ciphertextVec, constantsVec);
    }

    /**
   * EvalLinearWSum - OpenFHE EvalLinearWSum method to compute a linear
   * weighted sum (mutable version). Supported only in CKKS.
   *
   * @param constantVec& constants a list of weights
   * @param ciphertextVec& ciphertexts a list of mutable ciphertexts
   * @return new ciphertext containing the weighted sum
   */
    Ciphertext<Element> EvalLinearWSumMutable(const std::vector<double>& constantsVec,
                                              std::vector<Ciphertext<Element>>& ciphertextVec) const {
        return EvalLinearWSumMutable(ciphertextVec, constantsVec);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL POLYNOMIAL
    //------------------------------------------------------------------------------

    /**
   * Method for evaluation for polynomials represented as power series. Supported only in CKKS.
   * If the degree of the polynomial is less than 5, use
   * EvalPolyLinear (naive linear method), otherwise, use EvalPolyPS (Paterson-Stockmeyer method).
   *
   * @param ciphertext input ciphertext
   * @param &coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial + 1
   * @return the result of polynomial evaluation.
   */
    virtual Ciphertext<Element> EvalPoly(ConstCiphertext<Element> ciphertext,
                                         const std::vector<double>& coefficients) const {
        ValidateCiphertext(ciphertext);

        return GetScheme()->EvalPoly(ciphertext, coefficients);
    }

    /**
   * Naive method for polynomial evaluation for polynomials represented in the power
   * series (fast only for small-degree polynomials; less than 10). Uses a binary tree computation of
   * the polynomial powers. Supported only in CKKS.
   *
   * @param cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial
   * @return the result of polynomial evaluation.
   */
    Ciphertext<Element> EvalPolyLinear(ConstCiphertext<Element> ciphertext,
                                       const std::vector<double>& coefficients) const {
        ValidateCiphertext(ciphertext);

        return GetScheme()->EvalPolyLinear(ciphertext, coefficients);
    }

    /**
   * Paterson-Stockmeyer method for evaluation for polynomials represented in the power
   * series. Supported only in CKKS.
   *
   * @param cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in the polynomial; the
   * size of the vector is the degree of the polynomial
   * @return the result of polynomial evaluation.
   */
    Ciphertext<Element> EvalPolyPS(ConstCiphertext<Element> ciphertext, const std::vector<double>& coefficients) const {
        ValidateCiphertext(ciphertext);

        return GetScheme()->EvalPolyPS(ciphertext, coefficients);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL CHEBYSHEV SERIES
    //------------------------------------------------------------------------------

    /**
   * Method for evaluating Chebyshev polynomial interpolation;
   * first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2
   * (x-a)/(b-a) If the degree of the polynomial is less than 5, use
   * EvalChebyshevSeriesLinear (naive linear method), otherwise, use EvalChebyshevSeriesPS (Paterson-Stockmeyer method).
   * Supported only in CKKS.
   *
   * @param cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in Chebyshev expansion
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @return the result of polynomial evaluation.
   */
    Ciphertext<Element> EvalChebyshevSeries(ConstCiphertext<Element> ciphertext,
                                            const std::vector<double>& coefficients, double a, double b) const {
        ValidateCiphertext(ciphertext);

        return GetScheme()->EvalChebyshevSeries(ciphertext, coefficients, a, b);
    }

    /**
   * Naive linear method for evaluating Chebyshev polynomial interpolation;
   * first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2
   * (x-a)/(b-a). Supported only in CKKS.
   *
   * @param cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in Chebyshev expansion
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @return the result of polynomial evaluation.
   */
    Ciphertext<Element> EvalChebyshevSeriesLinear(ConstCiphertext<Element> ciphertext,
                                                  const std::vector<double>& coefficients, double a, double b) const {
        ValidateCiphertext(ciphertext);

        return GetScheme()->EvalChebyshevSeriesLinear(ciphertext, coefficients, a, b);
    }

    /**
   * Paterson-Stockmeyer method for evaluating Chebyshev polynomial interpolation;
   * first the range [a,b] is mapped to [-1,1] using linear transformation 1 + 2
   * (x-a)/(b-a). Supported only in CKKS.
   *
   * @param cipherText input ciphertext
   * @param &coefficients is the vector of coefficients in Chebyshev expansion
   * @param a - lower bound of argument for which the coefficients were found
   * @param b - upper bound of argument for which the coefficients were found
   * @return the result of polynomial evaluation.
   */
    Ciphertext<Element> EvalChebyshevSeriesPS(ConstCiphertext<Element> ciphertext,
                                              const std::vector<double>& coefficients, double a, double b) const {
        ValidateCiphertext(ciphertext);

        return GetScheme()->EvalChebyshevSeriesPS(ciphertext, coefficients, a, b);
    }

    /**
   * Method for calculating Chebyshev evaluation on a ciphertext for a smooth input
   * function over the range [a,b]. Supported only in CKKS.
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
   * Supported only in CKKS.
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
   * Supported only in CKKS.
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
   * Supported only in CKKS.
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
   * Supported only in CKKS.
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
   * EvalSumKeyGen Generates the key map to be used by EvalSum
   *
   * @param privateKey private key.
   * @param publicKey public key (used in NTRU schemes).
   */
    void EvalSumKeyGen(const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey = nullptr);

    // [[deprecated("Use EvalSumKeyGen(const PrivateKey<Element> privateKey) instead.")]] void EvalSumKeyGen(
    //     const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) {
    //     std::string errMsg("This API is deprecated. use EvalSumKeyGen(const PrivateKey<Element> privateKey)");
    //     OPENFHE_THROW( errMsg);
    // }

    /**
   * Generate the automorphism keys for EvalSumRows; works
   * only for packed encoding
   *
   * @param privateKey private key.
   * @param publicKey public key.
   * @param rowSize size of rows in the matrix
   * @param subringDim subring dimension (set to cyclotomic order if set to 0)
   * @return returns the evaluation keys
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumRowsKeyGen(const PrivateKey<Element> privateKey,
                                                                         const PublicKey<Element> publicKey = nullptr,
                                                                         usint rowSize = 0, usint subringDim = 0);

    // [[deprecated(
    //     "Use EvalSumRowKeyGen(const PrivateKey<Element> privateKey, usint rowSize = 0, usint subringDim = 0) instead.")]] std::
    //     shared_ptr<std::map<usint, EvalKey<Element>>>
    //     EvalSumRowsKeyGen(const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey, usint rowSize = 0,
    //                       usint subringDim = 0) {
    //     std::string errMsg(
    //         "This API is deprecated. use EvalSumRowsKeyGen(const PrivateKey<Element> privateKey, usint rowSize = 0, usint subringDim = 0)");
    //     OPENFHE_THROW( errMsg);
    // }

    /**
   * Generates the automorphism keys for EvalSumCols; works
   * only for packed encoding
   *
   * @param privateKey private key.
   * @param publicKey public key.
   * @return returns the evaluation keys
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumColsKeyGen(const PrivateKey<Element> privateKey,
                                                                         const PublicKey<Element> publicKey = nullptr);

    // [[deprecated("Use EvalSumColsKeyGen(const PrivateKey<Element> privateKey) instead.")]] std::shared_ptr<
    //     std::map<usint, EvalKey<Element>>>
    // EvalSumColsKeyGen(const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) {
    //     std::string errMsg("This API is deprecated. use EvalSumColsKeyGen(const PrivateKey<Element> privateKey)");
    //     OPENFHE_THROW( errMsg);
    // }

    // std::shared_ptr<std::map<usint, EvalKey<Element>>> EvalSumColsKeyGen(const PrivateKey<Element> privateKey);

    /**
   * Function for evaluating a sum of all components in a vector.
   *
   * @param ciphertext the input ciphertext.
   * @param batchSize size of the batch
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalSum(ConstCiphertext<Element> ciphertext, usint batchSize) const;

    /**
   * Sums all elements over row-vectors in a matrix - works only with packed
   * encoding
   *
   * @param ciphertext the input ciphertext.
   * @param numRows number of rows in the matrix
   * @param &evalSumKeyMap - reference to the map of evaluation keys generated by
   * @param subringDim the current cyclotomic order/subring dimension. If set to
   * 0, we use the full cyclotomic order.
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalSumRows(ConstCiphertext<Element> ciphertext, usint numRows,
                                    const std::map<usint, EvalKey<Element>>& evalSumKeyMap, usint subringDim = 0) const;

    /**
   * Sums all elements over column-vectors in a matrix - works only with packed
   * encoding
   *
   * @param ciphertext the input ciphertext.
   * @param numCols number of columns in the matrix
   * @param &evalSumKeyMap - reference to the map of evaluation keys generated by
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalSumCols(ConstCiphertext<Element> ciphertext, usint numCols,
                                    const std::map<usint, EvalKey<Element>>& evalSumKeyMap) const;

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL INNER PRODUCT
    //------------------------------------------------------------------------------

    /**
   * Evaluates inner product in packed encoding (uses EvalSum)
   *
   * @param ciphertext1 first vector.
   * @param ciphertext2 second vector.
   * @param batchSize size of the batch to be summed up
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element> ciphertext1, ConstCiphertext<Element> ciphertext2,
                                         usint batchSize) const;

    /**
   * Evaluates inner product in packed encoding (uses EvalSum)
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
   * ciphertext. The slot assignment is done based on the order of ciphertexts in
   * the vector. Requires the generation of rotation keys for the indices that are needed.
   *
   * @param ciphertextVector vector of ciphertexts to be merged.
   * @return resulting ciphertext
   */
    Ciphertext<Element> EvalMerge(const std::vector<Ciphertext<Element>>& ciphertextVec) const;

    //------------------------------------------------------------------------------
    // PRE Wrapper
    //------------------------------------------------------------------------------

    /**
   * ReKeyGen produces an Eval Key that OpenFHE can use for Proxy Re-Encryption
   * @param oldPrivateKey original secret key
   * @param newPublicKey public key for the new secret key
   * @return new evaluation key
   */
    EvalKey<Element> ReKeyGen(const PrivateKey<Element> oldPrivateKey, const PublicKey<Element> newPublicKey) const {
        ValidateKey(oldPrivateKey);
        ValidateKey(newPublicKey);

        return GetScheme()->ReKeyGen(oldPrivateKey, newPublicKey);
    }

    /**
   * ReKeyGen produces an Eval Key that OpenFHE can use for Proxy Re-Encryption
   * NOTE this functionality has been completely removed from OpenFHE
   * @param oldPrivateKey original secret key
   * @param newPrivateKey new secret key
   * @return new evaluation key
   */
    EvalKey<Element> ReKeyGen(const PrivateKey<Element> originalPrivateKey,
                              const PrivateKey<Element> newPrivateKey) const
        __attribute__((deprecated("functionality removed from OpenFHE")));

    /**
   * ReEncrypt - Proxy Re-Encryption mechanism for OpenFHE
   * @param ciphertext - input ciphertext
   * @param evalKey - evaluation key from the PRE keygen method
   * @param publicKey the public key of the recipient of the re-encrypted
   * ciphertext.
   * @return the resulting ciphertext
   */
    Ciphertext<Element> ReEncrypt(ConstCiphertext<Element> ciphertext, EvalKey<Element> evalKey,
                                  const PublicKey<Element> publicKey = nullptr) const {
        ValidateCiphertext(ciphertext);
        ValidateKey(evalKey);

        return GetScheme()->ReEncrypt(ciphertext, evalKey, publicKey);
    }

    //------------------------------------------------------------------------------
    // Multiparty Wrapper
    //------------------------------------------------------------------------------

    /**
   * Threshold FHE: Generates a public key from a vector of secret shares.
   * ONLY FOR DEBUGGIN PURPOSES. SHOULD NOT BE USED IN PRODUCTION.
   *
   * @param &privateKeyVec secrete key shares.
   * @return key pair including the private for the current party and joined
   * public key
   */
    KeyPair<Element> MultipartyKeyGen(const std::vector<PrivateKey<Element>>& privateKeyVec) {
        if (!privateKeyVec.size())
            OPENFHE_THROW("Input private key vector is empty");
        return GetScheme()->MultipartyKeyGen(GetContextForPointer(this), privateKeyVec, false);
    }

    /**
   * Threshold FHE: Generation of a public key derived
   * from a previous joined public key (for prior secret shares) and the secret
   * key share of the current party.
   *
   * @param publicKey joined public key from prior parties.
   * @param makeSparse set to true if ring reduce by a factor of 2 is to be
   * used. NOT SUPPORTED BY ANY SCHEME ANYMORE.
   * @param fresh set to true if proxy re-encryption is used in the multi-party
   * protocol or star topology is used
   * @return key pair including the secret share for the current party and
   * joined public key
   */
    KeyPair<Element> MultipartyKeyGen(const PublicKey<Element> publicKey, bool makeSparse = false, bool fresh = false) {
        if (!publicKey)
            OPENFHE_THROW("Input public key is empty");
        return GetScheme()->MultipartyKeyGen(GetContextForPointer(this), publicKey, makeSparse, fresh);
    }

    /**
   * Threshold FHE: Method for decryption operation run by the lead decryption
   * client
   *
   * @param &ciphertextVec a vector of ciphertexts
   * @param privateKey secret key share used for decryption.
   * @returm vector of partially decrypted ciphertexts.
   */
    std::vector<Ciphertext<Element>> MultipartyDecryptLead(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                           const PrivateKey<Element> privateKey) const {
        ValidateKey(privateKey);

        std::vector<Ciphertext<Element>> newCiphertextVec;
        for (const auto& ciphertext : ciphertextVec) {
            ValidateCiphertext(ciphertext);
            newCiphertextVec.push_back(GetScheme()->MultipartyDecryptLead(ciphertext, privateKey));
        }

        return newCiphertextVec;
    }

    /**
   * Threshold FHE: "Partial" decryption computed by all parties except for the
   * lead one
   *
   * @param &ciphertextVec a vector of ciphertexts
   * @param privateKey secret key share used for decryption.
   * @returm vector of partially decrypted ciphertexts.
   */
    std::vector<Ciphertext<Element>> MultipartyDecryptMain(const std::vector<Ciphertext<Element>>& ciphertextVec,
                                                           const PrivateKey<Element> privateKey) const {
        ValidateKey(privateKey);

        std::vector<Ciphertext<Element>> newCiphertextVec;
        for (const auto& ciphertext : ciphertextVec) {
            ValidateCiphertext(ciphertext);
            newCiphertextVec.push_back(GetScheme()->MultipartyDecryptMain(ciphertext, privateKey));
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
    DecryptResult MultipartyDecryptFusion(const std::vector<Ciphertext<Element>>& partialCiphertextVec,
                                          Plaintext* plaintext) const {
        std::string datatype = demangle(typeid(Element).name());
        OPENFHE_THROW(std::string(__func__) + " is not implemented for " + datatype);
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
            OPENFHE_THROW("Input first private key is nullptr");
        if (!newPrivateKey)
            OPENFHE_THROW("Input second private key is nullptr");
        if (!evalKey)
            OPENFHE_THROW("Input evaluation key is nullptr");

        return GetScheme()->MultiKeySwitchGen(originalPrivateKey, newPrivateKey, evalKey);
    }

    /**
   * Threshold FHE: Generates joined automorphism keys
   * from the current secret share and prior joined
   * automorphism keys
   *
   * @param privateKey secret key share.
   * @param evalKeyMap a dictionary with prior joined automorphism keys.
   * @param &indexList a vector of automorphism indices.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return a dictionary with new joined automorphism keys.
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalAutomorphismKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap,
        const std::vector<usint>& indexList, const std::string& keyId = "") {
        if (!privateKey)
            OPENFHE_THROW("Input private key is nullptr");
        if (!evalKeyMap)
            OPENFHE_THROW("Input evaluation key map is nullptr");
        if (!indexList.size())
            OPENFHE_THROW("Input index vector is empty");

        return GetScheme()->MultiEvalAutomorphismKeyGen(privateKey, evalKeyMap, indexList, keyId);
    }

    /**
   * Threshold FHE: Generates joined rotation keys
   * from the current secret share and prior joined
   * rotation keys
   *
   * @param privateKey secret key share.
   * @param evalKeyMap a dictionary with prior joined rotation keys.
   * @param &indexList a vector of rotation indices.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return a dictionary with new joined rotation keys.
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalAtIndexKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap,
        const std::vector<int32_t>& indexList, const std::string& keyId = "") {
        if (!privateKey)
            OPENFHE_THROW("Input private key is nullptr");
        if (!evalKeyMap)
            OPENFHE_THROW("Input evaluation key map is nullptr");
        if (!indexList.size())
            OPENFHE_THROW("Input index vector is empty");

        return GetScheme()->MultiEvalAtIndexKeyGen(privateKey, evalKeyMap, indexList, keyId);
    }

    /**
   * Threshold FHE: Generates joined summation evaluation keys
   * from the current secret share and prior joined
   * summation keys
   *
   * @param privateKey secret key share.
   * @param evalKeyMap a dictionary with prior joined summation keys.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return new joined summation keys.
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiEvalSumKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap,
        const std::string& keyId = "") {
        if (!privateKey)
            OPENFHE_THROW("Input private key is nullptr");
        if (!evalKeyMap)
            OPENFHE_THROW("Input evaluation key map is nullptr");
        return GetScheme()->MultiEvalSumKeyGen(privateKey, evalKeyMap, keyId);
    }

    /**
   * Threshold FHE: Adds two prior evaluation keys
   *
   * @param evalKey1 first evaluation key.
   * @param evalKey2 second evaluation key.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return the new joined key.
   */
    EvalKey<Element> MultiAddEvalKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2,
                                      const std::string& keyId = "") {
        if (!evalKey1)
            OPENFHE_THROW("Input first evaluation key is nullptr");
        if (!evalKey2)
            OPENFHE_THROW("Input second evaluation key is nullptr");

        return GetScheme()->MultiAddEvalKeys(evalKey1, evalKey2, keyId);
    }

    /**
   * Threshold FHE: Generates a partial evaluation key for homomorphic
   * multiplication based on the current secret share and an existing partial
   * evaluation key
   *
   * @param privateKey current secret share.
   * @param evalKey prior evaluation key.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return the new joined key.
   */
    EvalKey<Element> MultiMultEvalKey(PrivateKey<Element> privateKey, EvalKey<Element> evalKey,
                                      const std::string& keyId = "") {
        if (!privateKey)
            OPENFHE_THROW("Input private key is nullptr");
        if (!evalKey)
            OPENFHE_THROW("Input evaluation key is nullptr");

        return GetScheme()->MultiMultEvalKey(privateKey, evalKey, keyId);
    }

    /**
   * Threshold FHE: Adds two prior evaluation key sets for summation
   *
   * @param evalKeyMap1 first summation key set.
   * @param evalKeyMap2 second summation key set.
   * @param keyId - new key identifier used for the resulting evaluation key
   * @return the new joined key set for summation.
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiAddEvalSumKeys(
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap1,
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap2, const std::string& keyId = "") {
        if (!evalKeyMap1)
            OPENFHE_THROW("Input first evaluation key map is nullptr");
        if (!evalKeyMap2)
            OPENFHE_THROW("Input second evaluation key map is nullptr");

        return GetScheme()->MultiAddEvalSumKeys(evalKeyMap1, evalKeyMap2, keyId);
    }

    /**
   * Threshold FHE: Adds two prior evaluation key sets for automorphisms
   *
   * @param evalKeyMap1 first automorphism key set.
   * @param evalKeyMap2 second automorphism key set.
   * @param keyId - new key identifier used for the resulting evaluation key.
   * @return the new joined key set for summation.
   */
    std::shared_ptr<std::map<usint, EvalKey<Element>>> MultiAddEvalAutomorphismKeys(
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap1,
        const std::shared_ptr<std::map<usint, EvalKey<Element>>> evalKeyMap2, const std::string& keyId = "") {
        if (!evalKeyMap1)
            OPENFHE_THROW("Input first evaluation key map is nullptr");
        if (!evalKeyMap2)
            OPENFHE_THROW("Input second evaluation key map is nullptr");

        return GetScheme()->MultiAddEvalAutomorphismKeys(evalKeyMap1, evalKeyMap2, keyId);
    }

    /**
   * Threshold FHE: Adds two  partial public keys
   *
   * @param publicKey1 first public key.
   * @param publicKey2 second public key.
   * @param keyId - new key identifier used for the resulting evaluation key.
   * @return the new joined key.
   */
    PublicKey<Element> MultiAddPubKeys(PublicKey<Element> publicKey1, PublicKey<Element> publicKey2,
                                       const std::string& keyId = "") {
        if (!publicKey1)
            OPENFHE_THROW("Input first public key is nullptr");
        if (!publicKey2)
            OPENFHE_THROW("Input second public key is nullptr");

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
            OPENFHE_THROW("Input first evaluation key is nullptr");
        if (!evalKey2)
            OPENFHE_THROW("Input second evaluation key is nullptr");

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
                                                      ConstCiphertext<Element> ciphertext,
                                                      ConstCiphertext<Element> a) const;

    /**
    * Threshold FHE: Aggregates a vector of masked decryptions and re-encryotion shares,
    * which is the second step of the interactive multiparty bootstrapping procedure.
    *
    * @param sharesPairVec: vector of pair of ciphertexts, each element of this vector contains
    * (h_0i, h_1i) - the masked-decryption and encryption shares ofparty i
    * @return: aggregated pair of shares ((h_0, h_1)
    */
    std::vector<Ciphertext<Element>> IntMPBootAdd(std::vector<std::vector<Ciphertext<Element>>>& sharesPairVec) const;

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
    Ciphertext<Element> IntMPBootEncrypt(const PublicKey<Element> publicKey,
                                         const std::vector<Ciphertext<Element>>& sharesPair, ConstCiphertext<Element> a,
                                         ConstCiphertext<Element> ciphertext) const;

    /**
   * Threshold FHE with aborts: secret sharing of secret key for aborts
   *
   * @param &sk secret key to be shared.
   * @param N total number of parties.
   * @param threshold - threshold number of parties.
   * @param index - index of the party invoking the function.
   * @param shareType - Type of secret sharing to be used - additive or shamir sharing.
   * @return the secret shares of the secret key sk.
   */
    std::unordered_map<uint32_t, Element> ShareKeys(const PrivateKey<Element>& sk, usint N, usint threshold,
                                                    usint index, const std::string& shareType) const {
        std::string datatype = demangle(typeid(Element).name());
        OPENFHE_THROW(std::string(__func__) + " is not implemented for " + datatype);
    }

    /**
   * Threshold FHE with aborts: Recovers a secret key share from other existing secret shares.
   *
   * @param &sk secret recovered from the secret shares.
   * @param &sk_shares secret shares.
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
   * 3. EvalBootstrapPrecompute: computes and stores the plaintexts for encoding and decoding if not already done in EvalBootstrapSetup
   * 4. EvalBootstrap: refreshes the given ciphertext
   */

    /**
   * Sets all parameters for both linear  and FFT-like methods. Supported in CKKS only.
   *
   * @param levelBudget - vector of budgets for the amount of levels in encoding
   * and decoding
   * @param dim1 - vector of inner dimension in the baby-step giant-step routine
   * for encoding and decoding
   * @param slots - number of slots to be bootstrapped
   * @param correctionFactor - value to internally rescale message by to improve precision of bootstrapping. If set to 0, we use the default logic. This value is only used when NATIVE_SIZE=64
   * @param precompute - flag specifying whether to precompute the plaintexts for encoding and decoding.
   */
    void EvalBootstrapSetup(std::vector<uint32_t> levelBudget = {5, 4}, std::vector<uint32_t> dim1 = {0, 0},
                            uint32_t slots = 0, uint32_t correctionFactor = 0, bool precompute = true) {
        GetScheme()->EvalBootstrapSetup(*this, levelBudget, dim1, slots, correctionFactor, precompute);
    }
    /**
   * Generates all automorphism keys for EvalBootstrap. Supported in CKKS only.
   * EvalBootstrapKeyGen uses the baby-step/giant-step strategy.
   *
   * @param privateKey private key.
   * @param slots number of slots to support permutations on
   */
    void EvalBootstrapKeyGen(const PrivateKey<Element> privateKey, uint32_t slots) {
        ValidateKey(privateKey);

        auto evalKeys = GetScheme()->EvalBootstrapKeyGen(privateKey, slots);

        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, privateKey->GetKeyTag());
    }
    /**
   * Computes the plaintexts for encoding and decoding for both linear and FFT-like methods. Supported in CKKS only.
   *
   * @param slots - number of slots to be bootstrapped
   */
    void EvalBootstrapPrecompute(uint32_t slots = 0) {
        GetScheme()->EvalBootstrapPrecompute(*this, slots);
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
   * @param params objects holding all necessary paramters
   * @return the FHEW secret key
   * TODO: add an overload for when BinFHEContext is already generated and fed as a parameter
   */
    LWEPrivateKey EvalCKKStoFHEWSetup(SchSwchParams params) {
        VerifyCKKSScheme(__func__);
        SetParamsFromCKKSCryptocontext(params);
        return GetScheme()->EvalCKKStoFHEWSetup(params);
    }

    /**
   * Generates all keys for scheme switching: the rotation keys for the linear transform in the homomorphic decoding,
   * conjugation keys, switching key from CKKS to FHEW
   *
   * @param keypair CKKS key pair
   * @param lwesk FHEW secret key
   */
    void EvalCKKStoFHEWKeyGen(const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk) {
        VerifyCKKSScheme(__func__);
        ValidateKey(keyPair.secretKey);
        if (!lwesk) {
            OPENFHE_THROW("FHEW private key passed to EvalCKKStoFHEWKeyGen is null");
        }
        auto evalKeys = GetScheme()->EvalCKKStoFHEWKeyGen(keyPair, lwesk);
        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, keyPair.secretKey->GetKeyTag());
    }

    /**
   * Performs precomputations for the homomorphic decoding in CKKS. Given as a separate method than EvalCKKStoFHEWSetup
   * to allow the user to specify a scale that depends on the CKKS and FHEW cryptocontexts
   *
   * @param scale factor with which to scale the matrix in the linear transform
   */
    void EvalCKKStoFHEWPrecompute(double scale = 1.0) {
        VerifyCKKSScheme(__func__);
        GetScheme()->EvalCKKStoFHEWPrecompute(*this, scale);
    }

    /**
   * Performs the scheme switching on a CKKS ciphertext
   *
   * @param ciphertext CKKS ciphertext to switch
   * @param numCtxts number of coefficients to extract from the CKKS ciphertext. If it is zero, it defaults to number of slots
   * @return a vector of LWE ciphertexts of length the numCtxts
   */
    std::vector<std::shared_ptr<LWECiphertextImpl>> EvalCKKStoFHEW(ConstCiphertext<Element> ciphertext,
                                                                   uint32_t numCtxts = 0) {
        VerifyCKKSScheme(__func__);
        if (ciphertext == nullptr)
            OPENFHE_THROW("ciphertext passed to EvalCKKStoFHEW is empty");
        return GetScheme()->EvalCKKStoFHEW(ciphertext, numCtxts);
    }

    /**
   * Sets all parameters for switching from FHEW to CKKS. The CKKS cryptocontext to switch to is
   * already generated.
   *
   * @param ccLWE the FHEW cryptocontext from which to switch
   * @param numSlotsCKKS number of FHEW ciphertexts that becomes the number of slots in CKKS encryption
   * @param logQ size of ciphertext modulus in FHEW for large-precision evaluation
   */
    void EvalFHEWtoCKKSSetup(const std::shared_ptr<BinFHEContext>& ccLWE, uint32_t numSlotsCKKS = 0,
                             uint32_t logQ = 25) {
        VerifyCKKSScheme(__func__);
        GetScheme()->EvalFHEWtoCKKSSetup(*this, ccLWE, numSlotsCKKS, logQ);
    }

    /**
   * Generates all keys for scheme switching: the rotation keys for the baby-step/giant-step strategy
   * in the linear transform for the partial decryption, the switching key from FHEW to CKKS
   *
   * @param keypair CKKS key pair
   * @param lwesk FHEW secret key
   * @param numSlots number of slots for the CKKS encryption of the FHEW secret key
   * @param numCtxts number of values to encrypt from the LWE ciphertexts in the new CKKS ciphertext
   * @param dim1 baby-step for the linear transform
   * @param L level on which the hom. decoding matrix should be. We want the hom. decoded ciphertext to be on the last level
   */
    void EvalFHEWtoCKKSKeyGen(const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t numSlots = 0,
                              uint32_t numCtxts = 0, uint32_t dim1 = 0, uint32_t L = 0) {
        VerifyCKKSScheme(__func__);
        ValidateKey(keyPair.secretKey);

        auto evalKeys = GetScheme()->EvalFHEWtoCKKSKeyGen(keyPair, lwesk, numSlots, numCtxts, dim1, L);
        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, keyPair.secretKey->GetKeyTag());
    }

    /**
   * Performs the scheme switching on a vector of FHEW ciphertexts
   *
   * @param LWECiphertexts FHEW/LWE ciphertexts to switch
   * @param numCtxts number of values to encrypt from the LWE ciphertexts in the new CKKS ciphertext
   * @param numSlots number of slots to use in the encoding in the new CKKS/RLWE ciphertext
   * @param p plaintext modulus to use to decide postscaling, by default p = 4
   * @param pmin, pmax plaintext space of the resulting messages (by default [0,2] assuming
   * the LWE ciphertext had plaintext modulus p = 4 and only bits were encrypted)
   * @param dim1 baby-step for the linear transform, necessary only for argmin
   * @return a CKKS ciphertext encrypting in its slots the messages in the LWE ciphertexts
   */
    Ciphertext<Element> EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                       uint32_t numCtxts = 0, uint32_t numSlots = 0, uint32_t p = 4, double pmin = 0.0,
                                       double pmax = 2.0, uint32_t dim1 = 0) const {
        VerifyCKKSScheme(__func__);
        return GetScheme()->EvalFHEWtoCKKS(LWECiphertexts, numCtxts, numSlots, p, pmin, pmax, dim1);
    }

    /**
   * Gets data from CKKS cryptocontext to set some parameters for scheme switching
   */
    void SetParamsFromCKKSCryptocontext(SchSwchParams& params) {
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(GetCryptoParameters());
        if (!cryptoParams) {
            OPENFHE_THROW("std::dynamic_pointer_cast<CryptoParametersCKKSRNS>() failed");
        }
        params.SetInitialCKKSModulus(cryptoParams->GetElementParams()->GetParams()[0]->GetModulus());
        params.SetRingDimension(GetRingDimension());
        // TODO (dsuponit): is this correct - PlaintextModulus used as scalingModSize?
        params.SetScalingModSize(GetEncodingParams()->GetPlaintextModulus());
        params.SetBatchSize(GetEncodingParams()->GetBatchSize());

        params.SetParamsFromCKKSCryptocontextCalled();
    }

    /**
   * Sets all parameters for switching from CKKS to FHEW and back
   *
   * @param params objects holding all necessary paramters
   * @return the FHEW secret key
   * TODO: add an overload for when BinFHEContext is already generated and fed as a parameter
   */
    LWEPrivateKey EvalSchemeSwitchingSetup(SchSwchParams& params) {
        VerifyCKKSScheme(__func__);
        SetParamsFromCKKSCryptocontext(params);
        return GetScheme()->EvalSchemeSwitchingSetup(params);
    }

    /**
   * Generates all keys for scheme switching: the rotation keys for the linear transform for the homomorphic encoding
   * and partial decryption, the switching key from FHEW to CKKS
   *
   * @param keypair CKKS key pair
   * @param lwesk FHEW secret key
   */
    void EvalSchemeSwitchingKeyGen(const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk) {
        VerifyCKKSScheme(__func__);
        ValidateKey(keyPair.secretKey);

        auto evalKeys = GetScheme()->EvalSchemeSwitchingKeyGen(keyPair, lwesk);
        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, keyPair.secretKey->GetKeyTag());
    }

    /**
   * Performs precomputations for the homomorphic decoding in CKKS. Given as a separate method than EvalSchemeSwitchingSetup
   * to allow the user to specify a scale that depends on the CKKS and FHEW cryptocontexts
   *
   * @param pLWE the desired plaintext modulus for the new FHEW ciphertexts
   * @param scaleSign factor to multiply the CKKS ciphertext when switching to FHEW in case the messages are too small;
   * the resulting FHEW ciphertexts will encrypt values modulo pLWE, so scaleSign should account for this
   * @param unit whether the input messages are normalized to the unit circle
   */
    void EvalCompareSwitchPrecompute(uint32_t pLWE = 0, double scaleSign = 1.0, bool unit = false) {
        VerifyCKKSScheme(__func__);
        GetScheme()->EvalCompareSwitchPrecompute(*this, pLWE, scaleSign, unit);
    }

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
                                                   bool unit = false) {
        VerifyCKKSScheme(__func__);
        ValidateCiphertext(ciphertext1);
        ValidateCiphertext(ciphertext2);

        return GetScheme()->EvalCompareSchemeSwitching(ciphertext1, ciphertext2, numCtxts, numSlots, pLWE, scaleSign,
                                                       unit);
    }

    /**
   * Computes the minimum and argument of the first numValues packed in a CKKS ciphertext via repeated
   * scheme switchings to FHEW and back.
   *
   * @param ciphertext CKKS ciphertexts of values that need to be compared
   * @param publicKey public key of the CKKS cryptocontext
   * @param numValues number of values to extract from the CKKS ciphertext. We always assume for the moment numValues is a power of two
   * @param numSlots number of slots to encode the new CKKS ciphertext with
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
                                                            uint32_t numSlots = 0, uint32_t pLWE = 0,
                                                            double scaleSign = 1.0) {
        VerifyCKKSScheme(__func__);
        ValidateCiphertext(ciphertext);

        return GetScheme()->EvalMinSchemeSwitching(ciphertext, publicKey, numValues, numSlots, pLWE, scaleSign);
    }

    /**
     * Same as EvalMinSchemeSwitching but performs more operations in FHEW than in CKKS. Slightly better precision but slower.
    */
    std::vector<Ciphertext<Element>> EvalMinSchemeSwitchingAlt(ConstCiphertext<Element> ciphertext,
                                                               PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                               uint32_t numSlots = 0, uint32_t pLWE = 0,
                                                               double scaleSign = 1.0) {
        VerifyCKKSScheme(__func__);
        ValidateCiphertext(ciphertext);

        return GetScheme()->EvalMinSchemeSwitchingAlt(ciphertext, publicKey, numValues, numSlots, pLWE, scaleSign);
    }

    /**
   * Computes the maximum and argument of the first numValues packed in a CKKS ciphertext via repeated
   * scheme switchings to FHEW and back.
   *
   * @param ciphertext CKKS ciphertexts of values that need to be compared
   * @param publicKey public key of the CKKS cryptocontext
   * @param numValues number of values to extract from the CKKS ciphertext. We always assume for the moment numValues is a power of two
   * @param numSlots number of slots to encode the new CKKS ciphertext with
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
                                                            uint32_t numSlots = 0, uint32_t pLWE = 0,
                                                            double scaleSign = 1.0) {
        VerifyCKKSScheme(__func__);
        ValidateCiphertext(ciphertext);

        return GetScheme()->EvalMaxSchemeSwitching(ciphertext, publicKey, numValues, numSlots, pLWE, scaleSign);
    }

    /**
     * Same as EvalMaxSchemeSwitching but performs more operations in FHEW than in CKKS. Slightly better precision but slower.
    */
    std::vector<Ciphertext<Element>> EvalMaxSchemeSwitchingAlt(ConstCiphertext<Element> ciphertext,
                                                               PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                               uint32_t numSlots = 0, uint32_t pLWE = 0,
                                                               double scaleSign = 1.0) {
        VerifyCKKSScheme(__func__);
        ValidateCiphertext(ciphertext);

        return GetScheme()->EvalMaxSchemeSwitchingAlt(ciphertext, publicKey, numValues, numSlots, pLWE, scaleSign);
    }

    /* Getter and setter for the binFHE cryptocontext used in scheme switching
    */
    std::shared_ptr<lbcrypto::BinFHEContext> GetBinCCForSchemeSwitch() {
        return GetScheme()->GetBinCCForSchemeSwitch();
    }
    void SetBinCCForSchemeSwitch(std::shared_ptr<lbcrypto::BinFHEContext> ccLWE) {
        GetScheme()->SetBinCCForSchemeSwitch(ccLWE);
    }
    /* Getter and setter for the switching key between FHEW and CKKS
    */
    Ciphertext<Element> GetSwkFC() {
        return GetScheme()->GetSwkFC();
    }
    void SetSwkFC(Ciphertext<Element> FHEWtoCKKSswk) {
        GetScheme()->SetSwkFC(FHEWtoCKKSswk);
    }

    /**
     * @brief GetExistingEvalAutomorphismKeyIndices gets indices for all existing automorphism keys
     * @param keyTag map search id for the automorphism keys
     * @return vector with all indices in the map. if nothing is found for the given keyTag, then the vector is empty
     **/
    static std::set<uint32_t> GetExistingEvalAutomorphismKeyIndices(const std::string& keyTag);

    /**
     * @brief GetUniqueValues compares 2 sets to generate a set with unique values from the 2nd set
     * @param oldValues set of integers to compare against (passed by value)
     * @param newValues set of integers to find unique values from  (passed by value)
     * @return set with the unique values from newValues
     **/
    static std::set<uint32_t> GetUniqueValues(const std::set<uint32_t>& oldValues, const std::set<uint32_t>& newValues);

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::make_nvp("cc", params));
        ar(cereal::make_nvp("kt", scheme));
        ar(cereal::make_nvp("si", m_schemeId));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > CryptoContextImpl<Element>::SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
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
