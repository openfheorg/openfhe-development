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

#include "binfhecontext.h"

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

#include <algorithm>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef DEBUG_KEY
    #include <iostream>
#endif

namespace lbcrypto {

/**
 * @class CryptoContextImpl
 * @brief A class to simplify access to OpenFHE's PKE functionality.
 *
 * Functionality is accessed by creating an instance of CryptoContextImpl.
 * Various objects are "created" in the instance, but they can only be used with the context in which they were created.
 *
 * OpenFHE methods are accessed through CryptoContextImpl methods. Guards are implemented to make certain that
 * only valid objects that have been created in the context are used
 *
 * Contexts are created using GenCryptoContext(), and can be serialized and recovered from serialization
 */
template <typename Element>
class CryptoContextImpl : public Serializable {
    using IntType  = typename Element::Integer;
    using ParmType = typename Element::Params;

    /**
    * @brief Checks if the cryptocontext scheme is CKKS and throws an exception if it is not.
    * 
    * @param functionName the calling function name. __func__ can be used instead
    */
    inline void VerifyCKKSScheme(const std::string& functionName) const {
        if (!isCKKS(m_schemeId)) {
            std::string errMsg = std::string(functionName) + "() is available for the CKKS scheme only."
                                 " The current scheme is " + convertToString(m_schemeId);
            OPENFHE_THROW(errMsg);
        }
    }

    /**
    * @brief VerifyCKKSRealDataType Checks if the CKKS data type is real and throws an exception if it is not.
    * 
    * @param functionName the calling function name. __func__ can be used instead
    */
    inline void VerifyCKKSRealDataType(const std::string& functionName) const {
        if (GetCKKSDataType() != REAL) {
            std::string errMsg =
                "Function " + std::string(functionName) + " is available for the real CKKS data types only.";
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
    * @brief Constructs CoefPackedEncoding or PackedEncoding in this context
    * 
    * @param encoding encoding type
    * @param value the value to encode
    * @param depth the multiplicative depth to encode the plaintext at
    * @param level the level to encode the plaintext at
    * @return new plaintext
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
                    std::string errorMsg{"The level value should be less than or equal to "};
                    errorMsg +=
                        ((cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT) ? "(multiplicativeDepth + 1)." :
                                                                                    "multiplicativeDepth.");
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

        NativeInteger scf{1};
        bool setNoiseScaleDeg = false;
        auto scaleTech = cryptoParams->GetScalingTechnique();
        if (isBGVRNS(m_schemeId) && (scaleTech == FLEXIBLEAUTO || scaleTech == FLEXIBLEAUTOEXT)) {
            if (scaleTech == FLEXIBLEAUTOEXT && level == 0) {
                scf = cryptoParams->GetScalingFactorIntBig(level);
                depth = 1;
                setNoiseScaleDeg = true;
            }
            else
                scf = cryptoParams->GetScalingFactorInt(level);
        }

        Plaintext p = PlaintextFactory::MakePlaintext(value, encoding, elemParamsPtr, this->GetEncodingParams(),
                                                      getSchemeId(), depth, level, scf);
        if (setNoiseScaleDeg)
            p->SetNoiseScaleDeg(2);

        return p;
    }

    /**
    * @brief Constructs CoefPackedEncoding, PackedEncoding in this context
    * 
    * @param encoding encoding type
    * @param cc the context to create a plaintext with
    * @param value the value to encode
    * @return new plaintext
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
    * @brief Gets indices that do not have automorphism keys for the given secret key tag in the key map
    * 
    * @param keyTag secret key tag
    * @param indexList array of specific indices to check the key map against
    * @return indices that do not have automorphism keys associated with
    */
    static std::set<uint32_t> GetEvalAutomorphismNoKeyIndices(const std::string& keyTag,
                                                              const std::set<uint32_t>& indices) {
        std::set<uint32_t> existingIndices{CryptoContextImpl<Element>::GetExistingEvalAutomorphismKeyIndices(keyTag)};
        // if no index found for the given keyTag, then the entire set "indices" is returned
        return (existingIndices.empty()) ? indices :
                                           CryptoContextImpl<Element>::GetUniqueValues(existingIndices, indices);
    }

    /**
    * @brief Gets automorphism keys for a specific secret key tag and an array of specific indices
    * 
    * @param keyTag secret key tag
    * @param indexList array of specific indices to retrieve key for
    * @return shared_ptr to std::map where the map key/data pair is index/automorphism key
    */
    static std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> GetPartialEvalAutomorphismKeyMapPtr(
        const std::string& keyTag, const std::vector<uint32_t>& indexList);

    // cached evalmult keys, by secret key UID
    static std::map<std::string, std::vector<EvalKey<Element>>> s_evalMultKeyMap;
    // cached evalautomorphism keys, by secret key UID
    static std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> s_evalAutomorphismKeyMap;

protected:
    // crypto parameters
    std::shared_ptr<CryptoParametersBase<Element>> params{nullptr};
    // algorithm used; accesses all crypto methods
    std::shared_ptr<SchemeBase<Element>> scheme{nullptr};

    SCHEME m_schemeId{SCHEME::INVALID_SCHEME};

    uint32_t m_keyGenLevel{0};

    /**
    * @brief TypeCheck makes sure that an operation between two ciphertexts is permitted
    * 
    * @param a ciphertext1
    * @param b ciphertext2
    */
    void TypeCheck(ConstCiphertext<Element>& a, ConstCiphertext<Element>& b, CALLER_INFO_ARGS_HDR) const {
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
    * @brief TypeCheck makes sure that an operation between a ciphertext and a plaintext is permitted
    * 
    * @param a ciphertext
    * @param b plaintext
    */
    void TypeCheck(ConstCiphertext<Element>& a, const ConstPlaintext& b, CALLER_INFO_ARGS_HDR) const {
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
        return a.get() != this;
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

    void ValidateCiphertext(ConstCiphertext<Element>& ciphertext, CALLER_INFO_ARGS_HDR) const {
        if (ciphertext == nullptr) {
            std::string errorMsg(std::string("Ciphertext is nullptr") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
        if (Mismatched(ciphertext->GetCryptoContext())) {
            std::string errorMsg(std::string("Ciphertext was not generated with the same crypto context") + CALLER_INFO);
            OPENFHE_THROW(errorMsg);
        }
    }

    virtual Plaintext MakeCKKSPackedPlaintextInternal(const std::vector<std::complex<double>>& value,
                                                      size_t noiseScaleDeg, uint32_t level,
                                                      const std::shared_ptr<ParmType> params, uint32_t slots) const {
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
            // In FLEXIBLEAUTOEXT mode at level 0, we don't use the noiseScaleDeg in our encoding function,
            // so we set it to 1 to make sure it has no effect on the encoding.
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
            uint32_t ringDim = elemParamsPtr->GetRingDimension();
            size_t valueSize = value.size();
            if (valueSize > ringDim / 2) {
                OPENFHE_THROW("The size [" + std::to_string(valueSize) +
                              "] of the vector with values should not be greater than ringDim/2 [" +
                              std::to_string(ringDim / 2) + "] if the scheme is CKKS");
            }
            // TODO (dsuponit): we should call a version of MakePlaintext instead of calling Plaintext() directly here
            p = Plaintext(std::make_shared<CKKSPackedEncoding>(elemParamsPtr, this->GetEncodingParams(), value,
                                                               noiseScaleDeg, level, scFact, slots,
                                                               this->GetCKKSDataType()));
        }
        else {
            // Check if plaintext has got enough slots for data (value)
            uint32_t ringDim = params->GetRingDimension();
            size_t valueSize = value.size();
            if (valueSize > ringDim / 2) {
                OPENFHE_THROW("The size [" + std::to_string(valueSize) +
                              "] of the vector with values should not be greater than ringDim/2 [" +
                              std::to_string(ringDim / 2) + "] if the scheme is CKKS");
            }
            // TODO (dsuponit): we should call a version of MakePlaintext instead of calling Plaintext() directly here
            p = Plaintext(std::make_shared<CKKSPackedEncoding>(params, this->GetEncodingParams(), value, noiseScaleDeg,
                                                               level, scFact, slots, this->GetCKKSDataType()));
        }
        p->Encode();

        // In FLEXIBLEAUTOEXT mode, a fresh plaintext at level 0 always has noiseScaleDeg 2.
        if (cryptoParams->GetScalingTechnique() == FLEXIBLEAUTOEXT && level == 0) {
            p->SetNoiseScaleDeg(2);
        }
        return p;
    }

    /**
    * @brief Getter for composite degree of the current scheme crypto context.
    * @return integer value corresponding to composite degree
    */
    uint32_t GetCompositeDegreeFromCtxt() const {
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(params);
        if (!cryptoParams) {
            std::string errorMsg(std::string("std::dynamic_pointer_cast<CryptoParametersRNS>() failed"));
            OPENFHE_THROW(errorMsg);
        }

        return cryptoParams->GetCompositeDegree();
    }

#ifdef DEBUG_KEY
    PrivateKey<Element> privateKey;
#endif

public:
#ifdef DEBUG_KEY
    /**
    * SetPrivateKey() stores the private key in the crypto context.
    * GetPrivateKey() gets the private key from the crypto context.
    * 
    * Thees functions are only intended for debugging and should not be used in production systems.
    * Please define DEBUG_KEY in openfhe.h to enable them.
    *
    * If used, one can create a key pair and store the secret key in the crypto context like this:
    *
    * auto keys = cc->KeyGen();
    * cc->SetPrivateKey(keys.secretKey);
    *
    * After that, anyone in the code can access the secret key by getting the crypto context and doing the following:
    *
    * auto sk = cc->GetPrivateKey();
    *
    * The key can be used for decrypting any intermediate ciphertexts for debugging purposes.
    */
    void SetPrivateKey(const PrivateKey<Element> privateKey) {
        std::cerr << "Warning - SetPrivateKey is only intended to be used for debugging "
                     "purposes - not for production systems."
                  << std::endl;
        this->privateKey = privateKey;
    }

    const PrivateKey<Element>& GetPrivateKey() const {
        return this->privateKey;
    }
#endif

    void setSchemeId(SCHEME schemeTag) {
        this->m_schemeId = schemeTag;
    }

    SCHEME getSchemeId() const {
        return this->m_schemeId;
    }

    /**
    * @brief Constructor from raw pointers to parameters and scheme
    * 
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
    * @brief Constructor from shared pointers to parameters and scheme
    * 
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
    * @brief Copy constructor
    * @param other cryptocontext to copy from
    */
    CryptoContextImpl(const CryptoContextImpl<Element>& other) {
        params        = other.params;
        scheme        = other.scheme;
        m_keyGenLevel = 0;
        m_schemeId    = other.m_schemeId;
    }

    /**
    * @brief Assignment operator
    * @param rhs cryptocontext to assign values from
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
    * @brief Checks the CryptoContextImpl object health.
    * @return true if params and scheme exists in the object
    */
    operator bool() const {
        return params && scheme;
    }

    /**
    * @brief Equality comparison operator
    * 
    * @param a cryptocontext object1
    * @param b cryptocontext object2
    * @return true if the implementations have identical params and scheme
    * @attention this is for internal use only
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
    * @brief Inequality comparison operator
    * 
    * @param a cryptocontext object1
    * @param b cryptocontext object2
    * @return true if the implementations do not have identical params and scheme
    * @attention this is for internal use only
    */
    friend bool operator!=(const CryptoContextImpl<Element>& a, const CryptoContextImpl<Element>& b) {
        return !(a == b);
    }

    /**
    * @brief Serializes either all EvalMult keys (if keyTag is empty) or the EvalMult keys for keyTag
    *
    * @param ser stream to serialize to
    * @param sertype type of serialization
    * @param keyTag secret key tag
    * @return true on success
    */
    template <typename ST>
    static bool SerializeEvalMultKey(std::ostream& ser, const ST& sertype, const std::string& keyTag = "") {
        const auto& evalMultKeys = CryptoContextImpl<Element>::GetAllEvalMultKeys();
        if (keyTag.length() == 0) {
            Serial::Serialize(evalMultKeys, ser, sertype);
        }
        else {
            const auto it = evalMultKeys.find(keyTag);
            if (it == evalMultKeys.end())
                return false;  // no such keyTag

            std::map<std::string, std::vector<EvalKey<Element>>> omap{{it->first, it->second}};

            Serial::Serialize(omap, ser, sertype);
        }

        return true;
    }

    /**
    * @brief Serializes all EvalMult keys associated with the given CryptoContext
    * 
    * @param ser stream to serialize to
    * @param sertype type of serialization
    * @param cc the CryptoContext whose keys should be serialized
    * @return true on success
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
    * @brief Deserializes EvalMult keys
    * 
    * @param ser stream to deserialize from
    * @param sertype type of serialization
    * @return true on success
    * @attention Silently replaces any existing matching keys and creates a new CryptoContextImpl if necessary
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
    * @brief Clears the entire EvalMultKey cache
    */
    static void ClearEvalMultKeys();

    /**
    * @brief Clears the EvalMultKey cache for the given keyTag or the entire EvalMultKey cache if keyTag is empty
    * @param keyTag secret key tag
    */
    static void ClearEvalMultKeys(const std::string& keyTag);

    /**
    * @brief Clears EvalMultKey cache for the given context
    * @param cc the context to clear all EvalMultKey for
    */
    static void ClearEvalMultKeys(const CryptoContext<Element> cc);

    /**
    * @brief Adds the given vector of keys for the given keyTag to the map of all EvalMult keys
    * 
    * @param evalKeyVec vector of keys
    * @param keyTag secret key tag
    * @attention Silently replaces any existing matching keys and if keyTag is empty, then the key tag is retrieved from evalKeyVec
    */
    static void InsertEvalMultKey(const std::vector<EvalKey<Element>>& evalKeyVec, const std::string& keyTag = "");

    /**
    * @brief Serializes either all EvalSum keys (if keyTag is empty) or the EvalSum keys for keyTag
    *
    * @param ser stream to serialize to
    * @param sertype type of serialization
    * @param keyTag secret key tag
    * @return true on success
    */
    template <typename ST>
    static bool SerializeEvalSumKey(std::ostream& ser, const ST& sertype, const std::string& keyTag = "") {
        return CryptoContextImpl<Element>::SerializeEvalAutomorphismKey(ser, sertype, keyTag);
    }

    /**
    * @brief Serializes all EvalSum keys associated with the given CryptoContext
    * 
    * @param ser stream to serialize to
    * @param sertype type of serialization
    * @param cc the CryptoContext whose keys should be serialized
    * @return true on success
    */
    template <typename ST>
    static bool SerializeEvalSumKey(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {
        return CryptoContextImpl<Element>::SerializeEvalAutomorphismKey(ser, sertype, cc);
    }

    /**
    * @brief Deserializes EvalSum keys
    * 
    * @param ser stream to deserialize from
    * @param sertype type of serialization
    * @return true on success
    * @attention Silently replaces any existing matching keys and creates a new CryptoContextImpl if necessary
    */
    template <typename ST>
    static bool DeserializeEvalSumKey(std::istream& ser, const ST& sertype) {
        return CryptoContextImpl<Element>::DeserializeEvalAutomorphismKey(ser, sertype);
    }

    /**
    * @brief Clears the entire EvalSumKey cache
    */
    static void ClearEvalSumKeys();

    /**
    * @brief Clears the EvalSumKey cache for the given keyTag or the entire EvalSumKey cache if keyTag is empty
    * @param keyTag secret key tag
    */
    static void ClearEvalSumKeys(const std::string& keyTag);

    /**
    * @brief Clears EvalSumKey cache for the given context
    * @param cc the context to clear all EvalSumKey for
    */
    static void ClearEvalSumKeys(const CryptoContext<Element> cc);

    /**
    * @brief Adds the given map of keys for the given keyTag to the map of all EvalSum keys
    * 
    * @param mapToInsert map of keys
    * @param keyTag secret key tag
    * @attention Silently replaces any existing matching keys and if keyTag is empty, then the key tag is retrieved from mapToInsert
    */
    static void InsertEvalSumKey(const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> mapToInsert,
                                 std::string keyTag = "") {
        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(mapToInsert, keyTag);
    }

    /**
    * @brief Serializes either all EvalAutomorphism keys (if keyTag is empty) or the EvalAutomorphism keys for keyTag
    *
    * @param ser stream to serialize to
    * @param sertype type of serialization
    * @param keyTag secret key tag
    * @return true on success
    */
    template <typename ST>
    static bool SerializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype, const std::string& keyTag = "") {
        // TODO (dsuponit): do we need Serailize/Deserialized to return bool?
        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>* smap;
        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> omap;
        if (keyTag.length() == 0) {
            smap = &CryptoContextImpl<Element>::GetAllEvalAutomorphismKeys();
        }
        else {
            const auto keys = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMapPtr(keyTag);
            omap[keyTag]     = keys;
            smap            = &omap;
        }
        Serial::Serialize(*smap, ser, sertype);
        return true;
    }

    /**
    * @brief Serializes all EvalAutomorphism keys associated with the given CryptoContext
    * 
    * @param ser stream to serialize to
    * @param sertype type of serialization
    * @param cc the CryptoContext whose keys should be serialized
    * @return true on success
    */
    template <typename ST>
    static bool SerializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype, const CryptoContext<Element> cc) {
        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> omap;
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
    * @brief Serializes EvalAutomorphism keys for an array of specific indices associated with the given keyTag
    * 
    * @param ser stream to serialize to
    * @param sertype type of serialization
    * @param keyTag secret key tag
    * @param indexList array of specific indices to serialize keys for
    * @return true on success
    */
    template <typename ST>
    static bool SerializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype, const std::string& keyTag,
                                             const std::vector<uint32_t>& indexList) {
        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> keyMap = {
            {keyTag, CryptoContextImpl<Element>::GetPartialEvalAutomorphismKeyMapPtr(keyTag, indexList)}};

        Serial::Serialize(keyMap, ser, sertype);
        return true;
    }

    /**
    * @brief Deserializes EvalAutomorphism keys for an array of specific indices associated with the given keyTag
    * 
    * @param ser stream to deserialize from
    * @param sertype type of serialization
    * @param keyTag secret key tag
    * @param indexList array of specific indices to deserialize keys for
    * @return true on success
    */
    template <typename ST>
    static bool DeserializeEvalAutomorphismKey(std::ostream& ser, const ST& sertype, const std::string& keyTag,
                                               const std::vector<uint32_t>& indexList) {
        if (!indexList.size())
            OPENFHE_THROW("indexList may not be empty");
        if (keyTag.empty())
            OPENFHE_THROW("keyTag may not be empty");

        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> allDeserKeys;
        Serial::Deserialize(allDeserKeys, ser, sertype);

        const auto& keyMapIt = allDeserKeys.find(keyTag);
        if (keyMapIt == allDeserKeys.end()) {
            OPENFHE_THROW("Deserialized automorphism keys are not generated for ID [" + keyTag + "].");
        }

        // create a new map with evalkeys for the specified indices
        std::map<uint32_t, EvalKey<Element>> newMap;
        for (const uint32_t indx : indexList) {
            const auto& key = keyMapIt->find(indx);
            if (key == keyMapIt->end()) {
                OPENFHE_THROW("No automorphism key generated for index [" + std::to_string(indx) + "] within keyTag [" +
                              keyTag + "].");
            }
            newMap[indx] = key->second;
        }

        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(
            std::make_shared<std::map<uint32_t, EvalKey<Element>>>(newMap), keyTag);

        return true;
    }

    /**
    * @brief Deserializes EvalAutomorphism keys
    * 
    * @param ser stream to deserialize from
    * @param sertype type of serialization
    * @return true on success
    * @attention Silently replaces any existing matching keys and creates a new CryptoContextImpl if necessary
    */
    template <typename ST>
    static bool DeserializeEvalAutomorphismKey(std::istream& ser, const ST& sertype) {
        std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>> keyMap;

        Serial::Deserialize(keyMap, ser, sertype);

        // The deserialize call created any contexts that needed to be created....
        // so all we need to do is put the keys into the maps for their context
        for (auto& k : keyMap) {
            CryptoContextImpl<Element>::InsertEvalAutomorphismKey(k.second, k.first);
        }
        return true;
    }

    /**
    * @brief Clears the entire EvalAutomorphismKey cache
    */
    static void ClearEvalAutomorphismKeys();

    /**
    * @brief Clears the EvalAutomorphismKey cache for the given keyTag or the entire EvalAutomorphismKey cache if keyTag is empty
    * @param keyTag secret key tag
    */
    static void ClearEvalAutomorphismKeys(const std::string& keyTag);

    /**
    * @brief Clears EvalAutomorphismKey cache for the given context
    * @param cc the context to clear all EvalAutomorphismKeys for
    */
    static void ClearEvalAutomorphismKeys(const CryptoContext<Element> cc);

    /**
    * @brief Adds the given map of keys for the given keyTag to the map of all EvalAutomorphism keys
    * 
    * @param mapToInsert map of keys
    * @param keyTag secret key tag
    * @attention Silently replaces any existing matching keys and if keyTag is empty, then the key tag is retrieved from mapToInsert
    */
    // TODO (dsuponit): move InsertEvalAutomorphismKey() to the private section of the class
    static void InsertEvalAutomorphismKey(const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> mapToInsert,
                                          const std::string& keyTag = "");
    //------------------------------------------------------------------------------
    // TURN FEATURES ON
    //------------------------------------------------------------------------------

    /**
    * @brief Enable a particular feature for use with this CryptoContextImpl
    * @param feature the feature that should be enabled
    */
    void Enable(PKESchemeFeature feature) {
        scheme->Enable(feature);
    }

    /**
    * @brief Enable several features at once
    * @param featureMask bitwise value of several PKESchemeFeatures
    */
    void Enable(uint32_t featureMask) {
        scheme->Enable(featureMask);
    }

    // GETTERS
    /**
    * @brief Getter for Scheme
    * @return Scheme object
    */
    const std::shared_ptr<SchemeBase<Element>> GetScheme() const {
        return scheme;
    }

    /**
    * @brief Getter for CryptoParams
    * @return CryptoParams
    */
    const std::shared_ptr<CryptoParametersBase<Element>> GetCryptoParameters() const {
        return params;
    }

    /**
    * @brief Getter for the level at which evaluation keys should be generated
    * @return level
    * @attention For future use
    */
    size_t GetKeyGenLevel() const {
        return m_keyGenLevel;
    }

    /**
    * @brief Setter for the level at which evaluation keys should be generated
    * @attention For future use
    */
    void SetKeyGenLevel(size_t level) {
        m_keyGenLevel = level;
    }

    /**
    * @brief Getter for element params
    * @return ElementParams
    */
    const std::shared_ptr<ParmType> GetElementParams() const {
        return params->GetElementParams();
    }

    /**
    * @brief Getter for encoding params
    * @return EncodingParams
    */
    const EncodingParams GetEncodingParams() const {
        return params->GetEncodingParams();
    }

    /**
    * @brief Getter for cyclotomic order
    * @return CyclotomicOrder
    */
    uint32_t GetCyclotomicOrder() const {
        return params->GetElementParams()->GetCyclotomicOrder();
    }

    /**
    * @brief Getter for ring dimension
    * @return RingDimension
    */
    uint32_t GetRingDimension() const {
        return params->GetElementParams()->GetRingDimension();
    }

    /**
    * @brief Getter for ciphertext modulus
    * @return modulus
    */
    const IntType& GetModulus() const {
        return params->GetElementParams()->GetModulus();
    }

    /**
    * @brief Getter for root of unity
    * @return RootOfUnity
    */
    const IntType& GetRootOfUnity() const {
        return params->GetElementParams()->GetRootOfUnity();
    }

    /**
     * @brief Getter for the CKKS data type
     * @return data type of the CKKS data
     */
    CKKSDataType GetCKKSDataType() const {
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersRNS>(params);
        if (!cryptoParams) {
            std::string errorMsg(std::string("std::dynamic_pointer_cast<CryptoParametersRNS>() failed"));
            OPENFHE_THROW(errorMsg);
        }

        return cryptoParams->GetCKKSDataType();
    }

    //------------------------------------------------------------------------------
    // KEYS GETTERS
    //------------------------------------------------------------------------------

    /**
    * @brief Gets a map of all relinearization/evaluation multiplication keys
    * @return std::map where the map key/data pair is "keyTag"/"EvalMultKeys vector"
    */
    static std::map<std::string, std::vector<EvalKey<Element>>>& GetAllEvalMultKeys();

    /**
    * @brief Gets a vector of relinearization/evaluation multiplication keys for the given keyTag
    * @param keyTag secret key tag
    * @return vector of EvalMultKeys
    */
    static const std::vector<EvalKey<Element>>& GetEvalMultKeyVector(const std::string& keyTag);

    /**
    * @brief Gets a map of all EvalAutomorphism keys
    * @return std::map where the map key/data pair is "keyTag"/"shared_ptr to EvalMultKey map"
    */
    static std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>& GetAllEvalAutomorphismKeys();

    /**
    * @brief Gets a map of EvalAutomorphism keys for the given keyTag
    * @param keyTag secret key tag
    * @return shared_ptr to EvalAutomorphismKey map
    */
    static std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> GetEvalAutomorphismKeyMapPtr(const std::string& keyTag);

    /**
    * @brief Gets a map of EvalAutomorphism keys for the given keyTag
    * @param keyTag secret key tag
    * @return EvalAutomorphismKey map
    */
    static std::map<uint32_t, EvalKey<Element>>& GetEvalAutomorphismKeyMap(const std::string& keyTag) {
        return *(CryptoContextImpl<Element>::GetEvalAutomorphismKeyMapPtr(keyTag));
    }

    /**
    * @brief Gets a map of all summation keys
    * @return std::map where the map key/data pair is "keyTag"/"shared_ptr to EvalSumKey map"
    */
    static std::map<std::string, std::shared_ptr<std::map<uint32_t, EvalKey<Element>>>>& GetAllEvalSumKeys();

    /**
    * @brief Gets a map of EvalSum keys for the given keyTag
    * @param keyTag secret key tag
    * @return EvalSumKey map
    */
    static const std::map<uint32_t, EvalKey<Element>>& GetEvalSumKeyMap(const std::string& keyTag);

    //------------------------------------------------------------------------------
    // PLAINTEXT FACTORY METHODS
    //------------------------------------------------------------------------------

    // TODO to be deprecated in 2.0
    /**
    * @brief Creates a plaintext from a string using string encoding.
    *
    * @param str Input string to encode.
    * @return Encoded plaintext.
    */
    Plaintext MakeStringPlaintext(const std::string& str) const {
        return PlaintextFactory::MakePlaintext(str, STRING_ENCODING, this->GetElementParams(),
                                               this->GetEncodingParams());
    }

    /**
    * @brief Encodes a vector of integers into a coefficient-packed plaintext.
    *
    * @param value           Input vector to encode.
    * @param noiseScaleDeg   Degree of the scaling factor to encode the plaintext at.
    * @param level           Encryption level for the input vector.
    * @return Encoded plaintext.
    */
    Plaintext MakeCoefPackedPlaintext(const std::vector<int64_t>& value, size_t noiseScaleDeg = 1,
                                      uint32_t level = 0) const {
        if (!value.size())
            OPENFHE_THROW("Cannot encode an empty value vector");

        return MakePlaintext(COEF_PACKED_ENCODING, value, noiseScaleDeg, level);
    }

    /**
    * @brief Encodes a vector of integers into a packed plaintext.
    *
    * @param value           Input vector to encode.
    * @param noiseScaleDeg   Degree of the scaling factor to encode the plaintext at.
    * @param level           Encryption level for the input vector.
    * @return Encoded plaintext.
    */
    Plaintext MakePackedPlaintext(const std::vector<int64_t>& value, size_t noiseScaleDeg = 1,
                                  uint32_t level = 0) const {
        if (!value.size())
            OPENFHE_THROW("Cannot encode an empty value vector");

        return MakePlaintext(PACKED_ENCODING, value, noiseScaleDeg, level);
    }

    /**
    * @brief Encodes a vector of complex numbers into a CKKS packed plaintext.
    *
    * @param value           Input vector to encode.
    * @param noiseScaleDeg   Degree of the scaling factor to encode the plaintext at.
    * @param level           Encryption level for the input vector.
    * @param params          Encoding parameters.
    * @param slots           Number of slots to use.
    * @return Encoded CKKS plaintext.
    */
    Plaintext MakeCKKSPackedPlaintext(const std::vector<std::complex<double>>& value, size_t noiseScaleDeg = 1,
                                      uint32_t level = 0, const std::shared_ptr<ParmType> params = nullptr,
                                      uint32_t slots = 0) const {
        VerifyCKKSScheme(__func__);
        if (!value.size())
            OPENFHE_THROW("Cannot encode an empty value vector");

        return MakeCKKSPackedPlaintextInternal(value, noiseScaleDeg, level, params, slots);
    }

    /**
    * @brief Encodes a vector of real numbers into a CKKS packed plaintext.
    *
    * @param value           Input vector to encode.
    * @param noiseScaleDeg   Degree of the scaling factor to encode the plaintext at.
    * @param level           Encryption level for the input vector.
    * @param params          Encoding parameters.
    * @param slots           Number of slots to use.
    * @return Encoded CKKS plaintext.
    */
    Plaintext MakeCKKSPackedPlaintext(const std::vector<double>& value, size_t noiseScaleDeg = 1, uint32_t level = 0,
                                      const std::shared_ptr<ParmType> params = nullptr, uint32_t slots = 0) const {
        VerifyCKKSScheme(__func__);
        if (!value.size())
            OPENFHE_THROW("Cannot encode an empty value vector");

        std::vector<std::complex<double>> complexValue(value.size());
        std::transform(value.begin(), value.end(), complexValue.begin(),
                       [](double da) { return std::complex<double>(da); });

        return MakeCKKSPackedPlaintextInternal(complexValue, noiseScaleDeg, level, params, slots);
    }

    /**
    * @brief Returns a plaintext object for decryption based on encoding type and parameters.
    *
    * @param pte   Plaintext encoding type.
    * @param evp   Element parameters.
    * @param ep    Encoding parameters.
    * @param cdt   CKKS data type.
    * @return Plaintext for decryption.
    */
    static Plaintext GetPlaintextForDecrypt(PlaintextEncodings pte, std::shared_ptr<ParmType> evp, EncodingParams ep,
                                            CKKSDataType cdt = REAL);

    //------------------------------------------------------------------------------
    // PKE Wrapper
    //------------------------------------------------------------------------------

    /**
    * @brief Generates a standard public/secret key pair.
    *
    * @return Generated key pair.
    */
    KeyPair<Element> KeyGen() const {
        return GetScheme()->KeyGen(GetContextForPointer(this), false);
    }

    /**
    * @brief Generates a sparse key pair (with special structure and without full entropy) for special use cases like ring reduction.
    *
    * @return Generated key pair.
    * @attention Not supported by any crypto scheme currently.
    */
    KeyPair<Element> SparseKeyGen() const {
        return GetScheme()->KeyGen(GetContextForPointer(this), true);
    }

    /**
    * @brief Encrypts a plaintext using the given public key.
    *
    * @param plaintext  Plaintext to encrypt.
    * @param publicKey  Public key to use for encryption.
    * @return Encrypted ciphertext (or null on failure).
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
    * @brief Encrypts a plaintext using the given public key.
    *
    * @param publicKey  Public key to use for encryption.
    * @param plaintext  Plaintext to encrypt.
    * @return Encrypted ciphertext (or null on failure).
    */
    Ciphertext<Element> Encrypt(const PublicKey<Element> publicKey, Plaintext plaintext) const {
        return Encrypt(plaintext, publicKey);
    }

    /**
    * @brief Encrypts a plaintext using the given private key.
    *
    * @param plaintext   Plaintext to encrypt.
    * @param privateKey  Private key to use for encryption.
    * @return Encrypted ciphertext (or null on failure).
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
    * @brief Encrypts a plaintext using the given private key.
    *
    * @param privateKey  Private key to use for encryption.
    * @param plaintext   Plaintext to encrypt.
    * @return Encrypted ciphertext (or null on failure).
    */
    Ciphertext<Element> Encrypt(const PrivateKey<Element> privateKey, Plaintext plaintext) const {
        return Encrypt(plaintext, privateKey);
    }

    /**
    * @brief Decrypts a ciphertext using the given private key.
    *
    * @param ciphertext  Ciphertext to decrypt.
    * @param privateKey  Private key for decryption.
    * @param plaintext   Output pointer for the resulting plaintext.
    * @return Decryption result status.
    */
    DecryptResult Decrypt(ConstCiphertext<Element>& ciphertext, const PrivateKey<Element> privateKey,
                          Plaintext* plaintext);

    /**
    * @brief Decrypts a ciphertext using the given private key.
    *
    * @param privateKey  Private key for decryption.
    * @param ciphertext  Ciphertext to decrypt.
    * @param plaintext   Output pointer for the resulting plaintext.
    * @return Decryption result status.
    */
    inline DecryptResult Decrypt(const PrivateKey<Element> privateKey, ConstCiphertext<Element>& ciphertext,
                                 Plaintext* plaintext) {
        return Decrypt(ciphertext, privateKey, plaintext);
    }

    //------------------------------------------------------------------------------
    // KeySwitch Wrapper
    //------------------------------------------------------------------------------

    /**
    * @brief Generates a key switching key from one secret key to another.
    *
    * @param oldPrivateKey  Original secret key.
    * @param newPrivateKey  Target secret key.
    * @return New evaluation key for key switching.
    */
    EvalKey<Element> KeySwitchGen(const PrivateKey<Element> oldPrivateKey,
                                  const PrivateKey<Element> newPrivateKey) const {
        ValidateKey(oldPrivateKey);
        ValidateKey(newPrivateKey);
        return GetScheme()->KeySwitchGen(oldPrivateKey, newPrivateKey);
    }

    /**
    * @brief Applies key switching to a ciphertext using the given evaluation key.
    *
    * @param ciphertext  Input ciphertext.
    * @param evalKey     Evaluation key for key switching.
    * @return Ciphertext after key switching.
    */
    Ciphertext<Element> KeySwitch(ConstCiphertext<Element>& ciphertext, const EvalKey<Element> evalKey) const {
        ValidateCiphertext(ciphertext);
        ValidateKey(evalKey);
        return GetScheme()->KeySwitch(ciphertext, evalKey);
    }

    /**
    * @brief Applies key switching in place on the given ciphertext.
    *
    * @param ciphertext  Ciphertext to modify.
    * @param evalKey     Evaluation key for key switching.
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
    * @brief Negates a ciphertext.
    *
    * @param ciphertext  Input ciphertext.
    * @return Negated ciphertext.
    */
    Ciphertext<Element> EvalNegate(ConstCiphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);
        return GetScheme()->EvalNegate(ciphertext);
    }

    /**
    * @brief Performs in-place negation of a ciphertext.
    *
    * @param ciphertext  Ciphertext to negate.
    */
    void EvalNegateInPlace(Ciphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);
        GetScheme()->EvalNegateInPlace(ciphertext);
    }

    //------------------------------------------------------------------------------
    // SHE ADDITION Wrapper
    //------------------------------------------------------------------------------

    /**
    * @brief Homomorphic addition of two ciphertexts.
    *
    * @param ciphertext1  First addend.
    * @param ciphertext2  Second addend.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalAdd(ConstCiphertext<Element>& ciphertext1,
                                ConstCiphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalAdd(ciphertext1, ciphertext2);
    }

    /**
    * @brief In-place homomorphic addition of two ciphertexts.
    *
    * @param ciphertext1  First addend (modified in place).
    * @param ciphertext2  Second addend.
    */
    void EvalAddInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalAddInPlace(ciphertext1, ciphertext2);
    }

    /**
    * @brief Homomorphic addition of two mutable ciphertexts.
    *
    * @param ciphertext1  First addend (may be modified).
    * @param ciphertext2  Second addend (may be modified).
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalAddMutable(ciphertext1, ciphertext2);
    }

    /**
    * @brief In-place homomorphic addition of two mutable ciphertexts.
    *
    * @param ciphertext1  First addend (modified in place).
    * @param ciphertext2  Second addend (may be modified).
    */
    void EvalAddMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalAddMutableInPlace(ciphertext1, ciphertext2);
    }

    /**
    * @brief Homomorphic addition of a ciphertext and a plaintext.
    *
    * @param ciphertext  Input ciphertext.
    * @param plaintext   Input plaintext.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalAdd(ConstCiphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        plaintext->SetFormat(EVALUATION);
        return GetScheme()->EvalAdd(ciphertext, plaintext);
    }

    /**
    * @brief Homomorphic addition of a plaintext and a ciphertext.
    *
    * @param plaintext   Input plaintext.
    * @param ciphertext  Input ciphertext.
    * @return Resulting ciphertext.
    */
    inline Ciphertext<Element> EvalAdd(ConstPlaintext plaintext, ConstCiphertext<Element>& ciphertext) const {
        return EvalAdd(ciphertext, plaintext);
    }

    /**
    * @brief In-place addition of a ciphertext and a plaintext.
    *
    * @param ciphertext  Ciphertext to modify.
    * @param plaintext   Plaintext to add.
    */
    void EvalAddInPlace(Ciphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        plaintext->SetFormat(EVALUATION);
        GetScheme()->EvalAddInPlace(ciphertext, plaintext);
    }

    /**
    * @brief In-place addition of a plaintext and a ciphertext.
    *
    * @param plaintext   Plaintext to add.
    * @param ciphertext  Ciphertext to modify.
    */
    void EvalAddInPlace(ConstPlaintext plaintext, Ciphertext<Element>& ciphertext) const {
        EvalAddInPlace(ciphertext, plaintext);
    }

    /**
    * @brief Homomorphic addition of a mutable ciphertext and a plaintext.
    *
    * @param ciphertext  Input ciphertext (may be modified).
    * @param plaintext   Input plaintext.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalAddMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        TypeCheck((ConstCiphertext<Element>)ciphertext, (ConstPlaintext)plaintext);
        plaintext->SetFormat(EVALUATION);
        return GetScheme()->EvalAddMutable(ciphertext, plaintext);
    }

    /**
    * @brief Homomorphic addition of a plaintext and a mutable ciphertext.
    *
    * @param plaintext   Input plaintext.
    * @param ciphertext  Input ciphertext (may be modified).
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalAddMutable(Plaintext plaintext, Ciphertext<Element>& ciphertext) const {
        return EvalAddMutable(ciphertext, plaintext);
    }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalAdd(ConstCiphertext<Element> ciphertext, const NativeInteger& scalar) const {
    //  return GetScheme()->EvalAdd(ciphertext, scalar);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalAdd(const NativeInteger& scalar, ConstCiphertext<Element> ciphertext) const {
    //  return EvalAdd(ciphertext, scalar);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // void EvalAddInPlace(Ciphertext<Element>& ciphertext, const NativeInteger& scalar) const {
    //  GetScheme()->EvalAddInPlace(ciphertext, scalar);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // void EvalAddInPlace(const NativeInteger& scalar, Ciphertext<Element>& ciphertext) const {
    //  EvalAddInPlace(ciphertext, scalar);
    // }

    /**
    * @brief Homomorphic addition of a ciphertext and a real number (CKKS only).
    *
    * @param ciphertext  Input ciphertext.
    * @param scalar      Real number to add.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalAdd(ConstCiphertext<Element>& ciphertext, double scalar) const {
        return scalar >= 0. ? GetScheme()->EvalAdd(ciphertext, scalar) : GetScheme()->EvalSub(ciphertext, -scalar);
    }

    /**
    * @brief Homomorphic addition of a real number and a ciphertext (CKKS only).
    *
    * @param scalar      Real number to add.
    * @param ciphertext  Input ciphertext.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalAdd(double scalar, ConstCiphertext<Element>& ciphertext) const {
        return EvalAdd(ciphertext, scalar);
    }

    /**
    * @brief In-place addition of a ciphertext and a real number (CKKS only).
    *
    * @param ciphertext  Ciphertext to modify.
    * @param scalar      Real number to add.
    */
    void EvalAddInPlace(Ciphertext<Element>& ciphertext, double scalar) const {
        if (scalar == 0.)
            return;

        if (scalar > 0.) {
            GetScheme()->EvalAddInPlace(ciphertext, scalar);
        }
        else {
            GetScheme()->EvalSubInPlace(ciphertext, -scalar);
        }
    }

    /**
    * @brief In-place addition of a real number and a ciphertext (CKKS only).
    *
    * @param scalar      Real number to add.
    * @param ciphertext  Ciphertext to modify.
    */
    void EvalAddInPlace(double scalar, Ciphertext<Element>& ciphertext) const {
        EvalAddInPlace(ciphertext, scalar);
    }

    /**
    * @brief Homomorphic addition of a ciphertext and a complex number (CKKS only).
    *
    * @param ciphertext  Input ciphertext.
    * @param scalar      Complex number to add.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalAdd(ConstCiphertext<Element>& ciphertext, std::complex<double> scalar) const {
        return GetScheme()->EvalAdd(ciphertext, scalar);
    }

    /**
    * @brief Homomorphic addition of a complex number and a ciphertext (CKKS only).
    *
    * @param scalar      Complex number to add.
    * @param ciphertext  Input ciphertext.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalAdd(std::complex<double> scalar, ConstCiphertext<Element>& ciphertext) const {
        return EvalAdd(ciphertext, scalar);
    }

    /**
    * @brief In-place addition of a ciphertext and a complex number (CKKS only).
    *
    * @param ciphertext  Ciphertext to modify.
    * @param scalar      Complex number to add.
    */
    void EvalAddInPlace(Ciphertext<Element>& ciphertext, std::complex<double> scalar) const {
        if (scalar == std::complex<double>(0.0, 0.0))
            return;
        GetScheme()->EvalAddInPlace(ciphertext, scalar);
    }

    /**
    * @brief In-place addition of a complex number and a ciphertext (CKKS only).
    *
    * @param scalar      Complex number to add.
    * @param ciphertext  Ciphertext to modify.
    */
    void EvalAddInPlace(std::complex<double> scalar, Ciphertext<Element>& ciphertext) const {
        EvalAddInPlace(ciphertext, scalar);
    }

    //------------------------------------------------------------------------------
    // SHE SUBTRACTION Wrapper
    //------------------------------------------------------------------------------

    /**
    * @brief Homomorphic subtraction of two ciphertexts.
    *
    * @param ciphertext1  Minuend.
    * @param ciphertext2  Subtrahend.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalSub(ConstCiphertext<Element>& ciphertext1,
                                ConstCiphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalSub(ciphertext1, ciphertext2);
    }

    /**
    * @brief In-place homomorphic subtraction of two ciphertexts.
    *
    * @param ciphertext1  Minuend (modified in place).
    * @param ciphertext2  Subtrahend.
    */
    void EvalSubInPlace(Ciphertext<Element>& ciphertext1, ConstCiphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalSubInPlace(ciphertext1, ciphertext2);
    }

    /**
    * @brief Homomorphic subtraction of two mutable ciphertexts.
    *
    * @param ciphertext1  Minuend (may be modified).
    * @param ciphertext2  Subtrahend (may be modified).
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalSubMutable(ciphertext1, ciphertext2);
    }

    /**
    * @brief In-place homomorphic subtraction of two mutable ciphertexts.
    *
    * @param ciphertext1  Minuend (modified in place).
    * @param ciphertext2  Subtrahend (may be modified).
    */
    void EvalSubMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        GetScheme()->EvalSubMutableInPlace(ciphertext1, ciphertext2);
    }

    /**
    * @brief Homomorphic subtraction of a ciphertext and a plaintext.
    *
    * @param ciphertext  Minuend.
    * @param plaintext   Subtrahend.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalSub(ConstCiphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        return GetScheme()->EvalSub(ciphertext, plaintext);
    }

    /**
    * @brief Homomorphic subtraction of a ciphertext from a plaintext.
    *
    * @param plaintext   Minuend.
    * @param ciphertext  Subtrahend.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalSub(ConstPlaintext plaintext, ConstCiphertext<Element>& ciphertext) const {
        return EvalAdd(EvalNegate(ciphertext), plaintext);
    }

    /**
    * @brief Homomorphic subtraction of a plaintext from a mutable ciphertext.
    *
    * @param ciphertext  Minuend (may be modified).
    * @param plaintext   Subtrahend.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalSubMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        TypeCheck((ConstCiphertext<Element>)ciphertext, (ConstPlaintext)plaintext);
        return GetScheme()->EvalSubMutable(ciphertext, plaintext);
    }

    /**
    * @brief Homomorphic subtraction of a mutable ciphertext from a plaintext.
    *
    * @param plaintext   Minuend.
    * @param ciphertext  Subtrahend (may be modified).
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalSubMutable(Plaintext plaintext, Ciphertext<Element>& ciphertext) const {
        Ciphertext<Element> negated = EvalNegate(ciphertext);
        Ciphertext<Element> result  = EvalAddMutable(negated, plaintext);
        ciphertext                  = EvalNegate(negated);
        return result;
    }

    /**
    * @brief Homomorphic subtraction of a real number from a ciphertext (CKKS only).
    *
    * @param ciphertext  Input ciphertext.
    * @param scalar      Real number to subtract.
    * @return Resulting ciphertext (ciphertext - scalar).
    */
    Ciphertext<Element> EvalSub(ConstCiphertext<Element>& ciphertext, double scalar) const {
        return scalar >= 0 ? GetScheme()->EvalSub(ciphertext, scalar) : GetScheme()->EvalAdd(ciphertext, -scalar);
    }

    /**
    * @brief Homomorphic subtraction of a ciphertext from a real number (CKKS only).
    *
    * @param scalar      Real number.
    * @param ciphertext  Ciphertext to subtract.
    * @return Resulting ciphertext (scalar - ciphertext).
    */
    Ciphertext<Element> EvalSub(double scalar, ConstCiphertext<Element>& ciphertext) const {
        return EvalAdd(EvalNegate(ciphertext), scalar);
    }

    /**
    * @brief In-place subtraction of a real number from a ciphertext (CKKS only).
    *
    * @param ciphertext  Ciphertext to modify.
    * @param scalar      Real number to subtract.
    */
    void EvalSubInPlace(Ciphertext<Element>& ciphertext, double scalar) const {
        if (scalar >= 0.)
            GetScheme()->EvalSubInPlace(ciphertext, scalar);
        else
            GetScheme()->EvalAddInPlace(ciphertext, -scalar);
    }

    /**
    * @brief In-place subtraction of a ciphertext from a real number (CKKS only).
    *
    * @param scalar      Real number.
    * @param ciphertext  Ciphertext to modify.
    */
    void EvalSubInPlace(double scalar, Ciphertext<Element>& ciphertext) const {
        EvalNegateInPlace(ciphertext);
        EvalAddInPlace(ciphertext, scalar);
    }

    /**
    * @brief Homomorphic subtraction of a complex number from a ciphertext (CKKS only).
    *
    * @param ciphertext  Input ciphertext.
    * @param scalar      Complex number to subtract.
    * @return Resulting ciphertext (ciphertext - scalar).
    */
    Ciphertext<Element> EvalSub(ConstCiphertext<Element>& ciphertext, std::complex<double> scalar) const {
        return GetScheme()->EvalAdd(ciphertext, -scalar);
    }

    /**
    * @brief Homomorphic subtraction of a ciphertext from a complex number (CKKS only).
    *
    * @param scalar      Complex number.
    * @param ciphertext  Ciphertext to subtract.
    * @return Resulting ciphertext (scalar - ciphertext).
    */
    Ciphertext<Element> EvalSub(std::complex<double> scalar, ConstCiphertext<Element>& ciphertext) const {
        return EvalAdd(EvalNegate(ciphertext), scalar);
    }

    /**
    * @brief In-place subtraction of a complex number from a ciphertext (CKKS only).
    *
    * @param ciphertext  Ciphertext to modify.
    * @param scalar      Complex number to subtract.
    */
    void EvalSubInPlace(Ciphertext<Element>& ciphertext, std::complex<double> scalar) const {
        if (scalar == std::complex<double>(0.0, 0.0))
            return;
        GetScheme()->EvalAddInPlace(ciphertext, -scalar);
    }

    /**
    * @brief In-place subtraction of a ciphertext from a complex number (CKKS only).
    *
    * @param scalar      Complex number.
    * @param ciphertext  Ciphertext to modify.
    */
    void EvalSubInPlace(std::complex<double> scalar, Ciphertext<Element>& ciphertext) const {
        EvalNegateInPlace(ciphertext);
        EvalAddInPlace(ciphertext, scalar);
    }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalSub(ConstCiphertext<Element> ciphertext, const NativeInteger& scalar) const {
    //  return GetScheme()->EvalSub(ciphertext, scalar);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalSub(const NativeInteger& scalar, ConstCiphertext<Element> ciphertext) const {
    //  return EvalAdd(EvalNegate(ciphertext), scalar);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    //  void EvalSubInPlace(Ciphertext<Element>& ciphertext, const NativeInteger& constant) const {
    //    GetScheme()->EvalSubInPlace(ciphertext, constant);
    //  }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // void EvalSubInPlace(const NativeInteger& scalar, Ciphertext<Element>& ciphertext) const {
    //  EvalNegateInPlace(ciphertext);
    //  EvalAddInPlace(ciphertext, scalar);
    // }

    //------------------------------------------------------------------------------
    // SHE MULTIPLICATION Wrapper
    //------------------------------------------------------------------------------

    /**
    * @brief Creates a relinearization key (for s^2) that can be used with the OpenFHE EvalMult operator
    *
    * @param key secret key
    * @note the new evaluation key is stored in cryptocontext
    */
    void EvalMultKeyGen(const PrivateKey<Element> key);

    /**
    * @brief Creates a vector evalmult keys that can be used with the OpenFHE EvalMult operator
    * @param key secret key
    * 
    * @note 1st key (for s^2) is used for multiplication of ciphertexts of depth 1,
    * 2nd key (for s^3) is used for multiplication of ciphertexts of depth 2, etc.
    * A vector of new evaluation keys is stored in crytpocontext
    */
    void EvalMultKeysGen(const PrivateKey<Element> key);

    /**
    * @brief Homomorphic multiplication of two ciphertexts using a relinearization key.
    *
    * @param ciphertext1  Multiplier.
    * @param ciphertext2  Multiplicand.
    * @return Resulting ciphertext (ciphertext1 * ciphertext2).
    */
    Ciphertext<Element> EvalMult(ConstCiphertext<Element>& ciphertext1,
                                 ConstCiphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size())
            OPENFHE_THROW("Evaluation key has not been generated for EvalMult");

        return GetScheme()->EvalMult(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    /**
    * @brief Homomorphic multiplication of two mutable ciphertexts using a relinearization key.
    *
    * @param ciphertext1  Multiplier (may be modified).
    * @param ciphertext2  Multiplicand (may be modified).
    * @return Resulting ciphertext (ciphertext1 * ciphertext2).
    */
    Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size())
            OPENFHE_THROW("Evaluation key has not been generated for EvalMultMutable");

        return GetScheme()->EvalMultMutable(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    /**
    * @brief In-place homomorphic multiplication of two mutable ciphertexts using a relinearization key.
    *
    * @param ciphertext1  Multiplier (modified in place).
    * @param ciphertext2  Multiplicand (may be modified).
    */
    void EvalMultMutableInPlace(Ciphertext<Element>& ciphertext1, Ciphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size())
            OPENFHE_THROW("Evaluation key has not been generated for EvalMultMutableInPlace");

        GetScheme()->EvalMultMutableInPlace(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    /**
    * @brief Homomorphic squaring of a ciphertext using a relinearization key.
    *
    * @param ciphertext  Input ciphertext.
    * @return Squared ciphertext.
    */
    Ciphertext<Element> EvalSquare(ConstCiphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (!evalKeyVec.size())
            OPENFHE_THROW("Evaluation key has not been generated for EvalSquare");

        return GetScheme()->EvalSquare(ciphertext, evalKeyVec[0]);
    }

    /**
    * @brief Homomorphic squaring of a mutable ciphertext using a relinearization key.
    *
    * @param ciphertext  Input ciphertext (may be modified).
    * @return Squared ciphertext.
    */
    Ciphertext<Element> EvalSquareMutable(Ciphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (!evalKeyVec.size())
            OPENFHE_THROW("Evaluation key has not been generated for EvalSquareMutable");

        return GetScheme()->EvalSquareMutable(ciphertext, evalKeyVec[0]);
    }

    /**
    * @brief In-place homomorphic squaring of a ciphertext using a relinearization key.
    *
    * @param ciphertext  Ciphertext to square (modified in place).
    */
    void EvalSquareInPlace(Ciphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (!evalKeyVec.size())
            OPENFHE_THROW("Evaluation key has not been generated for EvalSquareInPlace");

        GetScheme()->EvalSquareInPlace(ciphertext, evalKeyVec[0]);
    }

    /**
    * @brief Homomorphic multiplication of two ciphertexts without relinearization.
    *
    * @param ciphertext1  Multiplier.
    * @param ciphertext2  Multiplicand.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalMultNoRelin(ConstCiphertext<Element>& ciphertext1,
                                        ConstCiphertext<Element>& ciphertext2) const {
        TypeCheck(ciphertext1, ciphertext2);
        return GetScheme()->EvalMult(ciphertext1, ciphertext2);
    }

    /**
    * @brief Relinearizes a ciphertext to reduce it to two components (2 polynomials per ciphertext).
    *
    * @param ciphertext  Input ciphertext.
    * @return Relinearized ciphertext.
    */
    Ciphertext<Element> Relinearize(ConstCiphertext<Element>& ciphertext) const {
        // input parameter check
        if (!ciphertext)
            OPENFHE_THROW("Input ciphertext is nullptr");

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext->GetKeyTag());

        if (evalKeyVec.size() < (ciphertext->NumberCiphertextElements() - 2))
            OPENFHE_THROW("Insufficient value was used for maxRelinSkDeg to generate keys for Relinearize");

        return GetScheme()->Relinearize(ciphertext, evalKeyVec);
    }

    /**
    * @brief In-place relinearization of a ciphertext to reduce it to two components (2 polynomials per ciphertext).
    *
    * @param ciphertext  Ciphertext to relinearize (modified in place).
    */
    void RelinearizeInPlace(Ciphertext<Element>& ciphertext) const {
        // input parameter check
        if (!ciphertext)
            OPENFHE_THROW("Input ciphertext is nullptr");

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext->GetKeyTag());
        if (evalKeyVec.size() < (ciphertext->NumberCiphertextElements() - 2))
            OPENFHE_THROW("Insufficient value was used for maxRelinSkDeg to generate keys for RelinearizeInPlace");

        GetScheme()->RelinearizeInPlace(ciphertext, evalKeyVec);
    }

    /**
    * @brief Homomorphic multiplication of two ciphertexts followed by relinearization to the lowest level.
    *
    * @param ciphertext1  First input ciphertext.
    * @param ciphertext2  Second input ciphertext.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalMultAndRelinearize(ConstCiphertext<Element>& ciphertext1,
                                               ConstCiphertext<Element>& ciphertext2) const {
        if (!ciphertext1 || !ciphertext2)
            OPENFHE_THROW("Input ciphertext is nullptr");

        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext1->GetKeyTag());

        if (evalKeyVec.size() <
            (ciphertext1->NumberCiphertextElements() + ciphertext2->NumberCiphertextElements() - 3)) {
            OPENFHE_THROW("Insufficient value was used for maxRelinSkDeg to generate keys for EvalMultAndRelinearize");
        }

        return GetScheme()->EvalMultAndRelinearize(ciphertext1, ciphertext2, evalKeyVec);
    }

    /**
    * @brief Homomorphic multiplication of a ciphertext by a plaintext.
    *
    * @param ciphertext  Multiplier.
    * @param plaintext   Multiplicand.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalMult(ConstCiphertext<Element>& ciphertext, ConstPlaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        return GetScheme()->EvalMult(ciphertext, plaintext);
    }

    /**
    * @brief Homomorphic multiplication of a plaintext by a ciphertext.
    *
    * @param plaintext   Multiplier.
    * @param ciphertext  Multiplicand.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalMult(ConstPlaintext plaintext, ConstCiphertext<Element>& ciphertext) const {
        return EvalMult(ciphertext, plaintext);
    }

    /**
    * @brief Homomorphic multiplication of a mutable ciphertext and a plaintext.
    *
    * @param ciphertext  Multiplier (may be modified).
    * @param plaintext   Multiplicand.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalMultMutable(Ciphertext<Element>& ciphertext, Plaintext plaintext) const {
        TypeCheck(ciphertext, plaintext);
        return GetScheme()->EvalMultMutable(ciphertext, plaintext);
    }

    /**
    * @brief Homomorphic multiplication of a mutable plaintext and a ciphertext.
    *
    * @param plaintext   Multiplier.
    * @param ciphertext  Multiplicand.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalMultMutable(Plaintext plaintext, Ciphertext<Element>& ciphertext) const {
        return EvalMultMutable(ciphertext, plaintext);
    }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalMult(ConstCiphertext<Element> ciphertext, const NativeInteger& scalar) const {
    //  if (!ciphertext) {
    //    OPENFHE_THROW( "Input ciphertext is nullptr");
    //  }
    //  return GetScheme()->EvalMult(ciphertext, scalar);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // Ciphertext<Element> EvalMult(const NativeInteger& scalar, ConstCiphertext<Element> ciphertext) const {
    //  return EvalMult(ciphertext, scalar);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // void EvalMultInPlace(Ciphertext<Element>& ciphertext, const NativeInteger& scalar) const {
    //  if (!ciphertext) {
    //    OPENFHE_THROW( "Input ciphertext is nullptr");
    //  }

    //  GetScheme()->EvalMultInPlace(ciphertext, scalar);
    // }

    // TODO (dsuponit): commented the code below to avoid compiler errors
    // void EvalMultInPlace(const NativeInteger& scalar, Ciphertext<Element>& ciphertext) const {
    //  EvalMultInPlace(ciphertext, scalar);
    // }

    /**
    * @brief Homomorphic multiplication of a ciphertext by a real number (CKKS only).
    *
    * @param ciphertext  Multiplier.
    * @param scalar      Real number multiplicand.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalMult(ConstCiphertext<Element>& ciphertext, double scalar) const {
        if (!ciphertext)
            OPENFHE_THROW("Input ciphertext is nullptr");
        return GetScheme()->EvalMult(ciphertext, scalar);
    }

    /**
    * @brief Homomorphic multiplication of a ciphertext by a real number (CKKS only).
    *
    * @param scalar      Real number multiplier.
    * @param ciphertext  Multiplicand.
    * @return Resulting ciphertext.
    */
    inline Ciphertext<Element> EvalMult(double scalar, ConstCiphertext<Element>& ciphertext) const {
        return EvalMult(ciphertext, scalar);
    }

    /**
    * @brief In-place multiplication of a ciphertext by a real number (CKKS only).
    *
    * @param ciphertext  Ciphertext to modify.
    * @param scalar      Real number multiplicand.
    */
    void EvalMultInPlace(Ciphertext<Element>& ciphertext, double scalar) const {
        if (!ciphertext)
            OPENFHE_THROW("Input ciphertext is nullptr");
        GetScheme()->EvalMultInPlace(ciphertext, scalar);
    }

    /**
    * @brief In-place multiplication of a ciphertext by a real number (CKKS only).
    *
    * @param scalar      Real number multiplier.
    * @param ciphertext  Ciphertext to modify (multiplicand).
    */
    inline void EvalMultInPlace(double scalar, Ciphertext<Element>& ciphertext) const {
        EvalMultInPlace(ciphertext, scalar);
    }

    /**
    * @brief Homomorphic multiplication of a ciphertext by a complex number (CKKS only).
    *
    * @param ciphertext  Multiplier.
    * @param scalar      Complex number multiplicand.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalMult(ConstCiphertext<Element>& ciphertext, std::complex<double> scalar) const {
        if (!ciphertext)
            OPENFHE_THROW("Input ciphertext is nullptr");
        return GetScheme()->EvalMult(ciphertext, scalar);
    }

    /**
    * @brief Homomorphic multiplication of a ciphertext by a complex number (CKKS only).
    *
    * @param scalar      Complex number multiplier.
    * @param ciphertext  Multiplicand.
    * @return Resulting ciphertext.
    */
    inline Ciphertext<Element> EvalMult(std::complex<double> scalar, ConstCiphertext<Element>& ciphertext) const {
        return EvalMult(ciphertext, scalar);
    }

    /**
    * @brief In-place multiplication of a ciphertext by a complex number (CKKS only).
    *
    * @param ciphertext  Ciphertext to modify.
    * @param scalar      Complex number multiplicand.
    */
    void EvalMultInPlace(Ciphertext<Element>& ciphertext, std::complex<double> scalar) const {
        if (!ciphertext)
            OPENFHE_THROW("Input ciphertext is nullptr");
        GetScheme()->EvalMultInPlace(ciphertext, scalar);
    }

    /**
    * @brief In-place multiplication of a ciphertext by a complex number (CKKS only).
    *
    * @param scalar      Complex number multiplier.
    * @param ciphertext  Ciphertext to modify (multiplicand).
    */
    inline void EvalMultInPlace(std::complex<double> scalar, Ciphertext<Element>& ciphertext) const {
        EvalMultInPlace(ciphertext, scalar);
    }

    //------------------------------------------------------------------------------
    // SHE AUTOMORPHISM Wrapper
    //------------------------------------------------------------------------------

    /**
    * @brief Generates automorphism evaluation keys for the given private key.
    *
    * @param privateKey   Private key to use for key generation.
    * @param indexList    List of automorphism indices to be computed.
    * @return Map of generated evaluation keys.
    */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalAutomorphismKeyGen(
        const PrivateKey<Element> privateKey, const std::vector<uint32_t>& indexList) const {
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
        shared_ptr<std::map<uint32_t, EvalKey<Element>>>
        EvalAutomorphismKeyGen(const PublicKey<Element> publicKey, const PrivateKey<Element> privateKey,
                               const std::vector<uint32_t>& indexList) const {
        std::string errMsg(
            "This API is deprecated. use EvalAutomorphismKeyGen(const PrivateKey<Element> privateKey, const std::vector<uint32_t>& indexList)");
        OPENFHE_THROW(errMsg);
    }

    /**
    * @brief Applies an automorphism to a ciphertext using the given evaluation keys.
    *
    * @param ciphertext   Input ciphertext.
    * @param i            Automorphism index.
    * @param evalKeyMap   Map of evaluation keys generated by EvalAutomorphismKeyGen.
    * @return Transformed ciphertext.
    */
    Ciphertext<Element> EvalAutomorphism(ConstCiphertext<Element>& ciphertext, uint32_t i,
                                         const std::map<uint32_t, EvalKey<Element>>& evalKeyMap,
                                         CALLER_INFO_ARGS_HDR) const {
        ValidateCiphertext(ciphertext);

        if (evalKeyMap.empty())
            OPENFHE_THROW(std::string("Empty input key map") + CALLER_INFO);

        auto key = evalKeyMap.find(i);
        if (key == evalKeyMap.end())
            OPENFHE_THROW(std::string("Could not find an EvalKey for index ") + std::to_string(i) + CALLER_INFO);

        auto evalKey = key->second;
        ValidateKey(evalKey);

        return GetScheme()->EvalAutomorphism(ciphertext, i, evalKeyMap);
    }

    /**
    * @brief Computes the automorphism index for a given vector index.
    *
    * @param idx  Vector index.
    * @return Corresponding automorphism index.
    */
    uint32_t FindAutomorphismIndex(const uint32_t idx) const {
        const auto cryptoParams  = GetCryptoParameters();
        const auto elementParams = cryptoParams->GetElementParams();
        uint32_t m               = elementParams->GetCyclotomicOrder();
        return GetScheme()->FindAutomorphismIndex(idx, m);
    }

    /**
    * @brief Computes automorphism indices for a list of vector indices.
    *
    * @param idxList  List of vector indices.
    * @return Vector of corresponding automorphism indices.
    */
    std::vector<uint32_t> FindAutomorphismIndices(const std::vector<uint32_t>& idxList) const {
        std::vector<uint32_t> newIndices;
        newIndices.reserve(idxList.size());
        for (const auto idx : idxList) {
            newIndices.emplace_back(FindAutomorphismIndex(idx));
        }
        return newIndices;
    }

    /**
    * @brief Rotates a ciphertext by the given index using a stored rotation key.
    *
    * @param ciphertext  Input ciphertext.
    * @param index       Rotation index (positive for left, negative for right).
    * @return Rotated ciphertext.
    */
    Ciphertext<Element> EvalRotate(ConstCiphertext<Element>& ciphertext, int32_t index) const {
        ValidateCiphertext(ciphertext);

        auto evalKeyMap = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
        return GetScheme()->EvalAtIndex(ciphertext, index, evalKeyMap);
    }

    /**
    * @brief implements the precomputation step of hoisted automorphisms.
    *
    * Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic linear transformations in HELib."
    * for more details, link: https://eprint.iacr.org/2018/244.
    *
    * Generally, automorphisms are performed with three steps:
    * (1) the automorphism is applied on the ciphertext
    * (2) the automorphed values are decomposed into digits
    * (3) key switching is applied to make it possible to further compute on the ciphertext.
    *
    * Hoisted automorphisms is a technique that performs the digit decomposition for the original ciphertext first,
    * and then performs the automorphism and the key switching on the decomposed digits. The benefit of this is that the
    * digit decomposition is independent of the automorphism rotation index, so  it can be reused for
    * multiple different indices. This can greatly improve performance when we have to compute many automorphisms
    * on the same ciphertext. This routinely happens when we do permutations (EvalPermute).
    *
    * it implements the digit decomposition step of hoisted automorphisms.
    *
    * @param ciphertext Input ciphertext on which to do the precomputation (digit decomposition).
    * @return Pointer to precomputed rotation data.
    */
    std::shared_ptr<std::vector<Element>> EvalFastRotationPrecompute(ConstCiphertext<Element>& ciphertext) const {
        return GetScheme()->EvalFastRotationPrecompute(ciphertext);
    }

    /**
    * @brief Implements the automorphism and key switching step of hoisted automorphisms.
    *
    * Please refer to Section 5 of Halevi and Shoup, "Faster Homomorphic linear transformations in HELib."
    * for more details, link: https://eprint.iacr.org/2018/244.
    *
    * Generally, automorphisms are performed with three steps:
    * (1) the automorphism is applied on the ciphertext
    * (2) the automorphed values are decomposed into digits
    * (3) key switching is applied to make it possible to further compute on the ciphertext.
    *
    * Hoisted automorphisms is a technique that performs the digit decomposition for the original ciphertext first,
    * and then performs the automorphism and the key switching on the decomposed digits. The benefit of this is that the
    * digit decomposition is independent of the automorphism rotation index, so  it can be reused for
    * multiple different indices. This can greatly improve performance when we have to compute many automorphisms
    * on the same ciphertext. This routinely happens when we do permutations (EvalPermute).
    *
    * This method assumes that all required rotation keys exist. This may not be true if we are
    * using baby-step/giant-step key switching. Please refer to Section 5.1 of the above reference and
    * EvalPermuteBGStepHoisted to see how to deal with this issue.
    *
    * @param ciphertext  Input ciphertext.
    * @param index       Rotation index (positive for left, negative for right).
    * @param m           Cyclotomic order.
    * @param digits      Precomputed rotation data (the digit decomposition created by EvalFastRotationPrecompute).
    * @return Rotated ciphertext.
    */
    Ciphertext<Element> EvalFastRotation(ConstCiphertext<Element>& ciphertext, const uint32_t index,
                                         const uint32_t m, const std::shared_ptr<std::vector<Element>> digits) const {
        return GetScheme()->EvalFastRotation(ciphertext, index, m, digits);
    }

    /**
    * @brief Performs fast (hoisted) rotation in the extended CRT basis P*Q. Only supported with hybrid key switching.
    *
    * @param ciphertext  Input ciphertext.
    * @param index       Rotation index (positive for left, negative for right).
    * @param digits      Precomputed digits for the ciphertext.
    * @param addFirst    If true, the first element c0 is also computed.
    * @return Rotated ciphertext in extended basis.
    */
    Ciphertext<Element> EvalFastRotationExt(ConstCiphertext<Element>& ciphertext, uint32_t index,
                                            const std::shared_ptr<std::vector<Element>> digits, bool addFirst) const {
        auto evalKeyMap = CryptoContextImpl<Element>::GetEvalAutomorphismKeyMap(ciphertext->GetKeyTag());
        return GetScheme()->EvalFastRotationExt(ciphertext, index, digits, addFirst, evalKeyMap);
    }

    /**
    * @brief Scales a ciphertext down from the extended CRT basis P*Q to Q. Only supported with hybrid key switching.
    *
    * @param ciphertext  Input ciphertext in extended basis.
    * @return Scaled ciphertext in basis Q.
    */
    Ciphertext<Element> KeySwitchDown(ConstCiphertext<Element>& ciphertext) const {
        return GetScheme()->KeySwitchDown(ciphertext);
    }

    /**
    * @brief Scales down the first polynomial c0 from extended CRT basis P*Q to Q. Only supported with hybrid key switching.
    *
    * @param ciphertext  Input ciphertext in extended basis.
    * @return Scaled polynomial c0 in basis Q.
    */
    Element KeySwitchDownFirstElement(ConstCiphertext<Element>& ciphertext) const {
        return GetScheme()->KeySwitchDownFirstElement(ciphertext);
    }

    /**
    * @brief Extends a ciphertext from basis Q to the extended CRT basis P*Q. Only supported with hybrid key switching.
    *
    * @param ciphertext  Input ciphertext in basis Q.
    * @param addFirst    If true, includes the first component c0 in the output.
    * @return Extended ciphertext in basis P*Q.
    */
    Ciphertext<Element> KeySwitchExt(ConstCiphertext<Element>& ciphertext, bool addFirst) const {
        return GetScheme()->KeySwitchExt(ciphertext, addFirst);
    }

    /**
    * @brief Generates evaluation keys for a list of rotation indices.
    *
    * @param privateKey  Private key used for key generation.
    * @param indexList   List of rotation indices.
    * @param publicKey   Public key (previously used in NTRU schemes; unused now).
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
    * @brief Generates rotation evaluation keys for a list of indices. Internally calls EvalAtIndexKeyGen.
    *
    * @param privateKey  Private key used for key generation.
    * @param indexList   List of rotation indices.
    * @param publicKey   Public key (previously used in NTRU schemes; unused now).
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
    * @brief Rotates a ciphertext by the given index using stored rotation keys.
    *        Positive index = left shift; negative index = right shift.
    *
    * @param ciphertext  Input ciphertext.
    * @param index       Rotation index.
    * @return Rotated ciphertext.
    */
    Ciphertext<Element> EvalAtIndex(ConstCiphertext<Element>& ciphertext, int32_t index) const;

    //------------------------------------------------------------------------------
    // SHE Leveled Methods Wrapper
    //------------------------------------------------------------------------------

    /**
    * @brief Performs multiplication, relinearization, and rescaling in one step.
    *        Uses a relinearization key from the crypto context.
    *
    * @param ciphertext1  First ciphertext.
    * @param ciphertext2  Second ciphertext.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> ComposedEvalMult(ConstCiphertext<Element>& ciphertext1,
                                         ConstCiphertext<Element>& ciphertext2) const {
        ValidateCiphertext(ciphertext1);
        ValidateCiphertext(ciphertext2);

        auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertext1->GetKeyTag());
        if (!evalKeyVec.size())
            OPENFHE_THROW("Evaluation key has not been generated for EvalMult");

        return GetScheme()->ComposedEvalMult(ciphertext1, ciphertext2, evalKeyVec[0]);
    }

    /**
    * @brief Rescales a ciphertext by reducing its modulus (alias for ModReduce in CKKS).
    *
    * @param ciphertext  Input ciphertext.
    * @return Rescaled ciphertext.
    */
    Ciphertext<Element> Rescale(ConstCiphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);
        return GetScheme()->ModReduce(ciphertext, GetCompositeDegreeFromCtxt());
    }

    /**
    * @brief In-place rescaling of a ciphertext (alias for ModReduceInPlace in CKKS).
    *
    * @param ciphertext  Ciphertext to rescale.
    */
    void RescaleInPlace(Ciphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);
        GetScheme()->ModReduceInPlace(ciphertext, GetCompositeDegreeFromCtxt());
    }

    /**
    * @brief Performs modulus reduction on a ciphertext (used in BGV/CKKS).
    *
    * @param ciphertext  Input ciphertext.
    * @return Modulus-reduced ciphertext.
    */
    Ciphertext<Element> ModReduce(ConstCiphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);
        return GetScheme()->ModReduce(ciphertext, GetCompositeDegreeFromCtxt());
    }

    /**
    * @brief In-place modulus reduction of a ciphertext (used in BGV/CKKS).
    *
    * @param ciphertext  Ciphertext to reduce.
    */
    void ModReduceInPlace(Ciphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);
        GetScheme()->ModReduceInPlace(ciphertext, GetCompositeDegreeFromCtxt());
    }

    /**
    * @brief Reduces the number of RNS limbs (levels) in a ciphertext and evaluation key.
    *
    * @param ciphertext  Input ciphertext.
    * @param evalKey     Evaluation key (modified in place).
    * @param levels      Number of levels to drop.
    * @return Ciphertext with reduced levels.
    *
    * @note Supported in BGV and CKKS. In CKKS with COMPOSITESCALING*, levels are scaled by the composite degree.
    */
    Ciphertext<Element> LevelReduce(ConstCiphertext<Element>& ciphertext, const EvalKey<Element> evalKey,
                                    size_t levels = 1) const {
        ValidateCiphertext(ciphertext);
        return GetScheme()->LevelReduce(ciphertext, evalKey, levels * GetCompositeDegreeFromCtxt());
    }

    /**
    * @brief In-place reduction of RNS limbs (levels) in a ciphertext and evaluation key.
    *
    * @param ciphertext  Ciphertext to modify.
    * @param evalKey     Evaluation key (modified in place).
    * @param levels      Number of levels to drop.
    *
    * @note Supported in BGV and CKKS. In CKKS with COMPOSITESCALING*, levels are scaled by the composite degree.
    */
    void LevelReduceInPlace(Ciphertext<Element>& ciphertext, const EvalKey<Element> evalKey, size_t levels = 1) const {
        ValidateCiphertext(ciphertext);
        if (levels <= 0)
            return;
        GetScheme()->LevelReduceInPlace(ciphertext, evalKey, levels * GetCompositeDegreeFromCtxt());
    }

    /**
    * @brief Compresses a ciphertext by reducing its modulus to lower communication cost.
    *
    * @param ciphertext  Input ciphertext.
    * @param towersLeft  Number of RNS limbs to retain.
    * @return Compressed ciphertext.
    */
    Ciphertext<Element> Compress(ConstCiphertext<Element>& ciphertext, uint32_t towersLeft = 1) const {
        if (ciphertext == nullptr)
            OPENFHE_THROW("input ciphertext is invalid (has no data)");
        return GetScheme()->Compress(ciphertext, towersLeft);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE Wrapper
    //------------------------------------------------------------------------------

    /**
    * @brief Homomorphic addition of multiple ciphertexts using a binary tree approach.
    *
    * @param ciphertextVec  Vector of ciphertexts.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalAddMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const {
        if (!ciphertextVec.size())
            OPENFHE_THROW("Empty input ciphertext vector");
        if (ciphertextVec.size() == 1)
            return ciphertextVec[0];
        return GetScheme()->EvalAddMany(ciphertextVec);
    }

    /**
    * @brief In-place homomorphic addition of multiple ciphertexts using a binary tree approach.
    *
    * @param ciphertextVec  Vector of ciphertexts (modified in place to store intermediate results).
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalAddManyInPlace(std::vector<Ciphertext<Element>>& ciphertextVec) const {
        if (!ciphertextVec.size())
            OPENFHE_THROW("Empty input ciphertext vector");
        return GetScheme()->EvalAddManyInPlace(ciphertextVec);
    }

    /**
    * @brief Homomorphic multiplication of multiple ciphertexts using a binary tree approach,
    *        followed by relinearization to reduce ciphertext size to two elements after each multiplication.
    *
    * @param ciphertextVec  Vector of ciphertexts to multiply.
    * @return Resulting ciphertext.
    *
    * @note Assumes each multiplication produces a ciphertext within the supported ring size
    *       (for the secret key degree used by EvalMultsKeyGen). 
    *       Otherwise, it throws an error
    */
    Ciphertext<Element> EvalMultMany(const std::vector<Ciphertext<Element>>& ciphertextVec) const {
        if (!ciphertextVec.size())
            OPENFHE_THROW("Empty input ciphertext vector");
        if (ciphertextVec.size() == 1)
            return ciphertextVec[0];
        const auto evalKeyVec = CryptoContextImpl<Element>::GetEvalMultKeyVector(ciphertextVec[0]->GetKeyTag());
        if (evalKeyVec.size() < (ciphertextVec[0]->NumberCiphertextElements() - 2))
            OPENFHE_THROW("Insufficient value was used for maxRelinSkDeg to generate keys");
        return GetScheme()->EvalMultMany(ciphertextVec, evalKeyVec);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE LINEAR WEIGHTED SUM
    //------------------------------------------------------------------------------

    /**
    * @brief Computes a linear weighted sum of ciphertexts (CKKS only).
    *
    * @param ciphertextVec  List of ciphertexts.
    * @param constantVec    Corresponding weights.
    * @return Weighted sum as a ciphertext.
    */
    Ciphertext<Element> EvalLinearWSum(std::vector<ReadOnlyCiphertext<Element>>& ciphertextVec,
                                       const std::vector<double>& constantVec) const {
        return GetScheme()->EvalLinearWSum(ciphertextVec, constantVec);
    }

    /**
    * @brief Computes a linear weighted sum of ciphertexts (CKKS only).
    *
    * @param constantVec    Corresponding weights.
    * @param ciphertextVec  List of ciphertexts.
    * @return Weighted sum as a ciphertext.
    */
    Ciphertext<Element> EvalLinearWSum(const std::vector<double>& constantsVec,
                                       std::vector<ReadOnlyCiphertext<Element>>& ciphertextVec) const {
        return EvalLinearWSum(ciphertextVec, constantsVec);
    }

    /**
    * @brief Computes a linear weighted sum using mutable ciphertexts (CKKS only).
    *
    * @param ciphertextVec  List of mutable ciphertexts.
    * @param constantsVec   Corresponding weights.
    * @return Weighted sum as a ciphertext.
    */
    Ciphertext<Element> EvalLinearWSumMutable(std::vector<Ciphertext<Element>>& ciphertextVec,
                                              const std::vector<double>& constantsVec) const {
        return GetScheme()->EvalLinearWSumMutable(ciphertextVec, constantsVec);
    }

    /**
    * @brief Computes a linear weighted sum using mutable ciphertexts (CKKS only).
    *
    * @param constantsVec   Corresponding weights.
    * @param ciphertextVec  List of mutable ciphertexts.
    * @return Weighted sum as a ciphertext.
    */
    Ciphertext<Element> EvalLinearWSumMutable(const std::vector<double>& constantsVec,
                                              std::vector<Ciphertext<Element>>& ciphertextVec) const {
        return EvalLinearWSumMutable(ciphertextVec, constantsVec);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL POLYNOMIAL
    //------------------------------------------------------------------------------

    /**
    * @brief Evaluates a polynomial (given as a power series) on a ciphertext (CKKS only).
    *        Use EvalPolyLinear() for low polynomial degrees (degree < 5), or EvalPolyPS() for higher degrees.
    *
    * @param ciphertext    Input ciphertext.
    * @param coefficients  Polynomial coefficients (vector's size = (degree + 1)).
    * @return Resulting ciphertext.
    */
    virtual Ciphertext<Element> EvalPoly(ConstCiphertext<Element>& ciphertext,
                                         const std::vector<double>& coefficients) const {
        ValidateCiphertext(ciphertext);
        return GetScheme()->EvalPoly(ciphertext, coefficients);
    }

    /**
    * @brief Naive polynomial evaluation using a binary tree approach (efficient for low-degree polynomials, <10).
    *        Polynomials are given as a power series. Supported only in CKKS.
    *
    * @param ciphertext    Input ciphertext.
    * @param coefficients  Polynomial coefficients (vector's size = degree).
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalPolyLinear(ConstCiphertext<Element>& ciphertext,
                                       const std::vector<double>& coefficients) const {
        ValidateCiphertext(ciphertext);
        return GetScheme()->EvalPolyLinear(ciphertext, coefficients);
    }

    /**
    * @brief Evaluates a polynomial (given as a power series) using the Paterson-Stockmeyer method (efficient for high-degree polynomials).
    *        Supported only in CKKS.
    *
    * @param ciphertext    Input ciphertext.
    * @param coefficients  Polynomial coefficients (vector's size = degree).
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalPolyPS(ConstCiphertext<Element>& ciphertext,
                                   const std::vector<double>& coefficients) const {
        ValidateCiphertext(ciphertext);
        return GetScheme()->EvalPolyPS(ciphertext, coefficients);
    }

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL CHEBYSHEV SERIES
    //------------------------------------------------------------------------------

    /**
    * @brief Evaluates a Chebyshev interpolated polynomial on a ciphertext.
    *        Uses a linear transformation to map [a, b] to [-1, 1] using linear transformation 1 + 2(x-a)/(b-a),
    *        then applies either EvalChebyshevSeriesLinear (degree < 5) or EvalChebyshevSeriesPS depending on degree.
    *        Supported only in CKKS.
    *
    * @param ciphertext    Input ciphertext.
    * @param coefficients  Chebyshev series coefficients.
    * @param a             Lower bound of argument for which the coefficients were found.
    * @param b             Upper bound of argument for which the coefficients were found.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalChebyshevSeries(ConstCiphertext<Element>& ciphertext,
                                            const std::vector<double>& coefficients, double a, double b) const {
        ValidateCiphertext(ciphertext);
        return GetScheme()->EvalChebyshevSeries(ciphertext, coefficients, a, b);
    }

    /**
    * @brief Evaluates a Chebyshev interpolated polynomial using a naive linear method.
    *        Maps [a, b] to [-1, 1] using linear transformation 1 + 2(x-a)/(b-a). Supported only in CKKS.
    *
    * @param ciphertext    Input ciphertext.
    * @param coefficients  Chebyshev series coefficients.
    * @param a             Lower bound of argument for which the coefficients were found.
    * @param b             Upper bound of argument for which the coefficients were found.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalChebyshevSeriesLinear(ConstCiphertext<Element>& ciphertext,
                                                  const std::vector<double>& coefficients, double a, double b) const {
        ValidateCiphertext(ciphertext);
        return GetScheme()->EvalChebyshevSeriesLinear(ciphertext, coefficients, a, b);
    }

    /**
    * @brief Evaluates a Chebyshev interpolated polynomial using the Paterson-Stockmeyer method.
    *        Maps [a, b] to [-1, 1] using linear transformation 1 + 2(x-a)/(b-a). Supported only in CKKS.
    *
    * @param ciphertext    Input ciphertext.
    * @param coefficients  Chebyshev series coefficients.
    * @param a             Lower bound of argument for which the coefficients were found.
    * @param b             Upper bound of argument for which the coefficients were found.
    * @return Resulting ciphertext.
    */
    Ciphertext<Element> EvalChebyshevSeriesPS(ConstCiphertext<Element>& ciphertext,
                                              const std::vector<double>& coefficients, double a, double b) const {
        ValidateCiphertext(ciphertext);
        return GetScheme()->EvalChebyshevSeriesPS(ciphertext, coefficients, a, b);
    }

    /**
    * @brief Evaluates a smooth function on a ciphertext using Chebyshev polynomial approximation over [a, b].
    *        Supported only in CKKS.
    *
    * @param func        Function to approximate.
    * @param ciphertext  Input ciphertext.
    * @param a           Lower bound of argument for which the coefficients were found.
    * @param b           Upper bound of argument for which the coefficients were found.
    * @param degree      Degree of the Chebyshev approximation.
    * @return Ciphertext after function evaluation.
    */
    Ciphertext<Element> EvalChebyshevFunction(std::function<double(double)> func,
                                              ConstCiphertext<Element>& ciphertext, double a, double b,
                                              uint32_t degree) const;

    /**
    * @brief Evaluates an approximate sine function on a ciphertext using Chebyshev approximation.
    *        Supported only in CKKS.
    *
    * @param ciphertext  Input ciphertext.
    * @param a           Lower bound of argument for which the coefficients were found.
    * @param b           Upper bound of argument for which the coefficients were found.
    * @param degree      Degree of the Chebyshev approximation.
    * @return Ciphertext after sine approximation.
    */
    Ciphertext<Element> EvalSin(ConstCiphertext<Element>& ciphertext, double a, double b, uint32_t degree) const;

    /**
    * @brief Evaluates an approximate cosine function on a ciphertext using Chebyshev approximation.
    *        Supported only in CKKS.
    *
    * @param ciphertext  Input ciphertext.
    * @param a           Lower bound of argument for which the coefficients were found.
    * @param b           Upper bound of argument for which the coefficients were found.
    * @param degree      Degree of the Chebyshev approximation.
    * @return Ciphertext after cosine approximation.
    */
    Ciphertext<Element> EvalCos(ConstCiphertext<Element>& ciphertext, double a, double b, uint32_t degree) const;

    /**
    * @brief Evaluates an approximate logistic function 1 / (1 + exp(-x)) on a ciphertext using Chebyshev approximation.
    *        Supported only in CKKS.
    *
    * @param ciphertext  Input ciphertext.
    * @param a           Lower bound of argument for which the coefficients were found.
    * @param b           Upper bound of argument for which the coefficients were found.
    * @param degree      Degree of the Chebyshev approximation.
    * @return Ciphertext after logistic approximation.
    */
    Ciphertext<Element> EvalLogistic(ConstCiphertext<Element>& ciphertext, double a, double b,
                                     uint32_t degree) const;

    /**
    * @brief Evaluates an approximate reciprocal function 1 / x (for x ≥ 1) on a ciphertext using Chebyshev approximation.
    *        Supported only in CKKS.
    *
    * @param ciphertext  Input ciphertext.
    * @param a           Lower bound of argument for which the coefficients were found.
    * @param b           Upper bound of argument for which the coefficients were found.
    * @param degree      Degree of the Chebyshev approximation.
    * @return Ciphertext after reciprocal approximation.
    */
    Ciphertext<Element> EvalDivide(ConstCiphertext<Element>& ciphertext, double a, double b,
                                   uint32_t degree) const;

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL SUM
    //------------------------------------------------------------------------------

    /**
    * @brief Generates evaluation keys required for homomorphic summation (EvalSum).
    *
    * @param privateKey  Private key used for key generation.
    * @param publicKey   Public key (used in NTRU schemes; unused now).
    */
    void EvalSumKeyGen(const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey = nullptr);

    // [[deprecated("Use EvalSumKeyGen(const PrivateKey<Element> privateKey) instead.")]] void EvalSumKeyGen(
    //     const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) {
    //     std::string errMsg("This API is deprecated. use EvalSumKeyGen(const PrivateKey<Element> privateKey)");
    //     OPENFHE_THROW( errMsg);
    // }

    /**
    * @brief Generates automorphism keys for EvalSumRows (only for packed encoding).
    *
    * @param privateKey    Private key used for key generation.
    * @param publicKey     Public key (used in NTRU schemes; unused now).
    * @param rowSize       Number of slots per row in the packed matrix.
    * @param subringDim    Subring dimension (use cyclotomic order if 0).
    * @return Map of generated evaluation keys.
    */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalSumRowsKeyGen(
        const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey = nullptr, uint32_t rowSize = 0,
        uint32_t subringDim = 0);

    // [[deprecated(
    //     "Use EvalSumRowKeyGen(const PrivateKey<Element> privateKey, uint32_t rowSize = 0, uint32_t subringDim = 0) instead.")]] std::
    //     shared_ptr<std::map<uint32_t, EvalKey<Element>>>
    //     EvalSumRowsKeyGen(const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey, uint32_t rowSize = 0,
    //                       uint32_t subringDim = 0) {
    //     std::string errMsg(
    //         "This API is deprecated. use EvalSumRowsKeyGen(const PrivateKey<Element> privateKey, uint32_t rowSize = 0, uint32_t subringDim = 0)");
    //     OPENFHE_THROW( errMsg);
    // }

    /**
    * @brief Generates automorphism keys for EvalSumCols (only for packed encoding).
    *
    * @param privateKey  Private key used for key generation.
    * @param publicKey   Public key (used in NTRU schemes; unused now).
    * @return Map of generated evaluation keys.
    */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalSumColsKeyGen(
        const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey = nullptr);

    // [[deprecated("Use EvalSumColsKeyGen(const PrivateKey<Element> privateKey) instead.")]] std::shared_ptr<
    //     std::map<uint32_t, EvalKey<Element>>>
    // EvalSumColsKeyGen(const PrivateKey<Element> privateKey, const PublicKey<Element> publicKey) {
    //     std::string errMsg("This API is deprecated. use EvalSumColsKeyGen(const PrivateKey<Element> privateKey)");
    //     OPENFHE_THROW( errMsg);
    // }

    // std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> EvalSumColsKeyGen(const PrivateKey<Element> privateKey);

    /**
    * @brief Computes the sum of all components in a packed ciphertext vector.
    *
    * @param ciphertext  Input ciphertext.
    * @param batchSize   Number of slots to sum over.
    * @return Resulting ciphertext containing the sum.
    */
    Ciphertext<Element> EvalSum(ConstCiphertext<Element>& ciphertext, uint32_t batchSize) const;

    /**
    * @brief Sums all elements across each row in a packed-encoded matrix ciphertext.
    *
    * @param ciphertext      Input ciphertext.
    * @param numRows         Number of rows in the matrix.
    * @param evalSumKeyMap   Map of evaluation keys generated for row summation.
    * @param subringDim      Subring dimension (use full cyclotomic order if 0).
    * @return Ciphertext containing row-wise sums.
    */
    Ciphertext<Element> EvalSumRows(ConstCiphertext<Element>& ciphertext, uint32_t numRows,
                                    const std::map<uint32_t, EvalKey<Element>>& evalSumKeyMap,
                                    uint32_t subringDim = 0) const;

    /**
    * @brief Sums all elements across each column in a packed-encoded matrix ciphertext.
    *
    * @param ciphertext      Input ciphertext.
    * @param numCols         Number of columns in the matrix.
    * @param evalSumKeyMap   Map of evaluation keys generated for column summation.
    * @return Ciphertext containing column-wise sums.
    */
    Ciphertext<Element> EvalSumCols(ConstCiphertext<Element>& ciphertext, uint32_t numCols,
                                    const std::map<uint32_t, EvalKey<Element>>& evalSumKeyMap) const;

    //------------------------------------------------------------------------------
    // Advanced SHE EVAL INNER PRODUCT
    //------------------------------------------------------------------------------

    /**
    * @brief Computes the inner product of two ciphertext vectors using packed encoding and EvalSum.
    *
    * @param ciphertext1  First input ciphertext vector.
    * @param ciphertext2  Second input ciphertext vector.
    * @param batchSize    Number of slots to sum over.
    * @return Ciphertext containing the inner product.
    */
    Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element>& ciphertext1,
                                         ConstCiphertext<Element>& ciphertext2, uint32_t batchSize) const;

    /**
    * @brief Computes the inner product of a ciphertext and a plaintext using packed encoding and EvalSum.
    *
    * @param ciphertext  Encrypted input vector.
    * @param plaintext   Plaintext input vector.
    * @param batchSize   Number of slots to sum over.
    * @return Ciphertext containing the inner product.
    */
    Ciphertext<Element> EvalInnerProduct(ConstCiphertext<Element>& ciphertext, ConstPlaintext plaintext,
                                         uint32_t batchSize) const;

    /**
    * @brief Merges multiple ciphertexts with values in slot 0 into a single packed ciphertext.
    *
    * @param ciphertextVec  Vector of ciphertexts to merge.
    * @return Merged ciphertext with values placed into slots in order.
    *
    * @note Requires rotation keys for the necessary indices.
    */
    Ciphertext<Element> EvalMerge(const std::vector<Ciphertext<Element>>& ciphertextVec) const;

    //------------------------------------------------------------------------------
    // PRE Wrapper
    //------------------------------------------------------------------------------

    /**
    * @brief Generates a re-encryption key for Proxy Re-Encryption (PRE).
    *
    * @param oldPrivateKey  Original private key.
    * @param newPublicKey   Public key of the target recipient.
    * @return Re-encryption evaluation key.
    */
    EvalKey<Element> ReKeyGen(const PrivateKey<Element> oldPrivateKey, const PublicKey<Element> newPublicKey) const {
        ValidateKey(oldPrivateKey);
        ValidateKey(newPublicKey);

        return GetScheme()->ReKeyGen(oldPrivateKey, newPublicKey);
    }

    /**
    * @brief Produces an Eval Key that OpenFHE can use for Proxy Re-Encryption
    * 
    * @param oldPrivateKey original secret key
    * @param newPrivateKey new secret key
    * @return new evaluation key
    * @attention This functionality has been completely removed from OpenFHE
    */
    EvalKey<Element> ReKeyGen(const PrivateKey<Element> originalPrivateKey,
                              const PrivateKey<Element> newPrivateKey) const
        __attribute__((deprecated("functionality removed from OpenFHE")));

    /**
    * @brief Re-encrypts a ciphertext using a re-encryption key for Proxy Re-Encryption.
    *
    * @param ciphertext  Input ciphertext.
    * @param evalKey     Re-encryption key.
    * @param publicKey   Optional public key of the recipient.
    * @return Re-encrypted ciphertext.
    */
    Ciphertext<Element> ReEncrypt(ConstCiphertext<Element>& ciphertext, EvalKey<Element> evalKey,
                                  const PublicKey<Element> publicKey = nullptr) const {
        ValidateCiphertext(ciphertext);
        ValidateKey(evalKey);
        return GetScheme()->ReEncrypt(ciphertext, evalKey, publicKey);
    }

    //------------------------------------------------------------------------------
    // Multiparty Wrapper
    //------------------------------------------------------------------------------

    /**
    * @brief Generates a joined public key from a set of secret key shares (Threshold FHE).
    *
    * @param privateKeyVec  Vector of secret key shares.
    * @return Key pair containing this party's private key and the joined public key.
    *
    * @attention Only for debugging purposes. Not for production use.
    */
    KeyPair<Element> MultipartyKeyGen(const std::vector<PrivateKey<Element>>& privateKeyVec) {
        if (!privateKeyVec.size())
            OPENFHE_THROW("Input private key vector is empty");
        return GetScheme()->MultipartyKeyGen(GetContextForPointer(this), privateKeyVec, false);
    }

    /**
    * @brief Generates a joined public key using a prior public key and the current party's secret share (Threshold FHE).
    *
    * @param publicKey   joined public key from prior parties.
    * @param makeSparse  Use ring reduction (no longer supported).
    * @param fresh       Indicates if proxy re-encryption is used in the multi-party protocol or star topology is used.
    * @return Key pair containing this party's private key and the updated joined public key.
    */
    KeyPair<Element> MultipartyKeyGen(const PublicKey<Element> publicKey, bool makeSparse = false, bool fresh = false) {
        if (!publicKey)
            OPENFHE_THROW("Input public key is empty");
        return GetScheme()->MultipartyKeyGen(GetContextForPointer(this), publicKey, makeSparse, fresh);
    }

    /**
    * @brief Performs partial decryption as the lead decryption party (Threshold FHE).
    *
    * @param ciphertextVec  Vector of ciphertexts to decrypt.
    * @param privateKey     Secret key share of the lead party.
    * @return Vector of partially decrypted ciphertexts.
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
    * @brief Performs partial decryption by non-lead parties in a Threshold FHE setting.
    *
    * @param ciphertextVec  Vector of ciphertexts to decrypt.
    * @param privateKey     Secret key share of a non-lead party.
    * @return Vector of partially decrypted ciphertexts.
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
    * @brief Combines partially decrypted ciphertexts into the final plaintext result (Threshold FHE).
    *
    * @param partialCiphertextVec  Vector of partial decryptions.
    * @param plaintext             Output plaintext.
    * @return Decoding result.
    */
    DecryptResult MultipartyDecryptFusion(const std::vector<Ciphertext<Element>>& partialCiphertextVec,
                                          Plaintext* plaintext) const {
        std::string datatype = demangle(typeid(Element).name());
        OPENFHE_THROW("Not implemented for " + datatype);
    }

    /**
    * @brief Generates a new joined evaluation key from a prior key and secret key shares (Threshold FHE).
    *
    * @param originalPrivateKey  Original private key.
    * @param newPrivateKey       New private key.
    * @param evalKey             Prior joined evaluation key.
    * @return New joined evaluation key.
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
    * @brief Generates joined automorphism keys from the current secret share and prior keys (Threshold FHE).
    *
    * @param privateKey   Secret key share.
    * @param evalKeyMap   Prior joined automorphism keys.
    * @param indexList    List of automorphism indices.
    * @param keyTag       Secret key tag (optional).
    * @return Map of updated joined automorphism keys.
    */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> MultiEvalAutomorphismKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap,
        const std::vector<uint32_t>& indexList, const std::string& keyTag = "") {
        if (!privateKey)
            OPENFHE_THROW("Input private key is nullptr");
        if (!evalKeyMap)
            OPENFHE_THROW("Input evaluation key map is nullptr");
        if (!indexList.size())
            OPENFHE_THROW("Input index vector is empty");
        return GetScheme()->MultiEvalAutomorphismKeyGen(privateKey, evalKeyMap, indexList, keyTag);
    }

    /**
    * @brief Generates joined rotation keys from the current secret share and prior keys (Threshold FHE).
    *
    * @param privateKey   Secret key share.
    * @param evalKeyMap   Prior joined rotation keys.
    * @param indexList    List of rotation indices.
    * @param keyTag       Secret key tag (optional).
    * @return Map of updated joined rotation keys.
    */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> MultiEvalAtIndexKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap,
        const std::vector<int32_t>& indexList, const std::string& keyTag = "") {
        if (!privateKey)
            OPENFHE_THROW("Input private key is nullptr");
        if (!evalKeyMap)
            OPENFHE_THROW("Input evaluation key map is nullptr");
        if (!indexList.size())
            OPENFHE_THROW("Input index vector is empty");
        return GetScheme()->MultiEvalAtIndexKeyGen(privateKey, evalKeyMap, indexList, keyTag);
    }

    /**
    * @brief Generates joined summation evaluation keys from the current secret share and prior keys (Threshold FHE).
    *
    * @param privateKey   Secret key share.
    * @param evalKeyMap   Prior summation evaluation keys.
    * @param keyTag       Secret key tag (optional).
    * @return Map of updated summation evaluation keys.
    */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> MultiEvalSumKeyGen(
        const PrivateKey<Element> privateKey, const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap,
        const std::string& keyTag = "") {
        if (!privateKey)
            OPENFHE_THROW("Input private key is nullptr");
        if (!evalKeyMap)
            OPENFHE_THROW("Input evaluation key map is nullptr");
        return GetScheme()->MultiEvalSumKeyGen(privateKey, evalKeyMap, keyTag);
    }

    /**
    * @brief Adds two evaluation keys to produce a new joined evaluation key (Threshold FHE).
    *
    * @param evalKey1  First evaluation key.
    * @param evalKey2  Second evaluation key.
    * @param keyTag    Secret key tag (optional).
    * @return Joined evaluation key.
    */
    EvalKey<Element> MultiAddEvalKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2,
                                      const std::string& keyTag = "") {
        if (!evalKey1)
            OPENFHE_THROW("Input first evaluation key is nullptr");
        if (!evalKey2)
            OPENFHE_THROW("Input second evaluation key is nullptr");
        return GetScheme()->MultiAddEvalKeys(evalKey1, evalKey2, keyTag);
    }

    /**
    * @brief Generates a joined partial evaluation key for homomorphic multiplication from a partial key and current secret share (Threshold FHE).
    *
    * @param privateKey  Current secret share.
    * @param evalKey     Prior partial evaluation key.
    * @param keyTag      Secret key tag (optional).
    * @return Joined evaluation key.
    */
    EvalKey<Element> MultiMultEvalKey(PrivateKey<Element> privateKey, EvalKey<Element> evalKey,
                                      const std::string& keyTag = "") {
        if (!privateKey)
            OPENFHE_THROW("Input private key is nullptr");
        if (!evalKey)
            OPENFHE_THROW("Input evaluation key is nullptr");
        return GetScheme()->MultiMultEvalKey(privateKey, evalKey, keyTag);
    }

    /**
    * @brief Adds two summation evaluation key sets (Threshold FHE).
    *
    * @param evalKeyMap1  First summation key set.
    * @param evalKeyMap2  Second summation key set.
    * @param keyTag       Secret key tag (optional).
    * @return Combined summation evaluation key set.
    */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> MultiAddEvalSumKeys(
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap1,
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap2, const std::string& keyTag = "") {
        if (!evalKeyMap1)
            OPENFHE_THROW("Input first evaluation key map is nullptr");
        if (!evalKeyMap2)
            OPENFHE_THROW("Input second evaluation key map is nullptr");
        return GetScheme()->MultiAddEvalSumKeys(evalKeyMap1, evalKeyMap2, keyTag);
    }

    /**
    * @brief Adds two automorphism evaluation key sets (Threshold FHE).
    *
    * @param evalKeyMap1  First automorphism key set.
    * @param evalKeyMap2  Second automorphism key set.
    * @param keyTag       Secret key tag (optional).
    * @return Combined automorphism evaluation key set.
    */
    std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> MultiAddEvalAutomorphismKeys(
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap1,
        const std::shared_ptr<std::map<uint32_t, EvalKey<Element>>> evalKeyMap2, const std::string& keyTag = "") {
        if (!evalKeyMap1)
            OPENFHE_THROW("Input first evaluation key map is nullptr");
        if (!evalKeyMap2)
            OPENFHE_THROW("Input second evaluation key map is nullptr");
        return GetScheme()->MultiAddEvalAutomorphismKeys(evalKeyMap1, evalKeyMap2, keyTag);
    }

    /**
    * @brief Adds two public keys to produce a combined public key (Threshold FHE).
    *
    * @param publicKey1  First public key.
    * @param publicKey2  Second public key.
    * @param keyTag      Secret key tag (optional).
    * @return Combined public key.
    */
    PublicKey<Element> MultiAddPubKeys(PublicKey<Element> publicKey1, PublicKey<Element> publicKey2,
                                       const std::string& keyTag = "") {
        if (!publicKey1)
            OPENFHE_THROW("Input first public key is nullptr");
        if (!publicKey2)
            OPENFHE_THROW("Input second public key is nullptr");
        return GetScheme()->MultiAddPubKeys(publicKey1, publicKey2, keyTag);
    }

    /**
    * @brief Adds two partial evaluation keys for multiplication (Threshold FHE).
    *
    * @param evalKey1  First evaluation key.
    * @param evalKey2  Second evaluation key.
    * @param keyTag    Secret key tag (optional).
    * @return Combined evaluation key.
    */
    EvalKey<Element> MultiAddEvalMultKeys(EvalKey<Element> evalKey1, EvalKey<Element> evalKey2,
                                          const std::string& keyTag = "") {
        if (!evalKey1)
            OPENFHE_THROW("Input first evaluation key is nullptr");
        if (!evalKey2)
            OPENFHE_THROW("Input second evaluation key is nullptr");
        return GetScheme()->MultiAddEvalMultKeys(evalKey1, evalKey2, keyTag);
    }

    /**
    * @brief Performs masked decryption for interactive bootstrapping (2-party protocol).
    *
    * @param privateKey   Secret key share.
    * @param ciphertext   Input ciphertext.
    * @return Masked decrypted ciphertext.
    *
    * @note For Server, expects ciphertext with both polynomials a and b.
    *       For Client, expects only the linear term a.
    *       Includes rounding as part of decryption.
    */
    Ciphertext<Element> IntBootDecrypt(const PrivateKey<Element> privateKey,
                                       ConstCiphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);
        ValidateKey(privateKey);
        return GetScheme()->IntBootDecrypt(privateKey, ciphertext);
    }

    /**
    * @brief Encrypts Client's masked decryption for interactive bootstrapping.
    *        Increases ciphertext modulus to allow further computation. Done by Client.
    *
    * @param publicKey   Joined public key (Threshold FHE).
    * @param ciphertext  Input ciphertext.
    * @return Encrypted ciphertext.
    */
    Ciphertext<Element> IntBootEncrypt(const PublicKey<Element> publicKey,
                                       ConstCiphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);
        ValidateKey(publicKey);
        return GetScheme()->IntBootEncrypt(publicKey, ciphertext);
    }

    /**
    * @brief Combines encrypted and unencrypted masked decryptions in 2-party interactive bootstrapping.
    *        It is the last step in the boostrapping.
    *
    * @param ciphertext1  Encrypted masked decryption.
    * @param ciphertext2  Unencrypted masked decryption.
    * @return Refreshed ciphertext.
    */
    Ciphertext<Element> IntBootAdd(ConstCiphertext<Element>& ciphertext1,
                                   ConstCiphertext<Element>& ciphertext2) const {
        ValidateCiphertext(ciphertext1);
        ValidateCiphertext(ciphertext2);
        return GetScheme()->IntBootAdd(ciphertext1, ciphertext2);
    }

    /**
    * @brief Prepares a ciphertext for interactive bootstrapping.
    *
    * @param ciphertext  Input ciphertext.
    * @return Adjusted ciphertext.
    *
    * @note CKKS FIXEDMANUAL/FIXEDAUTO: requires ≥ 2 towers; reduces to 2 towers and sets scale to Delta (not a power of Delta).
    *       CKKS FLEXIBLEAUTO: requires ≥ 3 towers; adjusts scale to level 0.
    */
    Ciphertext<Element> IntBootAdjustScale(ConstCiphertext<Element>& ciphertext) const {
        ValidateCiphertext(ciphertext);
        return GetScheme()->IntBootAdjustScale(ciphertext);
    }

    /**
    * @brief Prepares a ciphertext for multi-party interactive bootstrapping (Threshold FHE).
    *
    * @param ciphertext  Input ciphertext.
    * @return Adjusted ciphertext.
    */
    Ciphertext<Element> IntMPBootAdjustScale(ConstCiphertext<Element>& ciphertext) const;

    /**
    * @brief Generates a common random polynomial for Multi-Party Interactive Bootstrapping (Threshold FHE).
    *
    * @param publicKey  Scheme public key or lead party's public key.
    * @return Random ring element as ciphertext.
    */
    Ciphertext<Element> IntMPBootRandomElementGen(const PublicKey<Element> publicKey) const;

    /**
    * @brief Performs masked decryption as part of Multi-Party Interactive Bootstrapping (Threshold FHE).
    *        Each party calls this function as part of the protocol
    *
    * @param privateKey  Secret key share for the party.
    * @param ciphertext  Input ciphertext.
    * @param a           Common random polynomial.
    * @return Vector of masked decryption shares.
    */
    std::vector<Ciphertext<Element>> IntMPBootDecrypt(const PrivateKey<Element> privateKey,
                                                      ConstCiphertext<Element>& ciphertext,
                                                      ConstCiphertext<Element>& a) const;

    /**
    * @brief Aggregates masked decryption and re-encryption shares (Threshold FHE).
    *        It is the second step of the interactive multiparty bootstrapping procedure.
    *
    * @param sharesPairVec  Vector of (h_0i, h_1i) shares from each party.
    * @return Aggregated pair of shares (h_0, h_1).
    */
    std::vector<Ciphertext<Element>> IntMPBootAdd(std::vector<std::vector<Ciphertext<Element>>>& sharesPairVec) const;

    /**
    * @brief Encrypts the lead party's masked decryption result as the final step of Multi-Party Interactive Bootstrapping (Threshold FHE).
    *        It increases the ciphertext modulus and enables future computations. This operation is done by the lead party as the final step
    *        of interactive multi-party bootstrapping.
    *
    * @param publicKey   Lead party's public key.
    * @param sharesPair  Aggregated masked decryption and re-encryption shares.
    * @param a           Common random polynomial.
    * @param ciphertext  Input ciphertext.
    * @return Encrypted refreshed ciphertext.
    */
    Ciphertext<Element> IntMPBootEncrypt(const PublicKey<Element> publicKey,
                                         const std::vector<Ciphertext<Element>>& sharesPair,
                                         ConstCiphertext<Element>& a,
                                         ConstCiphertext<Element>& ciphertext) const;

    /**
    * @brief Performs secret sharing of a secret key for Threshold FHE with aborts.
    *
    * @param sk         Secret key to be shared.
    * @param N          Total number of parties.
    * @param threshold  Threshold number of parties required to reconstruct the key.
    * @param index      Index of the current party.
    * @param shareType  Type of secret sharing ("additive" or "shamir").
    * @return Map of secret key shares indexed by party ID.
    */
    std::unordered_map<uint32_t, Element> ShareKeys(const PrivateKey<Element>& sk, uint32_t N, uint32_t threshold,
                                                    uint32_t index, const std::string& shareType) const {
        std::string datatype = demangle(typeid(Element).name());
        OPENFHE_THROW("Not implemented for " + datatype);
    }

    /**
    * @brief Recovers a secret key share from existing shares for Threshold FHE with aborts.
    *
    * @param sk         Output: recovered secret key.
    * @param sk_shares  Map of secret key shares indexed by party ID.
    * @param N          Total number of parties.
    * @param threshold  Threshold number of parties required to reconstruct the key.
    * @param shareType  Type of secret sharing ("additive" or "shamir").
    */
    void RecoverSharedKey(PrivateKey<Element>& sk, std::unordered_map<uint32_t, Element>& sk_shares, uint32_t N,
                          uint32_t threshold, const std::string& shareType) const;

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
    * @brief Sets all bootstrapping parameters for both linear and FFT-like methods. Supported only in CKKS.
    *
    * @param levelBudget      Vector of level budgets for encoding and decoding.
    * @param dim1             Inner dimensions for baby-step giant-step routine.
    * @param slots            Number of slots to be bootstrapped.
    * @param correctionFactor Internal rescaling factor to improve precision (only for NATIVE_SIZE=64; 0 = default).
    * @param precompute       Whether to precompute plaintexts for encoding/decoding.
    */
    void EvalBootstrapSetup(std::vector<uint32_t> levelBudget = {5, 4}, std::vector<uint32_t> dim1 = {0, 0},
                            uint32_t slots = 0, uint32_t correctionFactor = 0, bool precompute = true) {
        GetScheme()->EvalBootstrapSetup(*this, levelBudget, dim1, slots, correctionFactor, precompute);
    }
    /**
    * @brief Generates automorphism keys for EvalBootstrap. Uses baby-step/giant-step strategy. Supported only in CKKS.
    *
    * @param privateKey  Secret key.
    * @param slots       Number of slots to support permutations on.
    */
    void EvalBootstrapKeyGen(const PrivateKey<Element> privateKey, uint32_t slots) {
        ValidateKey(privateKey);
        auto evalKeys = GetScheme()->EvalBootstrapKeyGen(privateKey, slots);
        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, privateKey->GetKeyTag());
    }

    /**
    * @brief Precomputes plaintexts for encoding and decoding used in bootstrapping. Supported only in CKKS.
    *
    * @param slots  Number of slots to be bootstrapped.
    */
    void EvalBootstrapPrecompute(uint32_t slots = 0) {
        GetScheme()->EvalBootstrapPrecompute(*this, slots);
    }

    /**
    * @brief Evaluates bootstrapping on a ciphertext using FFT-like or linear method. Supported only in CKKS.
    *
    * @param ciphertext     Input ciphertext.
    * @param numIterations  Number of Meta-BTS iterations to improve precision.
    * @param precision      Initial bootstrapping precision (set to 0 for default; tune experimentally).
    * @return Refreshed ciphertext.
    */
    Ciphertext<Element> EvalBootstrap(ConstCiphertext<Element>& ciphertext, uint32_t numIterations = 1,
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
    * @brief Sets all parameters for switching from CKKS to FHEW.
    *
    * @param params  Parameters for CKKS-to-FHEW scheme switching.
    * @return FHEW secret key.
    *
    * @note TODO: Add overload for pre-generated BinFHEContext.
    */
    LWEPrivateKey EvalCKKStoFHEWSetup(SchSwchParams params) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        SetParamsFromCKKSCryptocontext(params);
        return GetScheme()->EvalCKKStoFHEWSetup(params);
    }

    /**
    * @brief Generates keys for CKKS-to-FHEW scheme switching: rotation keys, conjugation keys, and switching key.
    *
    * @param keyPair  CKKS key pair.
    * @param lwesk    FHEW secret key.
    */
    void EvalCKKStoFHEWKeyGen(const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        ValidateKey(keyPair.secretKey);
        if (!lwesk)
            OPENFHE_THROW("FHEW private key passed to EvalCKKStoFHEWKeyGen is null");

        auto evalKeys = GetScheme()->EvalCKKStoFHEWKeyGen(keyPair, lwesk);
        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, keyPair.secretKey->GetKeyTag());
    }

    /**
    * @brief Performs precomputations for CKKS homomorphic decoding. Allows setting a custom scale factor. Given as
    *        a separate method than EvalCKKStoFHEWSetup to allow the user to specify a scale that depends on
    *        the CKKS and FHEW cryptocontexts
    *
    * @param scale  Scaling factor for the linear transform matrix.
    */
    void EvalCKKStoFHEWPrecompute(double scale = 1.0) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        GetScheme()->EvalCKKStoFHEWPrecompute(*this, scale);
    }

    /**
    * @brief Switches a CKKS ciphertext to a vector of FHEW ciphertexts.
    *
    * @param ciphertext  Input CKKS ciphertext.
    * @param numCtxts    Number of coefficients to extract (defaults to number of slots if 0).
    * @return Vector of LWE ciphertexts.
    */
    std::vector<std::shared_ptr<LWECiphertextImpl>> EvalCKKStoFHEW(ConstCiphertext<Element>& ciphertext,
                                                                   uint32_t numCtxts = 0) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        if (ciphertext == nullptr)
            OPENFHE_THROW("ciphertext passed to EvalCKKStoFHEW is empty");

        return GetScheme()->EvalCKKStoFHEW(ciphertext, numCtxts);
    }

    /**
    * @brief Sets parameters for switching from FHEW to CKKS. Requires existing CKKS context.
    *
    * @param ccLWE         Source FHEW crypto context.
    * @param numSlotsCKKS  Number of slots in resulting CKKS ciphertext.
    * @param logQ          Ciphertext modulus size in FHEW (for high precision).
    */
    void EvalFHEWtoCKKSSetup(const std::shared_ptr<BinFHEContext>& ccLWE, uint32_t numSlotsCKKS = 0,
                             uint32_t logQ = 25) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        GetScheme()->EvalFHEWtoCKKSSetup(*this, ccLWE, numSlotsCKKS, logQ);
    }

    /**
    * @brief Generates keys for switching from FHEW to CKKS.
    *
    * @param keyPair   CKKS key pair.
    * @param lwesk     FHEW secret key.
    * @param numSlots  Number of slots for CKKS encryption.
    * @param numCtxts  Number of LWE ciphertext values to encrypt.
    * @param dim1      Baby-step parameter for linear transform.
    * @param L         Target level for homomorphic decoding matrix.
    */
    void EvalFHEWtoCKKSKeyGen(const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk, uint32_t numSlots = 0,
                              uint32_t numCtxts = 0, uint32_t dim1 = 0, uint32_t L = 0) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        ValidateKey(keyPair.secretKey);

        auto evalKeys = GetScheme()->EvalFHEWtoCKKSKeyGen(keyPair, lwesk, numSlots, numCtxts, dim1, L);
        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, keyPair.secretKey->GetKeyTag());
    }

    /**
    * @brief Switches a vector of FHEW ciphertexts to a single CKKS ciphertext.
    *
    * @param LWECiphertexts  Input vector of FHEW ciphertexts.
    * @param numCtxts        Number of values to encode.
    * @param numSlots        Number of CKKS slots to use.
    * @param p               Plaintext modulus (default = 4).
    * @param pmin            Minimum expected plaintext value (default = 0.0).
    * @param pmax            Maximum expected plaintext value (default = 2.0).
    * @param dim1            Baby-step parameter (used in argmin).
    * @return CKKS ciphertext encoding the input LWE messages.
    */
    Ciphertext<Element> EvalFHEWtoCKKS(std::vector<std::shared_ptr<LWECiphertextImpl>>& LWECiphertexts,
                                       uint32_t numCtxts = 0, uint32_t numSlots = 0, uint32_t p = 4, double pmin = 0.0,
                                       double pmax = 2.0, uint32_t dim1 = 0) const {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        return GetScheme()->EvalFHEWtoCKKS(LWECiphertexts, numCtxts, numSlots, p, pmin, pmax, dim1);
    }

    /**
    * @brief Sets scheme switching parameters using the current CKKS crypto context.
    *
    * @param params  Scheme switching parameter object to populate.
    */
    void SetParamsFromCKKSCryptocontext(SchSwchParams& params) {
        const auto cryptoParams = std::dynamic_pointer_cast<CryptoParametersCKKSRNS>(GetCryptoParameters());
        if (!cryptoParams)
            OPENFHE_THROW("std::dynamic_pointer_cast<CryptoParametersCKKSRNS>() failed");
        params.SetInitialCKKSModulus(cryptoParams->GetElementParams()->GetParams()[0]->GetModulus());
        params.SetRingDimension(GetRingDimension());
        // TODO (dsuponit): is this correct - PlaintextModulus used as scalingModSize?
        params.SetScalingModSize(GetEncodingParams()->GetPlaintextModulus());
        params.SetBatchSize(GetEncodingParams()->GetBatchSize());
        params.SetParamsFromCKKSCryptocontextCalled();
    }

    /**
    * @brief Sets parameters for switching between CKKS and FHEW.
    *
    * @param params  Scheme switching parameter object.
    * @return FHEW secret key.
    *
    * @note TODO: Add overload for pre-generated BinFHEContext.
    */
    LWEPrivateKey EvalSchemeSwitchingSetup(SchSwchParams& params) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        SetParamsFromCKKSCryptocontext(params);
        return GetScheme()->EvalSchemeSwitchingSetup(params);
    }

    /**
    * @brief Generates keys for switching between CKKS and FHEW.
    *
    * @param keyPair  CKKS key pair.
    * @param lwesk    FHEW secret key.
    */
    void EvalSchemeSwitchingKeyGen(const KeyPair<Element>& keyPair, ConstLWEPrivateKey& lwesk) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        ValidateKey(keyPair.secretKey);

        auto evalKeys = GetScheme()->EvalSchemeSwitchingKeyGen(keyPair, lwesk);
        CryptoContextImpl<Element>::InsertEvalAutomorphismKey(evalKeys, keyPair.secretKey->GetKeyTag());
    }

    /**
    * @brief Performs precomputations for scheme switching in CKKS-to-FHEW comparison.
    *        Given as a separate method than EvalSchemeSwitchingSetup to allow the user to specify a scale.
    *
    * @param pLWE       Target plaintext modulus for FHEW ciphertexts.
    * @param scaleSign  Scaling factor for CKKS ciphertexts before switching.
    * @param unit       Indicates if input messages are normalized to unit circle.
    */
    void EvalCompareSwitchPrecompute(uint32_t pLWE = 0, double scaleSign = 1.0, bool unit = false) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        GetScheme()->EvalCompareSwitchPrecompute(*this, pLWE, scaleSign, unit);
    }

    /**
    * @brief Compares two CKKS ciphertexts using FHEW-based scheme switching and returns CKKS result.
    *
    * @param ciphertext1  First input CKKS ciphertext.
    * @param ciphertext2  Second input CKKS ciphertext.
    * @param numCtxts     Number of coefficients to extract.
    * @param numSlots     Number of slots to encode in the result.
    * @param pLWE         Target plaintext modulus for FHEW ciphertexts.
    * @param scaleSign    Scaling factor for CKKS ciphertexts before switching.
    * @param unit         Indicates if input messages are normalized to unit circle.
    * @return CKKS ciphertext encoding sign comparison result.
    */
    Ciphertext<Element> EvalCompareSchemeSwitching(ConstCiphertext<Element>& ciphertext1,
                                                   ConstCiphertext<Element>& ciphertext2, uint32_t numCtxts = 0,
                                                   uint32_t numSlots = 0, uint32_t pLWE = 0, double scaleSign = 1.0,
                                                   bool unit = false) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        ValidateCiphertext(ciphertext1);
        ValidateCiphertext(ciphertext2);
        return GetScheme()->EvalCompareSchemeSwitching(ciphertext1, ciphertext2, numCtxts, numSlots, pLWE, scaleSign,
                                                       unit);
    }

    /**
    * @brief Computes minimum and index of the first packed values using scheme switching.
    *
    * @param ciphertext  Input CKKS ciphertext.
    * @param publicKey   CKKS public key.
    * @param numValues   Number of values to compare (we assume that numValues is a power of two).
    * @param numSlots    Number of output slots.
    * @param pLWE        Target plaintext modulus for FHEW.
    * @param scaleSign   Scaling factor before switching to FHEW. The resulting FHEW ciphertexts will encrypt values modulo pLWE,
    *                    so scaleSign should account for this pLWE and is given here only if the homomorphic decoding matrix is
    *                    not scaled with the desired values
    * @return A vector of two CKKS ciphertexts: [min, argmin]. The ciphertexts have junk after the first slot in the first ciphertext
    *         and after numValues in the second ciphertext if oneHot=true and after the first slot if oneHot=false.
    */
    std::vector<Ciphertext<Element>> EvalMinSchemeSwitching(ConstCiphertext<Element>& ciphertext,
                                                            PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                            uint32_t numSlots = 0, uint32_t pLWE = 0,
                                                            double scaleSign = 1.0) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        ValidateCiphertext(ciphertext);
        return GetScheme()->EvalMinSchemeSwitching(ciphertext, publicKey, numValues, numSlots, pLWE, scaleSign);
    }

    /**
    * @brief Computes minimum and index using more FHEW operations than CKKS with higher precision, but slower than EvalMinSchemeSwitching.
    *
    * @param ciphertext  Input CKKS ciphertext.
    * @param publicKey   CKKS public key.
    * @param numValues   Number of packed values to compare.
    * @param numSlots    Number of slots in the output ciphertexts.
    * @param pLWE        Target plaintext modulus for FHEW ciphertexts.
    * @param scaleSign   Scaling factor before switching to FHEW.
    * @return A vector with two CKKS ciphertexts: [min, argmin].
    */
    std::vector<Ciphertext<Element>> EvalMinSchemeSwitchingAlt(ConstCiphertext<Element>& ciphertext,
                                                               PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                               uint32_t numSlots = 0, uint32_t pLWE = 0,
                                                               double scaleSign = 1.0) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        ValidateCiphertext(ciphertext);
        return GetScheme()->EvalMinSchemeSwitchingAlt(ciphertext, publicKey, numValues, numSlots, pLWE, scaleSign);
    }

    /**
    * @brief Computes maximum and index from the first packed values using scheme switching.
    *
    * @param ciphertext  Input CKKS ciphertext.
    * @param publicKey   CKKS public key.
    * @param numValues   Number of values to compare (we assume that numValues is a power of two).
    * @param numSlots    Number of output slots.
    * @param pLWE        Target plaintext modulus for FHEW.
    * @param scaleSign   Scaling factor before switching to FHEW.
    * @return A vector of two CKKS ciphertexts: [max, argmax]. The ciphertexts have junk after the first slot in the first ciphertext
    *         and after numValues in the second ciphertext if oneHot=true and after the first slot if oneHot=false.
    */
    std::vector<Ciphertext<Element>> EvalMaxSchemeSwitching(ConstCiphertext<Element>& ciphertext,
                                                            PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                            uint32_t numSlots = 0, uint32_t pLWE = 0,
                                                            double scaleSign = 1.0) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        ValidateCiphertext(ciphertext);
        return GetScheme()->EvalMaxSchemeSwitching(ciphertext, publicKey, numValues, numSlots, pLWE, scaleSign);
    }

    /**
    * @brief Computes max and index via scheme switching, with more FHEW operations for better precision than EvalMaxSchemeSwitching.
    *
    * @param ciphertext  Input CKKS ciphertext.
    * @param publicKey   CKKS public key.
    * @param numValues   Number of values to compare.
    * @param numSlots    Number of output slots.
    * @param pLWE        Target plaintext modulus for FHEW.
    * @param scaleSign   Scaling factor before switching to FHEW.
    * @return A vector of two CKKS ciphertexts: [max, argmax].
    */
    std::vector<Ciphertext<Element>> EvalMaxSchemeSwitchingAlt(ConstCiphertext<Element>& ciphertext,
                                                               PublicKey<Element> publicKey, uint32_t numValues = 0,
                                                               uint32_t numSlots = 0, uint32_t pLWE = 0,
                                                               double scaleSign = 1.0) {
        VerifyCKKSScheme(__func__);
        VerifyCKKSRealDataType(__func__);
        ValidateCiphertext(ciphertext);
        return GetScheme()->EvalMaxSchemeSwitchingAlt(ciphertext, publicKey, numValues, numSlots, pLWE, scaleSign);
    }

    /**
    * @brief Returns the BinFHE context used for scheme switching.
    * @return BinFHE context.
    */
    std::shared_ptr<lbcrypto::BinFHEContext> GetBinCCForSchemeSwitch() const {
        return GetScheme()->GetBinCCForSchemeSwitch();
    }

    /**
    * @brief Sets the BinFHE context to be used for scheme switching.
    * @param ccLWE BinFHE context.
    */
    void SetBinCCForSchemeSwitch(std::shared_ptr<lbcrypto::BinFHEContext> ccLWE) {
        GetScheme()->SetBinCCForSchemeSwitch(ccLWE);
    }

    /**
    * @brief Gets the FHEW-to-CKKS scheme switching key ciphertext.
    * @return Switching key ciphertext.
    */
    Ciphertext<Element> GetSwkFC() const {
        return GetScheme()->GetSwkFC();
    }

    /**
    * @brief Sets the FHEW-to-CKKS scheme switching key ciphertext.
    * @param FHEWtoCKKSswk Switching key ciphertext.
    */
    void SetSwkFC(Ciphertext<Element> FHEWtoCKKSswk) {
        GetScheme()->SetSwkFC(FHEWtoCKKSswk);
    }

    /**
    * @brief Returns automorphism indices for all existing evaluation keys.
    * @param keyTag      Secret key tag.
    * @return Set of indices found for the given key tag. Empty if none exist.
    */
    static std::set<uint32_t> GetExistingEvalAutomorphismKeyIndices(const std::string& keyTag);

    /**
    * @brief Compares two sets and returns unique values from the second set.
    * @param oldValues   First set to compare against.
    * @param newValues   Second set to extract unique values from.
    * @return Set of values present in newValues but not in oldValues.
    */
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
std::unordered_map<uint32_t, DCRTPoly> CryptoContextImpl<DCRTPoly>::ShareKeys(const PrivateKey<DCRTPoly>& sk,
                                                                              uint32_t N, uint32_t threshold,
                                                                              uint32_t index,
                                                                              const std::string& shareType) const;
}  // namespace lbcrypto

#endif /* SRC_PKE_CRYPTOCONTEXT_H_ */
