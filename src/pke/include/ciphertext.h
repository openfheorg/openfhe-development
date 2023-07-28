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
  Operations for the representation of ciphertext in OpenFHE
 */

#ifndef LBCRYPTO_CRYPTO_CIPHERTEXT_H
#define LBCRYPTO_CRYPTO_CIPHERTEXT_H

#include "ciphertext-fwd.h"
#include "cryptoobject.h"

#include "metadata.h"
#include "key/key.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

namespace lbcrypto {
/**
 * @brief CiphertextImpl
 *
 * The CiphertextImpl object is used to contain encrypted text in the OpenFHE
 * library
 *
 * @tparam Element a ring element.
 */
template <class Element>
class CiphertextImpl : public CryptoObject<Element> {
public:
    /**
   * Default constructor
   */
    CiphertextImpl() : CryptoObject<Element>() {}

    /**
   * Construct a new ciphertext in the given context
   *
   * @param cc
   */
    explicit CiphertextImpl(CryptoContext<Element> cc, const std::string& id = "",
                            PlaintextEncodings encType = INVALID_ENCODING)
        : CryptoObject<Element>(cc, id), encodingType(encType) {}

    /**
   * Construct a new ciphertext from the parameters of a given public key
   *
   * @param k key whose CryptoObject parameters will get cloned
   */
    explicit CiphertextImpl(const std::shared_ptr<Key<Element>> k)
        : CryptoObject<Element>(k->GetCryptoContext(), k->GetKeyTag()) {}

    /**
   * Copy constructor
   */
    CiphertextImpl(const CiphertextImpl<Element>& ciphertext) : CryptoObject<Element>(ciphertext) {
        m_elements         = ciphertext.m_elements;
        m_noiseScaleDeg    = ciphertext.m_noiseScaleDeg;
        m_level            = ciphertext.m_level;
        m_hopslevel        = ciphertext.m_hopslevel;
        m_scalingFactor    = ciphertext.m_scalingFactor;
        m_scalingFactorInt = ciphertext.m_scalingFactorInt;
        encodingType       = ciphertext.encodingType;
        m_slots            = ciphertext.m_slots;
        m_metadataMap      = ciphertext.m_metadataMap;
    }

    explicit CiphertextImpl(Ciphertext<Element> ciphertext) : CryptoObject<Element>(*ciphertext) {
        m_elements         = ciphertext->m_elements;
        m_noiseScaleDeg    = ciphertext->m_noiseScaleDeg;
        m_level            = ciphertext->m_level;
        m_hopslevel        = ciphertext->m_hopslevel;
        m_scalingFactor    = ciphertext->m_scalingFactor;
        m_scalingFactorInt = ciphertext->m_scalingFactorInt;
        encodingType       = ciphertext->encodingType;
        m_slots            = ciphertext->m_slots;
        m_metadataMap      = ciphertext->m_metadataMap;
    }

    /**
   * Move constructor
   */
    CiphertextImpl(CiphertextImpl<Element>&& ciphertext) : CryptoObject<Element>(ciphertext) {
        m_elements         = std::move(ciphertext.m_elements);
        m_noiseScaleDeg    = std::move(ciphertext.m_noiseScaleDeg);
        m_level            = std::move(ciphertext.m_level);
        m_hopslevel        = std::move(ciphertext.m_hopslevel);
        m_scalingFactor    = std::move(ciphertext.m_scalingFactor);
        m_scalingFactorInt = std::move(ciphertext.m_scalingFactorInt);
        encodingType       = std::move(ciphertext.encodingType);
        m_slots            = std::move(ciphertext.m_slots);
        m_metadataMap      = std::move(ciphertext.m_metadataMap);
    }

    explicit CiphertextImpl(Ciphertext<Element>&& ciphertext) : CryptoObject<Element>(*ciphertext) {
        m_elements         = std::move(ciphertext->m_elements);
        m_noiseScaleDeg    = std::move(ciphertext->m_noiseScaleDeg);
        m_level            = std::move(ciphertext->m_level);
        m_hopslevel        = std::move(ciphertext->m_hopslevel);
        m_scalingFactor    = std::move(ciphertext->m_scalingFactor);
        m_scalingFactorInt = std::move(ciphertext->m_scalingFactorInt);
        encodingType       = std::move(ciphertext->encodingType);
        m_slots            = std::move(ciphertext->m_slots);
        m_metadataMap      = std::move(ciphertext->m_metadataMap);
    }

    /**
   * This method creates a copy of this, skipping the actual encrypted
   * elements. This means it copies parameters, key tags, encoding type,
   * and metadata.
   */
    virtual Ciphertext<Element> CloneEmpty() const {
        Ciphertext<Element> ct(std::make_shared<CiphertextImpl<Element>>(this->GetCryptoContext(), this->GetKeyTag(),
                                                                         this->GetEncodingType()));

        ct->m_metadataMap    = std::make_shared<std::map<std::string, std::shared_ptr<Metadata>>>();
        *(ct->m_metadataMap) = *(this->m_metadataMap);

        return ct;
    }

    /**
   * Destructor
   */
    virtual ~CiphertextImpl() {}

    /**
   * GetEncodingType
   * @return how the Plaintext that this CiphertextImpl was created from was
   * encoded
   */
    PlaintextEncodings GetEncodingType() const {
        return encodingType;
    }

    /**
   * SetEncodingType - after Encrypt, remember the CiphertextImpl's encoding
   * type
   * @param et
   */
    void SetEncodingType(PlaintextEncodings et) {
        encodingType = et;
    }

    /**
   * Assignment Operator.
   *
   * @param &rhs the CiphertextImpl to assign from
   * @return this CiphertextImpl
   */
    CiphertextImpl<Element>& operator=(const CiphertextImpl<Element>& rhs) {
        if (this != &rhs) {
            CryptoObject<Element>::operator=(rhs);
            this->m_elements         = rhs.m_elements;
            this->m_noiseScaleDeg    = rhs.m_noiseScaleDeg;
            this->m_level            = rhs.m_level;
            this->m_hopslevel        = rhs.m_hopslevel;
            this->m_scalingFactor    = rhs.m_scalingFactor;
            this->m_scalingFactorInt = rhs.m_scalingFactorInt;
            this->encodingType       = rhs.encodingType;
            this->m_slots            = rhs.m_slots;
            this->m_metadataMap      = rhs.m_metadataMap;
        }

        return *this;
    }

    /**
   * Move Assignment Operator.
   *
   * @param &rhs the CiphertextImpl to move from
   * @return this CiphertextImpl
   */
    CiphertextImpl<Element>& operator=(CiphertextImpl<Element>&& rhs) {
        if (this != &rhs) {
            CryptoObject<Element>::operator=(rhs);
            this->m_elements         = std::move(rhs.m_elements);
            this->m_noiseScaleDeg    = std::move(rhs.m_noiseScaleDeg);
            this->m_level            = std::move(rhs.m_level);
            this->m_hopslevel        = std::move(rhs.m_hopslevel);
            this->m_scalingFactor    = std::move(rhs.m_scalingFactor);
            this->m_scalingFactorInt = std::move(rhs.m_scalingFactorInt);
            this->encodingType       = std::move(rhs.encodingType);
            this->m_slots            = std::move(rhs.m_slots);
            this->m_metadataMap      = std::move(rhs.m_metadataMap);
        }

        return *this;
    }

    /**
   * GetElement - get the ring element for the cases that use only one element
   * in the vector this method will throw an exception if it's ever called in
   * cases with other than 1 element
   * @return the first (and only!) ring element
   */
    const Element& GetElement() const {
        if (m_elements.size() == 1)
            return m_elements[0];

        OPENFHE_THROW(config_error,
                      "GetElement should only be used in cases with a "
                      "Ciphertext with a single element");
    }

    /**
   * GetElement - get the ring element for the cases that use only one element
   * in the vector this method will throw an exception if it's ever called in
   * cases with other than 1 element
   * @return the first (and only!) ring element
   */
    Element& GetElement() {
        if (m_elements.size() == 1)
            return m_elements[0];

        OPENFHE_THROW(config_error,
                      "GetElement should only be used in cases with a "
                      "Ciphertext with a single element");
    }

    /**
   * GetElements: get all of the ring elements in the CiphertextImpl
   * @return vector of ring elements
   */
    const std::vector<Element>& GetElements() const {
        return m_elements;
    }

    /**
   * GetElements: get all of the ring elements in the CiphertextImpl
   * @return vector of ring elements
   */
    std::vector<Element>& GetElements() {
        return m_elements;
    }

    /**
   * SetElement - sets the ring element for the cases that use only one element
   * in the vector this method will throw an exception if it's ever called in
   * cases with other than 1 element
   * @param &element is a polynomial ring element.
   */
    void SetElement(const Element& element) {
        if (m_elements.size() == 0)
            m_elements.push_back(element);
        else if (m_elements.size() == 1)
            m_elements[0] = element;
        else
            OPENFHE_THROW(config_error,
                          "SetElement should only be used in cases with a "
                          "Ciphertext with a single element");
    }

    /**
   * Sets the data elements.
   *
   * @param &element is a polynomial ring element.
   */
    void SetElements(const std::vector<Element>& elements) {
        m_elements = elements;
    }

    /**
   * Sets the data elements by std::move.
   *
   * @param &&element is a polynomial ring element.
   */
    void SetElements(std::vector<Element>&& elements) {
        m_elements = std::move(elements);
    }

    /**
   * Get the degree of the scaling factor for the encrypted message.
   */
    size_t GetNoiseScaleDeg() const {
        return m_noiseScaleDeg;
    }

    /**
   * Set the degree of the scaling factor for the encrypted message.
   */
    void SetNoiseScaleDeg(size_t noiseScaleDeg) {
        m_noiseScaleDeg = noiseScaleDeg;
    }

    /**
   * Get the number of scalings performed
   */
    size_t GetLevel() const {
        return m_level;
    }

    /**
   * Set the number of scalings
   */
    void SetLevel(size_t level) {
        m_level = level;
    }

    /**
   * Get the re-encryption level of the ciphertext.
   */
    size_t GetHopLevel() const {
        return m_hopslevel;
    }

    /**
   * Set the re-encryption level of the ciphertext.
   */
    void SetHopLevel(size_t hoplevel) {
        m_hopslevel = hoplevel;
    }

    /**
   * Get the scaling factor of the ciphertext.
   */
    double GetScalingFactor() const {
        return m_scalingFactor;
    }

    /**
   * Set the scaling factor of the ciphertext.
   */
    void SetScalingFactor(double sf) {
        m_scalingFactor = sf;
    }

    /**
   * Get the scaling factor of the ciphertext.
   */
    const NativeInteger& GetScalingFactorInt() const {
        return m_scalingFactorInt;
    }

    /**
   * Set the scaling factor of the ciphertext.
   */
    void SetScalingFactorInt(const NativeInteger sf) {
        m_scalingFactorInt = sf;
    }

    /**
   * Get the number of slots of the ciphertext.
   */
    size_t GetSlots() const {
        return m_slots;
    }

    /**
   * Set the number of slots of the ciphertext.
   */
    void SetSlots(usint slots) {
        m_slots = slots;
    }

    /**
   * Get the Metadata map of the ciphertext.
   */
    MetadataMap GetMetadataMap() const {
        return this->m_metadataMap;
    }

    /**
   * Set the Metadata map of the ciphertext.
   */
    void SetMetadataMap(const MetadataMap& mdata) {
        this->m_metadataMap = mdata;
    }

    /**
   * This method searches the metadata map for metadata of a specific key.
   *
   * @param key the string value which serves as a key in the metadata map
   * @return an iterator pointing at the position in the map where the key
   *         was found (or the map.end() if not found).
   */
    std::map<std::string, std::shared_ptr<Metadata>>::iterator FindMetadataByKey(std::string key) const {
        return m_metadataMap->find(key);
    }

    /**
   * This method checks whether an iterator return from FindMetadataByKey
   * corresponds to whether the key was found or not.
   *
   * @param it iterator pointing at the position in the map where the key
   *         was found (or the map.end() if not found).
   * @return a boolean value indicating whether the key was found or not.
   */
    bool MetadataFound(std::map<std::string, std::shared_ptr<Metadata>>::iterator it) const {
        return (it != m_metadataMap->end());
    }

    /**
   * This method returns the Metadata object stored in the iterator position
   * returned by FindMetadataByKey.
   *
   * @param it iterator pointing at the position in the map where the key
   *         was found (or the map.end() if not found).
   * @return a shared pointer pointing to the Metadata object in the map.
   */
    std::shared_ptr<Metadata>& GetMetadata(std::map<std::string, std::shared_ptr<Metadata>>::iterator it) const {
        return it->second;
    }

    /**
   * Get a Metadata element from the Metadata map of the ciphertext.
   */
    std::shared_ptr<Metadata> GetMetadataByKey(const std::string& key) const {
        auto it = m_metadataMap->find(key);
        if(it == m_metadataMap->end()) {
            OPENFHE_THROW(openfhe_error, "Metadata element with key [" + key + "] is not found in the Metadata map.");
        }
        return std::make_shared<Metadata>(*(it->second));
    }

    /**
   * Set a Metadata element in the Metadata map of the ciphertext.
   */
    void SetMetadataByKey(const std::string& key, std::shared_ptr<Metadata> value) {
        (*m_metadataMap)[key] = std::move(value);
    }

    virtual Ciphertext<Element> Clone() const {
        Ciphertext<Element> cRes = this->CloneZero();
        cRes->SetElements(this->GetElements());

        return cRes;
    }

    virtual Ciphertext<Element> CloneZero() const {
        Ciphertext<Element> cRes = this->CloneEmpty();
        cRes->SetNoiseScaleDeg(this->GetNoiseScaleDeg());
        cRes->SetLevel(this->GetLevel());
        cRes->SetHopLevel(this->GetHopLevel());
        cRes->SetScalingFactor(this->GetScalingFactor());
        cRes->SetScalingFactorInt(this->GetScalingFactorInt());
        cRes->SetSlots(this->GetSlots());

        return cRes;
    }

    bool operator==(const CiphertextImpl<Element>& rhs) const {
        if (!CryptoObject<Element>::operator==(rhs))
            return false;

        if (this->m_noiseScaleDeg != rhs.m_noiseScaleDeg)
            return false;

        if (this->m_level != rhs.m_level)
            return false;

        if (this->m_hopslevel != rhs.m_hopslevel)
            return false;

        if (this->m_scalingFactor != rhs.m_scalingFactor)
            return false;

        if (this->m_scalingFactorInt != rhs.m_scalingFactorInt)
            return false;

        if (this->m_slots != rhs.m_slots)
            return false;

        const std::vector<Element>& lhsE = this->GetElements();
        const std::vector<Element>& rhsE = rhs.GetElements();

        if (lhsE.size() != rhsE.size())
            return false;

        for (size_t i = 0; i < lhsE.size(); i++) {
            const Element& lE = lhsE[i];
            const Element& rE = rhsE[i];

            if (lE != rE)
                return false;
        }

        const std::shared_ptr<std::map<std::string, std::shared_ptr<Metadata>>> lhsMap = this->m_metadataMap;
        const std::shared_ptr<std::map<std::string, std::shared_ptr<Metadata>>> rhsMap = rhs.m_metadataMap;

        if (lhsMap->size() != rhsMap->size())
            return false;

        if (lhsMap->size() > 0) {
            for (auto i = lhsMap->begin(), j = rhsMap->begin(); i != lhsMap->end(); ++i, ++j)
                if (!(*(i->second) == *(j->second)))
                    return false;
        }

        return true;
    }

    bool operator!=(const CiphertextImpl<Element>& rhs) const {
        return !(*this == rhs);
    }

    friend std::ostream& operator<<(std::ostream& out, const CiphertextImpl<Element>& c) {
        out << "enc=" << c.encodingType << " noiseScaleDeg=" << c.m_noiseScaleDeg << std::endl;
        out << "metadata: [ ";
        for (auto i = c.m_metadataMap->begin(); i != c.m_metadataMap->end(); ++i)
            out << "(\"" << i->first << "\", " << *(i->second) << ") ";
        out << "]" << std::endl;
        for (size_t i = 0; i < c.m_elements.size(); i++) {
            if (i != 0)
                out << std::endl;
            out << "Element " << i << ": " << c.m_elements[i];
        }
        return out;
    }

    friend std::ostream& operator<<(std::ostream& out, Ciphertext<Element> c) {
        return out << *c;
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<CryptoObject<Element>>(this));
        ar(cereal::make_nvp("v", m_elements));
        ar(cereal::make_nvp("d", m_noiseScaleDeg));
        ar(cereal::make_nvp("l", m_level));
        ar(cereal::make_nvp("t", m_hopslevel));
        ar(cereal::make_nvp("s", m_scalingFactor));
        ar(cereal::make_nvp("si", m_scalingFactorInt));
        ar(cereal::make_nvp("e", encodingType));
        ar(cereal::make_nvp("sl", m_slots));
        ar(cereal::make_nvp("m", m_metadataMap));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(cereal::base_class<CryptoObject<Element>>(this));
        ar(cereal::make_nvp("v", m_elements));
        ar(cereal::make_nvp("d", m_noiseScaleDeg));
        ar(cereal::make_nvp("l", m_level));
        ar(cereal::make_nvp("t", m_hopslevel));
        ar(cereal::make_nvp("s", m_scalingFactor));
        ar(cereal::make_nvp("si", m_scalingFactorInt));
        ar(cereal::make_nvp("e", encodingType));
        ar(cereal::make_nvp("sl", m_slots));
        ar(cereal::make_nvp("m", m_metadataMap));
    }

    std::string SerializedObjectName() const {
        return "Ciphertext";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    // vector of ring elements for this Ciphertext
    std::vector<Element> m_elements;

    // the degree of the scaling factor for the encrypted message.
    uint32_t m_noiseScaleDeg = 1;

    // how was this Ciphertext encoded?
    PlaintextEncodings encodingType = INVALID_ENCODING;

    double m_scalingFactor           = 1;
    NativeInteger m_scalingFactorInt = 1;
    // holds the number of scalings performed before getting this ciphertext - initially 0
    uint32_t m_level = 0;

    // Parameter for re-encryption to store the number of times the ciphertext has been re-encrypted.
    uint32_t m_hopslevel = 0;

    uint32_t m_slots = 0;

    // A map to hold different Metadata objects - used for flexible extensions of Ciphertext
    MetadataMap m_metadataMap = std::make_shared<std::map<std::string, std::shared_ptr<Metadata>>>();
};

// TODO the op= are not doing the work in-place, and should be updated

/**
 * operator+ overload for Ciphertexts.  Performs EvalAdd.
 *
 * @tparam Element a ring element.
 * @param &a ciphertext operand
 * @param &b ciphertext operand
 *
 * @return The result of addition.
 */
template <class Element>
Ciphertext<Element> operator+(const Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a->GetCryptoContext()->EvalAdd(a, b);
}

/**
 * operator+= overload for Ciphertexts.  Performs EvalAdd.
 *
 * @tparam Element a ring element.
 * @param &a ciphertext to be added to
 * @param &b ciphertext to add to &a
 *
 * @return &a
 */
template <class Element>
const Ciphertext<Element>& operator+=(Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a = a->GetCryptoContext()->EvalAdd(a, b);
}

/**
 * Unary negation operator.
 *
 * @param &a ciphertext operand
 * @return the result of the negation.
 */
template <class Element>
Ciphertext<Element> operator-(const Ciphertext<Element>& a) {
    return a->GetCryptoContext()->EvalNegate(a);
}

/**
 * operator- overload.  Performs EvalSub.
 *
 * @tparam Element a ring element.
 * @param &a ciphertext operand
 * @param &b ciphertext operand
 *
 * @return The result of subtraction.
 */
template <class Element>
Ciphertext<Element> operator-(const Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a->GetCryptoContext()->EvalSub(a, b);
}

/**
 * operator-= overload for Ciphertexts.  Performs EvalAdd.
 *
 * @tparam Element a ring element.
 * @param &a ciphertext to be subtracted from
 * @param &b ciphertext to subtract from &a
 *
 * @return &a
 */
template <class Element>
const Ciphertext<Element>& operator-=(Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a = a->GetCryptoContext()->EvalSub(a, b);
}

/**
 * operator* overload.  Performs EvalMult.
 *
 * @tparam Element a ring element.
 * @param &a ciphertext operand
 * @param &b ciphertext operand
 *
 * @return The result of multiplication.
 */
template <class Element>
Ciphertext<Element> operator*(const Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a->GetCryptoContext()->EvalMult(a, b);
}

/**
 * operator*= overload for Ciphertexts.  Performs EvalMult.
 *
 * @tparam Element a ring element.
 * @param &a ciphertext to be multiplied
 * @param &b ciphertext to multiply by &a
 *
 * @return &a
 */
template <class Element>
const Ciphertext<Element>& operator*=(Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a = a->GetCryptoContext()->EvalMult(a, b);
}

}  // namespace lbcrypto

#endif
