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
#include "key/key.h"
#include "metadata.h"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

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
    CiphertextImpl() = default;

    /**
   * Construct a new ciphertext in the given context
   *
   * @param cc
   */
    explicit CiphertextImpl(const CryptoContext<Element>& cc, const std::string& id = "",
                            PlaintextEncodings encType = INVALID_ENCODING)
        : CryptoObject<Element>(cc, id), m_encodingType(encType) {}

    /**
   * Construct a new ciphertext from the parameters of a given public key
   *
   * @param k key whose CryptoObject parameters will get cloned
   */
    explicit CiphertextImpl(const std::shared_ptr<Key<Element>>& k)
        : CryptoObject<Element>(k->GetCryptoContext(), k->GetKeyTag()) {}

    /**
   * Copy constructor
   */
    CiphertextImpl(const CiphertextImpl<Element>& ct) = default;

    explicit CiphertextImpl(const Ciphertext<Element>& ct)
        : CryptoObject<Element>(*ct),
          m_elements(ct->m_elements),
          m_slots(ct->m_slots),
          m_level(ct->m_level),
          m_hopslevel(ct->m_hopslevel),
          m_noiseScaleDeg(ct->m_noiseScaleDeg),
          m_scalingFactor(ct->m_scalingFactor),
          m_scalingFactorInt(ct->m_scalingFactorInt),
          m_encodingType(ct->m_encodingType),
          m_metadataMap(ct->m_metadataMap) {}

    /**
   * Move constructor
   */
    CiphertextImpl(CiphertextImpl<Element>&& ct) noexcept = default;

    explicit CiphertextImpl(Ciphertext<Element>&& ct) noexcept
        : CryptoObject<Element>(std::move(*ct)),
          m_elements(std::move(ct->m_elements)),
          m_slots(std::move(ct->m_slots)),
          m_level(std::move(ct->m_level)),
          m_hopslevel(std::move(ct->m_hopslevel)),
          m_noiseScaleDeg(std::move(ct->m_noiseScaleDeg)),
          m_scalingFactor(std::move(ct->m_scalingFactor)),
          m_scalingFactorInt(std::move(ct->m_scalingFactorInt)),
          m_encodingType(std::move(ct->m_encodingType)),
          m_metadataMap(std::move(ct->m_metadataMap)) {}

    /**
   * Destructor
   */
    virtual ~CiphertextImpl() = default;

    /**
   * Assignment Operator.
   *
   * @param &rhs the CiphertextImpl to assign from
   * @return this CiphertextImpl
   */
    CiphertextImpl<Element>& operator=(const CiphertextImpl<Element>& rhs) = default;

    /**
   * Move Assignment Operator.
   *
   * @param &rhs the CiphertextImpl to move from
   * @return this CiphertextImpl
   */
    CiphertextImpl<Element>& operator=(CiphertextImpl<Element>&& rhs) noexcept = default;

    /**
   * GetElement - get the ring element for the cases that use only one element
   * in the vector this method will throw an exception if it's ever called in
   * cases with other than 1 element
   * @return the first (and only!) ring element
   */
    const Element& GetElement() const {
        if (m_elements.size() == 1)
            return m_elements[0];
        OPENFHE_THROW(
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
        OPENFHE_THROW(
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

    size_t NumberCiphertextElements() const {
        return m_elements.size();
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
            OPENFHE_THROW(
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
    void SetElements(std::vector<Element>&& elements) noexcept {
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
    // Generic case: no multiplicativeDepth validation. SetLevel() has a specialization for DCRTPoly
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
    NativeInteger GetScalingFactorInt() const {
        return m_scalingFactorInt;
    }

    /**
   * Set the scaling factor of the ciphertext.
   */
    void SetScalingFactorInt(NativeInteger sf) {
        m_scalingFactorInt = sf;
    }

    /**
   * Get the number of slots of the ciphertext.
   */
    uint32_t GetSlots() const {
        return m_slots;
    }

    /**
   * Set the number of slots of the ciphertext.
   */
    void SetSlots(uint32_t slots) {
        m_slots = slots;
    }

    /**
   * GetEncodingType
   * @return how the Plaintext that this CiphertextImpl was created from was
   * encoded
   */
    PlaintextEncodings GetEncodingType() const {
        return m_encodingType;
    }

    /**
   * SetEncodingType - after Encrypt, remember the CiphertextImpl's encoding
   * type
   * @param et
   */
    void SetEncodingType(PlaintextEncodings et) {
        m_encodingType = et;
    }

    /**
   * Get the Metadata map of the ciphertext.
   */
    MetadataMap GetMetadataMap() const {
        return m_metadataMap;
    }

    /**
   * Set the Metadata map of the ciphertext.
   */
    void SetMetadataMap(const MetadataMap& mdata) {
        m_metadataMap = mdata;
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
        if (it == m_metadataMap->end())
            OPENFHE_THROW("Metadata element with key [" + key + "] is not found in the Metadata map.");
        return std::make_shared<Metadata>(*(it->second));
    }

    /**
   * Set a Metadata element in the Metadata map of the ciphertext.
   */
    void SetMetadataByKey(const std::string& key, const std::shared_ptr<Metadata>& value) {
        (*m_metadataMap)[key] = value;
    }

    /**
   * This method creates a copy of this, skipping the actual encrypted
   * elements. This means it copies parameters, key tags, encoding type,
   * and metadata.
   */
    virtual Ciphertext<Element> CloneEmpty() const {
        auto ct(std::make_shared<CiphertextImpl<Element>>(this->GetCryptoContext(), this->GetKeyTag(), m_encodingType));
        ct->m_slots            = m_slots;
        ct->m_level            = m_level;
        ct->m_hopslevel        = m_hopslevel;
        ct->m_noiseScaleDeg    = m_noiseScaleDeg;
        ct->m_scalingFactor    = m_scalingFactor;
        ct->m_scalingFactorInt = m_scalingFactorInt;
        *(ct->m_metadataMap)   = *(m_metadataMap);
        return ct;
    }

    virtual Ciphertext<Element> Clone() const {
        auto ct        = this->CloneEmpty();
        ct->m_elements = m_elements;
        return ct;
    }

    bool operator==(const CiphertextImpl<Element>& rhs) const {
        if (!CryptoObject<Element>::operator==(rhs))
            return false;
        if (m_slots != rhs.m_slots)
            return false;
        if (m_level != rhs.m_level)
            return false;
        if (m_hopslevel != rhs.m_hopslevel)
            return false;
        if (m_noiseScaleDeg != rhs.m_noiseScaleDeg)
            return false;
        if (m_scalingFactor != rhs.m_scalingFactor)
            return false;
        if (m_scalingFactorInt != rhs.m_scalingFactorInt)
            return false;
        if (m_encodingType != rhs.m_encodingType)
            return false;
        if (m_metadataMap->size() != rhs.m_metadataMap->size())
            return false;
        for (auto x = m_metadataMap->begin(), y = rhs.m_metadataMap->begin(); x != m_metadataMap->end(); ++x, ++y)
            if (*(x->second) != *(y->second))
                return false;
        if (m_elements != rhs.m_elements)
            return false;
        return true;
    }

    bool operator!=(const CiphertextImpl<Element>& rhs) const {
        return !(*this == rhs);
    }

    friend std::ostream& operator<<(std::ostream& out, const CiphertextImpl<Element>& c) {
        out << "enc=" << c.m_encodingType << " noiseScaleDeg=" << c.m_noiseScaleDeg << std::endl;
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
        ar(cereal::make_nvp("sl", m_slots));
        ar(cereal::make_nvp("l", m_level));
        ar(cereal::make_nvp("t", m_hopslevel));
        ar(cereal::make_nvp("d", m_noiseScaleDeg));
        ar(cereal::make_nvp("s", m_scalingFactor));
        ar(cereal::make_nvp("si", m_scalingFactorInt));
        ar(cereal::make_nvp("e", m_encodingType));
        ar(cereal::make_nvp("m", m_metadataMap));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion())
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        ar(cereal::base_class<CryptoObject<Element>>(this));
        ar(cereal::make_nvp("v", m_elements));
        ar(cereal::make_nvp("sl", m_slots));
        ar(cereal::make_nvp("l", m_level));
        ar(cereal::make_nvp("t", m_hopslevel));
        ar(cereal::make_nvp("d", m_noiseScaleDeg));
        ar(cereal::make_nvp("s", m_scalingFactor));
        ar(cereal::make_nvp("si", m_scalingFactorInt));
        ar(cereal::make_nvp("e", m_encodingType));
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

    uint32_t m_slots{0};

    // holds the number of scalings performed before getting this ciphertext - initially 0
    uint32_t m_level{0};

    // Parameter for re-encryption to store the number of times the ciphertext has been re-encrypted.
    uint32_t m_hopslevel{0};

    // the degree of the scaling factor for the encrypted message.
    uint32_t m_noiseScaleDeg{1};

    double m_scalingFactor{1.0};

    NativeInteger m_scalingFactorInt{1};

    // how was this Ciphertext encoded?
    PlaintextEncodings m_encodingType{INVALID_ENCODING};

    // A map to hold different Metadata objects - used for flexible extensions of Ciphertext
    MetadataMap m_metadataMap{std::make_shared<std::map<std::string, std::shared_ptr<Metadata>>>()};
};

template <>
void CiphertextImpl<DCRTPoly>::SetLevel(size_t level);

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
Ciphertext<Element>& operator+=(Ciphertext<Element>& a, const Ciphertext<Element>& b) {
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
Ciphertext<Element>& operator-=(Ciphertext<Element>& a, const Ciphertext<Element>& b) {
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
Ciphertext<Element>& operator*=(Ciphertext<Element>& a, const Ciphertext<Element>& b) {
    return a = a->GetCryptoContext()->EvalMult(a, b);
}

}  // namespace lbcrypto

#endif
