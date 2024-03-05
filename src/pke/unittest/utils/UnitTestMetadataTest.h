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
#ifndef __UNITTESTMETADATATEST_H__
#define __UNITTESTMETADATATEST_H__

#include "metadata.h"
#include "ciphertext.h"

#include <memory>
#include <string>
#include <ostream>

namespace lbcrypto {

/**
 * @brief Example class inheriting from Metadata and adding a member.
 * This is used in unit tests.
 */
class MetadataTest : public Metadata {
public:
    /**
   * Default constructor
   */
    MetadataTest() : Metadata(), m_s("") {}
    /**
   * Destructor
   */
    virtual ~MetadataTest() {}

    /**
   * Copy constructor
   */
    MetadataTest(const MetadataTest& mdata) : Metadata() {
        m_s = mdata.m_s;
    }

    /**
   * This method creates a new MetadataTest object.
   *
   * Since Ciphertexts have a map of shared_ptr<Metadata>,
   * whenever we retrieve the contents of the map, we actually
   * get the shared pointer and we do not create a new object.
   *
   * If we do want to create a new object (e.g., because we
   * want to modify it only for a new Ciphertext), we can use
   * the Clone method.
   *
   */
    std::shared_ptr<Metadata> Clone() const {
        auto mdata = std::make_shared<MetadataTest>();
        mdata->m_s = this->m_s;
        return mdata;
    }

    /**
   * Setter method for the only value stored in this Metadata container.
   */
    void SetMetadata(std::string str) {
        m_s = std::string(str);
    }

    /**
   * This method returns the (only) value stored in this Metadata container
   */
    std::string GetMetadata() const {
        return m_s;
    }

    /**
   * Defines how to check equality between objects of this class.
   */
    bool operator==(const Metadata& mdata) const {
        try {
            const MetadataTest& mdataTest = dynamic_cast<const MetadataTest&>(mdata);
            return m_s == mdataTest.GetMetadata();  // All Metadata objects without
                                                    // any members are equal
        }
        catch (const std::bad_cast& e) {
            OPENFHE_THROW("Tried to downcast an object of different class to MetadataTest");
        }
    }

    /**
   * Defines how to print the contents of objects of this class.
   */
    std::ostream& print(std::ostream& out) const {
        out << "[ " << m_s << " ]";
        return out;
    }

    /**
   * save method for serialization
   */
    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(cereal::base_class<Metadata>(this));
        ar(cereal::make_nvp("str", m_s));
    }

    /**
   * load method for serialization
   */
    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(cereal::base_class<Metadata>(this));
        ar(cereal::make_nvp("str", m_s));
    }

    /**
   * This static method retrieves a MetadataTest object
   * from a Ciphertext, and clones it so we can further
   * modify it.
   *
   * @param ciphertext the ciphertext whose metadata to retrieve.
   */
    template <class Element>
    static const std::shared_ptr<MetadataTest> CloneMetadata(
        const std::shared_ptr<const CiphertextImpl<Element>> ciphertext) {
        auto it = ciphertext->FindMetadataByKey("test");

        if (ciphertext->MetadataFound(it)) {
            return std::dynamic_pointer_cast<MetadataTest>(ciphertext->GetMetadata(it)->Clone());
        }
        else {
            OPENFHE_THROW("Attempt to access metadata (MetadataTest) that has not been set.");
        }
    }

    /**
   * This static method retrieves a MetadataTest object
   * from a Ciphertext, without cloning it. This means that any
   * modifications on the MetadataTest object will affect the
   * original Ciphertext we retrieved the metadata from.
   *
   * @param ciphertext the ciphertext whose metadata to retrieve.
   */
    template <class Element>
    static const std::shared_ptr<MetadataTest> GetMetadata(
        const std::shared_ptr<const CiphertextImpl<Element>> ciphertext) {
        auto it = ciphertext->FindMetadataByKey("test");

        if (ciphertext->MetadataFound(it)) {
            return std::dynamic_pointer_cast<MetadataTest>(ciphertext->GetMetadata(it));
        }
        else {
            OPENFHE_THROW("Attempt to access metadata (MetadataTest) that has not been set.");
        }
    }

    /**
   * This static method stores a MetadataTest object
   * to a Ciphertext. If the Ciphertext already has another MetadataTest
   * object stored in its map, it will get overwritten by this MetadataTest
   * object.
   *
   * Whenever we want to modify the metadata of a ciphertext, it is
   * recommended to (1) clone the MetadataTest object from another
   * ciphertext or create a new MetadataTest object with
   * make_shared<MetadataTest>(), (2) modify it using the Setter methods
   * of MetadataTest, and (3) store it to the ciphertext we want using
   * this method.
   *
   * @param ciphertext the ciphertext whose metadata to retrieve.
   */
    template <class Element>
    static void StoreMetadata(std::shared_ptr<CiphertextImpl<Element>> ciphertext,
                              std::shared_ptr<MetadataTest> mdata) {
        ciphertext->SetMetadataByKey("test", mdata);
    }

protected:
    std::string m_s;
};

}  // namespace lbcrypto

#endif  // __UNITTESTMETADATATEST_H__
