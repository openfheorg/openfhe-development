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

#ifndef LBCRYPTO_CRYPTO_METADATA_H
#define LBCRYPTO_CRYPTO_METADATA_H

#include "utils/exception.h"

#include <map>
#include <memory>
#include <string>
#include <ostream>

namespace lbcrypto {

class Metadata;
using MetadataMap = std::shared_ptr<std::map<std::string, std::shared_ptr<Metadata>>>;

/**
 * @brief Empty metadata container
 */
class Metadata {
public:
    /**
   * Default constructor
   */
    Metadata() {}

    /**
   * Copy constructor
   */
    Metadata(const Metadata& mdata) {
        Metadata();
    }

    /**
   * Destructor
   */
    virtual ~Metadata() {}

    /**
   * This method creates a copy of the Metadata object
   * wrapped in a shared_ptr
   */
    virtual std::shared_ptr<Metadata> Clone() const {
        return std::make_shared<Metadata>();
    }

    /**
   * Equality operator for Metadata.
   * Unless overriden by subclasses, Metadata does not carry any
   * metadata, so all Metadata objects are equal.
   */
    virtual bool operator==(const Metadata& mdata) const {
        return true;
    }

    /**
   * Inequality operator, implemented by a call to the
   * equality operator.
   */
    virtual bool operator!=(const Metadata& mdata) const {
        return !(*this == mdata);
    }

    /**
   * << operator implements by calling member method PrintMetadata.
   * This is a friend method and cannot be overriden by subclasses.
   */
    friend std::ostream& operator<<(std::ostream& out, const Metadata& m) {
        m.PrintMetadata(out);
        return out;
    }

    /**
   * save method for serialization
   */
    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {}

    /**
   * load method for serialization
   */
    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
    }

    /**
   * SerializedObjectName method for serialization
   */
    virtual std::string SerializedObjectName() const {
        return "Metadata";
    }

    /**
   * SerializedVersion method for serialization
   */
    static uint32_t SerializedVersion() {
        return 1;
    }

protected:
    /**
    * A method that prints the contents of metadata objects.
    * Please override in subclasses to print all members.
    */
    virtual std::ostream& PrintMetadata(std::ostream& out) const {
        OPENFHE_THROW("Not implemented");
    }
};

}  // end namespace lbcrypto

#endif
