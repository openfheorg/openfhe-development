//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2023, NJIT, Duality Technologies Inc. and other contributors
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
  Wraps parameters for integer lattice operations. Inherits from ElemParams
 */

#ifndef LBCRYPTO_INC_LATTICE_ILPARAMS_H
#define LBCRYPTO_INC_LATTICE_ILPARAMS_H

#include "lattice/elemparams.h"

#include "math/math-hal.h"
#include "math/nbtheory.h"

#include "utils/exception.h"
#include "utils/inttypes.h"

#include <string>
#include <utility>

namespace lbcrypto {

/**
 * @class ILParamsImpl
 * @file ilparams.h
 * @brief Wrapper class to hold the parameters for integer lattice operations
 * and their inheritors.
 */
template <typename IntType>
class ILParamsImpl final : public ElemParams<IntType> {
public:
    using Integer = IntType;

    /**
   * Constructor that initializes nothing.
   * All of the private members will be initialized to zero.
   */
    constexpr ILParamsImpl() : ElemParams<IntType>() {}

    /**
   * @brief Constructor for the case of partially pre-computed parameters.
   *
   * @param &order the order of the ciphertext.
   * @param &modulus the ciphertext modulus.
   * @param &rootOfUnity the root of unity used in the ciphertext.
   * @param bigModulus the big ciphertext modulus.
   * @param bigRootOfUnity the big ciphertext modulus used for bit packing
   * operations.
   * @return
   */
    ILParamsImpl(usint order, const IntType& modulus, const IntType& rootOfUnity,
                 const IntType& bigModulus = IntType(0), const IntType& bigRootOfUnity = IntType(0))
        : ElemParams<IntType>(order, modulus, rootOfUnity, bigModulus, bigRootOfUnity) {}

    /**
   * @brief Constructor for the case of partially pre-computed parameters.
   *
   * @param &order the order of the ciphertext.
   * @param &modulus the ciphertext modulus.
   */
    ILParamsImpl(usint order, const IntType& modulus)
        : ElemParams<IntType>(order, modulus, RootOfUnity<IntType>(order, modulus)) {}

    /**
   * @brief Copy constructor.
   *
   * @param &rhs the input set of parameters which is copied.
   */
    ILParamsImpl(const ILParamsImpl& rhs) : ElemParams<IntType>(rhs) {}

    /**
   * @brief Assignment Operator.
   *
   * @param &rhs the params to be copied.
   * @return this object
   */
    ILParamsImpl& operator=(const ILParamsImpl& rhs) {
        ElemParams<IntType>::operator=(rhs);
        return *this;
    }

    /**
   * @brief Move constructor.
   *
   * @param &rhs the input set of parameters which is copied.
   */
    ILParamsImpl(ILParamsImpl&& rhs) noexcept : ElemParams<IntType>(std::move(rhs)) {}

    ILParamsImpl& operator=(ILParamsImpl&& rhs) noexcept {
        ElemParams<IntType>::operator=(std::move(rhs));
        return *this;
    }

    /**
   * @brief Standard Destructor method.
   */
    ~ILParamsImpl() override = default;

    /**
   * @brief Equality operator compares ElemParams (which will be dynamic casted)
   *
   * @param &rhs is the specified Poly to be compared with this Poly.
   * @return True if this Poly represents the same values as the specified
   * DCRTPoly, False otherwise
   */
    bool operator==(const ElemParams<IntType>& rhs) const override {
        if (dynamic_cast<const ILParamsImpl<IntType>*>(&rhs) == nullptr)
            return false;
        return ElemParams<IntType>::operator==(rhs);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::base_class<ElemParams<IntType>>(this));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }
        ar(::cereal::base_class<ElemParams<IntType>>(this));
    }

    std::string SerializedObjectName() const override {
        return "ILParms";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    std::ostream& doprint(std::ostream& out) const override {
        out << "ILParams ";
        ElemParams<IntType>::doprint(out);
        out << std::endl;
        return out;
    }
};

}  // namespace lbcrypto

#endif
