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

#ifndef SRC_BINFHE_INCLUDE_RGSW_EVALKEY_H_
#define SRC_BINFHE_INCLUDE_RGSW_EVALKEY_H_

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "lattice/lat-hal.h"
#include "lwe-ciphertext.h"
#include "lwe-cryptoparameters.h"
#include "lwe-keyswitchkey.h"
#include "lwe-privatekey.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

namespace lbcrypto {

class RingGSWEvalKeyImpl;
using RingGSWEvalKey = std::shared_ptr<RingGSWEvalKeyImpl>;
using ConstRingGSWEvalKey = const std::shared_ptr<const RingGSWEvalKeyImpl>;

/**
 * @brief Class that stores a RingGSW ciphertext; a two-dimensional vector of
 * ring elements
 */
class RingGSWEvalKeyImpl : public Serializable {
  public:
    RingGSWEvalKeyImpl() = default;

    /**
     * Allocates a rowSize x colSize matrix of default-constructed ring elements
     *
     * Every row of a RingGSW ciphertext is an RLWE pair (a, b) stored as columns 0 and 1, so colSize is 2.
     * An RGSW encryption of a monomial has 2 * (digitsG - 1) rows: row 2t adds the gadget power baseG^(t + 1)
     * times the monomial to "a" and row 2t + 1 adds it to "b" (the first gadget digit is dropped by the
     * approximate gadget decomposition). An LMKCDEY automorphism key has digitsG - 1 rows.
     *
     * @param rowSize the number of rows (RLWE pairs)
     * @param colSize the number of ring elements per row
     */
    RingGSWEvalKeyImpl(uint32_t rowSize, uint32_t colSize) noexcept
        : m_elements(rowSize, std::vector<NativePoly>(colSize)) {}

    /**
     * Constructs a RingGSW ciphertext from its matrix of ring elements
     *
     * @param elements the ring elements indexed [row][column]; each row is an RLWE pair (a, b) in columns 0 and 1
     */
    explicit RingGSWEvalKeyImpl(const std::vector<std::vector<NativePoly>>& elements) : m_elements(elements) {}

    /**
     * Constructs a RingGSW ciphertext from its matrix of ring elements, moving it
     *
     * @param elements the ring elements indexed [row][column]; each row is an RLWE pair (a, b) in columns 0 and 1
     */
    explicit RingGSWEvalKeyImpl(std::vector<std::vector<NativePoly>>&& elements) noexcept
        : m_elements(std::move(elements)) {}

    RingGSWEvalKeyImpl(const RingGSWEvalKeyImpl& rhs) : m_elements(rhs.m_elements) {}

    RingGSWEvalKeyImpl(RingGSWEvalKeyImpl&& rhs) noexcept : m_elements(std::move(rhs.m_elements)) {}

    RingGSWEvalKeyImpl& operator=(const RingGSWEvalKeyImpl& rhs) {
        RingGSWEvalKeyImpl::m_elements = rhs.m_elements;
        return *this;
    }

    RingGSWEvalKeyImpl& operator=(RingGSWEvalKeyImpl&& rhs) noexcept {
        RingGSWEvalKeyImpl::m_elements = std::move(rhs.m_elements);
        return *this;
    }

    const std::vector<std::vector<NativePoly>>& GetElements() const {
        return m_elements;
    }

    void SetElements(const std::vector<std::vector<NativePoly>>& elements) {
        m_elements = elements;
    }

    void SetElements(std::vector<std::vector<NativePoly>>&& elements) noexcept {
        m_elements = std::move(elements);
    }

    /**
     * Switches between COEFFICIENT and Format::EVALUATION polynomial
     * representations using NTT
     *
     * @param format the representation to switch all ring elements to
     */
    void SetFormat(const Format format) {
        for (size_t i = 0; i < m_elements.size(); ++i) {
            auto& l1 = m_elements[i];
            for (size_t j = 0; j < l1.size(); ++j)
                l1[j].SetFormat(format);
        }
    }

    /**
     * @param i the row index
     * @return the row i (an RLWE pair)
     */
    std::vector<NativePoly>& operator[](uint32_t i) {
        return m_elements[i];
    }

    /**
     * @param i the row index
     * @return the row i (an RLWE pair)
     */
    const std::vector<NativePoly>& operator[](uint32_t i) const {
        return m_elements[i];
    }

    /**
     * Compares the two matrices element by element
     *
     * @param other the RingGSW ciphertext to compare with
     * @return true if both have the same dimensions and equal ring elements
     */
    bool operator==(const RingGSWEvalKeyImpl& other) const {
        if (m_elements.size() != other.m_elements.size())
            return false;
        for (size_t i = 0; i < m_elements.size(); ++i) {
            const auto& l1 = m_elements[i];
            const auto& o1 = other.m_elements[i];
            if (l1.size() != o1.size())
                return false;
            for (size_t j = 0; j < l1.size(); ++j) {
                if (l1[j] != o1[j])
                    return false;
            }
        }
        return true;
    }

    /**
     * @param other the RingGSW ciphertext to compare with
     * @return true if the dimensions or any ring element differ
     */
    bool operator!=(const RingGSWEvalKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("elements", m_elements));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("elements", m_elements));
    }

    std::string SerializedObjectName() const override {
        return "RingGSWEvalKey";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

  private:
    std::vector<std::vector<NativePoly>> m_elements;  ///< ring elements indexed [row][column]; columns are (a, b)
};

}  // namespace lbcrypto

#endif  // SRC_BINFHE_INCLUDE_RGSW_EVALKEY_H_
