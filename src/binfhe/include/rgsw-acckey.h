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

#ifndef SRC_BINFHE_INCLUDE_RGSW_ACCKEY_H_
#define SRC_BINFHE_INCLUDE_RGSW_ACCKEY_H_

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
#include "rgsw-evalkey.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

namespace lbcrypto {

class RingGSWACCKeyImpl;
using RingGSWACCKey = std::shared_ptr<RingGSWACCKeyImpl>;
using ConstRingGSWACCKey = const std::shared_ptr<const RingGSWACCKeyImpl>;

/**
 * @brief Class that stores the refresh key (used in bootstrapping)
 * A three-dimensional vector of RingGSW ciphertexts
 */
class RingGSWACCKeyImpl : public Serializable {
  public:
    RingGSWACCKeyImpl() = default;

    /**
     * Allocates a dim1 x dim2 x dim3 array of (null) RingGSW evaluation keys
     *
     * The meaning of the three dimensions depends on the bootstrapping method; see the KeyGenAcc methods of the
     * RingGSWAccumulator classes. With s the LWE secret key of dimension n:
     * - DM (AP): [n][baseR][digitsR], indexed [i][j][k] with i the position in s, j in [1, baseR) the value of a
     *   base-baseR digit and k the digit position; the entry is RGSW(X^(s_i * j * baseR^k)). The entries with
     *   j = 0, and with j at or above the extent of the top digit position, stay null.
     * - CGGI (GINX): [1][2][n]; [0][0][i] encrypts 1 if s_i = 1 and 0 otherwise, [0][1][i] encrypts 1 if s_i = -1
     *   and 0 otherwise.
     * - LMKCDEY: [1][2][n]; [0][0][i] = RGSW(X^(s_i)), [0][1][0] is the automorphism key for the exponent 2N - 5
     *   and [0][1][t] for t = 1..numAutoKeys is the automorphism key for 5^t mod 2N; the remaining [0][1] entries
     *   stay null.
     *
     * @param dim1 the size of the first dimension
     * @param dim2 the size of the second dimension
     * @param dim3 the size of the third dimension
     */
    RingGSWACCKeyImpl(uint32_t dim1, uint32_t dim2, uint32_t dim3) : m_key(dim1, dim2_t(dim2, dim3_t(dim3))) {}

    /**
     * Constructs a refresh key from a three-dimensional array of RingGSW evaluation keys
     *
     * @param key the RingGSW evaluation keys, laid out per bootstrapping method as described for the constructor
     * taking the three dimensions
     */
    explicit RingGSWACCKeyImpl(const std::vector<std::vector<std::vector<RingGSWEvalKey>>>& key) : m_key(key) {}

    /**
     * Constructs a refresh key from a three-dimensional array of RingGSW evaluation keys, moving it
     *
     * @param key the RingGSW evaluation keys, laid out per bootstrapping method as described for the constructor
     * taking the three dimensions
     */
    explicit RingGSWACCKeyImpl(std::vector<std::vector<std::vector<RingGSWEvalKey>>>&& key) noexcept
        : m_key(std::move(key)) {}

    RingGSWACCKeyImpl(const RingGSWACCKeyImpl& rhs) : m_key(rhs.m_key) {}

    RingGSWACCKeyImpl(RingGSWACCKeyImpl&& rhs) noexcept : m_key(std::move(rhs.m_key)) {}

    RingGSWACCKeyImpl& operator=(const RingGSWACCKeyImpl& rhs) {
        m_key = rhs.m_key;
        return *this;
    }

    RingGSWACCKeyImpl& operator=(RingGSWACCKeyImpl&& rhs) noexcept {
        m_key = std::move(rhs.m_key);
        return *this;
    }

    const std::vector<std::vector<std::vector<RingGSWEvalKey>>>& GetElements() const {
        return m_key;
    }

    void SetElements(const std::vector<std::vector<std::vector<RingGSWEvalKey>>>& key) {
        m_key = key;
    }

    void SetElements(std::vector<std::vector<std::vector<RingGSWEvalKey>>>&& key) noexcept {
        m_key = std::move(key);
    }

    /**
     * @param i the index in the first dimension
     * @return the two-dimensional slice of RingGSW evaluation keys at index i
     */
    std::vector<std::vector<RingGSWEvalKey>>& operator[](uint32_t i) {
        return m_key[i];
    }

    /**
     * @param i the index in the first dimension
     * @return the two-dimensional slice of RingGSW evaluation keys at index i
     */
    const std::vector<std::vector<RingGSWEvalKey>>& operator[](uint32_t i) const {
        return m_key[i];
    }

    /**
     * Compares the two keys entry by entry through the shared pointers; two null entries compare equal
     *
     * @param other the refresh key to compare with
     * @return true if both keys have the same dimensions and equal RingGSW evaluation keys in every position
     */
    bool operator==(const RingGSWACCKeyImpl& other) const {
        // as RingGSWEvalKey is shared_ptr<RingGSWEvalKeyImpl>, we have to loop through all elements to compare them
        if (m_key.size() != other.m_key.size())
            return false;
        for (size_t i = 0; i < m_key.size(); ++i) {
            const auto& l1 = m_key[i];
            const auto& o1 = other.m_key[i];
            if (l1.size() != o1.size())
                return false;
            for (size_t j = 0; j < l1.size(); ++j) {
                const auto& l2 = l1[j];
                const auto& o2 = o1[j];
                if (l2.size() != o2.size())
                    return false;
                for (size_t k = 0; k < l2.size(); ++k) {
                    const auto& l3 = l2[k];
                    const auto& o3 = o2[k];
                    if (l3.get() == nullptr || o3.get() == nullptr) {
                        if (l3.get() != o3.get())
                            return false;
                    } else {
                        if (*l3 != *o3)
                            return false;
                    }
                }
            }
        }
        return true;
    }

    /**
     * @param other the refresh key to compare with
     * @return true if the dimensions or any RingGSW evaluation key differ
     */
    bool operator!=(const RingGSWACCKeyImpl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("k", m_key));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("k", m_key));
    }

    std::string SerializedObjectName() const override {
        return "RingGSWACCKey";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

  private:
    using dim3_t = std::vector<RingGSWEvalKey>;
    using dim2_t = std::vector<dim3_t>;
    using dim1_t = std::vector<dim2_t>;

    std::vector<std::vector<std::vector<RingGSWEvalKey>>> m_key;  ///< RingGSW evaluation keys, laid out per method
};

}  // namespace lbcrypto

#endif  // SRC_BINFHE_INCLUDE_RGSW_ACCKEY_H_
