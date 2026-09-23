//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2026, NJIT, Duality Technologies Inc. and other contributors
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

#ifndef SRC_BINFHE_INCLUDE_LWE_KEYSWITCHKEY32_H_
#define SRC_BINFHE_INCLUDE_LWE_KEYSWITCHKEY32_H_

#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "lwe-cryptoparameters.h"
#include "lwe-keyswitchkey-fwd.h"
#include "utils/serializable.h"

namespace lbcrypto {

#if NATIVEINT != 32

class LWESwitchingKey32Impl;
using LWESwitchingKey32 = std::shared_ptr<LWESwitchingKey32Impl>;
using ConstLWESwitchingKey32 = const std::shared_ptr<const LWESwitchingKey32Impl>;

/**
 * @brief 32-bit internal form of the LWE key switching key.
 *
 * Every stored value is a residue mod qKS, so when qKS fits a 32-bit word the key stores in half
 * the memory of the 64-bit form -- and it is by far the largest key object. Storage is two flat
 * arrays indexed by (LWE index i, digit position, digit value): rows of n words in m_keyA and one
 * word each in m_keyB, replacing the nested vector-of-vectors layout. Rows exist for digit values
 * 1..baseKS-1 only -- the value-0 row would encrypt zero and the key switch skips zero digits --
 * and the top digit position holds only the values a coefficient below qKS can reach. The key switch itself
 * accumulates rows in uint64 and reduces once per output coefficient, which yields the same
 * residues as the 64-bit path, so results are bit-identical.
 */
class LWESwitchingKey32Impl : public Serializable {
  public:
    LWESwitchingKey32Impl() = default;

    /**
   * Checks whether the parameters qualify for the 32-bit switching key: generation runs on 32-bit kernels, exact up
   * to MAX_MODULUS_SIZE32 bits of qKS, and the key switch accumulates N*digitCount unreduced rows below qKS in a
   * 64-bit word
   *
   * @param params LWE scheme parameters
   * @return true if qKS fits MAX_MODULUS_SIZE32 bits and N*digitCount*qKS does not overflow a uint64
   */
    static bool Fits(const LWECryptoParams& params) {
        const auto& qKS = params.GetqKS();
        if (qKS.GetMSB() > MAX_MODULUS_SIZE32)
            return false;
        uint64_t rows{static_cast<uint64_t>(params.GetN()) * params.GetDigitCountKS()};
        return rows <= static_cast<uint64_t>(-1) / qKS.ConvertToInt<uint64_t>();
    }

    /**
   * Allocates a key of the given shape with its storage deliberately left uninitialized: both generation paths write
   * every element, and value-initialization would fault and zero the whole key on the constructing thread before
   * the parallel fill re-touches it. Each LWE index holds baseKS-1 rows (digit values 1..baseKS-1) per digit
   * position except the top position, which holds topExtent-1: the values a coefficient below qKS can reach there
   *
   * @param N dimension of the source (old) secret key, the number of LWE indices
   * @param baseKS key-switching base
   * @param digitCount number of base-baseKS digits of a value below qKS
   * @param topExtent number of values the top digit can take (LWECryptoParams::GetDigitExtentKS(digitCount - 1))
   * @param n dimension of the target (new) secret key, the length of each row
   */
    LWESwitchingKey32Impl(uint32_t N, uint32_t baseKS, uint32_t digitCount, uint32_t topExtent, uint32_t n)
        : m_N(N),
          m_m(baseKS),
          m_d(digitCount),
          m_top(topExtent),
          m_n(n),
          m_rows(static_cast<uint64_t>(digitCount - 1) * (baseKS - 1) + (topExtent - 1)),
          m_sizeA(static_cast<uint64_t>(N) * m_rows * n),
          m_sizeB(static_cast<uint64_t>(N) * m_rows),
          m_keyA(new uint32_t[m_sizeA]),
          m_keyB(new uint32_t[m_sizeB]) {}

    /**
   * Narrows an existing 64-bit key, taking the shape from the parameters and copying only the reachable digit rows.
   * Peak memory holds both forms; the released pages come back only after AllocTrim(). Prefer
   * LWEEncryptionScheme::KeySwitchGen32, which never materialises the 64-bit key
   *
   * @param params LWE scheme parameters the key was generated with
   * @param K the 64-bit switching key, which must have N entries with baseKS-1 digit-value rows each
   */
    LWESwitchingKey32Impl(const LWECryptoParams& params, const LWESwitchingKeyImpl& K);

    /**
   * Produces an exact 64-bit copy of the key for serialization: every value fits, so 32 -> 64 -> 32 is the identity
   *
   * @param params LWE scheme parameters, supplying the key-switching modulus of the 64-bit vectors
   * @return a shared pointer to the 64-bit switching key
   */
    LWESwitchingKey Widen(const LWECryptoParams& params) const;

    /**
   * Accesses the A part of the encryption of val * baseKS^pos * skN[i]: a row of n residues mod qKS
   *
   * @param i LWE index of the source secret-key coefficient, in [0, N)
   * @param val digit value, in [1, GetDigitExtent(pos)); the value-0 row is not stored
   * @param pos digit position, in [0, digitCount)
   * @return pointer to the n words of the row
   */
    uint32_t* RowA(uint32_t i, uint32_t val, uint32_t pos) {
        return m_keyA.get() + Slot(i, val, pos) * m_n;
    }

    /**
   * Accesses the A part of the encryption of val * baseKS^pos * skN[i]: a row of n residues mod qKS
   *
   * @param i LWE index of the source secret-key coefficient, in [0, N)
   * @param val digit value, in [1, GetDigitExtent(pos)); the value-0 row is not stored
   * @param pos digit position, in [0, digitCount)
   * @return pointer to the n words of the row
   */
    const uint32_t* RowA(uint32_t i, uint32_t val, uint32_t pos) const {
        return m_keyA.get() + Slot(i, val, pos) * m_n;
    }

    /**
   * Accesses the B part of the encryption of val * baseKS^pos * skN[i]: one residue mod qKS
   *
   * @param i LWE index of the source secret-key coefficient, in [0, N)
   * @param val digit value, in [1, GetDigitExtent(pos)); the value-0 row is not stored
   * @param pos digit position, in [0, digitCount)
   * @return reference to the stored word
   */
    uint32_t& B(uint32_t i, uint32_t val, uint32_t pos) {
        return m_keyB[Slot(i, val, pos)];
    }

    /**
   * Reads the B part of the encryption of val * baseKS^pos * skN[i]: one residue mod qKS
   *
   * @param i LWE index of the source secret-key coefficient, in [0, N)
   * @param val digit value, in [1, GetDigitExtent(pos)); the value-0 row is not stored
   * @param pos digit position, in [0, digitCount)
   * @return the stored word
   */
    uint32_t B(uint32_t i, uint32_t val, uint32_t pos) const {
        return m_keyB[Slot(i, val, pos)];
    }

    /**
   * Gets the number of digit values stored for a digit position: baseKS for every position except the top one,
   * which holds topExtent
   *
   * @param pos digit position, in [0, digitCount)
   * @return the digit extent; rows exist for values 1..extent-1
   */
    uint32_t GetDigitExtent(uint32_t pos) const {
        return pos + 1 < m_d ? m_m : m_top;
    }

    uint32_t GetN() const {
        return m_N;
    }

    uint32_t GetBaseKS() const {
        return m_m;
    }

    uint32_t GetDigitCount() const {
        return m_d;
    }

    uint32_t Getn() const {
        return m_n;
    }

    /**
   * Gets the resident bytes of key material (the A rows and the B words), for memory accounting
   *
   * @return the size of the two flat arrays in bytes
   */
    uint64_t KeyBytes() const {
        return (m_sizeA + m_sizeB) * sizeof(uint32_t);
    }

    bool operator==(const LWESwitchingKey32Impl& other) const {
        if (m_N != other.m_N || m_m != other.m_m || m_d != other.m_d || m_top != other.m_top || m_n != other.m_n)
            return false;
        return std::equal(m_keyA.get(), m_keyA.get() + m_sizeA, other.m_keyA.get()) &&
               std::equal(m_keyB.get(), m_keyB.get() + m_sizeB, other.m_keyB.get());
    }

    bool operator!=(const LWESwitchingKey32Impl& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("N", m_N));
        ar(::cereal::make_nvp("m", m_m));
        ar(::cereal::make_nvp("d", m_d));
        ar(::cereal::make_nvp("top", m_top));
        ar(::cereal::make_nvp("n", m_n));
        Bytes(ar, m_keyA.get(), m_sizeA);
        Bytes(ar, m_keyB.get(), m_sizeB);
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("N", m_N));
        ar(::cereal::make_nvp("m", m_m));
        ar(::cereal::make_nvp("d", m_d));
        ar(::cereal::make_nvp("top", m_top));
        ar(::cereal::make_nvp("n", m_n));
        Size();
        m_keyA.reset(new uint32_t[m_sizeA]);
        m_keyB.reset(new uint32_t[m_sizeB]);
        Bytes(ar, m_keyA.get(), m_sizeA);
        Bytes(ar, m_keyB.get(), m_sizeB);
    }

    std::string SerializedObjectName() const override {
        return "LWESwitchingKey32";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

  private:
    // One flat array, in whichever form the archive takes: the binary archives move it as a block,
    // and the JSON archive, which has no binary support, takes it one element at a time. Both sides
    // call this, so the two representations stay paired.
    template <class Archive, typename T>
    static void Bytes(Archive& ar, T* p, uint64_t n) {
        if constexpr (::cereal::traits::is_output_serializable<::cereal::BinaryData<T*>, Archive>::value ||
                      ::cereal::traits::is_input_serializable<::cereal::BinaryData<T*>, Archive>::value) {
            ar(::cereal::binary_data(p, n * sizeof(T)));
        } else {
            for (uint64_t i = 0; i < n; ++i)
                ar(p[i]);
        }
    }

    void Size() {
        m_rows = static_cast<uint64_t>(m_d - 1) * (m_m - 1) + (m_top - 1);
        m_sizeA = static_cast<uint64_t>(m_N) * m_rows * m_n;
        m_sizeB = static_cast<uint64_t>(m_N) * m_rows;
    }

    uint64_t Slot(uint32_t i, uint32_t val, uint32_t pos) const {
        return static_cast<uint64_t>(i) * m_rows + static_cast<uint64_t>(pos) * (m_m - 1) + (val - 1);
    }

    uint32_t m_N{0};
    uint32_t m_m{0};
    uint32_t m_d{0};
    uint32_t m_top{0};
    uint32_t m_n{0};
    uint64_t m_rows{0};
    uint64_t m_sizeA{0};
    uint64_t m_sizeB{0};
    std::unique_ptr<uint32_t[]> m_keyA;
    std::unique_ptr<uint32_t[]> m_keyB;
};

#endif  // NATIVEINT != 32

}  // namespace lbcrypto

#endif  // SRC_BINFHE_INCLUDE_LWE_KEYSWITCHKEY32_H_
