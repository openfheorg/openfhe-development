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

#ifndef _LWE_CRYPTOPARAMETERS_H_
#define _LWE_CRYPTOPARAMETERS_H_

#include "binfhe-constants.h"

#include "math/discretegaussiangenerator.h"
#include "math/math-hal.h"
#include "utils/serializable.h"

#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

/**
 * @brief Class that stores all parameters for the LWE scheme
 */
class LWECryptoParams : public Serializable {
public:
    LWECryptoParams() = default;

    /**
   * Main constructor for LWECryptoParams
   *
   * @param n lattice parameter for additive LWE scheme
   * @param N ring dimension for RingGSW/RLWE used in bootstrapping
   * @param q modulus for additive LWE
   * @param Q modulus for RingGSW/RLWE used in bootstrapping
   * @param q_KS modulus for key switching
   * @param std standard deviation
   * @param baseKS the base used for key switching
   * @param keyDist the key distribution
   */
    explicit LWECryptoParams(uint32_t n, uint32_t N, const NativeInteger& q, const NativeInteger& Q,
                             const NativeInteger& q_KS, double std, uint32_t baseKS,
                             SecretKeyDist keyDist = UNIFORM_TERNARY)
        : m_q(q), m_Q(Q), m_qKS(q_KS), m_n(n), m_N(N), m_baseKS(baseKS), m_keyDist(keyDist) {
        if (!m_n)
            OPENFHE_THROW("m_n (lattice parameter) can not be zero");
        if (!m_N)
            OPENFHE_THROW("m_N (ring dimension) can not be zero");
        if (!m_q)
            OPENFHE_THROW("m_q (modulus for additive LWE) can not be zero");
        if (!m_Q)
            OPENFHE_THROW("m_Q (modulus for RingGSW/RLWE) can not be zero");
        if (!q_KS)
            OPENFHE_THROW("q_KS (modulus for key switching) can not be zero");
        if (!m_baseKS)
            OPENFHE_THROW("m_baseKS (the base used for key switching) can not be zero");
        if (m_Q.GetMSB() > MAX_MODULUS_SIZE)
            OPENFHE_THROW("Q.GetMSB() > MAX_MODULUS_SIZE");
        m_dgg.SetStd(std);
        m_ks_dgg.SetStd(std);
    }

    // TODO: add m_qKS, m_ks_dgg, and m_keyDist to copy/move operations?

    LWECryptoParams(const LWECryptoParams& rhs)
        : m_q(rhs.m_q),
          m_Q(rhs.m_Q),
          // m_qKS(rhs.m_qKS),
          m_n(rhs.m_n),
          m_N(rhs.m_N),
          m_baseKS(rhs.m_baseKS) {
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
        // this->m_ks_dgg.SetStd(rhs.m_ks_dgg.GetStd());
    }

    LWECryptoParams(LWECryptoParams&& rhs) noexcept
        : m_q(std::move(rhs.m_q)),
          m_Q(std::move(rhs.m_Q)),
          // m_qKS(std::move(rhs.m_qKS)),
          m_n(rhs.m_n),
          m_N(rhs.m_N),
          m_baseKS(rhs.m_baseKS) {
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
        // this->m_ks_dgg.SetStd(rhs.m_ks_dgg.GetStd());
    }

    LWECryptoParams& operator=(const LWECryptoParams& rhs) {
        this->m_q = rhs.m_q;
        this->m_Q = rhs.m_Q;
        // this->m_qKS    = rhs.m_qKS;
        this->m_n      = rhs.m_n;
        this->m_N      = rhs.m_N;
        this->m_baseKS = rhs.m_baseKS;
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
        // this->m_ks_dgg.SetStd(rhs.m_ks_dgg.GetStd());
        return *this;
    }

    LWECryptoParams& operator=(LWECryptoParams&& rhs) noexcept {
        this->m_q = std::move(rhs.m_q);
        this->m_Q = std::move(rhs.m_Q);
        // this->m_qKS    = std::move(rhs.m_qKS);
        this->m_n      = rhs.m_n;
        this->m_N      = rhs.m_N;
        this->m_baseKS = rhs.m_baseKS;
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
        // this->m_ks_dgg.SetStd(rhs.m_ks_dgg.GetStd());
        return *this;
    }

    uint32_t Getn() const {
        return m_n;
    }

    uint32_t GetN() const {
        return m_N;
    }

    const NativeInteger& Getq() const {
        return m_q;
    }

    const NativeInteger& GetQ() const {
        return m_Q;
    }

    const NativeInteger& GetqKS() const {
        return m_qKS;
    }

    uint32_t GetBaseKS() const {
        return m_baseKS;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& GetDgg() const {
        return m_dgg;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& GetDggKS() const {
        return m_ks_dgg;
    }

    SecretKeyDist GetKeyDist() const {
        return m_keyDist;
    }

    bool operator==(const LWECryptoParams& other) const {
        return m_n == other.m_n && m_N == other.m_N && m_q == other.m_q && m_Q == other.m_Q &&
               m_dgg.GetStd() == other.m_dgg.GetStd() && m_baseKS == other.m_baseKS;
    }

    bool operator!=(const LWECryptoParams& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("n", m_n));
        ar(::cereal::make_nvp("N", m_N));
        ar(::cereal::make_nvp("q", m_q));
        ar(::cereal::make_nvp("Q", m_Q));
        ar(::cereal::make_nvp("qKS", m_qKS));
        ar(::cereal::make_nvp("sigma", m_dgg.GetStd()));
        ar(::cereal::make_nvp("sigmaKS", m_ks_dgg.GetStd()));
        ar(::cereal::make_nvp("bKS", m_baseKS));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }

        ar(::cereal::make_nvp("n", m_n));
        ar(::cereal::make_nvp("N", m_N));
        ar(::cereal::make_nvp("q", m_q));
        ar(::cereal::make_nvp("Q", m_Q));
        ar(::cereal::make_nvp("qKS", m_qKS));
        double sigma = 0;
        ar(::cereal::make_nvp("sigma", sigma));
        double sigmaKS = 0;
        ar(::cereal::make_nvp("sigmaKS", sigmaKS));
        m_dgg.SetStd(sigma);
        m_ks_dgg.SetStd(sigmaKS);
        ar(::cereal::make_nvp("bKS", m_baseKS));
    }

    std::string SerializedObjectName() const override {
        return "LWECryptoParams";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

private:
    // modulus for the additive LWE scheme
    NativeInteger m_q{};
    // modulus for the RingGSW/RingLWE scheme
    NativeInteger m_Q{};
    // modulus for key-switching
    NativeInteger m_qKS{};
    // lattice parameter for the additive LWE scheme
    uint32_t m_n{};
    // ring dimension for RingGSW/RingLWE scheme
    uint32_t m_N{};
    // Base used in key switching
    uint32_t m_baseKS{};
    // Secret key distribution: GAUSSIAN, UNIFORM_TERNARY, etc.
    SecretKeyDist m_keyDist{SecretKeyDist::UNIFORM_TERNARY};
    // Error distribution generator
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg;
    // Error distribution generator for key switching
    DiscreteGaussianGeneratorImpl<NativeVector> m_ks_dgg;
};

}  // namespace lbcrypto

#endif  // _LWE_CRYPTOPARAMETERS_H_
