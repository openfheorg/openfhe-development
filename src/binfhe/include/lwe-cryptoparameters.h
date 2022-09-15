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

#include <string>
#include <utility>
#include <vector>

#include "math/hal.h"
#include "math/discretegaussiangenerator.h"
#include "utils/serializable.h"

namespace lbcrypto {

/**
 * @brief Class that stores all parameters for the LWE scheme
 */
class LWECryptoParams : public Serializable {
public:
    // NativeInteger m_qKS = 1<<20; //PreviousPrime<NativeInteger>(FirstPrime<NativeInteger>(26, 2048), 2048);
    LWECryptoParams() : m_n(0), m_N(0), m_q(0), m_Q(0), m_qKS(0), m_baseKS(0) {}

    /**
   * Main constructor for LWECryptoParams
   *
   * @param n lattice parameter for additive LWE scheme
   * @param N ring dimension for RingGSW/RLWE used in bootstrapping
   * @param &q modulus for additive LWE
   * @param &Q modulus for RingGSW/RLWE used in bootstrapping
   * @param &q_KS modulus for key switching
   * @param std standard deviation
   * @param baseKS the base used for key switching
   */
    explicit LWECryptoParams(uint32_t n, uint32_t N, const NativeInteger& q, const NativeInteger& Q,
                             const NativeInteger& q_KS, double std, uint32_t baseKS)
        : m_n(n), m_N(N), m_q(q), m_Q(Q), m_qKS(q_KS), m_baseKS(baseKS) {
        if (Q.GetMSB() > MAX_MODULUS_SIZE) {
            std::string errMsg = "ERROR: Maximum size of Q supported for FHEW is 60 bits.";
            OPENFHE_THROW(config_error, errMsg);
        }

        m_dgg.SetStd(std);
        m_ks_dgg.SetStd(std);
    }

    explicit LWECryptoParams(const LWECryptoParams& rhs) {
        this->m_n      = rhs.m_n;
        this->m_N      = rhs.m_N;
        this->m_q      = rhs.m_q;
        this->m_Q      = rhs.m_Q;
        this->m_baseKS = rhs.m_baseKS;
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
    }

    explicit LWECryptoParams(const LWECryptoParams&& rhs) {
        this->m_n      = std::move(rhs.m_n);
        this->m_N      = std::move(rhs.m_N);
        this->m_q      = std::move(rhs.m_q);
        this->m_Q      = std::move(rhs.m_Q);
        this->m_baseKS = std::move(rhs.m_baseKS);
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
    }

    const LWECryptoParams& operator=(const LWECryptoParams& rhs) {
        this->m_n      = rhs.m_n;
        this->m_N      = rhs.m_N;
        this->m_q      = rhs.m_q;
        this->m_Q      = rhs.m_Q;
        this->m_baseKS = rhs.m_baseKS;
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
        return *this;
    }

    const LWECryptoParams& operator=(const LWECryptoParams&& rhs) {
        this->m_n      = std::move(rhs.m_n);
        this->m_N      = std::move(rhs.m_N);
        this->m_q      = std::move(rhs.m_q);
        this->m_Q      = std::move(rhs.m_Q);
        this->m_baseKS = std::move(rhs.m_baseKS);
        this->m_dgg.SetStd(rhs.m_dgg.GetStd());
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
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
                                                 " is from a later version of the library");
        }

        ar(::cereal::make_nvp("n", m_n));
        ar(::cereal::make_nvp("N", m_N));
        ar(::cereal::make_nvp("q", m_q));
        ar(::cereal::make_nvp("Q", m_Q));
        ar(::cereal::make_nvp("qKS", m_qKS));
        double sigma;
        ar(::cereal::make_nvp("sigma", sigma));
        double sigmaKS;
        ar(::cereal::make_nvp("sigmaKS", sigmaKS));
        m_dgg.SetStd(sigma);
        m_ks_dgg.SetStd(sigmaKS);
        ar(::cereal::make_nvp("bKS", m_baseKS));
    }

    std::string SerializedObjectName() const {
        return "LWECryptoParams";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

    void SetQ(NativeInteger q) {
        m_q = q;
    }

private:
    // lattice parameter for the additive LWE scheme
    uint32_t m_n;
    // ring dimension for RingGSW/RingLWE scheme
    uint32_t m_N;
    // modulus for the additive LWE scheme
    NativeInteger m_q;
    // modulus for the RingGSW/RingLWE scheme
    NativeInteger m_Q;
    // modulus for key-switching
    NativeInteger m_qKS;
    // Error distribution generator
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg;
    // Error distribution generator for key switching
    DiscreteGaussianGeneratorImpl<NativeVector> m_ks_dgg;
    // Base used in key switching
    uint32_t m_baseKS;
};

}  // namespace lbcrypto

#endif  // _LWE_CRYPTOPARAMETERS_H_
