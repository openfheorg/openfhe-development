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

#ifndef _RGSW_CRYPTOPARAMETERS_H_
#define _RGSW_CRYPTOPARAMETERS_H_

#include "binfhe-constants.h"
#include "lattice/lat-hal.h"
#include "lwe-ciphertext.h"
#include "lwe-cryptoparameters.h"
#include "lwe-keyswitchkey.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace lbcrypto {

/**
 * @brief Class that stores all parameters for the RingGSW scheme used in
 * bootstrapping
 */
class RingGSWCryptoParams : public Serializable {
public:
    RingGSWCryptoParams() = default;

    /**
   * Main constructor for RingGSWCryptoParams
   *
   * @param N ring dimension for RingGSW/RLWE used in bootstrapping
   * @param Q modulus for RingGSW/RLWE used in bootstrapping
   * @param q ciphertext modulus for additive LWE
   * @param baseG the gadget base used in the bootstrapping
   * @param baseR the base for the refreshing key
   * @param method bootstrapping method (DM or CGGI or LMKCDEY)
   * @param std standar deviation
   * @param keyDist secret key distribution
   * @param signEval flag if sign evaluation is needed
   * @param numAutoKeys number of automorphism keys in LMKCDEY bootstrapping
   */
    explicit RingGSWCryptoParams(uint32_t N, NativeInteger Q, NativeInteger q, uint32_t baseG, uint32_t baseR,
                                 BINFHE_METHOD method, double std, SecretKeyDist keyDist = UNIFORM_TERNARY,
                                 bool signEval = false, uint32_t numAutoKeys = 10)
        : m_Q(Q),
          m_q(q),
          m_N(N),
          m_baseG(baseG),
          m_baseR(baseR),
          m_polyParams{std::make_shared<ILNativeParams>(2 * N, Q)},
          m_method(method),
          m_keyDist(keyDist),
          m_numAutoKeys(numAutoKeys) {
        if (baseG <= 1 || !IsPowerOfTwo(baseG))
            OPENFHE_THROW("Gadget base should be a power of two.");
        if ((method == LMKCDEY) && (numAutoKeys == 0))
            OPENFHE_THROW("numAutoKeys should be greater than 0.");
        m_digitsG = DigitsForBase(m_Q, m_baseG);
        m_dgg.SetStd(std);
        PreCompute(signEval);
    }

    /**
   * Constructor for using multiple gadget bases in bootstrapping
   *
   * @param N ring dimension for RingGSW/RLWE used in bootstrapping
   * @param Q modulus for RingGSW/RLWE used in bootstrapping
   * @param q ciphertext modulus for additive LWE
   * @param baseG the default gadget base, also used for automorphism keys
   * @param baseGMap number of LWE secret-key coefficients assigned to each gadget base
   * @param baseR the base for the refreshing key
   * @param method bootstrapping method (DM or CGGI or LMKCDEY)
   * @param std standard deviation
   * @param keyDist secret key distribution
   * @param signEval flag if sign evaluation is needed
   * @param numAutoKeys number of automorphism keys in LMKCDEY bootstrapping
   */
    explicit RingGSWCryptoParams(uint32_t N, NativeInteger Q, NativeInteger q, uint32_t baseG,
                                 const std::map<uint32_t, uint32_t>& baseGMap, uint32_t baseR, BINFHE_METHOD method,
                                 double std, SecretKeyDist keyDist = UNIFORM_TERNARY, bool signEval = false,
                                 uint32_t numAutoKeys = 10)
        : m_Q(Q),
          m_q(q),
          m_N(N),
          m_baseG(baseG),
          m_baseG_map(baseGMap),
          m_baseR(baseR),
          m_polyParams{std::make_shared<ILNativeParams>(2 * N, Q)},
          m_method(method),
          m_keyDist(keyDist),
          m_numAutoKeys(numAutoKeys) {
        if (baseGMap.empty())
            OPENFHE_THROW("Gadget base map should not be empty.");
        if (!IsPowerOfTwo(baseG))
            OPENFHE_THROW("Gadget base should be a power of two.");
        for (const auto& [baseG, count] : baseGMap) {
            if (count == 0 || baseG <= 1 || !IsPowerOfTwo(baseG))
                OPENFHE_THROW("Gadget base should be a power of two and its count should be greater than zero.");
        }
        if ((method == LMKCDEY) && (numAutoKeys == 0))
            OPENFHE_THROW("numAutoKeys should be greater than 0.");
        m_digitsG = DigitsForBase(m_Q, m_baseG);
        m_dgg.SetStd(std);
        PreCompute(signEval);
    }

    // gadget parameters for one LWE index: the base, its digit count, and its gadget powers
    struct BaseGParams {
        uint32_t baseG{0};
        uint32_t digitsG{0};
        uint32_t gBits{0};
        const std::vector<NativeInteger>* gpow{nullptr};
    };

    /**
   * Performs precomputations based on the supplied parameters
   */
    void PreCompute(bool signEval = false);

    // gadget powers baseG^i mod Q, computed once per base and cached in m_Gpower_map
    const std::vector<NativeInteger>& PrecomputeGPower(uint32_t baseG);

    uint32_t GetN() const {
        return m_N;
    }

    NativeInteger GetQ() const {
        return m_Q;
    }

    NativeInteger Getq() const {
        return m_q;
    }

    uint32_t GetBaseG() const {
        return m_baseG;
    }

    uint32_t GetDigitsG() const {
        return m_digitsG;
    }

    // Per-LWE-index gadget parameters. PreCompute() expands the base map into one entry per index.
    // Returned by value, and built from the live members when no base map is in use:
    // Change_BaseG() mutates m_baseG/m_digitsG/m_Gpower after PreCompute(), and the
    // large-precision path depends on those switches taking effect.
    BaseGParams GetDefaultBaseGParams() const {
        return {m_baseG, m_digitsG, lbcrypto::GetMSB(m_baseG) - 1, &m_Gpower};
    }

    BaseGParams GetBaseGParams(uint32_t index) const {
        if (m_baseGByIndex.empty())
            return GetDefaultBaseGParams();
        if (index >= m_baseGByIndex.size())
            OPENFHE_THROW("Gadget base map does not cover the LWE dimension.");
        return m_baseGByIndex[index];
    }

    uint32_t GetBaseG(uint32_t index) const {
        return GetBaseGParams(index).baseG;
    }

    uint32_t GetDigitsG(uint32_t index) const {
        return GetBaseGParams(index).digitsG;
    }

    // the per-index table is built from a map that never sees the LWE dimension, so the two can
    // only be reconciled by a caller that holds both; do it before entering a parallel region
    void VerifyBaseGCoverage(uint32_t n) const {
        if (!m_baseGByIndex.empty() && m_baseGByIndex.size() != n)
            OPENFHE_THROW("Gadget base map does not cover the LWE dimension.");
    }

    uint32_t GetBaseR() const {
        return m_baseR;
    }

    uint32_t GetNumAutoKeys() const {
        return m_numAutoKeys;
    }

    const std::vector<NativeInteger>& GetDigitsR() const {
        return m_digitsR;
    }

    const std::shared_ptr<ILNativeParams> GetPolyParams() const {
        return m_polyParams;
    }

    const std::vector<NativeInteger>& GetGPower() const {
        return m_Gpower;
    }

    const std::vector<NativeInteger>& GetGPower(uint32_t baseG) const {
        auto it = m_Gpower_map.find(baseG);
        if (it == m_Gpower_map.end())
            OPENFHE_THROW("No GPower found for the requested gadget base.");
        return it->second;
    }

    const std::vector<NativeInteger>& GetGPowerByIndex(uint32_t index) const {
        const auto* gpow = GetBaseGParams(index).gpow;
        return (gpow == nullptr) ? m_Gpower : *gpow;
    }

    const std::vector<int32_t>& GetLogGen() const {
        return m_logGen;
    }

    const std::map<uint32_t, std::vector<NativeInteger>>& GetGPowerMap() const {
        return m_Gpower_map;
    }

    const DiscreteGaussianGeneratorImpl<NativeVector>& GetDgg() const {
        return m_dgg;
    }

    const std::vector<NativeInteger>& GetGateConst() const {
        return m_gateConst;
    }

    const NativePoly& GetMonomial(uint32_t i) const {
        return m_monomials[i];
    }

    BINFHE_METHOD GetMethod() const {
        return m_method;
    }

    SecretKeyDist GetKeyDist() const {
        return m_keyDist;
    }

    bool operator==(const RingGSWCryptoParams& other) const {
        return m_N == other.m_N && m_Q == other.m_Q && m_baseR == other.m_baseR && m_baseG == other.m_baseG &&
               m_baseG_map == other.m_baseG_map;
    }

    bool operator!=(const RingGSWCryptoParams& other) const {
        return !(*this == other);
    }

    template <class Archive>
    void save(Archive& ar, std::uint32_t const version) const {
        ar(::cereal::make_nvp("bN", m_N));
        ar(::cereal::make_nvp("bQ", m_Q));
        ar(::cereal::make_nvp("bq", m_q));
        ar(::cereal::make_nvp("bR", m_baseR));
        ar(::cereal::make_nvp("bG", m_baseG));
        ar(::cereal::make_nvp("bmethod", m_method));
        ar(::cereal::make_nvp("bs", m_dgg.GetStd()));
        ar(::cereal::make_nvp("bdigitsG", m_digitsG));
        ar(::cereal::make_nvp("bparams", m_polyParams));
        ar(::cereal::make_nvp("numAutoKeys", m_numAutoKeys));
        ar(::cereal::make_nvp("baseGMap", m_baseG_map));
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW("serialized object version " + std::to_string(version) +
                          " is from a later version of the library");
        }
        ar(::cereal::make_nvp("bN", m_N));
        ar(::cereal::make_nvp("bQ", m_Q));
        ar(::cereal::make_nvp("bq", m_q));
        ar(::cereal::make_nvp("bR", m_baseR));
        ar(::cereal::make_nvp("bG", m_baseG));
        ar(::cereal::make_nvp("bmethod", m_method));
        double sigma = 0;
        ar(::cereal::make_nvp("bs", sigma));
        m_dgg.SetStd(sigma);
        ar(::cereal::make_nvp("bdigitsG", m_digitsG));
        ar(::cereal::make_nvp("bparams", m_polyParams));
        ar(::cereal::make_nvp("numAutoKeys", m_numAutoKeys));
        ar(::cereal::make_nvp("baseGMap", m_baseG_map));
        PreCompute();
    }

    std::string SerializedObjectName() const override {
        return "RingGSWCryptoParams";
    }

    static uint32_t SerializedVersion() {
        return 1;
    }

    void Change_BaseG(uint32_t BaseG) {
        if (m_baseG != BaseG) {
            if (!m_baseGByIndex.empty())
                OPENFHE_THROW("Change_BaseG is not supported with per-dimension gadget bases");
            m_baseG   = BaseG;
            m_Gpower  = PrecomputeGPower(BaseG);
            m_digitsG = DigitsForBase(m_Q, m_baseG);
        }
    }

private:
    static uint32_t DigitsForBase(const NativeInteger& Q, uint32_t baseG) {
        return lbcrypto::GetDigitCount(Q.ConvertToInt(), baseG);
    }

    // modulus for the RingGSW/RingLWE scheme
    NativeInteger m_Q;

    // modulus for the RingLWE scheme
    NativeInteger m_q;

    // ring dimension for RingGSW/RingLWE scheme
    uint32_t m_N;

    // gadget base used in bootstrapping
    uint32_t m_baseG;

    // number of LWE secret-key coefficients assigned to each gadget base, in ascending base order
    std::map<uint32_t, uint32_t> m_baseG_map;

    // m_baseG_map expanded to one entry per LWE index, filled by PreCompute()
    std::vector<BaseGParams> m_baseGByIndex;

    // base used for the refreshing key (used only for DM bootstrapping)
    uint32_t m_baseR;

    // number of digits in decomposing integers mod Q for given baseG
    uint32_t m_digitsG;

    // powers of m_baseR (used only for DM bootstrapping)
    std::vector<NativeInteger> m_digitsR;

    // A vector of powers of baseG
    std::vector<NativeInteger> m_Gpower;

    // A vector of log by generator g (=5) (only for LMKCDEY)
    // Not exactly log, but a mapping similar to logarithm for efficiency
    // m_logGen[5^i (mod M)] = i (i > 0)
    // m_logGen[-5^i (mod M)] = -i ()
    // m_logGen[1] = 0
    // m_logGen[-1 (mod M)] = M (special case for efficiency)
    std::vector<int32_t> m_logGen;

    // Error distribution generator
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg;

    // A map of vectors of powers for each gadget base
    std::map<uint32_t, std::vector<NativeInteger>> m_Gpower_map;

    // Parameters for polynomials in RingGSW/RingLWE
    std::shared_ptr<ILNativeParams> m_polyParams;

    // Constants used in evaluating binary gates
    std::vector<NativeInteger> m_gateConst;

    // Precomputed polynomials in Format::EVALUATION representation for X^m - 1
    // (used only for CGGI bootstrapping)
    std::vector<NativePoly> m_monomials;

    // Bootstrapping method (DM or CGGI or LMKCDEY)
    BINFHE_METHOD m_method{BINFHE_METHOD::INVALID_METHOD};

    // Secret key distribution: GAUSSIAN, UNIFORM_TERNARY, etc.
    SecretKeyDist m_keyDist{SecretKeyDist::UNIFORM_TERNARY};

    // number of automorphism keys (used only for LMKCDEY bootstrapping)
    uint32_t m_numAutoKeys;
};

}  // namespace lbcrypto

#endif  // _RGSW_CRYPTOPARAMETERS_H_
