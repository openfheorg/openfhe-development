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

#include "lattice/lat-hal.h"
#include "math/discretegaussiangenerator.h"
#include "math/nbtheory.h"
#include "utils/serializable.h"
#include "utils/utilities.h"

#include "binfhe-constants.h"

#include "lwe-ciphertext.h"
#include "lwe-keyswitchkey.h"
#include "lwe-cryptoparameters.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <map>

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
   * @param lweparams a shared poiter to an instance of LWECryptoParams
   * @param baseG the gadget base used in the bootstrapping
   * @param baseR the base for the refreshing key
   * @param method bootstrapping method (DM or CGGI or LMKCDEY)
   */
    explicit RingGSWCryptoParams(uint32_t N, NativeInteger Q, NativeInteger q, uint32_t baseG, uint32_t baseR,
                                 BINFHE_METHOD method, double std, bool signEval = false)
        : m_N(N), m_Q(Q), m_q(q), m_baseG(baseG), m_baseR(baseR), m_method(method) {
        if (!IsPowerOfTwo(baseG)) {
            OPENFHE_THROW(config_error, "Gadget base should be a power of two.");
        }

        m_dgg.SetStd(std);

        NativeInteger rootOfUnity = RootOfUnity<NativeInteger>(2 * N, Q);

        // Precomputes the table with twiddle factors to support fast NTT
        ChineseRemainderTransformFTT<NativeVector>().PreCompute(rootOfUnity, 2 * N, Q);

        // Precomputes a polynomial for MSB extraction
        m_polyParams = std::make_shared<ILNativeParams>(2 * N, Q, rootOfUnity);
        m_digitsG    = (uint32_t)std::ceil(log(Q.ConvertToDouble()) / log(static_cast<double>(m_baseG)));
        if (m_method == AP) {
            uint32_t digitCountR =
                (uint32_t)std::ceil(log(static_cast<double>(q.ConvertToInt())) / log(static_cast<double>(m_baseR)));
            // Populate digits
            NativeInteger value = 1;
            for (size_t i = 0; i < digitCountR; ++i) {
                m_digitsR.push_back(value);
                value *= m_baseR;
            }
        }

        // Computes baseG^i
        if (signEval) {
            uint32_t baseGlist[3] = {1 << 14, 1 << 18, 1 << 27};
            for (size_t j = 0; j < 3; ++j) {
                NativeInteger vTemp = NativeInteger(1);
                auto tempdigits =
                    (uint32_t)std::ceil(log(Q.ConvertToDouble()) / log(static_cast<double>(baseGlist[j])));
                std::vector<NativeInteger> tempvec(tempdigits);
                for (size_t i = 0; i < tempdigits; ++i) {
                    tempvec[i] = vTemp;
                    vTemp      = vTemp.ModMul(NativeInteger(baseGlist[j]), Q);
                }
                m_Gpower_map[baseGlist[j]] = tempvec;
                if (m_baseG == baseGlist[j])
                    m_Gpower = tempvec;
            }
        }
        else {
            NativeInteger vTemp = NativeInteger(1);
            for (size_t i = 0; i < m_digitsG; ++i) {
                m_Gpower.push_back(vTemp);
                vTemp = vTemp.ModMul(NativeInteger(m_baseG), Q);
            }
        }

        if (m_method == LMKCDEY){
            uint32_t M = 2*N;

            m_logGen.resize(M);
            uint32_t gen = 5;
            uint32_t gPow = 1;

            m_logGen[gPow] = 0; // for 1
            m_logGen[M - gPow] = M; // for -1

            for (size_t i = 1; i < N/2; i++)
            {
                gPow = (gPow*gen) % M;
                m_logGen[gPow] = i;
                m_logGen[M - gPow] = -i;
            }
        }

        // Sets the gate constants for supported binary operations
        m_gateConst = {
            NativeInteger(5) * (q >> 3),  // OR
            NativeInteger(7) * (q >> 3),  // AND
            NativeInteger(1) * (q >> 3),  // NOR
            NativeInteger(3) * (q >> 3),  // NAND
            NativeInteger(5) * (q >> 3),  // XOR_FAST
            NativeInteger(1) * (q >> 3)   // XNOR_FAST
        };

        // Computes polynomials X^m - 1 that are needed in the accumulator for the
        // CGGI bootstrapping
        if (m_method == GINX) {
            // loop for positive values of m
            for (size_t i = 0; i < N; ++i) {
                NativePoly aPoly = NativePoly(m_polyParams, Format::COEFFICIENT, true);
                aPoly[i].ModAddEq(NativeInteger(1), Q);  // X^m
                aPoly[0].ModSubEq(NativeInteger(1), Q);  // -1
                aPoly.SetFormat(Format::EVALUATION);
                m_monomials.push_back(aPoly);
            }

            // loop for negative values of m
            for (size_t i = 0; i < N; ++i) {
                NativePoly aPoly = NativePoly(m_polyParams, Format::COEFFICIENT, true);
                aPoly[i].ModSubEq(NativeInteger(1), Q);  // -X^m
                aPoly[0].ModSubEq(NativeInteger(1), Q);  // -1
                aPoly.SetFormat(Format::EVALUATION);
                m_monomials.push_back(aPoly);
            }
        }
    }

    /**
   * Performs precomputations based on the supplied parameters
   */
    void PreCompute(bool signEval = false);

    uint32_t GetN() const {
        return m_N;
    }

    const NativeInteger& GetQ() const {
        return m_Q;
    }

    const NativeInteger& Getq() const {
        return m_q;
    }

    uint32_t GetBaseG() const {
        return m_baseG;
    }

    uint32_t GetDigitsG() const {
        return m_digitsG;
    }

    uint32_t GetBaseR() const {
        return m_baseR;
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

    bool operator==(const RingGSWCryptoParams& other) const {
        return m_N == other.m_N && m_Q == other.m_Q && m_baseR == other.m_baseR && m_baseG == other.m_baseG;
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
    }

    template <class Archive>
    void load(Archive& ar, std::uint32_t const version) {
        if (version > SerializedVersion()) {
            OPENFHE_THROW(deserialize_error, "serialized object version " + std::to_string(version) +
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

        PreCompute();
    }

    std::string SerializedObjectName() const {
        return "RingGSWCryptoParams";
    }
    static uint32_t SerializedVersion() {
        return 1;
    }

    void Change_BaseG(uint32_t BaseG) {
        if (m_baseG != BaseG) {
            m_baseG   = BaseG;
            m_Gpower  = m_Gpower_map[m_baseG];
            m_digitsG = (uint32_t)std::ceil(log(m_Q.ConvertToDouble()) / log(static_cast<double>(m_baseG)));
        }
    }

private:
    // ring dimension for RingGSW/RingLWE scheme
    uint32_t m_N = 0;

    // modulus for the RingGSW/RingLWE scheme
    NativeInteger m_Q = 0;

    // modulus for the RingLWE scheme
    NativeInteger m_q = 0;

    // gadget base used in bootstrapping
    uint32_t m_baseG = 0;

    // number of digits in decomposing integers mod Q
    uint32_t m_digitsG = 0;

    // base used for the refreshing key (used only for DM bootstrapping)
    uint32_t m_baseR = 0;

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

    // A map of vectors of powers of baseG for sign evaluation
    std::map<uint32_t, std::vector<NativeInteger>> m_Gpower_map;

    // Parameters for polynomials in RingGSW/RingLWE
    std::shared_ptr<ILNativeParams> m_polyParams;

    // Constants used in evaluating binary gates
    std::vector<NativeInteger> m_gateConst;

    // Precomputed polynomials in Format::EVALUATION representation for X^m - 1
    // (used only for CGGI bootstrapping)
    std::vector<NativePoly> m_monomials;

    // Bootstrapping method (DM or CGGI or LMKCDEY)
    BINFHE_METHOD m_method = BINFHE_METHOD::INVALID_METHOD;
};

}  // namespace lbcrypto

#endif  // _RGSW_CRYPTOPARAMETERS_H_
