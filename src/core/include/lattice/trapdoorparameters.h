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
  Parameter definitions for trapdoor-related schemes (GPV signature, IBE, ABE)
 */

#ifndef SRC_CORE_INCLUDE_LATTICE_TRAPDOORPARAMETERS_H_
#define SRC_CORE_INCLUDE_LATTICE_TRAPDOORPARAMETERS_H_

#include <cmath>
#include <cstdint>
#include <memory>

#include "lattice/trapdoor.h"
#include "math/matrix.h"

namespace lbcrypto {
/**
 * @brief Base class for the parameters shared by the trapdoor-based schemes (GPV signature, IBE, ABE):
 * the ring element parameters, the discrete Gaussian generator, and its distribution parameter.
 * @tparam Element ring element
 */
template <class Element>
class TrapdoorParams {
    using ParmType = typename Element::Params;
    using DggType = typename Element::DggType;

  public:
    /**
     * @brief Default destructor
     */
    virtual ~TrapdoorParams() = default;
    /**
     * @brief Default constructor; sets the distribution parameter to 0 and leaves the ring element parameters unset.
     */
    TrapdoorParams() : m_stddev(0), m_elemparams(nullptr), m_dgg(0) {}
    /**
     * @brief Constructor for trapdoor parameters
     * @param elemparams parameters of the ring element
     * @param dgg discrete Gaussian generator used for sampling; copied into the object
     * @param stddev distribution parameter (standard deviation) of the Gaussian generator
     */
    TrapdoorParams(std::shared_ptr<ParmType> elemparams, DggType& dgg, double stddev)
        : m_stddev(stddev), m_elemparams(elemparams), m_dgg(dgg) {}
    /**
     * @brief Accessor function for the ring element parameters
     * @return the ring element parameters
     */
    std::shared_ptr<ParmType>& GetElemParams() const {
        return m_elemparams;
    }
    /**
     * @brief Mutator function for the ring element parameters
     * @param elemparams ring element parameters
     */
    void SetElemParams(std::shared_ptr<ParmType>& elemparams) {
        m_elemparams = elemparams;
    }
    /**
     * @brief Accessor function for the discrete Gaussian generator
     * @return the discrete Gaussian generator
     */
    DggType& GetDGG() {
        return m_dgg;
    }
    /**
     * @brief Mutator function for the discrete Gaussian generator
     * @param dgg discrete Gaussian generator to be set
     */
    void SetDGG(DggType& dgg) {
        m_dgg = dgg;
    }
    /**
     * @brief Accessor function for the distribution parameter
     * @return the distribution parameter (standard deviation) of the Gaussian generator
     */
    double GetStdDev() {
        return m_stddev;
    }
    /**
     * @brief Sets the distribution parameter and applies it to the stored discrete Gaussian generator as well.
     * @param stddev distribution parameter (standard deviation) to be set
     */
    void SetStdDev(double stddev) {
        m_stddev = stddev;
        m_dgg.SetStd(stddev);
    }

  protected:
    /** distribution parameter (standard deviation) of the discrete Gaussian generator */
    double m_stddev;
    /** parameters of the ring element */
    std::shared_ptr<ParmType> m_elemparams;
    /** discrete Gaussian generator used for sampling */
    DggType m_dgg;
};
/**
 * @brief Trapdoor parameters for the RLWE (Ring Learning With Errors) setting; adds the gadget base, the number
 * of gadget digits k, the ring dimension n, and the large-sigma Gaussian generator used for perturbation sampling.
 * @tparam Element ring element
 */
template <class Element>
class RLWETrapdoorParams : public TrapdoorParams<Element> {
    using ParmType = typename Element::Params;
    using DggType = typename Element::DggType;

  public:
    /**
     * @brief Default destructor
     */
    ~RLWETrapdoorParams() override = default;
    /**
     * @brief Default constructor; all numeric parameters are set to 0.
     */
    RLWETrapdoorParams() : TrapdoorParams<Element>(), m_base(0), m_k(0), m_bal(0), m_n(0), m_dggLargeSigma(0) {}
    /**
     * @brief Constructs the RLWE trapdoor parameters and derives the dependent quantities: the ring dimension
     * n = cyclotomic order / 2, the number of gadget digits k = floor(log_base(q - 1)) + 1, and the large-sigma
     * generator with standard deviation sqrt(s^2 - c^2), where c = SIGMA * (base + 1) and s = SPECTRAL_BOUND(n, k, base).
     * When that standard deviation exceeds KARNEY_THRESHOLD, a copy of dgg is stored instead (Karney sampling is
     * used for the perturbation vector in that case).
     * @param elemparams parameters of the ring element (modulus q and cyclotomic order)
     * @param dgg discrete Gaussian generator used for sampling
     * @param stddev distribution parameter (standard deviation) of the Gaussian generator
     * @param base base of the gadget matrix
     * @param bal true for balanced digit representation in the gadget decomposition
     */
    RLWETrapdoorParams(std::shared_ptr<ParmType>& elemparams, DggType& dgg, double stddev, int64_t base,
                       bool bal = false)
        : TrapdoorParams<Element>(elemparams, dgg, stddev),
          m_base(base),
          m_k(0),
          m_bal(bal),
          m_n(elemparams->GetCyclotomicOrder() >> 1),
          m_dggLargeSigma(0) {
        auto val = elemparams->GetModulus().ConvertToDouble();
        auto logTwo = std::log(val - 1.0) / std::log(base) + 1.0;
        m_k = static_cast<size_t>(std::floor(logTwo));

        auto c = static_cast<double>(SIGMA * (m_base + 1));
        auto s = static_cast<double>(SPECTRAL_BOUND(m_n, m_k, base));
        auto t = std::sqrt(s * s - c * c);
        m_dggLargeSigma = (t <= KARNEY_THRESHOLD) ? DggType(t) : dgg;
    }
    /**
     * @brief Accessor function for the gadget matrix base
     * @return base of the gadget matrix
     */
    int64_t GetBase() {
        return m_base;
    }
    /**
     * @brief Sets the gadget matrix base; k and the large-sigma generator are not recomputed.
     * @param base base of the gadget matrix to be set
     */
    void SetBase(int64_t base) {
        m_base = base;
    }
    /**
     * @brief Accessor function for the balanced digit representation flag
     * @return true if balanced digit representation is used
     */
    bool IsBal() {
        return m_bal;
    }
    /**
     * @brief Mutator function for the balanced digit representation flag
     * @param bal true to use balanced digit representation
     */
    void SetBal(bool bal) {
        m_bal = bal;
    }
    /**
     * @brief Accessor function for the number of gadget digits k = floor(log_base(q - 1)) + 1
     * @return number of gadget digits
     */
    size_t GetK() {
        return m_k;
    }
    /**
     * @brief Accessor function for the ring dimension n (half the cyclotomic order)
     * @return ring dimension
     */
    uint32_t GetN() {
        return m_n;
    }
    /**
     * @brief Accessor function for the discrete Gaussian generator with the large distribution parameter used for
     * perturbation sampling
     * @return the large-sigma discrete Gaussian generator
     */
    DggType& GetDGGLargeSigma() {
        return m_dggLargeSigma;
    }
    /**
     * @brief Mutator function for the discrete Gaussian generator with the large distribution parameter
     * @param dggLargeSigma discrete Gaussian generator to be set
     */
    void SetDGGLargeSigma(DggType& dggLargeSigma) {
        m_dggLargeSigma = dggLargeSigma;
    }

  protected:
    /** base of the gadget matrix */
    int64_t m_base;
    /** number of gadget digits, floor(log_base(q - 1)) + 1 */
    size_t m_k;
    /** true if balanced digit representation is used in the gadget decomposition */
    bool m_bal;
    /** ring dimension (half the cyclotomic order) */
    uint32_t m_n;
    /** discrete Gaussian generator with the large distribution parameter used for perturbation sampling */
    DggType m_dggLargeSigma;
    //    DggType m_dggLargeSigma = DggType(0);
};
/**
 * @brief Container for the perturbation vector produced by the offline stage of trapdoor sampling
 * (RLWETrapdoorUtility::GaussSampOffline) and consumed by the online stage (GaussSampOnline).
 * @tparam Element ring element
 */
template <class Element>
class PerturbationVector {
  public:
    /**
     * @brief Default constructor; holds no vector.
     */
    PerturbationVector() : m_pvector(nullptr) {};
    /**
     * @brief Constructor for the perturbation vector
     * @param pvector column matrix of ring elements holding the perturbation vector
     */
    explicit PerturbationVector(std::shared_ptr<Matrix<Element>>& pvector) : m_pvector(pvector) {}
    /**
     * @brief Mutator for the perturbation vector
     * @param pvector column matrix of ring elements holding the perturbation vector
     */
    void SetVector(std::shared_ptr<Matrix<Element>>& pvector) {
        m_pvector = pvector;
    }
    /**
     * @brief Accessor for the perturbation vector
     * @return column matrix of ring elements holding the perturbation vector
     */
    std::shared_ptr<Matrix<Element>>& GetVector() const {
        return m_pvector;
    }

  private:
    // Perturbation vector represented as a vector of ring elements
    std::shared_ptr<Matrix<Element>> m_pvector;
};
}  // namespace lbcrypto

#endif  // SRC_CORE_INCLUDE_LATTICE_TRAPDOORPARAMETERS_H_
