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

#ifndef LBCRYPTO_INC_LATTICE_TRAPDOORPARAMETERS_H
#define LBCRYPTO_INC_LATTICE_TRAPDOORPARAMETERS_H

#include "lattice/trapdoor.h"

#include "math/matrix.h"

#include <memory>

namespace lbcrypto {
/*
 *@brief Virtual templated class for trapdoor parameters
 *@tparam Element ring element
 */
template <class Element>
class TrapdoorParams {
    using ParmType = typename Element::Params;
    using DggType  = typename Element::DggType;

public:
    /*
   *@brief Default destructor
   */
    virtual ~TrapdoorParams() = default;
    /*
   *@brief Default constructor
   */
    TrapdoorParams() : m_stddev(0), m_elemparams(nullptr), m_dgg(0) {}
    /*
   *@brief Constructor for trapdoor parameters
   *@param elemparams Parameters for the ring element
   *@param dgg Discrete Gaussian Generator for random number generation
   *@param stddev Distribution parameter for the Gaussian Generator
   */
    TrapdoorParams(std::shared_ptr<ParmType> elemparams, DggType& dgg, double stddev)
        : m_stddev(stddev), m_elemparams(elemparams), m_dgg(dgg) {}
    /*
   *@brief Accessor function for ring element params
   *@return Ring element params
   */
    std::shared_ptr<ParmType>& GetElemParams() const {
        return m_elemparams;
    }
    /*
   *@brief Mutator function for ring element params
   *@param elemparams Ring element params
   */
    void SetElemParams(std::shared_ptr<ParmType>& elemparams) {
        m_elemparams = elemparams;
    }
    /*
   *@brief Accessor function for Discrete Gaussian Generator
   *@return the set Discrete Gaussian Generator
   */
    DggType& GetDGG() {
        return m_dgg;
    }
    /*
   *@brief Mutator function for Discrete Gaussian Generator
   *@param dgg Discrete Gaussian Generator to be set
   */
    void SetDGG(DggType& dgg) {
        m_dgg = dgg;
    }
    /*
   *@brief Accessor function for distribution parameter
   *@return Distribution parameter
   */
    double GetStdDev() {
        return m_stddev;
    }
    /*
   *@brief Mutator function for distribution parameter
   *@param stddev Distribution parameter to be set
   */
    void SetStdDev(double stddev) {
        m_stddev = stddev;
        m_dgg.SetStd(stddev);
    }

protected:
    double m_stddev;
    std::shared_ptr<ParmType> m_elemparams;
    DggType m_dgg;
};
/*
 *@brief Templated class for trapdoor parameters specifically designed for RLWE
 *(Ring Learning With Error) Setting
 *@tparam Element ring element
 */
template <class Element>
class RLWETrapdoorParams : public TrapdoorParams<Element> {
    using ParmType = typename Element::Params;
    using DggType  = typename Element::DggType;

public:
    /*
   *@brief Default destructor
   */
    ~RLWETrapdoorParams() override = default;
    /*
   *@brief Default constructor
   */
    RLWETrapdoorParams() : TrapdoorParams<Element>(), m_base(0), m_k(0), m_bal(0), m_n(0), m_dggLargeSigma(0) {}
    /*
   *@brief Constructor for trapdoor parameters
   *@param elemparams Parameters for the ring element
   *@param dgg Discrete Gaussian Generator for random number generation
   *@param stddev Distribution parameter for the Gaussian Generator
   *@param base Base for the gadget matrix
   *@param bal Flag for balanced generation in trapdoor
   */
    RLWETrapdoorParams(std::shared_ptr<ParmType>& elemparams, DggType& dgg, double stddev, int64_t base,
                       bool bal = false)
        : TrapdoorParams<Element>(elemparams, dgg, stddev),
          m_base(base),
          m_k(0),
          m_bal(bal),
          m_n(elemparams->GetCyclotomicOrder() >> 1),
          m_dggLargeSigma(0) {
        auto val    = elemparams->GetModulus().ConvertToDouble();
        auto logTwo = log(val - 1.0) / log(base) + 1.0;
        m_k         = static_cast<size_t>(floor(logTwo));

        auto c          = static_cast<double>(SIGMA * (m_base + 1));
        auto s          = static_cast<double>(SPECTRAL_BOUND(m_n, m_k, base));
        auto t          = sqrt(s * s - c * c);
        m_dggLargeSigma = (t <= KARNEY_THRESHOLD) ? DggType(t) : dgg;
    }
    /*
   *@brief Accessor function for the gadget matrix base
   *@return Base for gadget matrix
   */
    int64_t GetBase() {
        return m_base;
    }
    /*
   *@brief Mutator function for the gadget matrix base
   *@param base Base for gadget matrix to be set
   */
    void SetBase(int64_t base) {
        m_base = base;
    }
    /*
   *@brief Accessor function for balanced representation flag
   *@return Flag for balanced representation
   */
    bool IsBal() {
        return m_bal;
    }
    /*
   *@brief Mutator function for balanced representation flag
   *@param bal flag for balanced representation
   */
    void SetBal(bool bal) {
        m_bal = bal;
    }
    /*
   *@brief Accessor function for trapdoor length
   *@return Trapdoor length
   */
    size_t GetK() {
        return m_k;
    }
    /*
   *@brief Accessor function for ring size
   *@return Ring size
   */
    usint GetN() {
        return m_n;
    }
    /*
   *@brief Accessor function for Discrete Gaussian Generator with Large
   *Distribution Parameter
   *@return the set Discrete Gaussian Generator
   */
    DggType& GetDGGLargeSigma() {
        return m_dggLargeSigma;
    }
    /*
   *@brief Mutator function for Discrete Gaussian Generator with Large
   *Distribution Parameter
   *@param dgg Discrete Gaussian Generator to be set
   */
    void SetDGGLargeSigma(DggType& dggLargeSigma) {
        m_dggLargeSigma = dggLargeSigma;
    }

protected:
    int64_t m_base;
    size_t m_k;
    bool m_bal;
    usint m_n;
    DggType m_dggLargeSigma;
    //    DggType m_dggLargeSigma = DggType(0);
};
/*
 *@brief Templated class for perturbation vector container class, used for
 *online/offline splits in trapdoor sampling
 *@tparam Element ring element
 */
template <class Element>
class PerturbationVector {
public:
    /*
   *@brief Default constructor
   */
    PerturbationVector() : m_pvector(nullptr){};
    /*
   *@brief Constructor for perturbation vector
   *@param pvector Vector containing ring elements
   */
    explicit PerturbationVector(std::shared_ptr<Matrix<Element>>& pvector) : m_pvector(pvector) {}
    /*
   *@brief Mutator for perturbation vector
   *@param pvector Vector containing ring elements
   */
    void SetVector(std::shared_ptr<Matrix<Element>>& pvector) {
        m_pvector = pvector;
    }
    /*
   *@brief Accessor for perturbation vector
   *@return Vector containing ring elements
   */
    std::shared_ptr<Matrix<Element>>& GetVector() const {
        return m_pvector;
    }

private:
    // Perturbation vector represented as a vector of ring elements
    std::shared_ptr<Matrix<Element>> m_pvector;
};
}  // namespace lbcrypto

#endif
