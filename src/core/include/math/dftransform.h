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
  This code contains the discrete fourier transform definitions
 */

#ifndef LBCRYPTO_INC_MATH_DFTRANSFORM_H
#define LBCRYPTO_INC_MATH_DFTRANSFORM_H

#include <complex>
#include <cstdint>
#include <unordered_map>
#include <vector>

#ifndef M_PI
    #define M_PI 3.14159265358979323846
#endif

namespace lbcrypto {

/**
 * @brief Discrete Fourier Transform FFT implementation.
 */
class DiscreteFourierTransform {
public:
    /**
   * Virtual FFT forward transform.
   *
   * @param A is the element to perform the transform on.
   * @return is the output result of the transform.
   */
    static std::vector<std::complex<double>> FFTForwardTransform(std::vector<std::complex<double>>& A);

    /**
   * Virtual FFT inverse transform.
   *
   * @param A is the element to perform the inverse transform on.
   * @return is the output result of the inverse transform.
   */
    static std::vector<std::complex<double>> FFTInverseTransform(std::vector<std::complex<double>>& A);

    /**
   * Virtual forward transform.
   *
   * @param A is the element to perform the transform on.
   * @return is the output result of the transform.
   */
    static std::vector<std::complex<double>> ForwardTransform(std::vector<std::complex<double>> A);

    /**
   * Virtual inverse transform.
   *
   * @param A is the element to perform the inverse transform on.
   * @return is the output result of the inverse transform.
   */
    static std::vector<std::complex<double>> InverseTransform(std::vector<std::complex<double>> A);

    /**
   * In-place FFT-like algorithm used in CKKS encoding. For more details,
   * see Algorithm 1 in https://eprint.iacr.org/2018/1043.pdf.
   *
   * @param vals is a vector of complex numbers.
   */
    static void FFTSpecialInv(std::vector<std::complex<double>>& vals, uint32_t cyclOrder);

    /**
   * In-place FFT-like algorithm used in CKKS decoding. For more details,
   * see Algorithm 1 in https://eprint.iacr.org/2018/1043.pdf.
   *
   * @param vals is a vector of complex numbers.
   */
    static void FFTSpecial(std::vector<std::complex<double>>& vals, uint32_t cyclOrder);

    /**
   * Reset cached values for the transform to empty.
   */
    static void Reset();

    static void PreComputeTable(uint32_t s);

    static void Initialize(uint32_t m, uint32_t nh);

private:
    static std::complex<double>* rootOfUnityTable;

    // structure to keep values precomputed by Initialize() for every cyclotomic order value
    struct PrecomputedValues {
        // cyclotomic order
        uint32_t m_M;
        uint32_t m_Nh;
        // rotation group indexes
        std::vector<uint32_t> m_rotGroup;
        // ksi powers
        std::vector<std::complex<double>> m_ksiPows;

        PrecomputedValues(uint32_t m, uint32_t nh);
    };
    // precomputedValues: key - cyclotomic order, data - values precomputed for the given cyclotomic order
    static std::unordered_map<uint32_t, PrecomputedValues> precomputedValues;

    static void BitReverse(std::vector<std::complex<double>>& vals);
};

}  // namespace lbcrypto

#endif
