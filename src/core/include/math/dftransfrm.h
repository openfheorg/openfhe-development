// @file dftransfrm.h This file contains the discrete fourier transform
// definitions
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef LBCRYPTO_MATH_DFTRANSFRM_H
#define LBCRYPTO_MATH_DFTRANSFRM_H

#include <time.h>
#include <chrono>
#include <complex>
#include <fstream>
#include <map>
#include <thread>
#include <vector>

#include "math/backend.h"
#include "math/nbtheory.h"
#include "utils/utilities.h"

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

namespace lbcrypto {

/**
 * @brief Discrete Fourier Transform FFT implemetation.
 */
class DiscreteFourierTransform {
 public:
  /**
   * Virtual FFT forward transform.
   *
   * @param A is the element to perform the transform on.
   * @return is the output result of the transform.
   */
  static std::vector<std::complex<double>> FFTForwardTransform(
      std::vector<std::complex<double>> &A);

  /**
   * Virtual FFT inverse transform.
   *
   * @param A is the element to perform the inverse transform on.
   * @return is the output result of the inverse transform.
   */
  static std::vector<std::complex<double>> FFTInverseTransform(
      std::vector<std::complex<double>> &A);

  /**
   * Virtual forward transform.
   *
   * @param A is the element to perform the transform on.
   * @return is the output result of the transform.
   */
  static std::vector<std::complex<double>> ForwardTransform(
      std::vector<std::complex<double>> A);

  /**
   * Virtual inverse transform.
   *
   * @param A is the element to perform the inverse transform on.
   * @return is the output result of the inverse transform.
   */
  static std::vector<std::complex<double>> InverseTransform(
      std::vector<std::complex<double>> A);

  /**
   * In-place FFT-like algorithm used in CKKS encoding. For more details,
   * see Algorithm 1 in https://eprint.iacr.org/2018/1043.pdf.
   *
   * @param vals is a vector of complex numbers.
   */
  static void FFTSpecialInv(std::vector<std::complex<double>> &vals);

  /**
   * In-place FFT-like algorithm used in CKKS decoding. For more details,
   * see Algorithm 1 in https://eprint.iacr.org/2018/1043.pdf.
   *
   * @param vals is a vector of complex numbers.
   */
  static void FFTSpecial(std::vector<std::complex<double>> &vals);

  /**
   * Reset cached values for the transform to empty.
   */
  static void Reset();

  static void PreComputeTable(uint32_t s);

  static void Initialize(size_t m, size_t nh);

 private:
  static std::complex<double> *rootOfUnityTable;

  static size_t m_M;
  static size_t m_Nh;

  // flag that is set to false
  // when initialization is in progress
  static bool m_isInitialized;

  /// precomputed rotation group indexes
  static std::vector<uint32_t> m_rotGroup;
  /// precomputed ksi powers
  static std::vector<std::complex<double>> m_ksiPows;

  static void FFTSpecialInvLazy(std::vector<std::complex<double>> &vals);

  static void BitReverse(std::vector<std::complex<double>> &vals);
};

}  // namespace lbcrypto

#endif
