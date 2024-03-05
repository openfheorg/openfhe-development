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
  This file contains the discrete fourier transform implementation.
 */

#include "math/dftransform.h"
#include "math/nbtheory.h"

#include "utils/inttypes.h"
#include "utils/parallel.h"

#include <complex>
#include <vector>

namespace lbcrypto {

std::complex<double>* DiscreteFourierTransform::rootOfUnityTable = nullptr;
std::unordered_map<uint32_t, DiscreteFourierTransform::PrecomputedValues> DiscreteFourierTransform::precomputedValues;

DiscreteFourierTransform::PrecomputedValues::PrecomputedValues(uint32_t m, uint32_t nh) {
    m_M  = m;
    m_Nh = nh;

    m_rotGroup.resize(m_Nh);
    uint32_t fivePows = 1;
    for (size_t i = 0; i < m_Nh; ++i) {
        m_rotGroup[i] = fivePows;
        fivePows *= 5;
        fivePows %= m_M;
    }

    m_ksiPows.resize(m_M + 1);
    for (size_t j = 0; j < m_M; ++j) {
        double angle = 2.0 * M_PI * j / m_M;
        m_ksiPows[j].real(cos(angle));
        m_ksiPows[j].imag(sin(angle));
    }

    m_ksiPows[m_M] = m_ksiPows[0];
}

void DiscreteFourierTransform::Reset() {
    if (rootOfUnityTable) {
        delete[] rootOfUnityTable;
        rootOfUnityTable = nullptr;
    }
}

void DiscreteFourierTransform::Initialize(uint32_t m, uint32_t nh) {
#pragma omp critical
    // add a PrecomputedValues object to the map of precomputedValues only if it doesn't already exist for the given cyclotomic order
    if (precomputedValues.find(m) == precomputedValues.end()) {
        precomputedValues.insert({m, PrecomputedValues(m, nh)});
    }
}

void DiscreteFourierTransform::PreComputeTable(uint32_t s) {
    Reset();

    rootOfUnityTable = new std::complex<double>[s];
    for (size_t j = 0; j < s; j++) {
        rootOfUnityTable[j] = std::polar(1.0, -2 * M_PI * j / s);
    }
}

std::vector<std::complex<double>> DiscreteFourierTransform::FFTForwardTransform(std::vector<std::complex<double>>& A) {
    usint m = A.size();
    std::vector<std::complex<double>> B(A);
    usint l = floor(log2(m));

    // static usint maxMCached(131072);
    static usint LOGM_MAX(17);  // maximum supported is 2^17 = 131072
    static std::vector<usint> cachedM(LOGM_MAX + 1, 0);
    static std::vector<std::vector<double>> cosTable(LOGM_MAX + 1);
    static std::vector<std::vector<double>> sinTable(LOGM_MAX + 1);

#pragma omp critical
    {
        if (m != cachedM[l]) {
            // if (m > maxMCached) {
            //  // need to grow cachedM and the tables
            //  cachedM.resize(l);
            //  cosTable.resize(l);
            //  cosTable.resize(l);
            //  maxMCached = m;
            // }
            // std::cout<<"miss m "<<m<<" != M "<<cachedM[l]<<std::endl;
            cachedM[l] = m;

            sinTable[l].resize(m / 2);
            cosTable[l].resize(m / 2);
            for (usint i = 0; i < m / 2; i++) {
                cosTable[l][i] = cos(2 * M_PI * i / m);
                sinTable[l][i] = sin(2 * M_PI * i / m);
            }
        }
    }

    // Bit-reversed addressing permutation
    for (usint i = 0; i < m; i++) {
        usint j = ReverseBits(i, 32) >> (32 - l);
        if (j > i) {
            double temp = B[i].real();
            B[i].real(B[j].real());
            B[j].real(temp);
            temp = B[i].imag();
            B[i].imag(B[j].imag());
            B[j].imag(temp);
        }
    }

    // Cooley-Tukey decimation-in-time radix-2 FFT
    for (usint size = 2; size <= m; size *= 2) {
        usint halfsize  = size / 2;
        usint tablestep = m / size;
        for (usint i = 0; i < m; i += size) {
            for (usint j = i, k = 0; j < i + halfsize; j++, k += tablestep) {
                double tpre = B[j + halfsize].real() * cosTable[l][k] + B[j + halfsize].imag() * sinTable[l][k];
                double tpim = -B[j + halfsize].real() * sinTable[l][k] + B[j + halfsize].imag() * cosTable[l][k];
                B[j + halfsize].real(B[j].real() - tpre);
                B[j + halfsize].imag(B[j].imag() - tpim);
                B[j].real(B[j].real() + tpre);
                B[j].imag(B[j].imag() + tpim);
            }
        }
        if (size == m)  // Prevent overflow in 'size *= 2'
            break;
    }

    return B;
}

std::vector<std::complex<double>> DiscreteFourierTransform::FFTInverseTransform(std::vector<std::complex<double>>& A) {
    std::vector<std::complex<double>> result = DiscreteFourierTransform::FFTForwardTransform(A);
    double n                                 = result.size() / 2;
    for (int i = 0; i < n; i++) {
        result[i] = std::complex<double>(result[i].real() / n, result[i].imag() / n);
    }
    return result;
}

std::vector<std::complex<double>> DiscreteFourierTransform::ForwardTransform(std::vector<std::complex<double>> A) {
    int n = A.size();
    A.resize(2 * n);
    for (int i = 0; i < n; i++) {
        A[n + i] = 0;
    }
    // if (rootOfUnityTable == nullptr) {
    //   PreComputeTable(2 * n);
    // }
    std::vector<std::complex<double>> dft = FFTForwardTransform(A);
    std::vector<std::complex<double>> dftRemainder(dft.size() / 2);
    size_t k = 0;
    for (int i = dft.size() - 1; i > 0; i--) {
        if (i % 2 != 0) {
            dftRemainder[k] = dft[i];
            k++;
            // dftRemainder.push_back(dft[i]);
        }
    }
    return dftRemainder;
}

std::vector<std::complex<double>> DiscreteFourierTransform::InverseTransform(std::vector<std::complex<double>> A) {
    size_t n = A.size();
    std::vector<std::complex<double>> dft(2 * n);
    for (size_t i = 0; i < n; i++) {
        dft[2 * i]     = 0;
        dft[2 * i + 1] = A[i];
    }
    std::vector<std::complex<double>> invDft = FFTInverseTransform(dft);
    std::vector<std::complex<double>> invDftRemainder(invDft.size() / 2);
    for (size_t i = 0; i < invDft.size() / 2; i++) {
        invDftRemainder[i] = invDft[i];
    }
    return invDftRemainder;
}

void DiscreteFourierTransform::FFTSpecialInv(std::vector<std::complex<double>>& vals, uint32_t cyclOrder) {
    // check if the precomputed table exists for the given cyclotomic order
    const auto it = precomputedValues.find(cyclOrder);
    if (it == precomputedValues.end()) {
        std::string errMsg("DiscreteFourierTransform::Initialize() must be called for cyclOrder = ");
        errMsg += std::to_string(cyclOrder);
        OPENFHE_THROW(config_error, errMsg);
    }

    const uint32_t valsSize = vals.size();
    for (size_t len = valsSize; len >= 1; len >>= 1) {
        for (size_t i = 0; i < valsSize; i += len) {
            size_t lenh = len >> 1;
            size_t lenq = len << 2;
            size_t gap  = it->second.m_M / lenq;
            for (size_t j = 0; j < lenh; ++j) {
                size_t idx             = (lenq - (it->second.m_rotGroup[j] % lenq)) * gap;
                std::complex<double> u = vals[i + j] + vals[i + j + lenh];
                std::complex<double> v = vals[i + j] - vals[i + j + lenh];
                v *= it->second.m_ksiPows[idx];
                vals[i + j]        = u;
                vals[i + j + lenh] = v;
            }
        }
    }
    BitReverse(vals);

    for (size_t i = 0; i < valsSize; ++i) {
        vals[i] /= valsSize;
    }
}

void DiscreteFourierTransform::FFTSpecial(std::vector<std::complex<double>>& vals, uint32_t cyclOrder) {
    // check if the precomputed table exists for the given cyclotomic order
    const auto it = precomputedValues.find(cyclOrder);
    if (it == precomputedValues.end()) {
        std::string errMsg("DiscreteFourierTransform::Initialize() must be called for cyclOrder = ");
        errMsg += std::to_string(cyclOrder);
        OPENFHE_THROW(config_error, errMsg);
    }
    const PrecomputedValues& prepValues = it->second;

    BitReverse(vals);
    uint32_t size = vals.size();
    for (size_t len = 2; len <= size; len <<= 1) {
        size_t lenh = len >> 1;
        size_t lenq = len << 2;
        size_t gap  = prepValues.m_M / lenq;
        for (size_t i = 0; i < size; i += len) {
            for (size_t j = 0; j < lenh; ++j) {
                int64_t idx            = ((prepValues.m_rotGroup[j] % lenq)) * gap;
                std::complex<double> u = vals[i + j];
                std::complex<double> v = vals[i + j + lenh];
                v *= prepValues.m_ksiPows[idx];
                vals[i + j]        = u + v;
                vals[i + j + lenh] = u - v;
            }
        }
    }
}

void DiscreteFourierTransform::BitReverse(std::vector<std::complex<double>>& vals) {
    uint32_t size = vals.size();
    for (size_t i = 1, j = 0; i < size; ++i) {
        size_t bit = size >> 1;
        for (; j >= bit; bit >>= 1) {
            j -= bit;
        }
        j += bit;
        if (i < j) {
            swap(vals[i], vals[j]);
        }
    }
}

}  // namespace lbcrypto
