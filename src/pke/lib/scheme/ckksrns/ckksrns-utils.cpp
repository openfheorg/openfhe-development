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

#include "scheme/ckksrns/ckksrns-utils.h"
#include "utils/exception.h"
#include "utils/utilities.h"

#include <algorithm>
#include <cmath>
#include <complex>
#include <functional>
#include <vector>

namespace lbcrypto {

namespace {  // this namespace should stay unnamed

/**
 * Computes parameters to ensure the encoding and decoding computations take exactly the
 * specified number of levels. More specifically, it returns a vector than contains
 * layers (the number of layers to collapse in one level), rows (how many such levels),
 * rem (the number of layers remaining to be collapsed in one level)
 *
 * @param logSlots the base 2 logarithm of the number of slots.
 * @param budget the allocated level budget for the computation.
 */
std::vector<uint32_t> SelectLayers(uint32_t logSlots, uint32_t budget = 4) {
    uint32_t layers = std::ceil(static_cast<double>(logSlots) / budget);
    uint32_t rows   = logSlots / layers;
    uint32_t rem    = logSlots % layers;
    uint32_t dim    = (rem == 0) ? rows : (rows + 1);

    // the above choice ensures dim <= budget
    if (dim < budget) {
        layers -= 1;
        rows = logSlots / layers;
        rem  = logSlots - rows * layers;
        dim  = (rem == 0) ? rows : (rows + 1);

        // the above choice endures dim >=budget
        if (dim > budget) {
            while (dim != budget) {
                --rows;
                rem = logSlots - rows * layers;
                dim = (rem == 0) ? rows : (rows + 1);
            }
        }
    }

    return {layers, rows, rem};
}

/*  Populate statically the parameter m for the Paterson-Stockmeyer algorithm up
    to the degree value of upperBoundDegree.*/
enum { UPPER_BOUND_PS = 2204 };
std::vector<uint32_t> PopulateParameterPS(const uint32_t upperBoundDegree) {
    std::vector<uint32_t> mlist(upperBoundDegree);
    std::fill(mlist.begin(), mlist.begin() + 2, 1);            // n in [1,2], m = 1
    std::fill(mlist.begin() + 2, mlist.begin() + 11, 2);       // n in [3,11], m = 2
    std::fill(mlist.begin() + 11, mlist.begin() + 13, 3);      // n in [12,13], m = 3
    std::fill(mlist.begin() + 13, mlist.begin() + 17, 2);      // n in [14,17], m = 2
    std::fill(mlist.begin() + 17, mlist.begin() + 55, 3);      // n in [18,55], m = 3
    std::fill(mlist.begin() + 55, mlist.begin() + 59, 4);      // n in [56,59], m = 4
    std::fill(mlist.begin() + 59, mlist.begin() + 76, 3);      // n in [60,76], m = 3
    std::fill(mlist.begin() + 76, mlist.begin() + 239, 4);     // n in [77,239], m = 4
    std::fill(mlist.begin() + 239, mlist.begin() + 247, 5);    // n in [240,247], m = 5
    std::fill(mlist.begin() + 247, mlist.begin() + 284, 4);    // n in [248,284], m = 4
    std::fill(mlist.begin() + 284, mlist.begin() + 991, 5);    // n in [285,991], m = 5
    std::fill(mlist.begin() + 991, mlist.begin() + 1007, 6);   // n in [992,1007], m = 6
    std::fill(mlist.begin() + 1007, mlist.begin() + 1083, 5);  // n in [1008,1083], m = 5
    std::fill(mlist.begin() + 1083, mlist.begin() + 2015, 6);  // n in [1084,2015], m = 6
    std::fill(mlist.begin() + 2015, mlist.begin() + 2031, 7);  // n in [2016,2031], m = 7
    std::fill(mlist.begin() + 2031, mlist.end(), 6);           // n in [2032,2204], m = 6
    return mlist;
}

// clang-format off
// Populate the conversion table Degree-to-Multiplicative Depth
enum {
    LOWER_BOUND_DEGREE = 5,
    UPPER_BOUND_DEGREE = 261631,
};
std::vector<uint32_t> GenerateDepthByDegreeTable() {
    std::vector<uint32_t> depthTable(UPPER_BOUND_DEGREE + 1);
    std::fill(depthTable.begin(),        depthTable.begin() + 5,     3);  // degree in [0,4], depth = 3 - the Paterson-Stockmeyer algorithm is not used when degree < 5
    std::fill(depthTable.begin() + 5,    depthTable.begin() + 6,     4);  // degree in [5],         depth = 4
    std::fill(depthTable.begin() + 6,    depthTable.begin() + 14,    5);  // degree in [6,13],      depth = 5
    std::fill(depthTable.begin() + 14,   depthTable.begin() + 28,    6);  // degree in [14,27],     depth = 6
    std::fill(depthTable.begin() + 28,   depthTable.begin() + 60,    7);  // degree in [28,59],     depth = 7
    std::fill(depthTable.begin() + 60,   depthTable.begin() + 120,   8);  // degree in [60,119],    depth = 8
    std::fill(depthTable.begin() + 120,  depthTable.begin() + 248,   9);  // degree in [120,247],   depth = 9
    std::fill(depthTable.begin() + 248,  depthTable.begin() + 496,  10);  // degree in [248,495],   depth = 10
    std::fill(depthTable.begin() + 496,  depthTable.begin() + 1008, 11);  // degree in [496,1007],  depth = 11
    std::fill(depthTable.begin() + 1008, depthTable.begin() + 2031, 12);  // degree in [1008,2031], depth = 12
    std::fill(depthTable.begin() + 2032, depthTable.begin() + 4031, 13);  // degree in [2031,4031], depth = 13
    std::fill(depthTable.begin() + 4032, depthTable.begin() + 8127, 14);  // degree in [4032,8127], depth = 14
    std::fill(depthTable.begin() + 8128, depthTable.begin() + 16255, 15);  // degree in [8128, 16255], depth = 15
    std::fill(depthTable.begin() + 16256, depthTable.begin() + 32639, 16);  // degree in [16256, 32639], depth = 16
    std::fill(depthTable.begin() + 32640, depthTable.begin() + 65279, 17);  // degree in [32640, 65279], depth = 17
    std::fill(depthTable.begin() + 65280, depthTable.begin() + 130815, 18);  // degree in [65280, 130815], depth = 18
    std::fill(depthTable.begin() + 130816, depthTable.end(), 19);  // degree in [130816, 261631], depth = 19
    return depthTable;
}
// clang-format on

}  // namespace

uint32_t GetDepthByDegree(size_t degree) {
    if (degree >= LOWER_BOUND_DEGREE && degree <= UPPER_BOUND_DEGREE)
        return GenerateDepthByDegreeTable()[degree];

    std::string errMsg("Polynomial degree is supported from " + std::to_string(LOWER_BOUND_DEGREE) + " to " +
                       std::to_string(UPPER_BOUND_DEGREE) + " inclusive. Its current value is ");
    errMsg += std::to_string(degree);
    OPENFHE_THROW(errMsg);
}

template struct longDiv<int64_t>;
template struct longDiv<double>;
template struct longDiv<std::complex<double>>;

/* f and g are vectors of coefficients of the two polynomials. We assume their dominant
coefficient is not zero. LongDivisionPoly returns the vector of coefficients for the
quotient and remainder of the division f/g. longDiv is a struct that contains the
vectors of coefficients for the quotient and rest. */
template <typename VectorDataType>
std::shared_ptr<longDiv<VectorDataType>> LongDivisionPoly(const std::vector<VectorDataType>& f,
                                                          const std::vector<VectorDataType>& g) {
    auto n = Degree(f);
    if (n != f.size() - 1)
        OPENFHE_THROW("The dominant coefficient of the divident is zero");
    auto k = Degree(g);
    if (k != g.size() - 1)
        OPENFHE_THROW("The dominant coefficient of the divisor is zero");
    if (n < k)
        return std::make_shared<longDiv<VectorDataType>>(std::vector<VectorDataType>(1), f);

    std::vector<VectorDataType> q(n - k + 1);
    std::vector<VectorDataType> r(f);
    std::vector<VectorDataType> d;
    d.reserve(g.size() + n);

    while (n >= k) {
        // d is g padded with zeros before up to n
        d.clear();
        d.resize(n - k);
        d.insert(d.end(), g.begin(), g.end());

        q[n - k] = r.back();
        if (IsNotEqualOne(g[k]))
            q[n - k] /= g.back();

        // d *= q[n - k]
        std::transform(d.begin(), d.end(), d.begin(),
                       std::bind(std::multiplies<VectorDataType>(), std::placeholders::_1, q[n - k]));
        // f-=d
        std::transform(r.begin(), r.end(), d.begin(), r.begin(), std::minus<VectorDataType>());
        if (r.size() > 1) {
            n = Degree(r);
            r.resize(n + 1);
        }
    }
    return std::make_shared<longDiv<VectorDataType>>(q, r);
}

template std::shared_ptr<longDiv<int64_t>> LongDivisionPoly(const std::vector<int64_t>& f,
                                                            const std::vector<int64_t>& g);
template std::shared_ptr<longDiv<double>> LongDivisionPoly(const std::vector<double>& f, const std::vector<double>& g);
template std::shared_ptr<longDiv<std::complex<double>>> LongDivisionPoly(const std::vector<std::complex<double>>& f,
                                                                         const std::vector<std::complex<double>>& g);

/* f and g are vectors of Chebyshev interpolation coefficients of the two polynomials.
We assume their dominant coefficient is not zero. LongDivisionChebyshev returns the
vector of Chebyshev interpolation coefficients for the quotient and remainder of the
division f/g. longDiv is a struct that contains the vectors of coefficients for the
quotient and rest. We assume that the zero-th coefficient is c0, not c0/2 and returns
the same format.*/
template <typename VectorDataType>
std::shared_ptr<longDiv<VectorDataType>> LongDivisionChebyshev(const std::vector<VectorDataType>& f,
                                                               const std::vector<VectorDataType>& g) {
    auto n = Degree(f);
    if (n != f.size() - 1)
        OPENFHE_THROW("The dominant coefficient of the divident is zero");
    auto k = Degree(g);
    if (k != g.size() - 1)
        OPENFHE_THROW("The dominant coefficient of the divisor is zero");
    if (n < k)
        return std::make_shared<longDiv<VectorDataType>>(std::vector<VectorDataType>(1), f);

    std::vector<VectorDataType> q(n - k + 1);
    std::vector<VectorDataType> r(f);
    std::vector<VectorDataType> d;
    d.reserve(g.size() + n);

    while (n > k) {
        d.clear();
        d.resize(n + 1);

        q[n - k] = 2.0 * r.back();
        if (IsNotEqualOne(g[k]))
            q[n - k] /= g.back();

        if (k == n - k) {
            d.front() = 2.0 * g[n - k];

            for (size_t i = 1; i < 2 * k + 1; i++)
                d[i] = g[static_cast<size_t>(std::abs(static_cast<int32_t>(n - k - i)))];
        }
        else {
            if (k > (n - k)) {
                d.front() = 2.0 * g[n - k];
                for (size_t i = 1; i < k - (n - k) + 1; i++) {
                    d[i] = g[static_cast<size_t>(std::abs(static_cast<int32_t>(n - k - i)))] +
                           g[static_cast<size_t>(n - k + i)];
                }
                for (size_t i = k - (n - k) + 1; i < n + 1; i++) {
                    d[i] = g[static_cast<size_t>(std::abs(static_cast<int32_t>(i - n + k)))];
                }
            }
            else {
                d[n - k] = g.front();
                for (size_t i = n - 2 * k; i < n + 1; i++) {
                    if (i != n - k) {
                        d[i] = g[static_cast<size_t>(std::abs(int32_t(i - n + k)))];
                    }
                }
            }
        }

        if (IsNotEqualOne(r.back())) {
            // d *= f[n]
            std::transform(d.begin(), d.end(), d.begin(),
                           std::bind(std::multiplies<VectorDataType>(), std::placeholders::_1, r.back()));
        }
        if (IsNotEqualOne(g.back())) {
            // d /= g[k]
            std::transform(d.begin(), d.end(), d.begin(),
                           std::bind(std::divides<VectorDataType>(), std::placeholders::_1, g.back()));
        }
        // f-=d
        std::transform(r.begin(), r.end(), d.begin(), r.begin(), std::minus<VectorDataType>());
        if (r.size() > 1) {
            n = Degree(r);
            r.resize(n + 1);
        }
    }

    if (n == k) {
        d = g;

        q.front() = r.back();
        if (IsNotEqualOne(g.back())) {
            q.front() /= g.back();  // q[0] /= g[k]
        }
        if (IsNotEqualOne(r.back())) {
            // d *= f[n]
            std::transform(d.begin(), d.end(), d.begin(),
                           std::bind(std::multiplies<VectorDataType>(), std::placeholders::_1, r.back()));
        }
        if (IsNotEqualOne(g.back())) {
            // d /= g[k]
            std::transform(d.begin(), d.end(), d.begin(),
                           std::bind(std::divides<VectorDataType>(), std::placeholders::_1, g.back()));
        }
        // f-=d
        std::transform(r.begin(), r.end(), d.begin(), r.begin(), std::minus<VectorDataType>());
        if (r.size() > 1) {
            n = Degree(r);
            r.resize(n + 1);
        }
    }
    q.front() *= 2.0;  // Because we want to have [c0] in the last spot, not [c0/2]

    return std::make_shared<longDiv<VectorDataType>>(q, r);
}

template std::shared_ptr<longDiv<int64_t>> LongDivisionChebyshev(const std::vector<int64_t>& f,
                                                                 const std::vector<int64_t>& g);
template std::shared_ptr<longDiv<double>> LongDivisionChebyshev(const std::vector<double>& f,
                                                                const std::vector<double>& g);
template std::shared_ptr<longDiv<std::complex<double>>> LongDivisionChebyshev(
    const std::vector<std::complex<double>>& f, const std::vector<std::complex<double>>& g);

/*	Compute positive integers k,m such that n < k(2^m-1), k is close to sqrt(n/2)
	and the depth = ceil(log2(k))+m is minimized. Moreover, for that depth the
	number of homomorphic multiplications = k+2m+2^(m-1)-4 is minimized.
	Since finding these parameters involve testing many possible values, we
	hardcode them for commonly used degrees, and provide a heuristic which
	minimizes the number of homomorphic multiplications for the rest of the
	degrees.*/
std::vector<uint32_t> ComputeDegreesPS(uint32_t n) {
    if (n == 0)
        OPENFHE_THROW("ComputeDegreesPS: The degree is zero. There is no need to evaluate the polynomial.");

    // index n-1 in the vector corresponds to degree n
    if (n <= UPPER_BOUND_PS) {  // hard-coded values
        static const std::vector<uint32_t> mlist = PopulateParameterPS(UPPER_BOUND_PS);

        uint32_t m = mlist[n - 1];
        uint32_t k = static_cast<uint32_t>(std::floor(n / ((1U << m) - 1)) + 1);

        return std::vector<uint32_t>{k, m};
    }

    // heuristic for larger degrees
    std::vector<uint32_t> klist;
    std::vector<uint32_t> mlist;
    std::vector<uint32_t> multlist;

    for (size_t k = 1; k <= n; k++) {
        for (size_t m = 1; m <= static_cast<uint32_t>(std::ceil(log2(n / k) + 1) + 1); m++) {
            if (n < (k * ((1U << m) - 1))) {
                if (std::abs(std::floor(log2(k)) - std::floor(std::log2(std::sqrt(n / 2)))) <= 1) {
                    klist.push_back(k);
                    mlist.push_back(m);
                    multlist.push_back(k + 2 * m + (1U << (m - 1)) - 4);
                }
            }
        }
    }
    uint32_t minIndex = std::min_element(multlist.begin(), multlist.end()) - multlist.begin();

    return std::vector<uint32_t>{klist[minIndex], mlist[minIndex]};
}

std::vector<std::complex<double>> ExtractShiftedDiagonal(const std::vector<std::vector<std::complex<double>>>& A,
                                                         int index) {
    uint32_t cols = A[0].size();
    uint32_t rows = A.size();

    std::vector<std::complex<double>> result(cols);

    for (uint32_t k = 0; k < cols; k++) {
        result[k] = A[k % rows][(k + index) % cols];
    }

    return result;
}

std::vector<std::complex<double>> Rotate(const std::vector<std::complex<double>>& a, int32_t index) {
    const int32_t slots = a.size();

    if (index < 0 || index > slots) {
        index = ReduceRotation(index, slots);
    }

    if (index == 0) {
        return a;
    }

    std::vector<std::complex<double>> result(slots);
    // two cases: i+index <= slots and i+index > slots
    for (int32_t i = 0; i < slots - index; i++) {
        result[i] = a[i + index];
    }
    for (int32_t i = slots - index; i < slots; i++) {
        result[i] = a[i + index - slots];
    }

    return result;
}

template <typename VectorDataType>
std::vector<VectorDataType> RotateTwoHalves(const std::vector<VectorDataType>& a, int32_t index) {
    int32_t slots     = a.size();
    int32_t slotsHalf = slots / 2;

    std::vector<VectorDataType> result(slots);

    if (index < 0 || index > slotsHalf) {
        index = ReduceRotation(index, slotsHalf);
    }

    if (index == 0) {
        result = a;
    }

    else {
        // two cases: i+index <= slots and i+index > slots
        for (int32_t i = 0; i < slotsHalf - index; i++) {
            result[i] = a[i + index];
        }
        for (int32_t i = slotsHalf - index; i < slotsHalf; i++) {
            result[i] = a[i + index - slotsHalf];
        }
        for (int32_t i = slotsHalf; i < slots - index; i++) {
            result[i] = a[i + index];
        }
        for (int32_t i = slots - index; i < slots; i++) {
            result[i] = a[i + index - slotsHalf];
        }
    }

    return result;
}

template std::vector<int64_t> RotateTwoHalves(const std::vector<int64_t>& a, int32_t index);

uint32_t ReduceRotation(int32_t index, uint32_t slots) {
    int32_t islots = int32_t(slots);

    if (IsPowerOfTwo(slots)) {
        uint32_t n = static_cast<uint32_t>(std::log2(slots));
        if (index >= 0) {
            return index - ((index >> n) << n);
        }
        return index + islots + ((std::abs(index) >> n) << n);
    }
    return (islots + index % islots) % islots;
}

std::vector<std::complex<double>> Fill(const std::vector<std::complex<double>>& a, const uint32_t slots) {
    const size_t usedSlots = a.size();
    std::vector<std::complex<double>> result(slots);
    for (uint32_t i = 0; i < slots; ++i)
        result[i] = a[i % usedSlots];
    return result;
}

std::vector<double> FillDouble(const std::vector<double>& a, const uint32_t slots) {
    const size_t usedSlots = a.size();
    std::vector<double> result(slots);
    for (uint32_t i = 0; i < slots; ++i)
        result[i] = a[i % usedSlots];
    return result;
}

std::vector<int64_t> Fillint64(const std::vector<int64_t>& a, const uint32_t slots) {
    const size_t usedSlots = a.size();
    std::vector<int64_t> result(slots);
    for (uint32_t i = 0; i < slots; ++i)
        result[i] = a[i % usedSlots];
    return result;
}

std::vector<std::vector<std::complex<double>>> CoeffEncodingOneLevel(const std::vector<std::complex<double>>& pows,
                                                                     const std::vector<uint32_t>& rotGroup,
                                                                     bool flag_i) {
    constexpr std::complex<double> I(0.0, 1.0);
    const std::complex<double> neg_exp_M_PI = std::exp(-M_PI / 2 * I);

    uint32_t dim   = pows.size() - 1;
    uint32_t slots = rotGroup.size();

    // Each outer iteration from the FFT algorithm can be written a weighted sum of
    // three terms: the input shifted right by a power of two, the unshifted input,
    // and the input shifted left by a power of two. For each outer iteration
    // (log2(size) in total), the matrix coeff stores the coefficients in the
    // following order: the coefficients associated to the input shifted right,
    // the coefficients for the non-shifted input and the coefficients associated
    // to the input shifted left.
    const uint32_t log2slots = static_cast<uint32_t>(std::log2(slots));
    std::vector<std::vector<std::complex<double>>> coeff(3 * log2slots);

    for (uint32_t i = 0; i < 3 * log2slots; i++) {
        coeff[i] = std::vector<std::complex<double>>(slots);
    }

    for (uint32_t m = slots; m > 1; m >>= 1) {
        uint32_t s = std::log2(m) - 1;

        for (uint32_t k = 0; k < slots; k += m) {
            uint32_t lenh = m >> 1;
            uint32_t lenq = m << 2;

            for (uint32_t j = 0; j < lenh; j++) {
                uint32_t jTwiddle = (lenq - (rotGroup[j] % lenq)) * (dim / lenq);

                if (flag_i && (m == 2)) {
                    std::complex<double> w             = neg_exp_M_PI * pows[jTwiddle];
                    coeff[s + log2slots][j + k]        = neg_exp_M_PI;  // not shifted
                    coeff[s + 2 * log2slots][j + k]    = neg_exp_M_PI;  // shifted left
                    coeff[s + log2slots][j + k + lenh] = -w;            // not shifted
                    coeff[s][j + k + lenh]             = w;             // shifted right
                }
                else {
                    std::complex<double> w             = pows[jTwiddle];
                    coeff[s + log2slots][j + k]        = 1;   // not shifted
                    coeff[s + 2 * log2slots][j + k]    = 1;   // shifted left
                    coeff[s + log2slots][j + k + lenh] = -w;  // not shifted
                    coeff[s][j + k + lenh]             = w;   // shifted right
                }
            }
        }
    }

    return coeff;
}

std::vector<std::vector<std::complex<double>>> CoeffDecodingOneLevel(const std::vector<std::complex<double>>& pows,
                                                                     const std::vector<uint32_t>& rotGroup,
                                                                     bool flag_i) {
    constexpr std::complex<double> I(0.0, 1.0);
    const std::complex<double> pos_exp_M_PI = std::exp(M_PI / 2 * I);

    uint32_t dim   = pows.size() - 1;
    uint32_t slots = rotGroup.size();

    // Each outer iteration from the FFT algorithm can be written a weighted sum of
    // three terms: the input shifted right by a power of two, the unshifted input,
    // and the input shifted left by a power of two. For each outer iteration
    // (log2(size) in total), the matrix coeff stores the coefficients in the
    // following order: the coefficients associated to the input shifted right,
    // the coefficients for the non-shifted input and the coefficients associated
    // to the input shifted left.
    const uint32_t log2slots = static_cast<uint32_t>(std::log2(slots));
    std::vector<std::vector<std::complex<double>>> coeff(3 * log2slots);

    for (uint32_t i = 0; i < 3 * log2slots; i++) {
        coeff[i] = std::vector<std::complex<double>>(slots);
    }

    for (uint32_t m = 2; m <= slots; m <<= 1) {
        uint32_t s = std::log2(m) - 1;

        for (uint32_t k = 0; k < slots; k += m) {
            uint32_t lenh = m >> 1;
            uint32_t lenq = m << 2;

            for (uint32_t j = 0; j < lenh; j++) {
                uint32_t jTwiddle = (rotGroup[j] % lenq) * (dim / lenq);

                if (flag_i && (m == 2)) {
                    std::complex<double> w             = pos_exp_M_PI * pows[jTwiddle];
                    coeff[s + log2slots][j + k]        = pos_exp_M_PI;  // not shifted
                    coeff[s + 2 * log2slots][j + k]    = w;             // shifted left
                    coeff[s + log2slots][j + k + lenh] = -w;            // not shifted
                    coeff[s][j + k + lenh]             = pos_exp_M_PI;  // shifted right
                }
                else {
                    std::complex<double> w             = pows[jTwiddle];
                    coeff[s + log2slots][j + k]        = 1;   // not shifted
                    coeff[s + 2 * log2slots][j + k]    = w;   // shifted left
                    coeff[s + log2slots][j + k + lenh] = -w;  // not shifted
                    coeff[s][j + k + lenh]             = 1;   // shifted right
                }
            }
        }
    }

    return coeff;
}

std::vector<std::vector<std::vector<std::complex<double>>>> CoeffEncodingCollapse(
    const std::vector<std::complex<double>>& pows, const std::vector<uint32_t>& rotGroup, uint32_t levelBudget,
    bool flag_i) {
    const uint32_t slots = rotGroup.size();
    if (!slots)
        OPENFHE_THROW("rotGroup can not be empty");
    if (!levelBudget)
        OPENFHE_THROW("levelBudget can not be 0");

    const uint32_t log2slots = static_cast<uint32_t>(std::log2(slots));
    // Need to compute how many layers are collapsed in each of the level from the budget.
    // If there is no exact division between the maximum number of possible levels (log(slots)) and the
    // level budget, the last level will contain the remaining layers collapsed.
    const std::vector<uint32_t> dims = SelectLayers(log2slots, levelBudget);
    const uint32_t layersCollapse    = dims[0];
    const uint32_t remCollapse       = dims[2];

    const uint32_t dimCollapse = levelBudget;
    const uint32_t flagRem     = (remCollapse == 0) ? 0 : 1;

    const uint32_t numRotations    = (1U << (layersCollapse + 1)) - 1;
    const uint32_t numRotationsRem = (1U << (remCollapse + 1)) - 1;

    // Computing the coefficients for encoding for the given level budget
    std::vector<std::vector<std::complex<double>>> coeff1 = CoeffEncodingOneLevel(pows, rotGroup, flag_i);

    // Coeff stores the coefficients for the given budget of levels
    std::vector<std::vector<std::vector<std::complex<double>>>> coeff(
        dimCollapse,
        std::vector<std::vector<std::complex<double>>>(numRotations, std::vector<std::complex<double>>(slots)));
    if (flagRem) {
        // this one corresponds to the first index in encoding (same applies to the last index in decoding too)
        coeff[0] =
            std::vector<std::vector<std::complex<double>>>(numRotationsRem, std::vector<std::complex<double>>(slots));
    }

    if (layersCollapse) {  // this condition is necessary for the code executed before the inner loop
        std::vector<std::vector<std::complex<double>>> zeros(numRotations,
                                                             std::vector<std::complex<double>>(slots, 0.0));
        for (int32_t s = dimCollapse - 1; s >= static_cast<int32_t>(flagRem); s--) {
            // top is an index, so it can't be negative. let's check that
            if (log2slots < (dimCollapse - 1 - s) * layersCollapse + 1)
                OPENFHE_THROW("top can not be negative");
            uint32_t top = log2slots - (dimCollapse - 1 - s) * layersCollapse - 1;

            coeff[s][0] = coeff1[top];
            coeff[s][1] = coeff1[top + log2slots];
            coeff[s][2] = coeff1[top + 2 * log2slots];
            for (size_t l = 1; l < layersCollapse; l++) {
                std::vector<std::vector<std::complex<double>>> temp = coeff[s];
                coeff[s]                                            = zeros;

                for (size_t u = 0; u < (1U << (l + 1)) - 1; u++) {
                    for (size_t k = 0; k < slots; k++) {
                        coeff[s][2 * u][k] +=
                            coeff1[top - l][k] * temp[u][ReduceRotation(k - (1U << (top - l)), slots)];
                        coeff[s][2 * u + 1][k] += coeff1[top - l + log2slots][k] * temp[u][k];
                        coeff[s][2 * u + 2][k] +=
                            coeff1[top - l + 2 * log2slots][k] * temp[u][ReduceRotation(k + (1U << (top - l)), slots)];
                    }
                }
            }
        }
    }

    if (flagRem && remCollapse) {
        std::vector<std::vector<std::complex<double>>> zeros(numRotationsRem,
                                                             std::vector<std::complex<double>>(slots, 0.0));
        uint32_t s = 0;
        // top is an index, so it can't be negative. let's check that
        if (log2slots < (dimCollapse - 1 - s) * layersCollapse - 1)
            OPENFHE_THROW("top can not be negative");
        uint32_t top = log2slots - (dimCollapse - 1 - s) * layersCollapse - 1;

        coeff[s][0] = coeff1[top];
        coeff[s][1] = coeff1[top + log2slots];
        coeff[s][2] = coeff1[top + 2 * log2slots];
        for (size_t l = 1; l < remCollapse; l++) {
            std::vector<std::vector<std::complex<double>>> temp = coeff[s];
            coeff[s]                                            = zeros;

            for (size_t u = 0; u < (1U << (l + 1)) - 1; u++) {
                for (size_t k = 0; k < slots; k++) {
                    coeff[s][2 * u][k] += coeff1[top - l][k] * temp[u][ReduceRotation(k - (1U << (top - l)), slots)];
                    coeff[s][2 * u + 1][k] += coeff1[top - l + log2slots][k] * temp[u][k];
                    coeff[s][2 * u + 2][k] +=
                        coeff1[top - l + 2 * log2slots][k] * temp[u][ReduceRotation(k + (1U << (top - l)), slots)];
                }
            }
        }
    }

    return coeff;
}

std::vector<std::vector<std::vector<std::complex<double>>>> CoeffDecodingCollapse(
    const std::vector<std::complex<double>>& pows, const std::vector<uint32_t>& rotGroup, uint32_t levelBudget,
    bool flag_i) {
    const uint32_t slots = rotGroup.size();
    if (!slots)
        OPENFHE_THROW("rotGroup can not be empty");
    if (!levelBudget)
        OPENFHE_THROW("levelBudget can not be 0");

    const uint32_t log2slots = static_cast<uint32_t>(std::log2(slots));

    // Need to compute how many layers are collapsed in each of the level from the budget.
    // If there is no exact division between the maximum number of possible levels (log(slots)) and the
    // level budget, the last level will contain the remaining layers collapsed.
    std::vector<uint32_t> dims    = SelectLayers(log2slots, levelBudget);
    const uint32_t layersCollapse = dims[0];
    const uint32_t rowsCollapse   = dims[1];
    const uint32_t remCollapse    = dims[2];

    const uint32_t dimCollapse = levelBudget;
    const uint32_t flagRem     = (remCollapse == 0) ? 0 : 1;

    uint32_t numRotations    = (1U << (layersCollapse + 1)) - 1;
    uint32_t numRotationsRem = (1U << (remCollapse + 1)) - 1;

    // Computing the coefficients for decoding for the given level budget
    std::vector<std::vector<std::complex<double>>> coeff1 = CoeffDecodingOneLevel(pows, rotGroup, flag_i);

    // Coeff stores the coefficients for the given budget of levels
    std::vector<std::vector<std::vector<std::complex<double>>>> coeff(
        dimCollapse,
        std::vector<std::vector<std::complex<double>>>(numRotations, std::vector<std::complex<double>>(slots)));
    if (flagRem) {
        // this one corresponds to the last index in decoding (same applies to the first index in encoding too)
        coeff[dimCollapse - 1] =
            std::vector<std::vector<std::complex<double>>>(numRotationsRem, std::vector<std::complex<double>>(slots));
    }

    if (layersCollapse) {  // this condition is necessary for the code executed before the inner loop
        std::vector<std::vector<std::complex<double>>> zeros(numRotations,
                                                             std::vector<std::complex<double>>(slots, 0.0));
        for (size_t s = 0; s < rowsCollapse; s++) {
            coeff[s][0] = coeff1[s * layersCollapse];
            coeff[s][1] = coeff1[log2slots + s * layersCollapse];
            coeff[s][2] = coeff1[2 * log2slots + s * layersCollapse];

            for (size_t l = 1; l < layersCollapse; l++) {
                std::vector<std::vector<std::complex<double>>> temp = coeff[s];
                coeff[s]                                            = zeros;

                for (size_t t = 0; t < 3; t++) {
                    uint32_t shift = (t == 0) ? 0 : ((t == 1) ? (1U << l) : (1U << (l + 1)));
                    for (size_t u = 0; u < (1U << (l + 1)) - 1; u++) {
                        for (size_t k = 0; k < slots; k++) {
                            coeff[s][u + shift][k] += coeff1[s * layersCollapse + l + t * log2slots][k] * temp[u][k];
                        }
                    }
                }
            }
        }
    }

    if (flagRem && remCollapse) {  // check if (remCollapse > 0). it is necessary for the code executed before the loop
        const uint32_t s = rowsCollapse;

        coeff[s][0] = coeff1[s * layersCollapse];
        coeff[s][1] = coeff1[log2slots + s * layersCollapse];
        coeff[s][2] = coeff1[2 * log2slots + s * layersCollapse];

        std::vector<std::vector<std::complex<double>>> zeros(numRotationsRem,
                                                             std::vector<std::complex<double>>(slots, 0.0));
        for (size_t l = 1; l < remCollapse; l++) {
            std::vector<std::vector<std::complex<double>>> temp = coeff[s];
            coeff[s]                                            = zeros;

            for (size_t t = 0; t < 3; t++) {
                uint32_t shift = (t == 0) ? 0 : ((t == 1) ? (1U << l) : (1U << (l + 1)));
                for (size_t u = 0; u < (1U << (l + 1)) - 1; u++) {
                    for (size_t k = 0; k < slots; k++) {
                        coeff[s][u + shift][k] += coeff1[s * layersCollapse + l + t * log2slots][k] * temp[u][k];
                    }
                }
            }
        }
    }

    return coeff;
}

std::vector<int32_t> GetCollapsedFFTParams(uint32_t slots, uint32_t levelBudget, uint32_t dim1) {
    if (slots == 0)
        OPENFHE_THROW("slots can not be 0");
    if (levelBudget == 0)
        OPENFHE_THROW("levelBudget can not be 0");

    // even for the case of (slots = 1) we need one level for rescaling as (std::log2(1) = 0)
    uint32_t logSlots = (slots < 3) ? 1 : std::log2(slots);

    std::vector<uint32_t> dims = SelectLayers(logSlots, levelBudget);
    // Need to compute how many layers are collapsed in each of the level from the budget.
    // If there is no exact division between the maximum number of possible levels (log(slots)) and the
    // level budget, the last level will contain the remaining layers collapsed.
    const uint32_t layersCollapse = dims[0];
    const uint32_t remCollapse    = dims[2];

    const uint32_t numRotations    = (1U << (layersCollapse + 1)) - 1;
    const uint32_t numRotationsRem = (1U << (remCollapse + 1)) - 1;

    // Computing the baby-step b and the giant-step g for the collapsed layers for decoding.
    uint32_t g{0};
    if (dim1 == 0 || dim1 > numRotations) {
        if (numRotations > 7) {
            g = (1U << (layersCollapse / 2 + 2));
        }
        else {
            g = (1U << (layersCollapse / 2 + 1));
        }
    }
    else {
        g = dim1;
    }
    uint32_t b = (numRotations + 1) / g;

    uint32_t bRem{0};
    uint32_t gRem{0};

    // bool flagRem = (remCollapse == 0) ? false : true;
    if (remCollapse != 0) {
        if (numRotationsRem > 7) {
            gRem = (1U << (remCollapse / 2 + 2));
        }
        else {
            gRem = (1U << (remCollapse / 2 + 1));
        }
        bRem = (numRotationsRem + 1) / gRem;
    }

    // If this return statement changes then CKKS_BOOT_PARAMS should be altered as well
    return {static_cast<int32_t>(levelBudget),
            static_cast<int32_t>(layersCollapse),
            static_cast<int32_t>(remCollapse),
            static_cast<int32_t>(numRotations),
            static_cast<int32_t>(b),
            static_cast<int32_t>(g),
            static_cast<int32_t>(numRotationsRem),
            static_cast<int32_t>(bRem),
            static_cast<int32_t>(gRem)};
}

uint32_t getRatioBSGSLT(uint32_t slots) {  // returns powers of two
    return (slots <= 1) ? 1 : (1U << (static_cast<uint32_t>(std::log2(std::ceil(std::sqrt(slots))) + 1)));
}

std::vector<int32_t> FindLTRotationIndicesSwitch(uint32_t dim1, uint32_t m, uint32_t blockDimension) {
    uint32_t slots;
    // Set slots depending on packing mode (fully-packed or sparsely-packed)
    if ((blockDimension == 0) || (blockDimension == m / 4))
        slots = m / 4;
    else
        slots = blockDimension;

    // Computing the baby-step g and the giant-step h
    uint32_t bStep = (dim1 == 0) ? getRatioBSGSLT(slots) : dim1;
    uint32_t gStep = static_cast<uint32_t>(std::ceil(static_cast<double>(slots) / bStep));

    // Computing all indices for baby-step giant-step procedure
    std::vector<int32_t> indexList;
    indexList.reserve(bStep + gStep - 2);
    for (uint32_t i = 1; i <= bStep; i++)
        indexList.emplace_back(i);
    for (uint32_t i = 2; i < gStep; i++)
        indexList.emplace_back(bStep * i);

    // Remove possible duplicates
    sort(indexList.begin(), indexList.end());
    indexList.erase(unique(indexList.begin(), indexList.end()), indexList.end());

    // Remove automorphisms corresponding to 0
    auto it = std::find(indexList.begin(), indexList.end(), 0);
    if (it != indexList.end()) {
        indexList.erase(it);
    }

    return indexList;
}

std::vector<int32_t> FindLTRotationIndicesSwitchArgmin(uint32_t m, uint32_t blockDimension, uint32_t cols) {
    uint32_t slots;
    // Set slots depending on packing mode (fully-packed or sparsely-packed)
    if ((blockDimension == 0) || (blockDimension == m / 4))
        slots = m / 4;
    else
        slots = blockDimension;

    // Computing the baby-step g and the giant-step h
    uint32_t bStep = getRatioBSGSLT(slots);
    uint32_t gStep = std::ceil(static_cast<double>(slots) / bStep);
    uint32_t logl  = std::log2(cols / slots);  // These are powers of two, so log(l) is integer

    std::vector<int32_t> indexList;
    indexList.reserve(bStep + gStep +
                      cols);  // There will be a lot of intersection between the rotations, provide an upper bound

    while (slots >= 1) {
        // Computing all indices for baby-step giant-step procedure
        for (uint32_t i = 1; i <= bStep; i++)
            indexList.emplace_back(i);
        for (uint32_t i = 2; i < gStep; i++)
            indexList.emplace_back(bStep * i);

        // If the linear transform is wide instead of tall, we need extra rotations
        if (slots < cols) {
            logl = std::log2(cols / slots);  // These are powers of two, so log(l) is integer
            for (size_t j = 1; j <= logl; ++j) {
                indexList.emplace_back(slots * (1U << (j - 1)));
            }
        }

        // Go deeper into the binary tree
        slots /= 2;

        // Computing the baby-step g and the giant-step h
        bStep = getRatioBSGSLT(slots);
        gStep = std::ceil(static_cast<double>(slots) / bStep);
    }

    // Remove possible duplicates
    sort(indexList.begin(), indexList.end());
    indexList.erase(unique(indexList.begin(), indexList.end()), indexList.end());

    // Remove automorphisms corresponding to 0
    auto it = std::find(indexList.begin(), indexList.end(), 0);
    if (it != indexList.end()) {
        indexList.erase(it);
    }

    return indexList;
}

}  // namespace lbcrypto
