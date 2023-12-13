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

#include <cmath>
#include <algorithm>
#include <functional>
#include <vector>

namespace lbcrypto {

namespace {  // this namespace should stay unnamed

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
    UPPER_BOUND_DEGREE = 2031,
};
std::vector<uint32_t> GenerateDepthByDegreeTable() {
    std::vector<uint32_t> depthTable(UPPER_BOUND_DEGREE+1);

    std::fill(depthTable.begin(),        depthTable.begin() + 5,     3);  // degree in [0,4], depth = 3 - the Paterson-Stockmeyer algorithm is not used when degree < 5
    std::fill(depthTable.begin() + 5,    depthTable.begin() + 6,     4);  // degree in [5],         depth = 4
    std::fill(depthTable.begin() + 6,    depthTable.begin() + 14,    5);  // degree in [6,13],      depth = 5
    std::fill(depthTable.begin() + 14,   depthTable.begin() + 28,    6);  // degree in [14,27],     depth = 6
    std::fill(depthTable.begin() + 28,   depthTable.begin() + 60,    7);  // degree in [28,59],     depth = 7
    std::fill(depthTable.begin() + 60,   depthTable.begin() + 120,   8);  // degree in [60,119],    depth = 8
    std::fill(depthTable.begin() + 120,  depthTable.begin() + 248,   9);  // degree in [120,247],   depth = 9
    std::fill(depthTable.begin() + 248,  depthTable.begin() + 496,  10);  // degree in [248,495],   depth = 10
    std::fill(depthTable.begin() + 496,  depthTable.begin() + 1008, 11);  // degree in [496,1007],  depth = 11
    std::fill(depthTable.begin() + 1008, depthTable.end(),          12);  // degree in [1008,2031], depth = 12

    return depthTable;
}
// clang-format on

uint32_t GetDepthByDegree(size_t degree) {
    static const std::vector<uint32_t> depthTable = GenerateDepthByDegreeTable();
    if (degree >= LOWER_BOUND_DEGREE && degree <= UPPER_BOUND_DEGREE)
        return depthTable[degree];

    std::string errMsg("Polynomial degree is supported from 5 to 2031 inclusive. Its current value is ");
    errMsg += std::to_string(degree);
    OPENFHE_THROW(math_error, errMsg);
}

}  // namespace

const std::complex<double> I(0.0, 1.0);
double PREC = std::pow(2, -20);

inline bool IsNotEqualOne(double val) {
    if (1 - PREC >= val) {
        return true;
    }
    if (1 + PREC <= val) {
        return true;
    }
    return false;
}

uint32_t Degree(const std::vector<double>& coefficients) {
    const size_t coefficientsSize = coefficients.size();
    if (!coefficientsSize) {
        OPENFHE_THROW(math_error, "The coefficients vector can not be empty");
    }

    int32_t indx = coefficientsSize;
    while (--indx >= 0) {
        if (coefficients[indx])
            break;
    }

    // indx becomes negative (-1) only when all coefficients are zeroes. in this case we return 0
    return static_cast<uint32_t>((indx < 0) ? 0 : indx);
}

/* f and g are vectors of coefficients of the two polynomials. We assume their dominant
coefficient is not zero. LongDivisionPoly returns the vector of coefficients for the
quotient and remainder of the division f/g. longDiv is a struct that contains the
vectors of coefficients for the quotient and rest. */
std::shared_ptr<longDiv> LongDivisionPoly(const std::vector<double>& f, const std::vector<double>& g) {
    uint32_t n = Degree(f);
    uint32_t k = Degree(g);

    if (n != f.size() - 1) {
        OPENFHE_THROW(math_error, "LongDivisionPoly: The dominant coefficient of the divident is zero.");
    }

    if (k != g.size() - 1) {
        OPENFHE_THROW(math_error, "LongDivisionPoly: The dominant coefficient of the divisor is zero.");
    }

    std::vector<double> q;
    std::vector<double> r = f;
    std::vector<double> d;

    if (int32_t(n - k) >= 0) {
        std::vector<double> q2(n - k + 1, 0.0);
        q = q2;

        while (int32_t(n - k) >= 0) {
            d = g;
            d.insert(d.begin(), n - k, 0);  // d is g padded with zeros before up to n
            q[n - k] = r.back();

            if (IsNotEqualOne(g[k])) {
                q[n - k] /= g.back();
            }

            // d *= q[n - k]
            std::transform(d.begin(), d.end(), d.begin(),
                           std::bind(std::multiplies<double>(), std::placeholders::_1, q[n - k]));
            // f-=d
            std::transform(r.begin(), r.end(), d.begin(), r.begin(), std::minus<double>());
            if (r.size() > 1) {
                n = Degree(r);
                r.resize(n + 1);
            }
        }
    }
    else {
        std::vector<double> q2(1, 0.0);
        q = q2;
        r = f;
    }

    return std::make_shared<longDiv>(q, r);
}

/* f and g are vectors of Chebyshev interpolation coefficients of the two polynomials.
We assume their dominant coefficient is not zero. LongDivisionChebyshev returns the
vector of Chebyshev interpolation coefficients for the quotient and remainder of the
division f/g. longDiv is a struct that contains the vectors of coefficients for the
quotient and rest. We assume that the zero-th coefficient is c0, not c0/2 and returns
the same format.*/
std::shared_ptr<longDiv> LongDivisionChebyshev(const std::vector<double>& f, const std::vector<double>& g) {
    uint32_t n = Degree(f);
    uint32_t k = Degree(g);

    if (n != f.size() - 1) {
        OPENFHE_THROW(math_error, "LongDivisionChebyshev: The dominant coefficient of the divident is zero.");
    }

    if (k != g.size() - 1) {
        OPENFHE_THROW(math_error, "LongDivisionChebyshev: The dominant coefficient of the divisor is zero.");
    }

    std::vector<double> q;
    std::vector<double> r = f;

    if (int32_t(n - k) >= 0) {
        std::vector<double> q2(n - k + 1, 0.0);
        q = q2;

        while (int32_t(n - k) > 0) {
            q[n - k] = 2 * r.back();
            if (IsNotEqualOne(g[k])) {
                q[n - k] /= g.back();
            }

            std::vector<double> d(n + 1, 0.0);

            if (int32_t(k) == int32_t(n - k)) {
                d.front() = 2 * g[n - k];

                for (uint32_t i = 1; i < 2 * k + 1; i++) {
                    d[i] = g[abs(int32_t(n - k - i))];
                }
            }
            else {
                if (int32_t(k) > int32_t(n - k)) {
                    d.front() = 2 * g[n - k];
                    for (uint32_t i = 1; i < k - (n - k) + 1; i++) {
                        d[i] = g[abs(int32_t(n - k - i))] + g[int32_t(n - k + i)];
                    }

                    for (uint32_t i = k - (n - k) + 1; i < n + 1; i++) {
                        d[i] = g[abs(int32_t(i - n + k))];
                    }
                }
                else {
                    d[n - k] = g.front();
                    for (uint32_t i = n - 2 * k; i < n + 1; i++) {
                        if (i != n - k) {
                            d[i] = g[abs(int32_t(i - n + k))];
                        }
                    }
                }
            }

            if (IsNotEqualOne(r.back())) {
                // d *= f[n]
                std::transform(d.begin(), d.end(), d.begin(),
                               std::bind(std::multiplies<double>(), std::placeholders::_1, r.back()));
            }
            if (IsNotEqualOne(g.back())) {
                // d /= g[k]
                std::transform(d.begin(), d.end(), d.begin(),
                               std::bind(std::divides<double>(), std::placeholders::_1, g.back()));
            }

            // f-=d
            std::transform(r.begin(), r.end(), d.begin(), r.begin(), std::minus<double>());
            if (r.size() > 1) {
                n = Degree(r);
                r.resize(n + 1);
            }
        }

        if (n == k) {
            q.front() = r.back();
            if (IsNotEqualOne(g.back())) {
                q.front() /= g.back();  // q[0] /= g[k]
            }
            std::vector<double> d = g;
            if (IsNotEqualOne(r.back())) {
                // d *= f[n]
                std::transform(d.begin(), d.end(), d.begin(),
                               std::bind(std::multiplies<double>(), std::placeholders::_1, r.back()));
            }
            if (IsNotEqualOne(g.back())) {
                // d /= g[k]
                std::transform(d.begin(), d.end(), d.begin(),
                               std::bind(std::divides<double>(), std::placeholders::_1, g.back()));
            }
            // f-=d
            std::transform(r.begin(), r.end(), d.begin(), r.begin(), std::minus<double>());
            if (r.size() > 1) {
                n = Degree(r);
                r.resize(n + 1);
            }
        }
        q.front() *= 2;  // Because we want to have [c0] in the last spot, not [c0/2]
    }
    else {
        std::vector<double> q2(1, 0.0);
        q = q2;
        r = f;
    }

    return std::make_shared<longDiv>(q, r);
}

/*	Compute positive integers k,m such that n < k(2^m-1), k is close to sqrt(n/2)
	and the depth = ceil(log2(k))+m is minimized. Moreover, for that depth the
	number of homomorphic multiplications = k+2m+2^(m-1)-4 is minimized.
	Since finding these parameters involve testing many possible values, we
	hardcode them for commonly used degrees, and provide a heuristic which
	minimizes the number of homomorphic multiplications for the rest of the
	degrees.*/
std::vector<uint32_t> ComputeDegreesPS(const uint32_t n) {
    if (n == 0) {
        OPENFHE_THROW(math_error, "ComputeDegreesPS: The degree is zero. There is no need to evaluate the polynomial.");
    }

    // index n-1 in the vector corresponds to degree n
    if (n <= UPPER_BOUND_PS) {  // hard-coded values
        static const std::vector<uint32_t> mlist = PopulateParameterPS(UPPER_BOUND_PS);
        uint32_t m                               = mlist[n - 1];
        uint32_t k                               = std::floor(n / ((1 << m) - 1)) + 1;

        return std::vector<uint32_t>{k, m};
    }
    else {  // heuristic for larger degrees
        std::vector<uint32_t> klist;
        std::vector<uint32_t> mlist;
        std::vector<uint32_t> multlist;

        for (uint32_t k = 1; k <= n; k++) {
            for (uint32_t m = 1; m <= std::ceil(log2(n / k) + 1) + 1; m++) {
                if (int32_t(n) - int32_t(k * ((1 << m) - 1)) < 0) {
                    if (std::abs(std::floor(log2(k)) - std::floor(log2(sqrt(n / 2)))) <= 1) {
                        klist.push_back(k);
                        mlist.push_back(m);
                        multlist.push_back(k + 2 * m + (1 << (m - 1)) - 4);
                    }
                }
            }
        }
        uint32_t minIndex = std::min_element(multlist.begin(), multlist.end()) - multlist.begin();

        return std::vector<uint32_t>{klist[minIndex], mlist[minIndex]};
    }
}

uint32_t GetMultiplicativeDepthByCoeffVector(const std::vector<double>& vec, bool isNormalized) {
    size_t vecSize = vec.size();
    if (!vecSize) {
        OPENFHE_THROW(math_error, "Cannot perform operation on empty vector. vec.size() == 0");
    }

    size_t degree      = vecSize - 1;
    uint32_t multDepth = GetDepthByDegree(degree);

    return (isNormalized) ? (multDepth - 1) : multDepth;
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
    int32_t slots = a.size();

    std::vector<std::complex<double>> result(slots);

    if (index < 0 || index > slots) {
        index = ReduceRotation(index, slots);
    }

    if (index == 0) {
        result = a;
    }

    else {
        // two cases: i+index <= slots and i+index > slots
        for (int32_t i = 0; i < slots - index; i++) {
            result[i] = a[i + index];
        }
        for (int32_t i = slots - index; i < slots; i++) {
            result[i] = a[i + index - slots];
        }
    }

    return result;
}

uint32_t ReduceRotation(int32_t index, uint32_t slots) {
    int32_t islots = int32_t(slots);

    // if slots is a power of 2
    if ((slots & (slots - 1)) == 0) {
        int32_t n = std::log2(slots);
        if (index >= 0) {
            return index - ((index >> n) << n);
        }
        return index + islots + ((int32_t(std::fabs(index)) >> n) << n);
    }
    return (islots + index % islots) % islots;
}

std::vector<std::complex<double>> Fill(const std::vector<std::complex<double>>& a, int slots) {
    int usedSlots = a.size();

    std::vector<std::complex<double>> result(slots);

    for (int i = 0; i < slots; i++) {
        result[i] = a[i % usedSlots];
    }

    return result;
}

std::vector<std::vector<std::complex<double>>> CoeffEncodingOneLevel(const std::vector<std::complex<double>>& pows,
                                                                     const std::vector<uint32_t>& rotGroup,
                                                                     bool flag_i) {
    uint32_t dim   = pows.size() - 1;
    uint32_t slots = rotGroup.size();

    // Each outer iteration from the FFT algorithm can be written a weighted sum of
    // three terms: the input shifted right by a power of two, the unshifted input,
    // and the input shifted left by a power of two. For each outer iteration
    // (log2(size) in total), the matrix coeff stores the coefficients in the
    // following order: the coefficients associated to the input shifted right,
    // the coefficients for the non-shifted input and the coefficients associated
    // to the input shifted left.
    std::vector<std::vector<std::complex<double>>> coeff(3 * std::log2(slots));

    for (uint32_t i = 0; i < 3 * std::log2(slots); i++) {
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
                    std::complex<double> w                    = std::exp(-M_PI / 2 * I) * pows[jTwiddle];
                    coeff[s + std::log2(slots)][j + k]        = std::exp(-M_PI / 2 * I);  // not shifted
                    coeff[s + 2 * std::log2(slots)][j + k]    = std::exp(-M_PI / 2 * I);  // shifted left
                    coeff[s + std::log2(slots)][j + k + lenh] = -w;                       // not shifted
                    coeff[s][j + k + lenh]                    = w;                        // shifted right
                }
                else {
                    std::complex<double> w                    = pows[jTwiddle];
                    coeff[s + std::log2(slots)][j + k]        = 1;   // not shifted
                    coeff[s + 2 * std::log2(slots)][j + k]    = 1;   // shifted left
                    coeff[s + std::log2(slots)][j + k + lenh] = -w;  // not shifted
                    coeff[s][j + k + lenh]                    = w;   // shifted right
                }
            }
        }
    }

    return coeff;
}

std::vector<std::vector<std::complex<double>>> CoeffDecodingOneLevel(const std::vector<std::complex<double>>& pows,
                                                                     const std::vector<uint32_t>& rotGroup,
                                                                     bool flag_i) {
    uint32_t dim   = pows.size() - 1;
    uint32_t slots = rotGroup.size();

    // Each outer iteration from the FFT algorithm can be written a weighted sum of
    // three terms: the input shifted right by a power of two, the unshifted input,
    // and the input shifted left by a power of two. For each outer iteration
    // (log2(size) in total), the matrix coeff stores the coefficients in the
    // following order: the coefficients associated to the input shifted right,
    // the coefficients for the non-shifted input and the coefficients associated
    // to the input shifted left.
    std::vector<std::vector<std::complex<double>>> coeff(3 * std::log2(slots));

    for (uint32_t i = 0; i < 3 * std::log2(slots); i++) {
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
                    std::complex<double> w                    = std::exp(M_PI / 2 * I) * pows[jTwiddle];
                    coeff[s + std::log2(slots)][j + k]        = std::exp(M_PI / 2 * I);  // not shifted
                    coeff[s + 2 * std::log2(slots)][j + k]    = w;                       // shifted left
                    coeff[s + std::log2(slots)][j + k + lenh] = -w;                      // not shifted
                    coeff[s][j + k + lenh]                    = std::exp(M_PI / 2 * I);  // shifted right
                }
                else {
                    std::complex<double> w                    = pows[jTwiddle];
                    coeff[s + std::log2(slots)][j + k]        = 1;   // not shifted
                    coeff[s + 2 * std::log2(slots)][j + k]    = w;   // shifted left
                    coeff[s + std::log2(slots)][j + k + lenh] = -w;  // not shifted
                    coeff[s][j + k + lenh]                    = 1;   // shifted right
                }
            }
        }
    }

    return coeff;
}

std::vector<std::vector<std::vector<std::complex<double>>>> CoeffEncodingCollapse(
    const std::vector<std::complex<double>>& pows, const std::vector<uint32_t>& rotGroup, uint32_t levelBudget,
    bool flag_i) {
    uint32_t slots = rotGroup.size();
    // Need to compute how many layers are collapsed in each of the level from the budget.
    // If there is no exact division between the maximum number of possible levels (log(slots)) and the
    // level budget, the last level will contain the remaining layers collapsed.
    int32_t layersCollapse;
    int32_t remCollapse;

    std::vector<uint32_t> dims = SelectLayers(std::log2(slots), levelBudget);
    layersCollapse             = dims[0];
    remCollapse                = dims[2];

    int32_t dimCollapse = int32_t(levelBudget);
    int32_t stop        = 0;
    int32_t flagRem     = 0;

    if (remCollapse == 0) {
        stop    = -1;
        flagRem = 0;
    }
    else {
        stop    = 0;
        flagRem = 1;
    }

    uint32_t numRotations    = (1 << (layersCollapse + 1)) - 1;
    uint32_t numRotationsRem = (1 << (remCollapse + 1)) - 1;

    // Computing the coefficients for encoding for the given level budget
    std::vector<std::vector<std::complex<double>>> coeff1 = CoeffEncodingOneLevel(pows, rotGroup, flag_i);

    // Coeff stores the coefficients for the given budget of levels
    std::vector<std::vector<std::vector<std::complex<double>>>> coeff(dimCollapse);
    for (uint32_t i = 0; i < uint32_t(dimCollapse); i++) {
        if (flagRem) {
            if (i >= 1) {
                // after remainder
                coeff[i] = std::vector<std::vector<std::complex<double>>>(numRotations);
                for (uint32_t j = 0; j < numRotations; j++) {
                    coeff[i][j] = std::vector<std::complex<double>>(slots);
                }
            }
            else {
                // remainder corresponds to the first index in encoding and to the last one in decoding
                coeff[i] = std::vector<std::vector<std::complex<double>>>(numRotationsRem);
                for (uint32_t j = 0; j < numRotationsRem; j++) {
                    coeff[i][j] = std::vector<std::complex<double>>(slots);
                }
            }
        }
        else {
            coeff[i] = std::vector<std::vector<std::complex<double>>>(numRotations);
            for (uint32_t j = 0; j < numRotations; j++) {
                coeff[i][j] = std::vector<std::complex<double>>(slots);
            }
        }
    }

    for (int32_t s = dimCollapse - 1; s > stop; s--) {
        int32_t top = int32_t(std::log2(slots)) - (dimCollapse - 1 - s) * layersCollapse - 1;

        for (int32_t l = 0; l < layersCollapse; l++) {
            if (l == 0) {
                coeff[s][0] = coeff1[top];
                coeff[s][1] = coeff1[top + std::log2(slots)];
                coeff[s][2] = coeff1[top + 2 * std::log2(slots)];
            }
            else {
                std::vector<std::vector<std::complex<double>>> temp = coeff[s];
                std::vector<std::vector<std::complex<double>>> zeros(numRotations,
                                                                     std::vector<std::complex<double>>(slots, 0.0));
                coeff[s]   = zeros;
                uint32_t t = 0;

                for (int32_t u = 0; u < (1 << (l + 1)) - 1; u++) {
                    for (uint32_t k = 0; k < slots; k++) {
                        coeff[s][u + t][k] += coeff1[top - l][k] * temp[u][ReduceRotation(k - (1 << (top - l)), slots)];
                        coeff[s][u + t + 1][k] += coeff1[top - l + std::log2(slots)][k] * temp[u][k];
                        coeff[s][u + t + 2][k] += coeff1[top - l + 2 * std::log2(slots)][k] *
                                                  temp[u][ReduceRotation(k + (1 << (top - l)), slots)];
                    }
                    t += 1;
                }
            }
        }
    }

    if (flagRem) {
        int32_t s   = 0;
        int32_t top = int32_t(std::log2(slots)) - (dimCollapse - 1 - s) * layersCollapse - 1;

        for (int32_t l = 0; l < remCollapse; l++) {
            if (l == 0) {
                coeff[s][0] = coeff1[top];
                coeff[s][1] = coeff1[top + std::log2(slots)];
                coeff[s][2] = coeff1[top + 2 * std::log2(slots)];
            }
            else {
                std::vector<std::vector<std::complex<double>>> temp = coeff[s];
                std::vector<std::vector<std::complex<double>>> zeros(numRotationsRem,
                                                                     std::vector<std::complex<double>>(slots, 0.0));
                coeff[s]   = zeros;
                uint32_t t = 0;

                for (int32_t u = 0; u < (1 << (l + 1)) - 1; u++) {
                    for (uint32_t k = 0; k < slots; k++) {
                        coeff[s][u + t][k] += coeff1[top - l][k] * temp[u][ReduceRotation(k - (1 << (top - l)), slots)];
                        coeff[s][u + t + 1][k] += coeff1[top - l + std::log2(slots)][k] * temp[u][k];
                        coeff[s][u + t + 2][k] += coeff1[top - l + 2 * std::log2(slots)][k] *
                                                  temp[u][ReduceRotation(k + (1 << (top - l)), slots)];
                    }
                    t += 1;
                }
            }
        }
    }

    return coeff;
}

std::vector<std::vector<std::vector<std::complex<double>>>> CoeffDecodingCollapse(
    const std::vector<std::complex<double>>& pows, const std::vector<uint32_t>& rotGroup, uint32_t levelBudget,
    bool flag_i) {
    uint32_t slots = rotGroup.size();
    // Need to compute how many layers are collapsed in each of the level from the budget.
    // If there is no exact division between the maximum number of possible levels (log(slots)) and the
    // level budget, the last level will contain the remaining layers collapsed.
    int32_t layersCollapse;
    int32_t rowsCollapse;
    int32_t remCollapse;

    std::vector<uint32_t> dims = SelectLayers(std::log2(slots), levelBudget);
    layersCollapse             = dims[0];
    rowsCollapse               = dims[1];
    remCollapse                = dims[2];

    int32_t dimCollapse = int32_t(levelBudget);
    int32_t flagRem     = 0;

    if (remCollapse == 0) {
        flagRem = 0;
    }
    else {
        flagRem = 1;
    }

    uint32_t numRotations    = (1 << (layersCollapse + 1)) - 1;
    uint32_t numRotationsRem = (1 << (remCollapse + 1)) - 1;

    // Computing the coefficients for decoding for the given level budget
    std::vector<std::vector<std::complex<double>>> coeff1 = CoeffDecodingOneLevel(pows, rotGroup, flag_i);

    // Coeff stores the coefficients for the given budget of levels
    std::vector<std::vector<std::vector<std::complex<double>>>> coeff(dimCollapse);

    for (uint32_t i = 0; i < uint32_t(dimCollapse); i++) {
        if (flagRem) {
            if (i < levelBudget - 1) {
                // before remainder
                coeff[i] = std::vector<std::vector<std::complex<double>>>(numRotations);

                for (uint32_t j = 0; j < numRotations; j++) {
                    coeff[i][j] = std::vector<std::complex<double>>(slots);
                }
            }
            else {
                // remainder corresponds to the first index in encoding and to the last one in decoding
                coeff[i] = std::vector<std::vector<std::complex<double>>>(numRotationsRem);

                for (uint32_t j = 0; j < numRotationsRem; j++) {
                    coeff[i][j] = std::vector<std::complex<double>>(slots);
                }
            }
        }
        else {
            coeff[i] = std::vector<std::vector<std::complex<double>>>(numRotations);

            for (uint32_t j = 0; j < numRotations; j++) {
                coeff[i][j] = std::vector<std::complex<double>>(slots);
            }
        }
    }

    for (int32_t s = 0; s < rowsCollapse; s++) {
        for (int32_t l = 0; l < layersCollapse; l++) {
            if (l == 0) {
                coeff[s][0] = coeff1[s * layersCollapse];
                coeff[s][1] = coeff1[std::log2(slots) + s * layersCollapse];
                coeff[s][2] = coeff1[2 * std::log2(slots) + s * layersCollapse];
            }
            else {
                std::vector<std::vector<std::complex<double>>> temp = coeff[s];
                std::vector<std::vector<std::complex<double>>> zeros(numRotations,
                                                                     std::vector<std::complex<double>>(slots, 0.0));
                coeff[s] = zeros;

                for (uint32_t t = 0; t < 3; t++) {
                    for (int32_t u = 0; u < (1 << (l + 1)) - 1; u++) {
                        for (uint32_t k = 0; k < slots; k++) {
                            if (t == 0)
                                coeff[s][u][k] += coeff1[s * layersCollapse + l][k] * temp[u][k];
                            if (t == 1)
                                coeff[s][u + (1 << l)][k] +=
                                    coeff1[s * layersCollapse + l + std::log2(slots)][k] * temp[u][k];
                            if (t == 2)
                                coeff[s][u + (1 << (l + 1))][k] +=
                                    coeff1[s * layersCollapse + l + 2 * std::log2(slots)][k] * temp[u][k];
                        }
                    }
                }
            }
        }
    }

    if (flagRem) {
        int32_t s = rowsCollapse;

        for (int32_t l = 0; l < remCollapse; l++) {
            if (l == 0) {
                coeff[s][0] = coeff1[s * layersCollapse];
                coeff[s][1] = coeff1[std::log2(slots) + s * layersCollapse];
                coeff[s][2] = coeff1[2 * std::log2(slots) + s * layersCollapse];
            }
            else {
                std::vector<std::vector<std::complex<double>>> temp = coeff[s];
                std::vector<std::vector<std::complex<double>>> zeros(numRotationsRem,
                                                                     std::vector<std::complex<double>>(slots, 0.0));
                coeff[s] = zeros;

                for (uint32_t t = 0; t < 3; t++) {
                    for (int32_t u = 0; u < (1 << (l + 1)) - 1; u++) {
                        for (uint32_t k = 0; k < slots; k++) {
                            if (t == 0)
                                coeff[s][u][k] += coeff1[s * layersCollapse + l][k] * temp[u][k];
                            if (t == 1)
                                coeff[s][u + (1 << l)][k] +=
                                    coeff1[s * layersCollapse + l + std::log2(slots)][k] * temp[u][k];
                            if (t == 2)
                                coeff[s][u + (1 << (l + 1))][k] +=
                                    coeff1[s * layersCollapse + l + 2 * std::log2(slots)][k] * temp[u][k];
                        }
                    }
                }
            }
        }
    }

    return coeff;
}

std::vector<uint32_t> SelectLayers(uint32_t logSlots, uint32_t budget) {
    uint32_t layers = ceil(static_cast<double>(logSlots) / budget);
    uint32_t rows   = logSlots / layers;
    uint32_t rem    = logSlots % layers;

    uint32_t dim = rows;
    if (rem != 0) {
        dim = rows + 1;
    }

    // the above choice ensures dim <= budget
    if (dim < budget) {
        layers -= 1;
        rows = logSlots / layers;
        rem  = logSlots - rows * layers;
        dim  = rows;

        if (rem != 0) {
            dim = rows + 1;
        }

        // the above choice endures dim >=budget
        while (dim != budget) {
            rows -= 1;
            rem = logSlots - rows * layers;
            dim = rows;
            if (rem != 0) {
                dim = rows + 1;
            }
        }
    }

    return {layers, rows, rem};
}

std::vector<int32_t> GetCollapsedFFTParams(uint32_t slots, uint32_t levelBudget, uint32_t dim1) {
    uint32_t logSlots = std::log2(slots);
    // even for the case of a single slot we need one level for rescaling
    if (logSlots == 0) {
        logSlots = 1;
    }

    std::vector<uint32_t> dims = SelectLayers(logSlots, levelBudget);
    // Need to compute how many layers are collapsed in each of the level from the budget.
    // If there is no exact division between the maximum number of possible levels (log(slots)) and the
    // level budget, the last level will contain the remaining layers collapsed.
    int32_t layersCollapse     = dims[0];
    int32_t remCollapse        = dims[2];

    bool flagRem = (remCollapse == 0) ? false : true;

    uint32_t numRotations    = (1 << (layersCollapse + 1)) - 1;
    uint32_t numRotationsRem = (1 << (remCollapse + 1)) - 1;

    // Computing the baby-step b and the giant-step g for the collapsed layers for decoding.
    int32_t g;
    if (dim1 == 0 || dim1 > numRotations) {
        if (numRotations > 7) {
            g = (1 << (int32_t(layersCollapse / 2) + 2));
        }
        else {
            g = (1 << (int32_t(layersCollapse / 2) + 1));
        }
    }
    else {
        g = dim1;
    }
    int32_t b    = (numRotations + 1) / g;

    int32_t bRem = 0;
    int32_t gRem = 0;
    if (flagRem) {
        if (numRotationsRem > 7) {
            gRem = (1 << (int32_t(remCollapse / 2) + 2));
        }
        else {
            gRem = (1 << (int32_t(remCollapse / 2) + 1));
        }
        bRem = (numRotationsRem + 1) / gRem;
    }

    // If this return statement changes then CKKS_BOOT_PARAMS should be altered as well
    return {int32_t(levelBudget),     layersCollapse, remCollapse, int32_t(numRotations), b, g,
            int32_t(numRotationsRem), bRem,           gRem};
}

uint32_t getRatioBSGSLT(uint32_t slots) {
    return ceil(sqrt(slots));
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
    uint32_t gStep = ceil(static_cast<double>(slots) / bStep);

    // Computing all indices for baby-step giant-step procedure
    std::vector<int32_t> indexList;
    indexList.reserve(bStep + gStep - 2);
    for (uint32_t i = 0; i < bStep; i++)
        indexList.emplace_back(i + 1);
    for (uint32_t i = 2; i < gStep; i++)
        indexList.emplace_back(bStep * i);

    // Remove possible duplicates
    sort(indexList.begin(), indexList.end());
    indexList.erase(unique(indexList.begin(), indexList.end()), indexList.end());

    // Remove automorphisms corresponding to 0
    indexList.erase(std::remove(indexList.begin(), indexList.end(), 0), indexList.end());

    return indexList;
}

}  // namespace lbcrypto
