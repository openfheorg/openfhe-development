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
#include "utils/inttypes.h"
#include "utils/exception.h"

#include <cmath>
#include <algorithm>
#include <functional>

namespace lbcrypto {

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

/*Return the degree of the polynomial described by coefficients,
which is the index of the last non-zero element in the coefficients - 1.
Don't throw an error if all the coefficients are zero, but return 0. */
uint32_t Degree(const std::vector<double>& coefficients) {
    uint32_t deg = 1;
    if (coefficients.size() > 1) {
        for (size_t i = coefficients.size() - 1; i > 0; --i) {
            if (coefficients[i] == 0) {
                ++deg;
            }
            else
                break;
        }
    }
    return coefficients.size() - deg;
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

                for (size_t i = 1; i < 2 * k + 1; ++i) {
                    d[i] = g[abs(int32_t(n - k - i))];
                }
            }
            else {
                if (int32_t(k) > int32_t(n - k)) {
                    d.front() = 2 * g[n - k];
                    for (size_t i = 1; i < k - (n - k) + 1; ++i) {
                        d[i] = g[abs(int32_t(n - k - i))] + g[int32_t(n - k + i)];
                    }

                    for (size_t i = k - (n - k) + 1; i < n + 1; ++i) {
                        d[i] = g[abs(int32_t(i - n + k))];
                    }
                }
                else {
                    d[n - k] = g.front();
                    for (size_t i = n - 2 * k; i < n + 1; ++i) {
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

/* Compute positive integers k,m such that n < k(2^m-1) and k close to sqrt(n/2) */
std::vector<uint32_t> ComputeDegreesPS(const uint32_t n) {
    if (n == 0) {
        OPENFHE_THROW(math_error, "ComputeDegreesPS: The degree is zero. There is no need to evaluate the polynomial.");
    }

    std::vector<uint32_t> klist;
    std::vector<uint32_t> mlist;

    double sqn2 = sqrt(n / 2);

    for (size_t k = 1; k <= n; k++) {
        size_t max = static_cast<size_t>(ceil(log2(n / k) + 1)) + 1;
        for (size_t m = 1; m <= max; ++m) {
            if (int32_t(n - k * ((1 << m) - 1)) < 0) {
                if ((static_cast<double>(k - sqn2) >= -2) && ((static_cast<double>(k - sqn2) <= 2))) {
                    klist.push_back(k);
                    mlist.push_back(m);
                }
            }
        }
    }

    uint32_t minIndex = std::min_element(mlist.begin(), mlist.end()) - mlist.begin();

    return std::vector<uint32_t>{{klist[minIndex], mlist[minIndex]}};
}

std::vector<std::complex<double>> ExtractShiftedDiagonal(const std::vector<std::vector<std::complex<double>>>& A,
                                                         int index) {
    uint32_t cols = A[0].size();
    uint32_t rows = A.size();

    std::vector<std::complex<double>> result(cols);

    for (size_t k = 0; k < cols; ++k) {
        result[k] = A[k % rows][(k + index) % cols];
    }

    return result;
}

std::vector<std::complex<double>> Rotate(const std::vector<std::complex<double>>& a, int32_t index) {
    size_t slots = a.size();

    std::vector<std::complex<double>> result(slots);

    if (index < 0 || static_cast<size_t>(index) > slots) {
        index = ReduceRotation(index, slots);
    }

    if (index == 0) {
        result = a;
    }
    else {
        // two cases: i+index <= slots and i+index > slots
        for (size_t i = 0; i < slots - index; ++i) {
            result[i] = a[i + index];
        }
        for (size_t i = slots - index; i < slots; ++i) {
            result[i] = a[i + index - slots];
        }
    }

    return result;
}

uint32_t ReduceRotation(int32_t index, uint32_t slots) {
    // if slots is a power of 2
    if ((slots & (slots - 1)) == 0) {
        int32_t n = std::log2(slots);
        if (index >= 0) {
            return index - ((index >> n) << n);
        }
        return index + slots + ((int32_t(std::fabs(index)) >> n) << n);
    }
    return (slots + index % slots) % slots;
}

std::vector<std::complex<double>> Fill(const std::vector<std::complex<double>>& a, size_t slots) {
    size_t usedSlots = a.size();

    std::vector<std::complex<double>> result(slots);

    for (size_t i = 0; i < slots; ++i) {
        result[i] = a[i % usedSlots];
    }

    return result;
}

std::vector<std::vector<std::complex<double>>> CoeffEncodingOneLevel(const std::vector<std::complex<double>>& pows,
                                                                     const std::vector<uint32_t>& rotGroup,
                                                                     bool flag_i) {
    size_t dim   = pows.size() - 1;
    size_t slots = rotGroup.size();

    // Each outer iteration from the FFT algorithm can be written a weighted sum of
    // three terms: the input shifted right by a power of two, the unshifted input,
    // and the input shifted left by a power of two. For each outer iteration
    // (log2(size) in total), the matrix coeff stores the coefficients in the
    // following order: the coefficients associated to the input shifted right,
    // the coefficients for the non-shifted input and the coefficients associated
    // to the input shifted left.
    std::vector<std::vector<std::complex<double>>> coeff(3 * std::log2(slots));

    for (size_t i = 0; i < 3 * std::log2(slots); ++i) {
        coeff[i] = std::vector<std::complex<double>>(slots);
    }

    for (size_t m = slots; m > 1; m >>= 1) {
        uint32_t s = std::log2(m) - 1;

        for (size_t k = 0; k < slots; k += m) {
            size_t lenh = m >> 1;
            size_t lenq = m << 2;

            for (size_t j = 0; j < lenh; ++j) {
                size_t jTwiddle = (lenq - (rotGroup[j] % lenq)) * (dim / lenq);

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
    size_t dim   = pows.size() - 1;
    size_t slots = rotGroup.size();

    // Each outer iteration from the FFT algorithm can be written a weighted sum of
    // three terms: the input shifted right by a power of two, the unshifted input,
    // and the input shifted left by a power of two. For each outer iteration
    // (log2(size) in total), the matrix coeff stores the coefficients in the
    // following order: the coefficients associated to the input shifted right,
    // the coefficients for the non-shifted input and the coefficients associated
    // to the input shifted left.
    std::vector<std::vector<std::complex<double>>> coeff(3 * std::log2(slots));

    for (size_t i = 0; i < 3 * std::log2(slots); ++i) {
        coeff[i] = std::vector<std::complex<double>>(slots);
    }

    for (size_t m = 2; m <= slots; m <<= 1) {
        uint32_t s = std::log2(m) - 1;

        for (size_t k = 0; k < slots; k += m) {
            size_t lenh = m >> 1;
            size_t lenq = m << 2;

            for (size_t j = 0; j < lenh; ++j) {
                size_t jTwiddle = (rotGroup[j] % lenq) * (dim / lenq);

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
    size_t slots = rotGroup.size();
    // Need to compute how many layers are collapsed in each of the level from the budget.
    // If there is no exact division between the maximum number of possible levels (log(slots)) and the
    // level budget, the last level will contain the remaining layers collapsed.
    std::vector<uint32_t> dims = SelectLayers(std::log2(slots), levelBudget);
    usint layersCollapse       = dims[0];
    usint remCollapse          = dims[2];

    size_t dimCollapse = levelBudget;
    bool flagRem       = (remCollapse == 0) ? false : true;

    uint32_t numRotations    = (static_cast<uint32_t>(1) << (layersCollapse + 1)) - 1;
    uint32_t numRotationsRem = (static_cast<uint32_t>(1) << (remCollapse + 1)) - 1;

    // Computing the coefficients for encoding for the given level budget
    std::vector<std::vector<std::complex<double>>> coeff1 = CoeffEncodingOneLevel(pows, rotGroup, flag_i);

    // Coeff stores the coefficients for the given budget of levels
    std::vector<std::vector<std::vector<std::complex<double>>>> coeff(dimCollapse);
    for (size_t i = 0; i < dimCollapse; ++i) {
        if (i == 0 && flagRem) {
            // remainder corresponds to the first index in encoding and to the last one in decoding
            coeff[i] = std::vector<std::vector<std::complex<double>>>(numRotationsRem);
            for (size_t j = 0; j < numRotationsRem; ++j) {
                coeff[i][j] = std::vector<std::complex<double>>(slots);
            }
        }
        else {
            coeff[i] = std::vector<std::vector<std::complex<double>>>(numRotations);
            for (size_t j = 0; j < numRotations; ++j) {
                coeff[i][j] = std::vector<std::complex<double>>(slots);
            }
        }
    }

    int32_t stop = (remCollapse == 0) ? -1 : 0;
    for (int32_t s = dimCollapse - 1; s > stop; s--) {
        int32_t top = int32_t(std::log2(slots)) - (dimCollapse - 1 - s) * layersCollapse - 1;

        // TODO (dsuponit): is this only if layersCollapse is 1? Or should it be completely removed?
        coeff[s][0] = coeff1[top];
        coeff[s][1] = coeff1[top + std::log2(slots)];
        coeff[s][2] = coeff1[top + 2 * std::log2(slots)];
        for (size_t l = 1; l < layersCollapse; ++l) {
            std::vector<std::vector<std::complex<double>>> temp = coeff[s];
            std::vector<std::vector<std::complex<double>>> zeros(numRotations,
                                                                 std::vector<std::complex<double>>(slots, 0.0));
            coeff[s] = zeros;
            for (size_t u = 0; u < static_cast<size_t>((1 << (l + 1)) - 1); ++u) {
                for (size_t k = 0; k < slots; k++) {
                    coeff[s][2 * u][k] += coeff1[top - l][k] * temp[u][ReduceRotation(k - (1 << (top - l)), slots)];
                    coeff[s][2 * u + 1][k] += coeff1[top - l + std::log2(slots)][k] * temp[u][k];
                    coeff[s][2 * u + 2][k] += coeff1[top - l + 2 * std::log2(slots)][k] *
                                              temp[u][ReduceRotation(k + (1 << (top - l)), slots)];
                }
            }
        }
    }

    if (flagRem) {
        int32_t s   = 0;
        int32_t top = int32_t(std::log2(slots)) - (dimCollapse - 1 - s) * layersCollapse - 1;

        for (size_t l = 0; l < remCollapse; ++l) {
            // TODO (dsuponit): is this only if remCollapse is 1? should it be moved outside of the loop?
            if (l == 0) {
                coeff[s][0] = coeff1[top];
                coeff[s][1] = coeff1[top + std::log2(slots)];
                coeff[s][2] = coeff1[top + 2 * std::log2(slots)];
            }
            else {
                std::vector<std::vector<std::complex<double>>> temp = coeff[s];
                std::vector<std::vector<std::complex<double>>> zeros(numRotationsRem,
                                                                     std::vector<std::complex<double>>(slots, 0.0));
                coeff[s] = zeros;

                for (size_t u = 0; u < static_cast<size_t>((1 << (l + 1)) - 1); ++u) {
                    for (size_t k = 0; k < slots; k++) {
                        coeff[s][2 * u][k] += coeff1[top - l][k] * temp[u][ReduceRotation(k - (1 << (top - l)), slots)];
                        coeff[s][2 * u + 1][k] += coeff1[top - l + std::log2(slots)][k] * temp[u][k];
                        coeff[s][2 * u + 2][k] += coeff1[top - l + 2 * std::log2(slots)][k] *
                                                  temp[u][ReduceRotation(k + (1 << (top - l)), slots)];
                    }
                }
            }
        }
    }

    return coeff;
}

std::vector<std::vector<std::vector<std::complex<double>>>> CoeffDecodingCollapse(
    const std::vector<std::complex<double>>& pows, const std::vector<uint32_t>& rotGroup, uint32_t levelBudget,
    bool flag_i) {
    size_t slots = rotGroup.size();
    // Need to compute how many layers are collapsed in each of the level from the budget.
    // If there is no exact division between the maximum number of possible levels (log(slots)) and the
    // level budget, the last level will contain the remaining layers collapsed.
    std::vector<usint> dims = SelectLayers(std::log2(slots), levelBudget);
    usint layersCollapse    = dims[0];
    usint rowsCollapse      = dims[1];
    usint remCollapse       = dims[2];

    bool flagRem = (remCollapse == 0) ? false : true;

    uint32_t numRotations    = (static_cast<uint32_t>(1) << (layersCollapse + 1)) - 1;
    uint32_t numRotationsRem = (static_cast<uint32_t>(1) << (remCollapse + 1)) - 1;

    // Computing the coefficients for decoding for the given level budget
    std::vector<std::vector<std::complex<double>>> coeff1 = CoeffDecodingOneLevel(pows, rotGroup, flag_i);

    // Coeff stores the coefficients for the given budget of levels
    std::vector<std::vector<std::vector<std::complex<double>>>> coeff(levelBudget);
    if (levelBudget > 0) {
        for (size_t i = 0; i < (levelBudget - 1); ++i) {
            coeff[i] = std::vector<std::vector<std::complex<double>>>(numRotations);
            for (size_t j = 0; j < numRotations; ++j) {
                coeff[i][j] = std::vector<std::complex<double>>(slots);
            }
        }
        // remainder corresponds to the first index in encoding and to the last one in decoding
        if (flagRem) {
            size_t i = (levelBudget - 1);
            coeff[i] = std::vector<std::vector<std::complex<double>>>(numRotationsRem);
            for (size_t j = 0; j < numRotationsRem; ++j) {
                coeff[i][j] = std::vector<std::complex<double>>(slots);
            }
        }
    }

    for (size_t s = 0; s < rowsCollapse; ++s) {
        for (size_t l = 0; l < layersCollapse; ++l) {
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
                for (size_t t = 0; t < 3; t++) {
                    for (size_t u = 0; u < (static_cast<uint32_t>(1) << (l + 1)) - 1; ++u) {
                        for (size_t k = 0; k < slots; ++k) {
                            if (t == 0)
                                coeff[s][u][k] += coeff1[s * layersCollapse + l][k] * temp[u][k];
                            else if (t == 1)
                                coeff[s][u + (1 << l)][k] +=
                                    coeff1[s * layersCollapse + l + std::log2(slots)][k] * temp[u][k];
                            else if (t == 2)
                                coeff[s][u + (1 << (l + 1))][k] +=
                                    coeff1[s * layersCollapse + l + 2 * std::log2(slots)][k] * temp[u][k];
                        }
                    }
                }
            }
        }
    }

    if (flagRem) {
        size_t s = rowsCollapse;

        for (size_t l = 0; l < remCollapse; ++l) {
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
                for (size_t t = 0; t < 3; ++t) {
                    for (size_t u = 0; u < (static_cast<uint32_t>(1) << (l + 1)) - 1; ++u) {
                        for (size_t k = 0; k < slots; ++k) {
                            if (t == 0)
                                coeff[s][u][k] += coeff1[s * layersCollapse + l][k] * temp[u][k];
                            else if (t == 1)
                                coeff[s][u + (1 << l)][k] +=
                                    coeff1[s * layersCollapse + l + std::log2(slots)][k] * temp[u][k];
                            else if (t == 2)
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
    uint32_t layers = static_cast<uint32_t>(ceil(static_cast<double>(logSlots) / budget));
    uint32_t rows   = logSlots / layers;
    uint32_t rem    = logSlots % layers;
    uint32_t dim    = (rem == 0) ? rows : (rows + 1);

    // the above choice ensures dim <= budget
    if (dim < budget) {
        if (layers < 2)
            OPENFHE_THROW(math_error, "layers must not be less than 2");

        // if layers is 0 then "layers -= 1" which means that layers is overflown
        // if layers is 1 then we get "rows = logSlots / 0";
        --layers;
        rows = logSlots / layers;
        rem  = logSlots - rows * layers;
        dim  = (rem == 0) ? rows : (rows + 1);

        // the above choice endures dim >=budget
        while (dim != budget) {
            if (rows == 0)
                OPENFHE_THROW(math_error, "rows must not be zero");

            --rows;
            rem = logSlots - rows * layers;
            dim = (rem == 0) ? rows : (rows + 1);
        }
    }

    return {layers, rows, rem};
}

std::vector<int32_t> GetCollapsedFFTParams(uint32_t slots, uint32_t levelBudget, uint32_t dim1) {
    // Need to compute how many layers are collapsed in each of the level from the budget.
    // If there is no exact division between the maximum number of possible levels (log(slots)) and the
    // level budget, the last level will contain the remaining layers collapsed.
    std::vector<uint32_t> dims = SelectLayers(std::log2(slots), levelBudget);
    uint32_t layersCollapse    = dims[0];
    uint32_t remCollapse       = dims[2];

    bool flagRem = (remCollapse == 0) ? false : true;

    uint32_t numRotations    = (static_cast<uint32_t>(1) << (layersCollapse + 1)) - 1;
    uint32_t numRotationsRem = (static_cast<uint32_t>(1) << (remCollapse + 1)) - 1;

    // Computing the baby-step b and the giant-step g for the collapsed layers for decoding.
    uint32_t g = 0;
    if (dim1 == 0 || dim1 > numRotations) {
        if (numRotations > 7) {
            g = (static_cast<uint32_t>(1) << (layersCollapse / 2 + 2));
        }
        else {
            g = (static_cast<uint32_t>(1) << (layersCollapse / 2 + 1));
        }
    }
    else {
        g = dim1;
    }

    uint32_t b    = (numRotations + 1) / g;
    uint32_t bRem = 0;
    uint32_t gRem = 0;

    if (flagRem) {
        if (numRotationsRem > 7) {
            gRem = (static_cast<uint32_t>(1) << (remCollapse / 2 + 2));
        }
        else {
            gRem = (static_cast<uint32_t>(1) << (remCollapse / 2 + 1));
        }
        bRem = (numRotationsRem + 1) / gRem;
    }

    // If this return statement changes anything (including the order of returned values) then CKKS_BOOT_PARAMS should be altered as well
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

}  // namespace lbcrypto
