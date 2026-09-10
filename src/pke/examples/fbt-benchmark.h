// BSD 2-Clause License; see LICENSE. Adapted from the ac-81 research driver.
#pragma once
#include "openfhe.h"
#include <algorithm>
#include <complex>
#include <vector>

namespace fbt_artifact {
using namespace lbcrypto;
DCRTPoly DecryptCore(const std::vector<DCRTPoly>& cv, const PrivateKey<DCRTPoly> privateKey) {
    const DCRTPoly& s = privateKey->GetPrivateElement();

    size_t sizeQ  = s.GetParams()->GetParams().size();
    size_t sizeQl = cv[0].GetParams()->GetParams().size();

    size_t diffQl = sizeQ - sizeQl;

    auto scopy(s);
    scopy.DropLastElements(diffQl);

    DCRTPoly sPower(scopy);

    DCRTPoly b(cv[0]);
    b.SetFormat(Format::EVALUATION);

    DCRTPoly ci;
    for (size_t i = 1; i < cv.size(); i++) {
        ci = cv[i];
        ci.SetFormat(Format::EVALUATION);

        b += sPower * ci;
        sPower *= scopy;
    }
    return b;
}

std::vector<std::complex<double>> multiplyByUComplex(std::vector<double> input) {
    // Original computes:
    // result[i] = sum_{j=0}^{2*slots-1} input[j] * exp(2*pi*i*j*rotGroup[i]/m)
    //
    // This is an unnormalized inverse DFT of length m = 4*slots,
    // where input is zero-padded from length 2*slots to length m.

    if (input.size() % 2 != 0) {
        throw std::invalid_argument("input.size() must be even");
    }

    const size_t slots = input.size() / 2;
    const size_t m     = 4 * slots;

    if (m == 0 || (m & (m - 1)) != 0) {
        throw std::invalid_argument("m = 4 * slots must be a power of two");
    }

    std::vector<std::complex<double>> a(m, std::complex<double>(0.0, 0.0));
    for (size_t i = 0; i < input.size(); ++i) {
        a[i] = std::complex<double>(input[i], 0.0);
    }

    // Bit-reversal permutation.
    for (size_t i = 1, j = 0; i < m; ++i) {
        size_t bit = m >> 1;
        for (; j & bit; bit >>= 1) {
            j ^= bit;
        }
        j ^= bit;

        if (i < j) {
            std::swap(a[i], a[j]);
        }
    }

    // Unnormalized inverse FFT:
    // a[k] = sum_j input[j] * exp(+2*pi*i*j*k/m)
    const double pi = std::acos(-1.0);

    for (size_t len = 2; len <= m; len <<= 1) {
        const double angle = 2.0 * pi / static_cast<double>(len);
        const std::complex<double> wLen(std::cos(angle), std::sin(angle));

        for (size_t start = 0; start < m; start += len) {
            std::complex<double> w(1.0, 0.0);

            for (size_t j = 0; j < len / 2; ++j) {
                const std::complex<double> u = a[start + j];
                const std::complex<double> v = a[start + j + len / 2] * w;

                a[start + j]           = u + v;
                a[start + j + len / 2] = u - v;

                w *= wLen;
            }
        }
    }

    // Gather primitive-root indices: 1, 5, 5^2, ... mod m.
    std::vector<std::complex<double>> result(slots);

    const size_t mmask = m - 1;
    size_t fivePows    = 1;

    for (size_t i = 0; i < slots; ++i) {
        result[i] = a[fivePows & mmask];
        fivePows  = (fivePows * 5) & mmask;
    }

    return result;
}
// Worst Euclidean complex residual modulo the LUT grid, as in the paper driver.
inline double MeasureSlotNoise(ConstCiphertext<DCRTPoly> ct, const PrivateKey<DCRTPoly>& key, uint32_t p,
                               uint32_t slots, bool sparse, double correction) {
    auto b = DecryptCore(ct->GetElements(), key);
    b.SetFormat(Format::COEFFICIENT);
    auto polynomial = b.CRTInterpolate();
    const auto q    = b.GetParams()->GetModulus();
    const auto half = q >> 1;
    std::vector<double> values;
    const uint32_t stride = sparse ? std::max(1U, b.GetRingDimension() / (4 * slots)) : 1;
    for (uint32_t i = 0; i < b.GetRingDimension(); i += stride) {
        auto value          = polynomial[i];
        const bool negative = value > half;
        if (negative)
            value = q - value;
        values.push_back((negative ? -1 : 1) * value.ConvertToDouble() / ct->GetScalingFactor() * correction);
    }
    double worst = 0;
    for (auto z : multiplyByUComplex(values)) {
        auto nearest = std::complex<double>(std::round(z.real() * p) / p, std::round(z.imag() * p) / p);
        worst        = std::max(worst, std::abs(z - nearest));
    }
    return std::log2(worst);
}
}  // namespace fbt_artifact
