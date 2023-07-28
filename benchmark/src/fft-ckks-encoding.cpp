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
#define _USE_MATH_DEFINES
#include "math/distributiongenerator.h"
#include "math/dftransform.h"

#include "benchmark/benchmark.h"

#include <random>

using namespace lbcrypto;

/**
 * GenerateRandNumberVector generates a vector of real values in the range (-1,1)
 * @param vecSize is number of elements in the returned vector
 * @return generated vector
*/
std::vector<std::complex<double>> GenerateRandNumberVector(size_t vecSize) {
    std::vector<std::complex<double>> result(vecSize);

    std::uniform_real_distribution<double> uniform_real(-1.0, 1.0);
    for (size_t i = 0; i < vecSize; ++i) {
        result[i] = std::complex<double>(uniform_real(PseudoRandomNumberGenerator::GetPRNG()), 0);
    }

    return result;
}

//=====================================================================================================================
void FFTSpecial_RingDim4096(benchmark::State& state) {
    const uint32_t ringDim                 = 4096;
    std::vector<std::complex<double>> vals = GenerateRandNumberVector(ringDim / 4);
    DiscreteFourierTransform::Initialize(ringDim * 2, ringDim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::FFTSpecial(vals, ringDim * 2);
    }
}
BENCHMARK(FFTSpecial_RingDim4096)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================
void FFTSpecialInv_RingDim4096(benchmark::State& state) {
    const uint32_t ringDim                 = 4096;
    std::vector<std::complex<double>> vals = GenerateRandNumberVector(ringDim / 4);
    DiscreteFourierTransform::Initialize(ringDim * 2, ringDim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::FFTSpecialInv(vals, ringDim * 2);
    }
}
BENCHMARK(FFTSpecialInv_RingDim4096)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================
void FFTSpecial_RingDim16384(benchmark::State& state) {
    const uint32_t ringDim                 = 16384;
    std::vector<std::complex<double>> vals = GenerateRandNumberVector(ringDim / 4);
    DiscreteFourierTransform::Initialize(ringDim * 2, ringDim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::FFTSpecial(vals, ringDim * 2);
    }
}
BENCHMARK(FFTSpecial_RingDim16384)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================
void FFTSpecialInv_RingDim16384(benchmark::State& state) {
    const uint32_t ringDim                 = 16384;
    std::vector<std::complex<double>> vals = GenerateRandNumberVector(ringDim / 4);
    DiscreteFourierTransform::Initialize(ringDim * 2, ringDim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::FFTSpecialInv(vals, ringDim * 2);
    }
}
BENCHMARK(FFTSpecialInv_RingDim16384)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================
void FFTSpecial_RingDim65536(benchmark::State& state) {
    const uint32_t ringDim                 = 65536;
    std::vector<std::complex<double>> vals = GenerateRandNumberVector(ringDim / 4);
    DiscreteFourierTransform::Initialize(ringDim * 2, ringDim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::FFTSpecial(vals, ringDim * 2);
    }
}
BENCHMARK(FFTSpecial_RingDim65536)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================
void FFTSpecialInv_RingDim65536(benchmark::State& state) {
    const uint32_t ringDim                 = 65536;
    std::vector<std::complex<double>> vals = GenerateRandNumberVector(ringDim / 4);
    DiscreteFourierTransform::Initialize(ringDim * 2, ringDim / 2);

    while (state.KeepRunning()) {
        DiscreteFourierTransform::FFTSpecialInv(vals, ringDim * 2);
    }
}
BENCHMARK(FFTSpecialInv_RingDim65536)->Unit(benchmark::kMicrosecond);
//=====================================================================================================================

BENCHMARK_MAIN();
